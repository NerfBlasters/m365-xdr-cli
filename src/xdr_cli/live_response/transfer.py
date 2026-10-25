"""Bounded private Live Response transfers without content execution or extraction."""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import tempfile
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    ConflictError,
    LiveResponseSizeLimitError,
    NetworkError,
    RateLimitError,
    TimeoutError,
    UsageError,
    parse_retry_after,
)
from xdr_cli.package_download import package_destination, validate_package_url

DEFAULT_MAX_BYTES = 3 * 1024**3
LIBRARY_MAX_BYTES = 250 * 1024**2


@contextmanager
def open_library_source(path: Path):
    """Reject devices/FIFOs before a blocking read or any network submission."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > LIBRARY_MAX_BYTES:
                raise UsageError("Live Response upload requires a regular file of at most 250 MiB.")
            yield source
    except OSError:
        raise ArtifactError("Could not open the regular Live Response upload file.") from None


@dataclass(frozen=True, repr=False)
class SignedTransfer:
    """Private one-use transfer descriptor; authentication never appears in repr."""

    _url: str | None = field(default=None, repr=False)
    expires_at: str | None = None
    expected_kind: str = "raw"
    _stream_factory: Callable[[], AbstractAsyncContextManager[httpx.Response]] | None = field(
        default=None,
        repr=False,
    )

    def __repr__(self) -> str:
        return f"SignedTransfer(kind={self.expected_kind!r}, location=<private>)"


async def download_transfer(
    transfer: SignedTransfer,
    dest: Path,
    *,
    force: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = 120,
) -> dict:
    """Publish complete bytes atomically; download URLs and credentials stay private."""
    if type(max_bytes) is not int or max_bytes < 1:
        raise UsageError("--max-bytes must be a positive integer.")
    destination = package_destination(dest, force=force)
    if transfer._stream_factory is None:
        validate_package_url(transfer._url)
    staged = None
    identity = None
    total = 0
    head = b""
    digest = hashlib.sha256()
    try:
        fd, name = tempfile.mkstemp(prefix=".xdr-lr-", dir=destination.parent)
        staged = Path(name)
        with os.fdopen(fd, "wb") as sink:
            identity = os.fstat(sink.fileno())
            async with contextlib.AsyncExitStack() as stack:
                if transfer._stream_factory is not None:
                    stream = transfer._stream_factory()
                else:
                    client = await stack.enter_async_context(
                        httpx.AsyncClient(
                            timeout=timeout,
                            follow_redirects=False,
                            trust_env=False,
                            headers={"Accept-Encoding": "identity"},
                        )
                    )
                    stream = client.stream("GET", transfer._url)
                response = await stack.enter_async_context(stream)
                if response.status_code == 429:
                    raise RateLimitError(parse_retry_after(response.headers.get("Retry-After")))
                if response.status_code != 200:
                    raise APIError(
                        "Live Response transfer failed; request a fresh result link.",
                        status_code=response.status_code,
                    )
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise APIError("Live Response transfer used an unsupported content encoding.")
                if "text/html" in response.headers.get("content-type", "").lower():
                    raise APIError(
                        "Live Response transfer returned an HTML page instead of file bytes."
                    )
                length = response.headers.get("content-length")
                if length is not None and (not length.isascii() or not length.isdecimal()):
                    raise APIError("Live Response transfer returned an invalid Content-Length.")
                expected = int(length) if length is not None else None
                if expected is not None and expected > max_bytes:
                    raise LiveResponseSizeLimitError("Live Response download exceeds --max-bytes.")
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    total += len(chunk)
                    if total > max_bytes:
                        raise LiveResponseSizeLimitError(
                            "Live Response download exceeds --max-bytes."
                        )
                    if len(head) < 2:
                        head += chunk[:2 - len(head)]
                    sink.write(chunk)
                    digest.update(chunk)
                if expected is not None and total != expected:
                    raise APIError("Live Response transfer length mismatch.")
            sink.flush()
            os.fsync(sink.fileno())
        current = staged.lstat()
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
            identity.st_dev,
            identity.st_ino,
        ):
            raise ArtifactError("Live Response staging file changed.")
        if force:
            os.replace(staged, destination)
        else:
            os.link(staged, destination)
        return {
            "data_path": str(destination),
            "bytes": total,
            "sha256": digest.hexdigest(),
            # Official GetFile results arrive gzip-wrapped; label what was saved.
            "kind": "gzip" if head == b"\x1f\x8b" else transfer.expected_kind,
            "extracted": False,
        }
    except httpx.TimeoutException:
        raise TimeoutError("Live Response transfer timed out; no file was published.") from None
    except httpx.TransportError:
        raise NetworkError("Live Response transfer failed; no file was published.") from None
    except FileExistsError:
        raise ConflictError(
            "Live Response output already exists; use --force to replace it."
        ) from None
    except OSError:
        raise ArtifactError("Could not publish the private Live Response download.") from None
    finally:
        if staged is not None and identity is not None:
            with contextlib.suppress(OSError):
                current = staged.lstat()
                if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    staged.unlink()
