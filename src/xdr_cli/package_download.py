"""Private archive transfer, isolated from portal credentials and signed-URL output."""
from __future__ import annotations

import contextlib
import hashlib
import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path

import httpx

from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    ConflictError,
    NetworkError,
    RateLimitError,
    TimeoutError,
    UsageError,
    parse_retry_after,
)

DEFAULT_MAX_BYTES = 1024 * 1024 * 1024


def validate_package_url(value: str) -> None:
    """Accept only the observed public Azure Blob HTTPS signed-link contract."""
    try:
        url = httpx.URL(value)
        valid = (
            url.scheme == "https" and url.port in (None, 443)
            and re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", url.host)
            and not url.userinfo and not url.fragment
            and len(url.params.get_list("sig")) == 1 and bool(url.params.get("sig"))
        )
    except (httpx.InvalidURL, ValueError, TypeError):
        valid = False
    if not valid:
        raise APIError("Portal returned an unsupported package download URL.")


def package_destination(output: Path, *, force: bool) -> Path:
    """Preflight without following the final path component."""
    expanded = output.expanduser()
    try:
        destination = expanded.parent.resolve(strict=True) / expanded.name
        mode = destination.parent.stat().st_mode
        if not stat.S_ISDIR(mode):
            raise ArtifactError("Package output parent must be a directory.")
        if os.name == "posix" and mode & 0o022 and not mode & stat.S_ISVTX:
            raise ArtifactError("Package output requires a private or sticky directory.")
        if os.path.lexists(destination):
            if not force:
                raise ConflictError("Package output already exists; use --force to replace it.")
            if destination.is_dir() and not destination.is_symlink():
                raise ConflictError("Package output is an existing directory.")
        return destination
    except OSError:
        raise ArtifactError("Could not access the package output directory.") from None


async def download_package_archive(
    url: str, output: Path, *, force: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES, timeout: float = 120,
) -> dict:
    """Stream once, check the ZIP container, and atomically publish a private file."""
    validate_package_url(url)
    if type(max_bytes) is not int or max_bytes < 1:
        raise UsageError("--max-bytes must be a positive integer.")
    destination = package_destination(output, force=force)
    temp_path = None
    identity = None
    total = 0
    digest = hashlib.sha256()
    try:
        fd, name = tempfile.mkstemp(prefix=".xdr-package-", suffix=".tmp", dir=destination.parent)
        temp_path = Path(name)
        with os.fdopen(fd, "w+b") as sink:
            identity = os.fstat(sink.fileno())
            # No shared cookie jar, auth, tenant headers, redirects, or environment credentials.
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=False, trust_env=False,
                headers={"Accept-Encoding": "identity"},
            ) as client, client.stream("GET", url) as response:
                if response.status_code == 429:
                    raise RateLimitError(parse_retry_after(response.headers.get("Retry-After")))
                if response.status_code != 200:
                    raise APIError(
                        "Package transfer failed; request a fresh link by rerunning the command.",
                        status_code=response.status_code,
                    )
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise APIError("Package transfer used an unsupported content encoding.")
                length = response.headers.get("content-length")
                if length is not None and not re.fullmatch(r"[0-9]+", length):
                    raise APIError("Package transfer returned an invalid Content-Length.")
                expected = int(length) if length is not None else None
                if expected is not None and expected > max_bytes:
                    raise APIError("Package exceeds --max-bytes; no output was published.")
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    total += len(chunk)
                    if total > max_bytes:
                        raise APIError("Package exceeds --max-bytes; no output was published.")
                    sink.write(chunk)
                    digest.update(chunk)
                if expected is not None and total != expected:
                    raise APIError("Package transfer length mismatch; no output was published.")
            sink.flush()
            sink.seek(0)
            if not zipfile.is_zipfile(sink):
                raise APIError("Package response is not a complete ZIP container.")
            os.fsync(sink.fileno())
            current = temp_path.lstat()
            if (not stat.S_ISREG(current.st_mode)
                    or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)):
                raise ArtifactError("Package staging file changed; no output was published.")
        if force:
            os.replace(temp_path, destination)
        else:
            os.link(temp_path, destination)
        return {
            "data_path": str(destination), "bytes": total, "sha256": digest.hexdigest(),
            "archive_format": "zip", "validation": "zip-container", "extracted": False,
        }
    except httpx.TimeoutException:
        raise TimeoutError("Package transfer timed out; no output was published.") from None
    except httpx.TransportError:
        raise NetworkError("Package transfer failed; no output was published.") from None
    except FileExistsError:
        raise ConflictError(
            "Package output was created concurrently; no file was replaced."
        ) from None
    except OSError:
        raise ArtifactError("Could not write or publish the private package archive.") from None
    finally:
        if temp_path is not None and identity is not None:
            with contextlib.suppress(OSError):
                current = temp_path.lstat()
                if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    temp_path.unlink()
