"""Closed deterministic value-normalization registry for graph identifiers."""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Callable
from urllib.parse import SplitResult, urlsplit, urlunsplit


class NormalizationError(ValueError):
    """A value is invalid for the selected identifier namespace."""


_EMAIL = re.compile(r"^[^\s@]{1,128}@[^\s@]{1,255}$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise NormalizationError("identifier value must be a string")
    text = value.strip()
    if not text:
        raise NormalizationError("identifier value cannot be empty")
    return text


def _identity(value: object) -> str:
    return _string(value)


def _guid_lower(value: object) -> str:
    text = _string(value)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise NormalizationError("value is not a GUID") from exc
    if parsed.int == 0:
        raise NormalizationError("zero GUID is not a discriminative identifier")
    return str(parsed)


def _address_lower(value: object) -> str:
    text = _string(value)
    if not _EMAIL.fullmatch(text):
        raise NormalizationError("value is not a UPN or SMTP address")
    local, domain = text.rsplit("@", 1)
    return f"{local.casefold()}@{_domain_lower(domain)}"


def _ip_canonical(value: object) -> str:
    try:
        return ipaddress.ip_address(_string(value)).compressed
    except ValueError as exc:
        raise NormalizationError("value is not an IPv4 or IPv6 address") from exc


def _sha1_lower(value: object) -> str:
    text = _string(value)
    if len(text) != 40 or not _HEX.fullmatch(text):
        raise NormalizationError("value is not a SHA-1 hex digest")
    return text.lower()


def _sha256_lower(value: object) -> str:
    text = _string(value)
    if len(text) != 64 or not _HEX.fullmatch(text):
        raise NormalizationError("value is not a SHA-256 hex digest")
    return text.lower()


def _hex40_lower(value: object) -> str:
    """Normalize a 40-hex opaque identifier without calling it a SHA-1."""

    text = _string(value)
    if len(text) != 40 or not _HEX.fullmatch(text):
        raise NormalizationError("value is not a 40-hex identifier")
    return text.lower()


def _hostname_lower(value: object) -> str:
    """Normalize MDE host labels while retaining short-name/FQDN semantics."""

    text = _string(value).rstrip(".")
    if (
        len(text) > 255
        or any(character.isspace() or ord(character) < 32 for character in text)
        or "/" in text
        or "\\" in text
    ):
        raise NormalizationError("value is not a bounded hostname")
    return text.casefold()


def _domain_lower(value: object) -> str:
    text = _string(value).rstrip(".")
    if "://" in text or "/" in text or "@" in text:
        raise NormalizationError("value is not a bare DNS domain")
    try:
        ascii_domain = text.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise NormalizationError("value is not a valid IDNA domain") from exc
    labels = ascii_domain.split(".")
    if (
        len(ascii_domain) > 253
        or len(labels) < 2
        or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
    ):
        raise NormalizationError("value is not a valid DNS domain")
    return ascii_domain


def _url_canonical(value: object) -> str:
    text = _string(value)
    parsed = urlsplit(text)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise NormalizationError("value is not an absolute HTTP(S) URL")
    raw_host = parsed.hostname
    try:
        ip_host = ipaddress.ip_address(raw_host)
    except ValueError:
        try:
            host = raw_host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise NormalizationError("URL host is invalid") from exc
    else:
        host = ip_host.compressed
        if ip_host.version == 6:
            host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError as exc:
        raise NormalizationError("URL port is invalid") from exc
    if port is None or (parsed.scheme.lower(), port) in {("http", 80), ("https", 443)}:
        authority = host
    else:
        authority = f"{host}:{port}"
    if parsed.username is not None or parsed.password is not None:
        raise NormalizationError("credential-bearing URLs are not graph identifiers")
    normalized = SplitResult(
        parsed.scheme.lower(),
        authority,
        parsed.path or "/",
        parsed.query,
        "",
    )
    return urlunsplit(normalized)


NORMALIZERS: dict[str, Callable[[object], str]] = {
    "domain-lower": _domain_lower,
    "guid-lower": _guid_lower,
    "hex40-lower": _hex40_lower,
    "hostname-lower": _hostname_lower,
    "identity": _identity,
    "ip-canonical": _ip_canonical,
    "sha1-lower": _sha1_lower,
    "sha256-lower": _sha256_lower,
    "smtp-lower": _address_lower,
    "upn-lower": _address_lower,
    "url-canonical": _url_canonical,
}


def normalize_value(normalizer: str, value: object) -> str:
    try:
        function = NORMALIZERS[normalizer]
    except KeyError as exc:
        raise NormalizationError(f"unknown normalizer: {normalizer}") from exc
    return function(value)
