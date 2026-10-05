"""HTTPS registration-data adapter for the pinned GuardDog 3.2.0 scanner.

Use IANA's RDAP bootstrap (RFC 9224) and domain responses (RFC 9083).
Only transport changes: GuardDog still evaluates its own email-domain rules.
"""

# The pinned GuardDog image runs Python 3.10, unlike the application.
# ruff: noqa: UP017

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
MAX_BYTES = 2 * 1024 * 1024
# .io is absent from IANA's bootstrap as of 2026-10-04. Registry service:
# https://www.identity.digital/help-articles/whois-faq
# Verified its authoritative /domain/stufft.io response before adding this
# routing supplement. It never overrides an IANA-listed HTTPS service.
SUPPLEMENTAL_SERVICES = {"io": "https://rdap.identitydigital.services/rdap/"}


def domain_name(value: str) -> str:
    """Accept a DNS name only, before passing it to WHOIS's suffix normalizer."""
    name = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if (
        len(name) > 253
        or "." not in name
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in name.split(".")
        )
    ):
        raise ValueError("Invalid maintainer domain")
    return name


def https_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise ValueError("RDAP requires an HTTPS endpoint without credentials")
    if parts.fragment or parts.port not in (None, 443):
        raise ValueError("Invalid RDAP endpoint")
    return url


class HTTPSRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class RDAPLookup:
    """Supply WHOIS-compatible creation_date objects and native absence errors.

    Cache within a scan, serializing lookups to avoid duplicate domain requests.
    Transport/schema errors propagate to GuardDog's native incomplete-scan gate.
    """

    def __init__(self, normalize, legacy_lookup, not_found):
        self.normalize = normalize
        self.legacy_lookup = legacy_lookup
        self.not_found = not_found
        self.opener = build_opener(HTTPSRedirects())
        self.evidence = []
        self.services = None
        self.cache = {}
        self.lock = threading.Lock()

    def request(self, url):
        https_url(url)
        for attempt in range(3):
            try:
                try:
                    response = self.opener.open(
                        Request(
                            url,
                            headers={
                                "Accept": "application/rdap+json, application/json",
                                "User-Agent": "xdr-cli-ci-rdap/1",
                            },
                        ),
                        timeout=15,
                    )
                except HTTPError as exc:
                    response = exc
                with response:
                    status = response.code
                    final_url = https_url(response.geturl())
                    raw = response.read(MAX_BYTES + 1)
                    retry_after = response.headers.get("Retry-After")
                if len(raw) > MAX_BYTES:
                    raise ValueError("RDAP response exceeds size limit")
                self.evidence.append(
                    {
                        "url": url,
                        "response_url": final_url,
                        "status": status,
                        "attempt": attempt + 1,
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
                if status in (429, 500, 502, 503, 504) and attempt < 2:
                    delay = (2, 5)[attempt]
                    if retry_after:
                        if retry_after.isdigit():
                            delay = max(delay, int(retry_after))
                        else:
                            retry_at = parsedate_to_datetime(retry_after)
                            delay = max(
                                delay, (retry_at - datetime.now(timezone.utc)).total_seconds()
                            )
                        if delay > 30:
                            raise ValueError("RDAP Retry-After exceeds bounded retry budget")
                    time.sleep(delay)
                    continue
                if status not in (200, 404):
                    raise ValueError(f"RDAP HTTP {status} at {url}")
                # RFC 7480 section 5.3 permits a negative answer without a body.
                # Accept it only from the exact authoritative URL requested.
                if status == 404 and not raw and final_url == url:
                    return status, None
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("RDAP response is not a JSON object")
                return status, data
            except (URLError, ConnectionError, TimeoutError) as exc:
                self.evidence.append(
                    {"url": url, "attempt": attempt + 1, "error": type(exc).__name__}
                )
                if attempt == 2:
                    raise
                time.sleep((2, 5)[attempt])
        raise AssertionError("unreachable")

    def endpoint(self, domain):
        if self.services is None:
            status, data = self.request(BOOTSTRAP)
            if status != 200 or not isinstance(data.get("services"), list):
                raise ValueError("Invalid IANA RDAP bootstrap")
            services = {}
            for suffixes, urls in data["services"]:
                if not isinstance(suffixes, list) or not isinstance(urls, list):
                    raise ValueError("Invalid IANA service entry")
                endpoints = [https_url(url) for url in urls if url.startswith("https:")]
                for suffix in suffixes:
                    services[suffix.lower()] = endpoints
            if not services:
                raise ValueError("Empty IANA RDAP bootstrap")
            self.services = services
        # RFC 9224: use the longest matching label-wise suffix.
        labels = domain.split(".")
        for index in range(len(labels)):
            urls = self.services.get(".".join(labels[index:]))
            if urls:
                return urls[0].rstrip("/") + "/domain/" + domain
        if labels[-1] in SUPPLEMENTAL_SERVICES:
            base = https_url(SUPPLEMENTAL_SERVICES[labels[-1]])
            self.evidence.append(
                {
                    "domain": domain,
                    "transport": "rdap",
                    "reason": "reviewed registry bootstrap supplement",
                    "service": base,
                }
            )
            return base + "domain/" + domain
        return None

    def __call__(self, value):
        name = domain_name(value)
        with self.lock:
            domain = domain_name(self.normalize(name))
            if domain not in self.cache:
                self.cache[domain] = self.lookup(domain)
            created, exists = self.cache[domain]
        if not exists:
            # This exact native exception convention drives the unclaimed rule.
            raise self.not_found(f"No match for {domain}")
        return SimpleNamespace(creation_date=created)

    def lookup(self, domain):
        url = self.endpoint(domain)
        if url is None:
            self.evidence.append(
                {"domain": domain, "transport": "whois", "reason": "no HTTPS IANA RDAP service"}
            )
            # Do not let python-whois hide socket errors as missing dates.
            result = self.legacy_lookup(domain, ignore_socket_errors=False)
            return result.creation_date, True
        status, data = self.request(url)
        if status == 404 and data is None:
            return None, False
        conformance = data.get("rdapConformance")
        if (
            not isinstance(conformance, list)
            or not all(isinstance(item, str) for item in conformance)
            or "rdap_level_0" not in conformance
        ):
            raise ValueError("Missing RDAP conformance declaration")
        if status == 404:
            if type(data.get("errorCode")) is not int or data["errorCode"] != 404:
                raise ValueError("Unverified RDAP not-found response")
            return None, False
        if (
            data.get("objectClassName") != "domain"
            or domain_name(data.get("ldhName", "")) != domain
        ):
            raise ValueError("RDAP response does not identify the requested domain")
        events = data.get("events", [])
        if not isinstance(events, list):
            raise ValueError("Invalid RDAP events")
        dates = []
        for event in events:
            if not isinstance(event, dict):
                raise ValueError("Invalid RDAP event")
            if (
                not isinstance(event.get("eventAction"), str)
                or not event["eventAction"]
                or not isinstance(event.get("eventDate"), str)
            ):
                raise ValueError("RDAP event lacks an action or date")
            value = event["eventDate"]
            # Python 3.10 fromisoformat accepts only 3/6 fractional digits;
            # RFC 3339 permits any precision. Normalize to microseconds first.
            value = re.sub(
                r"\.(\d+)(?=Z$|[+-]\d{2}:\d{2}$)",
                lambda match: "." + match[1][:6].ljust(6, "0"),
                value,
            )
            created = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if created.tzinfo is None:
                raise ValueError("RDAP event date lacks a timezone")
            if event["eventAction"] == "registration":
                dates.append(created.astimezone(timezone.utc))
        # Preserve GuardDog's existing registered-but-date-unavailable semantics.
        return min(dates) if dates else None, True
