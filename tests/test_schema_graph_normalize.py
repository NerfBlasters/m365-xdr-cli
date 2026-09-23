from __future__ import annotations

import pytest

from xdr_cli.schema_graph.normalize import NormalizationError, normalize_value


@pytest.mark.parametrize(
    ("normalizer", "source", "expected"),
    [
        (
            "guid-lower",
            "A0B1C2D3-E4F5-4678-9ABC-0123456789AB",
            "a0b1c2d3-e4f5-4678-9abc-0123456789ab",
        ),
        ("upn-lower", "User@EXAMPLE.COM", "user@example.com"),
        ("smtp-lower", "Sender@Example.com", "sender@example.com"),
        ("ip-canonical", "2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
        ("sha1-lower", "A" * 40, "a" * 40),
        ("sha256-lower", "A" * 64, "a" * 64),
        ("hex40-lower", "B" * 40, "b" * 40),
        ("hostname-lower", "HOST.Example.COM.", "host.example.com"),
        ("domain-lower", "Sub.Example.COM.", "sub.example.com"),
        ("url-canonical", "HTTPS://Example.COM:443/a?q=1#fragment", "https://example.com/a?q=1"),
        ("url-canonical", "http://[2001:0db8::1]:80/a", "http://[2001:db8::1]/a"),
        (
            "url-canonical",
            "https://[2001:db8::1]:8443/a",
            "https://[2001:db8::1]:8443/a",
        ),
    ],
)
def test_normalizers_are_deterministic(normalizer, source, expected):
    assert normalize_value(normalizer, source) == expected
    assert normalize_value(normalizer, source) == expected


@pytest.mark.parametrize(
    ("normalizer", "value"),
    [
        ("guid-lower", "00000000-0000-0000-0000-000000000000"),
        ("upn-lower", "not-an-address"),
        ("ip-canonical", "999.1.1.1"),
        ("sha1-lower", "a" * 64),
        ("sha256-lower", "a" * 40),
        ("hex40-lower", "a" * 64),
        ("hostname-lower", "bad host"),
        ("domain-lower", "process.exe/path"),
        ("url-canonical", "file:///tmp/data"),
        ("url-canonical", "https://user:password@example.com/"),
        ("not-registered", "anything"),
    ],
)
def test_normalizers_fail_closed(normalizer, value):
    with pytest.raises(NormalizationError):
        normalize_value(normalizer, value)
