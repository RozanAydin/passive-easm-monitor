"""Unit tests for strict domain normalization and SSRF/injection validation."""

from __future__ import annotations

import pytest

from src.utils.validators import (
    is_domain_allowlisted,
    parse_allowlist_input,
    validate_and_normalize_domain,
)


def test_validate_and_normalize_domain_accepts_valid_inputs() -> None:
    assert validate_and_normalize_domain("Example.COM") == "example.com"
    assert validate_and_normalize_domain("  https://OWASP.org/www-project/  ") == "owasp.org"
    assert validate_and_normalize_domain("http://sub.domain.co.id/") == "sub.domain.co.id"


@pytest.mark.parametrize(
    "bad_input",
    [
        "",
        "   ",
        "127.0.0.1",
        "192.168.1.10",
        "::1",
        "localhost",
        "api.localhost",
        "printer.local",
        "metadata.internal",
        "*.example.com",
        "example.com;id",
        "example.com && whoami",
        "$(whoami).example.com",
        "not-a-domain",
        "example.123",
        "example.com:8080",
    ],
)
def test_validate_and_normalize_domain_rejects_ssrf_and_injection(bad_input: str) -> None:
    with pytest.raises(ValueError):
        validate_and_normalize_domain(bad_input)


def test_allowlist_parsing_and_matching() -> None:
    parsed = parse_allowlist_input("Example.org, *.dev.example.com, example.org")
    assert parsed == ["example.org", "*.dev.example.com"]
    assert is_domain_allowlisted("example.org", parsed) is True
    assert is_domain_allowlisted("api.dev.example.com", parsed) is True
    assert is_domain_allowlisted("prod.example.com", parsed) is False
