"""Strict domain and allowlist input validation & normalization (SSRF/injection defense)."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

# Reject shell metacharacters, whitespace, wildcards, credentials, or query/fragment delimiters
FORBIDDEN_CHARS_REGEX = re.compile(r"[\s;@*?$`|\\<>'\"(){}\[\]!#&]")

# RFC-compliant FQDN: labels 1-63 alphanumeric/hyphen, non-numeric TLD >= 2 chars (or punycode xn--)
FQDN_REGEX = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9]{1,59})$"
)

WILDCARD_SUBDOMAIN_REGEX = re.compile(
    r"^\*\.(?=.{1,251}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9]{1,59})$"
)

RESERVED_HOSTNAMES = frozenset({"localhost", "localhost.localdomain"})
RESERVED_TLDS = (".local", ".internal", ".localhost", ".arpa", ".lan", ".home", ".corp")


def _strip_scheme_and_path(raw: str) -> str:
    """Normalize whitespace, lowercase, remove http(s):// prefix, paths, and trailing dot."""
    cleaned = raw.strip().lower()
    if "://" in cleaned:
        scheme, rest = cleaned.split("://", 1)
        if scheme not in {"http", "https"}:
            raise ValueError(f"Unsupported URL scheme in domain input: '{raw}'")
        cleaned = rest
    # Remove any URL path, query, or fragment after host
    cleaned = cleaned.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    cleaned = cleaned.rstrip(".")
    return cleaned


def _reject_ip_and_reserved(host: str, original: str) -> None:
    """Reject IPv4/IPv6 addresses and internal/reserved hostnames to prevent SSRF."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        raise ValueError(f"IP addresses are not permitted as domain targets: '{original}'")
    except ValueError as exc:
        if "not permitted" in str(exc):
            raise

    if host in RESERVED_HOSTNAMES or any(host.endswith(suffix) for suffix in RESERVED_TLDS):
        raise ValueError(
            f"Reserved or internal hostname is not permitted: '{original}'"
        )


def validate_and_normalize_domain(value: str) -> str:
    """Validate and normalize a domain name against strict RFC FQDN and SSRF rules."""
    if not isinstance(value, str):
        raise ValueError("Domain must be a string.")

    raw_stripped = value.strip()
    if not raw_stripped:
        raise ValueError("Domain cannot be empty.")

    if FORBIDDEN_CHARS_REGEX.search(raw_stripped):
        raise ValueError(f"Invalid domain format (forbidden characters): '{value}'")

    normalized = _strip_scheme_and_path(raw_stripped)
    if not normalized or ":" in normalized:
        raise ValueError(f"Invalid domain format: '{value}'")

    _reject_ip_and_reserved(normalized, value)

    if not FQDN_REGEX.match(normalized):
        raise ValueError(f"Invalid domain format: '{value}'")

    return normalized


def validate_allowlist_entry(value: str, allow_wildcard: bool = True) -> str:
    """Validate and normalize a domain or subdomain allowlist pattern."""
    if not isinstance(value, str):
        raise ValueError("Allowlist entry must be a string.")

    raw_stripped = value.strip()
    if not raw_stripped:
        raise ValueError("Allowlist entry cannot be empty.")

    # Allow leading '*.' for wildcard subdomain exclusions when allow_wildcard is True
    check_target = raw_stripped[2:] if allow_wildcard and raw_stripped.startswith("*.") else raw_stripped
    if FORBIDDEN_CHARS_REGEX.search(check_target):
        raise ValueError(f"Invalid allowlist entry (forbidden characters): '{value}'")

    if allow_wildcard and raw_stripped.startswith("*."):
        normalized = "*." + _strip_scheme_and_path(raw_stripped[2:])
        _reject_ip_and_reserved(normalized[2:], value)
        if not WILDCARD_SUBDOMAIN_REGEX.match(normalized):
            raise ValueError(f"Invalid wildcard allowlist format: '{value}'")
        return normalized

    return validate_and_normalize_domain(raw_stripped)


def parse_allowlist_input(raw: str | Iterable[str] | None) -> list[str]:
    """Parse comma-separated string or iterable into validated unique allowlist entries."""
    if raw is None:
        return []
    if isinstance(raw, str):
        items = [part.strip() for part in raw.split(",") if part.strip()]
    else:
        items = [str(part).strip() for part in raw if str(part).strip()]

    seen: list[str] = []
    seen_set: set[str] = set()
    for item in items:
        validated = validate_allowlist_entry(item, allow_wildcard=True)
        if validated not in seen_set:
            seen_set.add(validated)
            seen.append(validated)
    return seen


def is_domain_allowlisted(domain: str, allowlist: Iterable[str]) -> bool:
    """Return True if domain matches an exact or wildcard entry in allowlist."""
    normalized = domain.strip().lower().rstrip(".")
    for pattern in allowlist:
        pat = pattern.strip().lower().rstrip(".")
        if not pat:
            continue
        if pat.startswith("*."):
            suffix = pat[1:]
            if normalized.endswith(suffix) or normalized == pat[2:]:
                return True
        elif normalized == pat:
            return True
    return False
