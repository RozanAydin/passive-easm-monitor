"""Risk scoring and severity classification rules for EASM & brand findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

SEVERITY_RANK: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

DEFAULT_SENSITIVE_PORTS: frozenset[int] = frozenset(
    {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017}
)

RECENT_REG_DAYS = 90
OLD_REG_DAYS = 365 * 5


def meets_severity_threshold(severity: str, min_severity: str) -> bool:
    """Return True if severity >= min_severity according to the severity hierarchy."""
    return SEVERITY_RANK.get(severity.upper(), 0) >= SEVERITY_RANK.get(min_severity.upper(), 0)


def _parse_registration_age_days(
    registration_date: str | None,
    now: datetime | None = None,
) -> int | None:
    """Parse an RDAP ISO registration timestamp and return age in days."""
    if not registration_date:
        return None
    raw = registration_date.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        try:
            parsed = datetime.strptime(raw[:10], "%Y-%m-%d")
        except ValueError:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    ref = now or datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    delta = ref - parsed
    return max(0, delta.days)


def score_new_subdomain(
    is_resolving: bool,
    open_ports: Iterable[int] = (),
    cves: Iterable[str] = (),
    sensitive_ports: Iterable[int] = DEFAULT_SENSITIVE_PORTS,
) -> str:
    """Classify severity of a newly discovered subdomain."""
    ports_set = set(open_ports)
    cve_list = list(cves)
    sensitive_set = set(sensitive_ports)

    if not is_resolving:
        return "LOW"
    if cve_list or (ports_set & sensitive_set):
        return "CRITICAL"
    return "MEDIUM"


def score_new_ports(
    new_ports: Iterable[int],
    sensitive_ports: Iterable[int] = DEFAULT_SENSITIVE_PORTS,
) -> str:
    """Classify severity when new open ports appear on an existing asset."""
    ports_set = set(new_ports)
    sensitive_set = set(sensitive_ports)
    if ports_set & sensitive_set:
        return "CRITICAL"
    return "HIGH"


def score_new_cves() -> str:
    """Classify severity when new CVEs are detected on an existing asset."""
    return "CRITICAL"


def score_typosquat(
    has_a_record: bool,
    has_mx_record: bool,
    registration_date: str | None = None,
    now: datetime | None = None,
) -> str:
    """Classify severity of a typosquatting domain based on DNS activity and registration age.

    Rules:
    - CRITICAL: Registered within the last 90 days AND has active MX records.
    - HIGH: Active MX records (potential phishing / BEC risk).
    - MEDIUM: Active A/AAAA web IP without MX records.
    - LOW: Registered > 5 years ago with no active web IP or MX (or inactive DNS).
    """
    age_days = _parse_registration_age_days(registration_date, now=now)

    if has_mx_record:
        if age_days is not None and age_days <= RECENT_REG_DAYS:
            return "CRITICAL"
        return "HIGH"

    if has_a_record:
        return "MEDIUM"

    if age_days is not None and age_days > OLD_REG_DAYS:
        return "LOW"
    return "LOW"


def score_ip_change() -> str:
    """Classify severity when an existing subdomain changes its resolved IP."""
    return "MEDIUM"


def recommend_action(
    category: str,
    indicator: str,
    sensitive_ports_found: list[int] | None = None,
    cves: list[str] | None = None,
    has_mx_record: bool = False,
) -> str:
    """Generate a professional English remediation recommendation for an IoC / alert."""
    cat = category.upper()
    if cat == "TYPOSQUAT_ACTIVE":
        if has_mx_record:
            return (
                f"Initiate a domain takedown request for {indicator} and block sender traffic "
                "from this domain on your Secure Email Gateway (SEG)."
            )
        return (
            f"Monitor lookalike domain {indicator}, verify brand ownership, and consider "
            "blocking resolution on corporate DNS resolvers and web proxies."
        )
    if cat in {"NEW_PORT", "NEW_SUBDOMAIN"} and sensitive_ports_found:
        ports_str = ", ".join(str(p) for p in sorted(sensitive_ports_found))
        return (
            f"Verify ownership of {indicator} and restrict public internet exposure on "
            f"sensitive port(s) ({ports_str}) via firewall or security group rules."
        )
    if cat == "NEW_CVE" or cves:
        cve_str = ", ".join(cves[:5]) if cves else "associated vulnerabilities"
        return (
            f"Prioritize patch management and validate remediation for ({cve_str}) on {indicator}."
        )
    if cat == "IP_CHANGE":
        return (
            f"Confirm legitimacy of the DNS IP change for {indicator} to rule out "
            "unauthorized DNS modification or subdomain takeover."
        )
    if cat == "NEW_SUBDOMAIN":
        return (
            f"Verify {indicator} against your asset inventory (CMDB) and ensure baseline "
            "security hardening and TLS policies are enforced."
        )
    return f"Investigate {cat} finding associated with indicator {indicator}."
