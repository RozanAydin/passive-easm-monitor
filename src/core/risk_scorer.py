"""Risk scoring and severity classification rules for EASM & brand findings."""

from __future__ import annotations

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


def meets_severity_threshold(severity: str, min_severity: str) -> bool:
    """Return True if severity >= min_severity according to the severity hierarchy."""
    return SEVERITY_RANK.get(severity.upper(), 0) >= SEVERITY_RANK.get(min_severity.upper(), 0)


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


def score_typosquat(has_a_record: bool, has_mx_record: bool) -> str:
    """Classify severity of an active typosquatting domain."""
    if has_mx_record or has_a_record:
        return "HIGH"
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
    """Generate an actionable remediation recommendation for an IoC / alert."""
    cat = category.upper()
    if cat == "TYPOSQUAT_ACTIVE":
        if has_mx_record:
            return (
                f"Ajukan takedown domain {indicator} dan blokir domain pengirim pada Secure Email Gateway."
            )
        return (
            f"Pantau domain tiruan {indicator}, verifikasi kepemilikan, dan pertimbangkan pemblokiran pada DNS/web proxy."
        )
    if cat in {"NEW_PORT", "NEW_SUBDOMAIN"} and sensitive_ports_found:
        ports_str = ", ".join(str(p) for p in sorted(sensitive_ports_found))
        return (
            f"Verifikasi kepemilikan aset {indicator} dan batasi akses port sensitif ({ports_str}) dari internet publik."
        )
    if cat == "NEW_CVE" or cves:
        cve_str = ", ".join(cves[:5]) if cves else "terkait"
        return (
            f"Lakukan patch management dan verifikasi kerentanan ({cve_str}) pada aset {indicator}."
        )
    if cat == "IP_CHANGE":
        return f"Konfirmasi legitimasi perubahan DNS A record untuk {indicator} guna mencegah subdomain takeover."
    if cat == "NEW_SUBDOMAIN":
        return f"Verifikasi aset {indicator} dalam inventaris CMDB dan pastikan konfigurasi keamanan standar diterapkan."
    return f"Investigasi temuan {cat} pada indikator {indicator}."
