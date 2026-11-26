"""State comparison (diffing) engine across consecutive scan runs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.collectors.dns_resolver import DNSResolutionResult
from src.collectors.typosquat import ActiveTyposquat
from src.core.database import (
    Alert,
    IPEnrichment,
    ScanRun,
    Subdomain,
    Target,
    TyposquatDomain,
    utc_now,
)
from src.core.risk_scorer import (
    DEFAULT_SENSITIVE_PORTS,
    score_ip_change,
    score_new_cves,
    score_new_ports,
    score_new_subdomain,
    score_typosquat,
)
from src.enrichment.internetdb import InternetDBResult
from src.logger import get_logger
from src.utils.validators import is_domain_allowlisted

logger = get_logger("core.diff_engine")


@dataclass
class DiffSummary:
    """Output summary returned after diffing and persisting a scan run."""

    scan_run_id: int
    target_domain: str
    alerts: list[Alert] = field(default_factory=list)
    total_subdomains: int = 0
    total_typosquats: int = 0


def _loads_json_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except ValueError:
        return []


class StateDiffEngine:
    """Compares current scan observations against the last completed scan run."""

    def __init__(self, sensitive_ports: list[int] | None = None) -> None:
        self.sensitive_ports = (
            list(sensitive_ports) if sensitive_ports is not None else sorted(DEFAULT_SENSITIVE_PORTS)
        )

    def _get_previous_completed_run(
        self,
        session: Session,
        target_id: int,
        current_run_id: int,
    ) -> ScanRun | None:
        stmt = (
            select(ScanRun)
            .where(
                ScanRun.target_id == target_id,
                ScanRun.status == "COMPLETED",
                ScanRun.id != current_run_id,
            )
            .order_by(ScanRun.id.desc())
            .limit(1)
        )
        return session.scalars(stmt).first()

    def process_scan(
        self,
        session: Session,
        target: Target,
        current_run: ScanRun,
        dns_results: dict[str, DNSResolutionResult],
        enrichments: dict[str, InternetDBResult],
        typosquats: list[ActiveTyposquat],
    ) -> DiffSummary:
        """Persist observations, detect deltas vs T_{n-1}, and emit scored alerts."""
        prev_run = self._get_previous_completed_run(session, target.id, current_run.id)
        allowlist = target.get_allowlist()

        filtered_dns = {
            fqdn: res
            for fqdn, res in dns_results.items()
            if not is_domain_allowlisted(fqdn, allowlist)
        }
        filtered_typosquats = [
            ts for ts in typosquats if not is_domain_allowlisted(ts.spoof_domain, allowlist)
        ]

        existing_subdomains: dict[str, Subdomain] = {
            sub.fqdn: sub
            for sub in session.scalars(
                select(Subdomain).where(Subdomain.target_id == target.id)
            ).all()
        }
        existing_typosquats: dict[str, TyposquatDomain] = {
            ts.spoof_domain: ts
            for ts in session.scalars(
                select(TyposquatDomain).where(TyposquatDomain.target_id == target.id)
            ).all()
        }

        prev_enrichment_by_ip: dict[str, tuple[set[int], set[str]]] = {}
        if prev_run is not None:
            prev_rows = session.scalars(
                select(IPEnrichment).where(IPEnrichment.scan_run_id == prev_run.id)
            ).all()
            for row in prev_rows:
                prev_enrichment_by_ip[row.ip_address] = (
                    set(int(p) for p in _loads_json_list(row.open_ports)),
                    set(str(c) for c in _loads_json_list(row.cves)),
                )

        new_alerts: list[Alert] = []
        ip_to_subdomains: dict[str, list[str]] = {}
        new_subdomain_ips: set[str] = set()
        old_ip_by_new_ip_from_existing_sub: dict[str, set[str]] = {}

        # 1. Process subdomains & IP changes
        for fqdn, dns_res in sorted(filtered_dns.items()):
            ip = dns_res.primary_ip
            if ip:
                ip_to_subdomains.setdefault(ip, []).append(fqdn)

            enrichment = enrichments.get(ip) if ip else None
            ports = enrichment.open_ports if enrichment else []
            cves = enrichment.cves if enrichment else []

            if fqdn not in existing_subdomains:
                sub = Subdomain(
                    target_id=target.id,
                    fqdn=fqdn,
                    ip_address=ip,
                    cname_record=dns_res.cname_record,
                    mx_records=json.dumps(dns_res.mx_records),
                    is_resolving=dns_res.is_resolving,
                    first_seen_run_id=current_run.id,
                    last_seen_run_id=current_run.id,
                )
                session.add(sub)
                if ip:
                    new_subdomain_ips.add(ip)

                severity = score_new_subdomain(
                    is_resolving=dns_res.is_resolving,
                    open_ports=ports,
                    cves=cves,
                    sensitive_ports=self.sensitive_ports,
                )
                if dns_res.is_resolving:
                    desc = (
                        f"New resolving subdomain '{fqdn}' discovered (IP: {ip or 'N/A'}, "
                        f"ports: {ports}, CVEs: {cves})."
                    )
                else:
                    desc = (
                        f"New non-resolving subdomain '{fqdn}' observed in CT logs (NXDOMAIN)."
                    )

                alert = Alert(
                    scan_run_id=current_run.id,
                    target_id=target.id,
                    category="NEW_SUBDOMAIN",
                    severity=severity,
                    indicator=fqdn,
                    description=desc,
                )
                session.add(alert)
                new_alerts.append(alert)
            else:
                existing = existing_subdomains[fqdn]
                old_ip = existing.ip_address
                if ip and old_ip != ip:
                    if old_ip:
                        old_ip_by_new_ip_from_existing_sub.setdefault(ip, set()).add(old_ip)
                    alert = Alert(
                        scan_run_id=current_run.id,
                        target_id=target.id,
                        category="IP_CHANGE",
                        severity=score_ip_change(),
                        indicator=fqdn,
                        description=(
                            f"DNS IP change detected for '{fqdn}': {old_ip or 'N/A'} -> {ip}."
                        ),
                    )
                    session.add(alert)
                    new_alerts.append(alert)

                existing.ip_address = ip
                existing.cname_record = dns_res.cname_record
                existing.mx_records = json.dumps(dns_res.mx_records)
                existing.is_resolving = dns_res.is_resolving
                existing.last_seen_run_id = current_run.id
                existing.last_seen_at = utc_now()

        # 2. Persist current IP enrichments & diff ports / CVEs against T_{n-1}
        for ip, res in sorted(enrichments.items()):
            enrichment_row = IPEnrichment(
                scan_run_id=current_run.id,
                ip_address=ip,
                open_ports=json.dumps(res.open_ports),
                cves=json.dumps(res.cves),
                cpes=json.dumps(res.cpes),
                tags=json.dumps(res.tags),
            )
            session.add(enrichment_row)

            if prev_run is None:
                continue

            associated_subs = sorted(ip_to_subdomains.get(ip, []))
            subs_label = ", ".join(associated_subs) if associated_subs else ip

            if ip in prev_enrichment_by_ip:
                prev_ports, prev_cves = prev_enrichment_by_ip[ip]
            elif ip not in new_subdomain_ips and ip in old_ip_by_new_ip_from_existing_sub:
                prev_ports = set()
                prev_cves = set()
                for old_ip in old_ip_by_new_ip_from_existing_sub[ip]:
                    p_ports, p_cves = prev_enrichment_by_ip.get(old_ip, (set(), set()))
                    prev_ports |= p_ports
                    prev_cves |= p_cves
            else:
                continue

            new_ports = sorted(set(res.open_ports) - prev_ports)
            if new_ports:
                port_severity = score_new_ports(new_ports, self.sensitive_ports)
                alert = Alert(
                    scan_run_id=current_run.id,
                    target_id=target.id,
                    category="NEW_PORT",
                    severity=port_severity,
                    indicator=ip,
                    description=(
                        f"New open port(s) {new_ports} detected on {ip} "
                        f"(associated with: {subs_label})."
                    ),
                )
                session.add(alert)
                new_alerts.append(alert)

            new_cves = sorted(set(res.cves) - prev_cves)
            if new_cves:
                alert = Alert(
                    scan_run_id=current_run.id,
                    target_id=target.id,
                    category="NEW_CVE",
                    severity=score_new_cves(),
                    indicator=ip,
                    description=(
                        f"New CVE(s) {new_cves} detected on {ip} "
                        f"(associated with: {subs_label})."
                    ),
                )
                session.add(alert)
                new_alerts.append(alert)

        # 3. Process active typosquatting domains
        for ts in filtered_typosquats:
            if ts.spoof_domain not in existing_typosquats:
                row = TyposquatDomain(
                    target_id=target.id,
                    spoof_domain=ts.spoof_domain,
                    permutation_type=ts.permutation_type,
                    ip_address=ts.ip_address,
                    has_mx_record=ts.has_mx_record,
                    registrar=ts.registrar,
                    registration_date=ts.registration_date,
                    first_seen_run_id=current_run.id,
                    last_seen_run_id=current_run.id,
                )
                session.add(row)

                severity = score_typosquat(
                    has_a_record=bool(ts.ip_address),
                    has_mx_record=ts.has_mx_record,
                    registration_date=ts.registration_date,
                )
                alert = Alert(
                    scan_run_id=current_run.id,
                    target_id=target.id,
                    category="TYPOSQUAT_ACTIVE",
                    severity=severity,
                    indicator=ts.spoof_domain,
                    description=(
                        f"Active typosquatting domain '{ts.spoof_domain}' "
                        f"(type={ts.permutation_type}, IP={ts.ip_address or 'N/A'}, "
                        f"MX={ts.has_mx_record}, registrar={ts.registrar or 'N/A'}, "
                        f"registered={ts.registration_date or 'N/A'})."
                    ),
                )
                session.add(alert)
                new_alerts.append(alert)
            else:
                existing_ts = existing_typosquats[ts.spoof_domain]
                existing_ts.ip_address = ts.ip_address
                existing_ts.has_mx_record = ts.has_mx_record
                existing_ts.registrar = ts.registrar or existing_ts.registrar
                existing_ts.registration_date = ts.registration_date or existing_ts.registration_date
                existing_ts.last_seen_run_id = current_run.id

        # 4. Finalize ScanRun metrics
        current_run.total_subdomains = len(filtered_dns)
        current_run.new_findings_count = len(new_alerts)
        current_run.status = "COMPLETED"
        current_run.finished_at = utc_now()
        session.flush()

        logger.info(
            "Diff engine completed for %s (run_id=%d): %d subdomain(s), %d new alert(s)",
            target.domain,
            current_run.id,
            current_run.total_subdomains,
            len(new_alerts),
        )
        return DiffSummary(
            scan_run_id=current_run.id,
            target_domain=target.domain,
            alerts=new_alerts,
            total_subdomains=len(filtered_dns),
            total_typosquats=len(filtered_typosquats),
        )
