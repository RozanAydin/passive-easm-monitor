"""Intelligence report generator (Jinja2 Markdown/HTML) and IoC feed exporter (JSON/CSV)."""

from __future__ import annotations

import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.database import (
    Alert,
    IPEnrichment,
    ScanRun,
    Subdomain,
    Target,
    TyposquatDomain,
)
from src.core.risk_scorer import DEFAULT_SENSITIVE_PORTS, recommend_action
from src.logger import get_logger

logger = get_logger("outputs.reporter")


def _loads_json_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except ValueError:
        return []


def _format_utc_iso(dt: datetime | None = None) -> str:
    now = dt or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


FORMAT_EXTENSIONS: dict[str, tuple[str, str]] = {
    "md": ("markdown", "executive_report.md"),
    "markdown": ("markdown", "executive_report.md"),
    "html": ("html", "executive_report.html"),
    "json": ("json", "ioc_feed.json"),
    "csv": ("csv", "ioc_feed.csv"),
}


class IntelligenceReporter:
    """Generates executive reports and structured IoC feeds from persisted scan results."""

    def __init__(
        self,
        output_dir: str | Path = "./reports",
        template_dir: str | Path = "templates",
        sensitive_ports: list[int] | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.template_dir = Path(template_dir)
        self.sensitive_ports = (
            set(sensitive_ports) if sensitive_ports is not None else set(DEFAULT_SENSITIVE_PORTS)
        )
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(enabled_extensions=("html", "xml")),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def build_report_context(
        self,
        session: Session,
        target: Target,
        scan_run: ScanRun,
    ) -> dict[str, Any]:
        """Collect all DB entities for a scan run into a template & IoC context."""
        subdomains = session.scalars(
            select(Subdomain)
            .where(Subdomain.target_id == target.id)
            .order_by(Subdomain.fqdn.asc())
        ).all()

        enrichments = session.scalars(
            select(IPEnrichment).where(IPEnrichment.scan_run_id == scan_run.id)
        ).all()
        enrichment_by_ip: dict[str, dict[str, list]] = {}
        for row in enrichments:
            enrichment_by_ip[row.ip_address] = {
                "open_ports": [int(p) for p in _loads_json_list(row.open_ports)],
                "cves": [str(c) for c in _loads_json_list(row.cves)],
                "cpes": [str(c) for c in _loads_json_list(row.cpes)],
                "tags": [str(t) for t in _loads_json_list(row.tags)],
            }

        typosquats = session.scalars(
            select(TyposquatDomain)
            .where(TyposquatDomain.target_id == target.id)
            .order_by(TyposquatDomain.spoof_domain.asc())
        ).all()
        typosquat_by_domain = {ts.spoof_domain: ts for ts in typosquats}

        alerts = session.scalars(
            select(Alert)
            .where(Alert.scan_run_id == scan_run.id)
            .order_by(Alert.id.asc())
        ).all()

        ip_to_subs: dict[str, list[str]] = {}
        subdomain_views: list[dict[str, Any]] = []
        for sub in subdomains:
            if sub.ip_address:
                ip_to_subs.setdefault(sub.ip_address, []).append(sub.fqdn)
            enrich = enrichment_by_ip.get(sub.ip_address or "", {})
            subdomain_views.append(
                {
                    "fqdn": sub.fqdn,
                    "is_resolving": sub.is_resolving,
                    "ip_address": sub.ip_address,
                    "cname_record": sub.cname_record,
                    "open_ports": enrich.get("open_ports", []),
                    "cves": enrich.get("cves", []),
                }
            )
        sub_by_fqdn = {s.fqdn: s for s in subdomains}

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        indicators: list[dict[str, Any]] = []

        for alert in alerts:
            sev = alert.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

            cat = alert.category.upper()
            if cat == "TYPOSQUAT_ACTIVE":
                ts = typosquat_by_domain.get(alert.indicator)
                has_mx = bool(ts.has_mx_record) if ts else False
                indicators.append(
                    {
                        "indicator_type": "domain-name",
                        "indicator_value": alert.indicator,
                        "category": alert.category,
                        "severity": alert.severity,
                        "attributes": {
                            "permutation_type": ts.permutation_type if ts else "unknown",
                            "resolved_ip": ts.ip_address if ts else None,
                            "has_mx_record": has_mx,
                        },
                        "recommended_action": recommend_action(
                            cat, alert.indicator, has_mx_record=has_mx
                        ),
                    }
                )
            elif cat in {"NEW_PORT", "NEW_CVE"}:
                enrich = enrichment_by_ip.get(alert.indicator, {})
                ports = enrich.get("open_ports", [])
                cves = enrich.get("cves", [])
                sens_ports = sorted(p for p in ports if p in self.sensitive_ports)
                assoc_subs = ip_to_subs.get(alert.indicator, [])
                indicators.append(
                    {
                        "indicator_type": "ipv4-addr",
                        "indicator_value": alert.indicator,
                        "category": alert.category,
                        "severity": alert.severity,
                        "attributes": {
                            "associated_subdomain": assoc_subs[0] if assoc_subs else alert.indicator,
                            "exposed_ports": ports,
                            "cves": cves,
                        },
                        "recommended_action": recommend_action(
                            cat,
                            assoc_subs[0] if assoc_subs else alert.indicator,
                            sensitive_ports_found=sens_ports,
                            cves=cves,
                        ),
                    }
                )
            else:
                sub = sub_by_fqdn.get(alert.indicator)
                ip = sub.ip_address if sub else None
                enrich = enrichment_by_ip.get(ip or "", {})
                ports = enrich.get("open_ports", [])
                cves = enrich.get("cves", [])
                sens_ports = sorted(p for p in ports if p in self.sensitive_ports)
                indicators.append(
                    {
                        "indicator_type": "domain-name",
                        "indicator_value": alert.indicator,
                        "category": alert.category,
                        "severity": alert.severity,
                        "attributes": {
                            "resolved_ip": ip,
                            "is_resolving": bool(sub.is_resolving) if sub else False,
                            "exposed_ports": ports,
                            "cves": cves,
                        },
                        "recommended_action": recommend_action(
                            cat,
                            alert.indicator,
                            sensitive_ports_found=sens_ports,
                            cves=cves,
                        ),
                    }
                )

        generated_at = _format_utc_iso()
        return {
            "generated_at": generated_at,
            "target_domain": target.domain,
            "scan_run_id": scan_run.id,
            "total_subdomains": scan_run.total_subdomains,
            "total_new_findings": len(alerts),
            "severity_counts": severity_counts,
            "alerts": alerts,
            "subdomains": subdomain_views,
            "typosquats": typosquats,
            "indicators": indicators,
        }

    def run_report_path(self, domain: str, run_id: int, filename: str) -> Path:
        """Return isolated per-target, per-run report path."""
        return self.output_dir / domain / f"run_{run_id}_{filename}"

    def _write_format(
        self,
        fmt: str,
        context: dict[str, Any],
        dest_path: Path,
    ) -> None:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "markdown":
            template = self.jinja_env.get_template("executive_report.md.j2")
            dest_path.write_text(template.render(**context), encoding="utf-8")
        elif fmt == "html":
            template = self.jinja_env.get_template("executive_report.md.j2")
            escaped = html.escape(template.render(**context))
            html_content = (
                "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
                f"<title>Threat Intel Report - {html.escape(context['target_domain'])}</title>"
                "<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;}"
                "pre{white-space:pre-wrap;background:#f6f8fa;padding:1rem;border-radius:6px;}</style>"
                f"</head><body><pre>{escaped}</pre></body></html>"
            )
            dest_path.write_text(html_content, encoding="utf-8")
        elif fmt == "json":
            ioc_payload = {
                "metadata": {
                    "generated_at": context["generated_at"],
                    "target_domain": context["target_domain"],
                    "scan_run_id": context["scan_run_id"],
                    "total_new_findings": context["total_new_findings"],
                },
                "indicators": context["indicators"],
            }
            dest_path.write_text(json.dumps(ioc_payload, indent=2), encoding="utf-8")
        elif fmt == "csv":
            with dest_path.open("w", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(
                    csv_file,
                    fieldnames=[
                        "indicator_type",
                        "indicator_value",
                        "category",
                        "severity",
                        "attributes",
                        "recommended_action",
                    ],
                )
                writer.writeheader()
                for ioc in context["indicators"]:
                    writer.writerow(
                        {
                            "indicator_type": ioc["indicator_type"],
                            "indicator_value": ioc["indicator_value"],
                            "category": ioc["category"],
                            "severity": ioc["severity"],
                            "attributes": json.dumps(ioc["attributes"]),
                            "recommended_action": ioc["recommended_action"],
                        }
                    )

    def export_reports(
        self,
        session: Session,
        target: Target,
        scan_run: ScanRun,
        export_formats: list[str] | None = None,
        update_latest: bool = True,
    ) -> dict[str, Path]:
        """Render per-target/run reports and also update top-level latest report files."""
        formats = [f.lower() for f in (export_formats or ["markdown", "json", "csv"])]
        self.output_dir.mkdir(parents=True, exist_ok=True)
        context = self.build_report_context(session, target, scan_run)
        generated_files: dict[str, Path] = {}

        for raw_fmt in formats:
            if raw_fmt not in FORMAT_EXTENSIONS:
                continue
            norm_fmt, filename = FORMAT_EXTENSIONS[raw_fmt]
            per_run_path = self.run_report_path(target.domain, scan_run.id, filename)
            self._write_format(norm_fmt, context, per_run_path)
            generated_files[norm_fmt] = per_run_path

            if update_latest:
                latest_path = self.output_dir / filename
                self._write_format(norm_fmt, context, latest_path)

            logger.info("Generated %s report: %s", norm_fmt, per_run_path)

        return generated_files

    def get_or_generate_report_file(
        self,
        session: Session,
        target: Target,
        scan_run: ScanRun,
        fmt: str,
    ) -> Path:
        """Return path to a specific run's report, generating it on-demand if absent."""
        fmt_key = fmt.lower()
        if fmt_key not in FORMAT_EXTENSIONS:
            raise ValueError(f"Unsupported report format: '{fmt}'")
        norm_fmt, filename = FORMAT_EXTENSIONS[fmt_key]
        path = self.run_report_path(target.domain, scan_run.id, filename)
        if not path.exists():
            context = self.build_report_context(session, target, scan_run)
            self._write_format(norm_fmt, context, path)
        return path
