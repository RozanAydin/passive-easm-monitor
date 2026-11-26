"""Shared scan execution service used by both the CLI and FastAPI background tasks."""

from __future__ import annotations

from sqlalchemy import select

from src.collectors.crtsh_collector import CrtShCollector
from src.collectors.dns_resolver import AsyncDNSResolver, DNSResolutionResult
from src.collectors.typosquat import ActiveTyposquat, TyposquatCollector
from src.config_loader import AppConfig, SecretsConfig
from src.core.database import DatabaseManager, ScanRun, Target, utc_now
from src.core.diff_engine import DiffSummary, StateDiffEngine
from src.enrichment.internetdb import InternetDBClient, InternetDBResult
from src.logger import get_logger
from src.outputs.notifier import WebhookNotifier
from src.outputs.reporter import IntelligenceReporter

logger = get_logger("core.scanner")


async def execute_target_scan(
    target_id: int,
    app_config: AppConfig,
    secrets: SecretsConfig,
    db_manager: DatabaseManager,
    skip_notify: bool = False,
    enable_easm: bool = True,
    enable_typosquat: bool = True,
    crtsh_collector: CrtShCollector | None = None,
    dns_resolver: AsyncDNSResolver | None = None,
    typosquat_collector: TyposquatCollector | None = None,
    internetdb_client: InternetDBClient | None = None,
    notifier: WebhookNotifier | None = None,
    reporter: IntelligenceReporter | None = None,
) -> DiffSummary:
    """Run the full passive OSINT pipeline for a SQLite-backed Target record."""
    settings = app_config.collector_settings
    active_dns = dns_resolver or AsyncDNSResolver(
        concurrency=settings.dns_concurrency,
        timeout_sec=settings.request_timeout_sec,
    )
    active_crtsh = crtsh_collector or CrtShCollector(
        timeout_sec=settings.crtsh_timeout_sec,
        rate_limit_delay_sec=settings.rate_limit_delay_sec,
    )
    active_typosquat = typosquat_collector or TyposquatCollector(
        dns_resolver=active_dns,
        timeout_sec=settings.request_timeout_sec,
        rate_limit_delay_sec=settings.rate_limit_delay_sec,
    )
    active_internetdb = internetdb_client or InternetDBClient(
        timeout_sec=settings.request_timeout_sec,
        rate_limit_delay_sec=settings.rate_limit_delay_sec,
    )
    diff_engine = StateDiffEngine(sensitive_ports=settings.sensitive_ports)
    active_notifier = notifier or WebhookNotifier(
        alerting_config=app_config.alerting,
        secrets=secrets,
        timeout_sec=settings.request_timeout_sec,
    )
    active_reporter = reporter or IntelligenceReporter(
        output_dir=app_config.reporting.output_dir,
        sensitive_ports=settings.sensitive_ports,
    )

    with db_manager.get_session() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target id={target_id} not found in database.")
        domain = target.domain
        allowlist = target.get_allowlist()

        target.scan_status = "running"
        target.last_error = None
        scan_run = ScanRun(
            target_id=target.id,
            started_at=utc_now(),
            status="RUNNING",
        )
        session.add(scan_run)
        session.commit()
        scan_run_id = scan_run.id

    logger.info("Starting passive scan pipeline for target: %s (run_id=%d)", domain, scan_run_id)

    try:
        dns_results: dict[str, DNSResolutionResult] = {}
        if enable_easm:
            subdomains = await active_crtsh.collect(domain, exclude_subdomains=allowlist)
            if subdomains:
                dns_results = await active_dns.resolve_many(subdomains)

        typosquats: list[ActiveTyposquat] = []
        if enable_typosquat:
            typosquats = await active_typosquat.collect(domain, allowlist=allowlist)

        unique_ipv4s = sorted(
            {ip for res in dns_results.values() for ip in res.a_records if ip}
        )
        enrichments: dict[str, InternetDBResult] = {}
        if unique_ipv4s:
            enrichments = await active_internetdb.enrich_ips(unique_ipv4s)

        with db_manager.get_session() as session:
            target = session.get(Target, target_id)
            scan_run = session.get(ScanRun, scan_run_id)
            if target is None or scan_run is None:
                raise RuntimeError(
                    f"Target id={target_id} or ScanRun id={scan_run_id} disappeared during scan."
                )

            summary = diff_engine.process_scan(
                session=session,
                target=target,
                current_run=scan_run,
                dns_results=dns_results,
                enrichments=enrichments,
                typosquats=typosquats,
            )

            if not skip_notify:
                await active_notifier.notify_alerts(summary.alerts, target.domain)

            target.scan_status = "completed"
            target.last_scanned_at = utc_now()
            target.last_error = None
            session.commit()

            active_reporter.export_reports(
                session=session,
                target=target,
                scan_run=scan_run,
                export_formats=app_config.reporting.export_formats,
                update_latest=True,
            )

        logger.info(
            "Completed scan for %s (run_id=%d): %d findings.",
            domain,
            scan_run_id,
            len(summary.alerts),
        )
        return summary

    except Exception as exc:
        err_msg = f"{type(exc).__name__}: {exc}"
        logger.exception("Scan failed for target %s (run_id=%d): %s", domain, scan_run_id, err_msg)
        with db_manager.get_session() as session:
            failed_run = session.get(ScanRun, scan_run_id)
            if failed_run is not None:
                failed_run.status = "FAILED"
                failed_run.finished_at = utc_now()
            failed_target = session.get(Target, target_id)
            if failed_target is not None:
                failed_target.scan_status = "failed"
                failed_target.last_scanned_at = utc_now()
                failed_target.last_error = err_msg[:1000]
            session.commit()
        raise


def upsert_target(
    db_manager: DatabaseManager,
    domain: str,
    allowlist: list[str] | None = None,
    is_active: bool = True,
) -> Target:
    """Create or reactivate a target in SQLite, merging allowlist if provided."""
    with db_manager.get_session() as session:
        target = session.scalars(select(Target).where(Target.domain == domain)).first()
        if target is None:
            target = Target(
                domain=domain,
                is_active=is_active,
                scan_status="idle",
            )
            if allowlist is not None:
                target.set_allowlist(allowlist)
            session.add(target)
        else:
            target.is_active = is_active
            if allowlist is not None:
                merged = sorted(set(target.get_allowlist()) | set(allowlist))
                target.set_allowlist(merged)
        session.commit()
        session.refresh(target)
        return target
