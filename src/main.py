"""CLI entry point and pipeline orchestrator for the Passive EASM & Brand Threat Monitor."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Sequence

from sqlalchemy import select

from src.collectors.crtsh_collector import CrtShCollector
from src.collectors.dns_resolver import AsyncDNSResolver, DNSResolutionResult
from src.collectors.typosquat import ActiveTyposquat, TyposquatCollector
from src.config_loader import AppConfig, SecretsConfig, TargetConfig, load_config
from src.core.database import DatabaseManager, ScanRun, Target, utc_now
from src.core.diff_engine import DiffSummary, StateDiffEngine
from src.enrichment.internetdb import InternetDBClient, InternetDBResult
from src.logger import get_logger, setup_logging
from src.outputs.notifier import WebhookNotifier
from src.outputs.reporter import IntelligenceReporter

logger = get_logger("main")


def _get_or_create_target(session, domain: str) -> Target:
    target = session.scalars(select(Target).where(Target.domain == domain)).first()
    if target is None:
        target = Target(domain=domain, is_active=True)
        session.add(target)
        session.flush()
    return target


async def process_target(
    target_cfg: TargetConfig,
    app_config: AppConfig,
    db_manager: DatabaseManager,
    crtsh_collector: CrtShCollector,
    dns_resolver: AsyncDNSResolver,
    typosquat_collector: TyposquatCollector,
    internetdb_client: InternetDBClient,
    diff_engine: StateDiffEngine,
    notifier: WebhookNotifier,
    reporter: IntelligenceReporter,
    skip_notify: bool = False,
    per_target_subdir: bool = False,
) -> DiffSummary:
    """Execute the full passive EASM & brand monitoring pipeline for a single target."""
    logger.info("Starting passive scan pipeline for target: %s", target_cfg.domain)

    with db_manager.get_session() as session:
        target = _get_or_create_target(session, target_cfg.domain)
        scan_run = ScanRun(
            target_id=target.id,
            started_at=utc_now(),
            status="RUNNING",
        )
        session.add(scan_run)
        session.commit()
        target_id = target.id
        scan_run_id = scan_run.id

    try:
        # Module 1 & 2: Passive Collection
        dns_results: dict[str, DNSResolutionResult] = {}
        if target_cfg.enable_easm:
            subdomains = await crtsh_collector.collect(
                target_cfg.domain,
                exclude_subdomains=target_cfg.exclude_subdomains,
            )
            if subdomains:
                dns_results = await dns_resolver.resolve_many(subdomains)

        typosquats: list[ActiveTyposquat] = []
        if target_cfg.enable_typosquat:
            typosquats = await typosquat_collector.collect(target_cfg.domain)

        # Module 3: Passive IP Enrichment (IPv4s from resolved subdomains)
        unique_ipv4s = sorted(
            {
                ip
                for res in dns_results.values()
                for ip in res.a_records
                if ip
            }
        )
        enrichments: dict[str, InternetDBResult] = {}
        if unique_ipv4s:
            enrichments = await internetdb_client.enrich_ips(unique_ipv4s)

        # Module 4 & 5: Diffing, Alerting, and Reporting
        with db_manager.get_session() as session:
            target = session.get(Target, target_id)
            scan_run = session.get(ScanRun, scan_run_id)
            assert target is not None and scan_run is not None

            summary = diff_engine.process_scan(
                session=session,
                target=target,
                current_run=scan_run,
                dns_results=dns_results,
                enrichments=enrichments,
                typosquats=typosquats,
            )

            if not skip_notify:
                await notifier.notify_alerts(summary.alerts, target.domain)

            session.commit()

            reporter.export_reports(
                session=session,
                target=target,
                scan_run=scan_run,
                export_formats=app_config.reporting.export_formats,
                per_target_subdir=per_target_subdir,
            )

        logger.info(
            "Completed scan for %s (run_id=%d): %d findings.",
            target_cfg.domain,
            scan_run_id,
            len(summary.alerts),
        )
        return summary

    except Exception as exc:
        logger.exception("Scan failed for target %s (run_id=%d): %s", target_cfg.domain, scan_run_id, exc)
        with db_manager.get_session() as session:
            failed_run = session.get(ScanRun, scan_run_id)
            if failed_run is not None:
                failed_run.status = "FAILED"
                failed_run.finished_at = utc_now()
                session.commit()
        raise


async def run_pipeline(
    app_config: AppConfig,
    secrets: SecretsConfig,
    target_filter: str | None = None,
    skip_notify: bool = False,
    crtsh_collector: CrtShCollector | None = None,
    dns_resolver: AsyncDNSResolver | None = None,
    typosquat_collector: TyposquatCollector | None = None,
    internetdb_client: InternetDBClient | None = None,
    notifier: WebhookNotifier | None = None,
    reporter: IntelligenceReporter | None = None,
) -> list[DiffSummary]:
    """Run the monitoring pipeline across all configured (or filtered) targets."""
    db_manager = DatabaseManager(app_config.database.url)
    db_manager.init_db()

    settings = app_config.collector_settings
    active_dns = dns_resolver or AsyncDNSResolver(
        concurrency=settings.dns_concurrency,
        timeout_sec=settings.request_timeout_sec,
    )
    active_crtsh = crtsh_collector or CrtShCollector(
        timeout_sec=settings.request_timeout_sec,
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

    targets = app_config.targets
    if target_filter:
        normalized_filter = target_filter.strip().lower().rstrip(".")
        targets = [t for t in targets if t.domain == normalized_filter]
        if not targets:
            raise ValueError(f"Requested target '{target_filter}' is not configured in config.yaml.")

    multi_target = len(targets) > 1
    summaries: list[DiffSummary] = []
    for target_cfg in targets:
        summary = await process_target(
            target_cfg=target_cfg,
            app_config=app_config,
            db_manager=db_manager,
            crtsh_collector=active_crtsh,
            dns_resolver=active_dns,
            typosquat_collector=active_typosquat,
            internetdb_client=active_internetdb,
            diff_engine=diff_engine,
            notifier=active_notifier,
            reporter=active_reporter,
            skip_notify=skip_notify,
            per_target_subdir=multi_target,
        )
        summaries.append(summary)

    return summaries


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automated Passive External Attack Surface & Brand Threat Intelligence Monitor"
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to YAML configuration file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--env",
        default=".env",
        help="Path to .env secrets file (default: .env)",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Optional single target domain from config.yaml to scan",
    )
    parser.add_argument(
        "--skip-notify",
        action="store_true",
        help="Skip sending real-time webhook alerts",
    )
    parser.add_argument(
        "--log-file",
        default="logs/monitor.log",
        help="Path to structured log output file (default: logs/monitor.log)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(
        log_file=Path(args.log_file),
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    try:
        app_config, secrets = load_config(config_path=args.config, env_path=args.env)
        asyncio.run(
            run_pipeline(
                app_config=app_config,
                secrets=secrets,
                target_filter=args.target,
                skip_notify=args.skip_notify,
            )
        )
        return 0
    except Exception as exc:
        logger.error("Execution terminated with error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
