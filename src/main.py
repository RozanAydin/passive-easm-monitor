"""CLI entry point and pipeline orchestrator for the Hybrid EASM & Brand Threat Monitor."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Sequence

from sqlalchemy import select

from src.collectors.crtsh_collector import CrtShCollector
from src.collectors.dns_resolver import AsyncDNSResolver
from src.collectors.typosquat import TyposquatCollector
from src.config_loader import AppConfig, SecretsConfig, load_config
from src.core.database import DatabaseManager, Target
from src.core.diff_engine import DiffSummary
from src.core.scanner import execute_target_scan, upsert_target
from src.enrichment.internetdb import InternetDBClient
from src.logger import get_logger, setup_logging
from src.outputs.notifier import WebhookNotifier
from src.outputs.reporter import IntelligenceReporter
from src.utils.validators import validate_and_normalize_domain

logger = get_logger("main")


def _init_db_and_seed(
    db_url: str,
    app_config: AppConfig | None = None,
    targets_yaml_path: str | Path = "config/targets.yaml",
    fallback_config_path: str | Path = "config/config.yaml",
) -> DatabaseManager:
    db_manager = DatabaseManager(db_url)
    db_manager.init_db()
    if app_config and app_config.targets:
        # Ensure any targets explicitly configured in the passed AppConfig are present
        with db_manager.get_session() as session:
            existing_count = len(session.scalars(select(Target.id)).all())
        if existing_count == 0:
            for t_cfg in app_config.targets:
                upsert_target(
                    db_manager,
                    domain=t_cfg.domain,
                    allowlist=t_cfg.exclude_subdomains,
                    is_active=True,
                )
    else:
        db_manager.seed_initial_targets(
            targets_yaml_path=targets_yaml_path,
            fallback_config_path=fallback_config_path,
        )
    return db_manager


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
    """Run the monitoring pipeline for a specific target or all active SQLite targets."""
    db_manager = _init_db_and_seed(app_config.database.url, app_config=app_config)

    cfg_map = {t.domain: t for t in app_config.targets}

    if target_filter:
        normalized_domain = validate_and_normalize_domain(target_filter)
        target_cfg = cfg_map.get(normalized_domain)
        target = upsert_target(
            db_manager,
            domain=normalized_domain,
            allowlist=target_cfg.exclude_subdomains if target_cfg else None,
            is_active=True,
        )
        targets_to_scan = [target]
    else:
        with db_manager.get_session() as session:
            targets_to_scan = list(
                session.scalars(
                    select(Target).where(Target.is_active.is_(True)).order_by(Target.id.asc())
                ).all()
            )

    if not targets_to_scan:
        logger.warning("No active targets found in database. Nothing to scan.")
        return []

    summaries: list[DiffSummary] = []
    for target in targets_to_scan:
        target_cfg = cfg_map.get(target.domain)
        summary = await execute_target_scan(
            target_id=target.id,
            app_config=app_config,
            secrets=secrets,
            db_manager=db_manager,
            skip_notify=skip_notify,
            enable_easm=target_cfg.enable_easm if target_cfg else True,
            enable_typosquat=target_cfg.enable_typosquat if target_cfg else True,
            crtsh_collector=crtsh_collector,
            dns_resolver=dns_resolver,
            typosquat_collector=typosquat_collector,
            internetdb_client=internetdb_client,
            notifier=notifier,
            reporter=reporter,
        )
        summaries.append(summary)

    return summaries


def list_targets_table(db_manager: DatabaseManager) -> str:
    """Return a clean formatted table of all registered targets in SQLite."""
    with db_manager.get_session() as session:
        targets = list(session.scalars(select(Target).order_by(Target.id.asc())).all())

    if not targets:
        return "No targets registered in database."

    headers = ("ID", "Domain", "Active", "Scan Status", "Last Scanned (UTC)", "Allowlist")
    rows: list[tuple[str, str, str, str, str, str]] = []
    for t in targets:
        last_ts = (
            t.last_scanned_at.strftime("%Y-%m-%d %H:%M:%S")
            if t.last_scanned_at
            else "N/A"
        )
        allow = ", ".join(t.get_allowlist()) if t.get_allowlist() else "-"
        rows.append(
            (
                str(t.id),
                t.domain,
                "Yes" if t.is_active else "No",
                t.scan_status,
                last_ts,
                allow,
            )
        )

    widths = [
        max(len(headers[i]), *(len(r[i]) for r in rows))
        for i in range(len(headers))
    ]
    fmt = " | ".join(f"{{:<{w}}}" for w in widths)
    sep = "-+-".join("-" * w for w in widths)
    lines = [fmt.format(*headers), sep]
    for r in rows:
        lines.append(fmt.format(*r))
    return "\n".join(lines)


def remove_target_by_domain(db_manager: DatabaseManager, domain: str) -> bool:
    """Validate domain and delete it from the SQLite targets table."""
    normalized = validate_and_normalize_domain(domain)
    with db_manager.get_session() as session:
        target = session.scalars(select(Target).where(Target.domain == normalized)).first()
        if target is None:
            return False
        session.delete(target)
        session.commit()
        return True


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

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument(
        "--target",
        default=None,
        help="Validate, upsert into SQLite, and scan a single target domain",
    )
    action_group.add_argument(
        "--all",
        action="store_true",
        help="Scan all active targets in SQLite (default behavior)",
    )
    action_group.add_argument(
        "--list-targets",
        action="store_true",
        help="List all registered targets, status, and last scan timestamps",
    )
    action_group.add_argument(
        "--remove-target",
        default=None,
        help="Remove a registered target domain from the database",
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

        if args.list_targets:
            db_manager = _init_db_and_seed(app_config.database.url, app_config=app_config)
            print(list_targets_table(db_manager))
            return 0

        if args.remove_target:
            db_manager = _init_db_and_seed(app_config.database.url, app_config=app_config)
            removed = remove_target_by_domain(db_manager, args.remove_target)
            if removed:
                logger.info("Removed target '%s' from database.", args.remove_target)
                print(f"Removed target '{validate_and_normalize_domain(args.remove_target)}'.")
                return 0
            logger.warning("Target '%s' was not found in database.", args.remove_target)
            print(f"Target '{args.remove_target}' not found in database.", file=sys.stderr)
            return 1

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
        logger.error("Execution terminated with error (%s: %s)", type(exc).__name__, exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
