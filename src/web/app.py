"""FastAPI Web Dashboard & REST API for Hybrid EASM & Brand Threat Intelligence Monitor."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import select

from src.config_loader import AppConfig, SecretsConfig, load_config
from src.core.database import DatabaseManager, ScanRun, Target
from src.core.scanner import execute_target_scan
from src.logger import get_logger, setup_logging
from src.outputs.reporter import FORMAT_EXTENSIONS, IntelligenceReporter
from src.utils.validators import parse_allowlist_input, validate_and_normalize_domain

logger = get_logger("web.app")

WEB_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


class CreateTargetRequest(BaseModel):
    domain: str
    allowlist: str | list[str] | None = None
    scan_now: bool = True


class TargetStatusResponse(BaseModel):
    id: int
    domain: str
    is_active: bool
    scan_status: str
    last_scanned_at: str | None
    last_error: str | None
    latest_run_id: int | None = None


def _serialize_dt(dt) -> str | None:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


async def _run_background_scan(
    target_id: int,
    app_config: AppConfig,
    secrets: SecretsConfig,
    db_manager: DatabaseManager,
    reporter: IntelligenceReporter,
) -> None:
    try:
        await execute_target_scan(
            target_id=target_id,
            app_config=app_config,
            secrets=secrets,
            db_manager=db_manager,
            reporter=reporter,
        )
    except Exception as exc:
        logger.error(
            "Background scan failed for target_id=%d (%s: %s)",
            target_id,
            type(exc).__name__,
            exc,
        )


def create_app(
    config_path: str | Path = "config/config.yaml",
    env_path: str | Path | None = ".env",
    db_manager: DatabaseManager | None = None,
    app_config: AppConfig | None = None,
    secrets: SecretsConfig | None = None,
    reporter: IntelligenceReporter | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application."""

    def _load_runtime():
        if app_config is not None and secrets is not None:
            cfg, sec = app_config, secrets
        else:
            cfg, sec = load_config(config_path=config_path, env_path=env_path)
        db = db_manager or DatabaseManager(cfg.database.url)
        db.init_db()
        db.seed_initial_targets()
        rep = reporter or IntelligenceReporter(
            output_dir=cfg.reporting.output_dir,
            sensitive_ports=cfg.collector_settings.sensitive_ports,
        )
        return cfg, sec, db, rep

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        setup_logging(log_file=Path("logs/monitor.log"), level=logging.INFO)
        cfg, sec, db, rep = _load_runtime()
        application.state.app_config = cfg
        application.state.secrets = sec
        application.state.db_manager = db
        application.state.reporter = rep
        yield

    application = FastAPI(
        title="Passive EASM & Brand Threat Intelligence Monitor",
        version="2.0.0",
        lifespan=lifespan,
    )
    templates = Jinja2Templates(directory=str(WEB_TEMPLATES_DIR))

    def _get_state() -> tuple[AppConfig, SecretsConfig, DatabaseManager, IntelligenceReporter]:
        if not hasattr(application.state, "db_manager"):
            cfg, sec, db, rep = _load_runtime()
            application.state.app_config = cfg
            application.state.secrets = sec
            application.state.db_manager = db
            application.state.reporter = rep
        return (
            application.state.app_config,
            application.state.secrets,
            application.state.db_manager,
            application.state.reporter,
        )

    @application.get("/", response_class=HTMLResponse)
    def dashboard_home(request: Request):
        _, _, db, _ = _get_state()
        with db.get_session() as session:
            targets = list(session.scalars(select(Target).order_by(Target.id.asc())).all())
            target_views: list[dict[str, Any]] = []
            has_running = False
            for t in targets:
                if t.scan_status == "running":
                    has_running = True
                latest_run = session.scalars(
                    select(ScanRun)
                    .where(ScanRun.target_id == t.id)
                    .order_by(ScanRun.id.desc())
                    .limit(1)
                ).first()
                target_views.append(
                    {
                        "id": t.id,
                        "domain": t.domain,
                        "is_active": t.is_active,
                        "allowlist": t.get_allowlist(),
                        "scan_status": t.scan_status,
                        "last_scanned_at": _serialize_dt(t.last_scanned_at),
                        "last_error": t.last_error,
                        "latest_run_id": latest_run.id if latest_run else None,
                        "total_subdomains": latest_run.total_subdomains if latest_run else 0,
                        "new_findings_count": latest_run.new_findings_count if latest_run else 0,
                    }
                )

        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "targets": target_views,
                "has_running": has_running,
            },
        )

    @application.get("/targets/{domain}", response_class=HTMLResponse)
    def target_detail(
        request: Request,
        domain: str,
        run_id: int | None = Query(default=None),
    ):
        _, _, db, rep = _get_state()
        try:
            normalized_domain = validate_and_normalize_domain(domain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        with db.get_session() as session:
            target = session.scalars(
                select(Target).where(Target.domain == normalized_domain)
            ).first()
            if target is None:
                raise HTTPException(status_code=404, detail=f"Target '{normalized_domain}' not found.")

            scan_runs = list(
                session.scalars(
                    select(ScanRun)
                    .where(ScanRun.target_id == target.id)
                    .order_by(ScanRun.id.desc())
                ).all()
            )

            selected_run: ScanRun | None = None
            if scan_runs:
                if run_id is not None:
                    selected_run = next((r for r in scan_runs if r.id == run_id), None)
                    if selected_run is None:
                        raise HTTPException(
                            status_code=404,
                            detail=f"ScanRun ID {run_id} not found for target '{normalized_domain}'.",
                        )
                else:
                    selected_run = next(
                        (r for r in scan_runs if r.status == "COMPLETED"),
                        scan_runs[0],
                    )

            report_context: dict[str, Any] | None = None
            if selected_run is not None:
                report_context = rep.build_report_context(session, target, selected_run)

            run_options = [
                {
                    "id": r.id,
                    "status": r.status,
                    "started_at": _serialize_dt(r.started_at),
                    "new_findings_count": r.new_findings_count,
                }
                for r in scan_runs
            ]

            target_info = {
                "id": target.id,
                "domain": target.domain,
                "is_active": target.is_active,
                "allowlist": target.get_allowlist(),
                "scan_status": target.scan_status,
                "last_scanned_at": _serialize_dt(target.last_scanned_at),
                "last_error": target.last_error,
            }

        return templates.TemplateResponse(
            request=request,
            name="target_detail.html",
            context={
                "target": target_info,
                "scan_runs": run_options,
                "selected_run_id": selected_run.id if selected_run else None,
                "selected_run_status": selected_run.status if selected_run else None,
                "report": report_context,
            },
        )

    @application.post("/api/targets")
    async def api_create_target(
        payload: CreateTargetRequest,
        background_tasks: BackgroundTasks,
    ):
        cfg, sec, db, rep = _get_state()
        try:
            normalized_domain = validate_and_normalize_domain(payload.domain)
            allowlist = parse_allowlist_input(payload.allowlist)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        with db.get_session() as session:
            existing = session.scalars(
                select(Target).where(Target.domain == normalized_domain)
            ).first()
            if existing is not None:
                raise HTTPException(
                    status_code=409,
                    detail=f"Target '{normalized_domain}' already exists.",
                )

            target = Target(
                domain=normalized_domain,
                is_active=True,
                scan_status="running" if payload.scan_now else "idle",
            )
            target.set_allowlist(allowlist)
            session.add(target)
            session.commit()
            session.refresh(target)
            target_id = target.id

        if payload.scan_now:
            background_tasks.add_task(
                _run_background_scan,
                target_id=target_id,
                app_config=cfg,
                secrets=sec,
                db_manager=db,
                reporter=rep,
            )
            return JSONResponse(
                status_code=202,
                content={
                    "id": target_id,
                    "domain": normalized_domain,
                    "allowlist": allowlist,
                    "is_active": True,
                    "scan_status": "running",
                },
            )

        return JSONResponse(
            status_code=201,
            content={
                "id": target_id,
                "domain": normalized_domain,
                "allowlist": allowlist,
                "is_active": True,
                "scan_status": "idle",
            },
        )

    @application.post("/api/targets/{target_id}/scan", status_code=202)
    async def api_trigger_scan(
        target_id: int,
        background_tasks: BackgroundTasks,
    ):
        cfg, sec, db, rep = _get_state()
        with db.get_session() as session:
            target = session.get(Target, target_id)
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found.")
            if target.scan_status == "running":
                raise HTTPException(status_code=409, detail="Scan is already running for this target.")
            target.scan_status = "running"
            target.last_error = None
            session.commit()
            domain = target.domain

        background_tasks.add_task(
            _run_background_scan,
            target_id=target_id,
            app_config=cfg,
            secrets=sec,
            db_manager=db,
            reporter=rep,
        )
        return {
            "status": "accepted",
            "target_id": target_id,
            "domain": domain,
            "scan_status": "running",
        }

    @application.patch("/api/targets/{target_id}/toggle")
    def api_toggle_target(target_id: int):
        _, _, db, _ = _get_state()
        with db.get_session() as session:
            target = session.get(Target, target_id)
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found.")
            target.is_active = not target.is_active
            session.commit()
            return {
                "id": target.id,
                "domain": target.domain,
                "is_active": target.is_active,
            }

    @application.delete("/api/targets/{target_id}")
    def api_delete_target(target_id: int):
        _, _, db, _ = _get_state()
        with db.get_session() as session:
            target = session.get(Target, target_id)
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found.")
            if target.scan_status == "running":
                raise HTTPException(
                    status_code=409,
                    detail="Cannot delete target while a scan is currently running.",
                )
            domain = target.domain
            session.delete(target)
            session.commit()
            return {"deleted": True, "id": target_id, "domain": domain}

    @application.get("/api/targets/{target_id}/status", response_model=TargetStatusResponse)
    def api_target_status(target_id: int):
        _, _, db, _ = _get_state()
        with db.get_session() as session:
            target = session.get(Target, target_id)
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found.")
            latest_run = session.scalars(
                select(ScanRun)
                .where(ScanRun.target_id == target.id)
                .order_by(ScanRun.id.desc())
                .limit(1)
            ).first()
            return TargetStatusResponse(
                id=target.id,
                domain=target.domain,
                is_active=target.is_active,
                scan_status=target.scan_status,
                last_scanned_at=_serialize_dt(target.last_scanned_at),
                last_error=target.last_error,
                latest_run_id=latest_run.id if latest_run else None,
            )

    @application.get("/api/reports/{run_id}/{fmt}")
    def api_download_report(run_id: int, fmt: str):
        _, _, db, rep = _get_state()
        fmt_lower = fmt.lower()
        if fmt_lower not in FORMAT_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported report format '{fmt}'. Use md, json, or csv.",
            )

        with db.get_session() as session:
            scan_run = session.get(ScanRun, run_id)
            if scan_run is None:
                raise HTTPException(status_code=404, detail=f"ScanRun {run_id} not found.")
            target = session.get(Target, scan_run.target_id)
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found.")

            report_path = rep.get_or_generate_report_file(session, target, scan_run, fmt_lower)
            _, base_filename = FORMAT_EXTENSIONS[fmt_lower]
            download_name = f"{target.domain}_run_{run_id}_{base_filename}"

        media_types = {
            "md": "text/markdown",
            "markdown": "text/markdown",
            "json": "application/json",
            "csv": "text/csv",
            "html": "text/html",
        }
        return FileResponse(
            path=report_path,
            media_type=media_types.get(fmt_lower, "application/octet-stream"),
            filename=download_name,
        )

    return application


app = create_app()
