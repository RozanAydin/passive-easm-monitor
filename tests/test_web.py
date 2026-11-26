"""Tests for SQLite WAL mode, CLI management commands, and FastAPI Web Dashboard."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from src.collectors.dns_resolver import DNSResolutionResult
from src.collectors.typosquat import ActiveTyposquat
from src.config_loader import AppConfig, SecretsConfig
from src.core.database import DatabaseManager, ScanRun, Target, utc_now
from src.core.diff_engine import StateDiffEngine
from src.enrichment.internetdb import InternetDBResult
from src.main import list_targets_table, remove_target_by_domain
from src.outputs.reporter import IntelligenceReporter
from src.web.app import create_app


def test_sqlite_wal_mode_and_seeding(tmp_path: Path) -> None:
    db_file = tmp_path / "wal_test.db"
    db = DatabaseManager(f"sqlite:///{db_file}")
    db.init_db()
    seeded = db.seed_initial_targets(targets_yaml_path=Path("config/targets.yaml"))
    assert seeded >= 1

    with db.engine.connect() as conn:
        mode = conn.execute(text("PRAGMA journal_mode;")).scalar()
        assert str(mode).lower() == "wal"


def test_cli_list_and_remove_target_helpers(tmp_path: Path) -> None:
    db = DatabaseManager(f"sqlite:///{tmp_path / 'cli_test.db'}")
    db.init_db()
    db.seed_initial_targets(targets_yaml_path=Path("config/targets.yaml"))

    table = list_targets_table(db)
    assert "example.com" in table
    assert "idle" in table

    assert remove_target_by_domain(db, "example.com") is True
    assert remove_target_by_domain(db, "example.com") is False


def test_web_dashboard_and_rest_api_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "web_test.db"
    reports_dir = tmp_path / "reports"
    db = DatabaseManager(f"sqlite:///{db_path}")
    db.init_db()
    db.seed_initial_targets(targets_yaml_path=Path("config/targets.yaml"))

    cfg = AppConfig(
        database={"url": f"sqlite:///{db_path}"},
        reporting={"output_dir": str(reports_dir), "export_formats": ["markdown", "json", "csv"]},
    )
    secrets = SecretsConfig()
    reporter = IntelligenceReporter(output_dir=reports_dir, template_dir=Path("templates"))

    # Seed one completed scan run on example.com for detail/report tests
    with db.get_session() as session:
        t = session.query(Target).filter_by(domain="example.com").first()
        assert t is not None
        run = ScanRun(target_id=t.id, started_at=utc_now(), status="RUNNING")
        session.add(run)
        session.flush()
        engine = StateDiffEngine()
        engine.process_scan(
            session=session,
            target=t,
            current_run=run,
            dns_results={
                "api.example.com": DNSResolutionResult(
                    fqdn="api.example.com", a_records=["93.184.216.34"], is_resolving=True
                )
            },
            enrichments={
                "93.184.216.34": InternetDBResult(
                    ip_address="93.184.216.34", open_ports=[443], found=True
                )
            },
            typosquats=[
                ActiveTyposquat(
                    spoof_domain="examp1e.com",
                    permutation_type="homoglyph",
                    ip_address="198.51.100.42",
                    has_mx_record=True,
                    registrar="MockRegistrar",
                    registration_date="2026-11-20T00:00:00Z",
                )
            ],
        )
        t.scan_status = "completed"
        t.last_scanned_at = utc_now()
        session.commit()
        run_id = run.id

    async def _noop_bg_scan(**_kwargs) -> None:
        return None

    monkeypatch.setattr("src.web.app._run_background_scan", _noop_bg_scan)

    app = create_app(db_manager=db, app_config=cfg, secrets=secrets, reporter=reporter)
    client = TestClient(app)

    # 1. Homepage renders target list
    resp_home = client.get("/")
    assert resp_home.status_code == 200
    assert "example.com" in resp_home.text

    # 2. SSRF / invalid domain rejected cleanly
    resp_bad = client.post("/api/targets", json={"domain": "127.0.0.1", "scan_now": False})
    assert resp_bad.status_code == 400
    resp_bad2 = client.post("/api/targets", json={"domain": "evil.local", "scan_now": False})
    assert resp_bad2.status_code == 400

    # 3. Create valid target without immediate scan
    resp_create = client.post(
        "/api/targets",
        json={"domain": "https://OWASP.org/", "allowlist": "owasp.net", "scan_now": False},
    )
    assert resp_create.status_code == 201
    created = resp_create.json()
    assert created["domain"] == "owasp.org"
    assert created["allowlist"] == ["owasp.net"]
    new_id = created["id"]

    # 4. Duplicate target returns 409
    resp_dup = client.post("/api/targets", json={"domain": "owasp.org", "scan_now": False})
    assert resp_dup.status_code == 409

    # 5. Toggle active & check status
    resp_toggle = client.patch(f"/api/targets/{new_id}/toggle")
    assert resp_toggle.status_code == 200
    assert resp_toggle.json()["is_active"] is False

    resp_status = client.get(f"/api/targets/{new_id}/status")
    assert resp_status.status_code == 200
    assert resp_status.json()["scan_status"] == "idle"

    # 6. Trigger background scan returns 202 Accepted
    resp_scan = client.post(f"/api/targets/{new_id}/scan")
    assert resp_scan.status_code == 202
    assert resp_scan.json()["scan_status"] == "running"

    # 7. Target detail page & report downloads
    resp_detail = client.get(f"/targets/example.com?run_id={run_id}")
    assert resp_detail.status_code == 200
    assert "api.example.com" in resp_detail.text
    assert "examp1e.com" in resp_detail.text

    for fmt in ("md", "json", "csv"):
        dl = client.get(f"/api/reports/{run_id}/{fmt}")
        assert dl.status_code == 200
        assert len(dl.content) > 10

    # 8. Delete target (reset scan_status first if running)
    with db.get_session() as session:
        t_new = session.get(Target, new_id)
        assert t_new is not None
        t_new.scan_status = "idle"
        session.commit()

    resp_del = client.delete(f"/api/targets/{new_id}")
    assert resp_del.status_code == 200
    assert resp_del.json()["deleted"] is True
