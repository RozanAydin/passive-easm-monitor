"""Unit tests for StateDiffEngine, severity rules, and scan idempotency."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from src.collectors.dns_resolver import DNSResolutionResult
from src.collectors.typosquat import ActiveTyposquat
from src.core.database import (
    Alert,
    DatabaseManager,
    ScanRun,
    Subdomain,
    Target,
    TyposquatDomain,
    utc_now,
)
from src.core.diff_engine import StateDiffEngine
from src.core.risk_scorer import score_typosquat
from src.enrichment.internetdb import InternetDBResult


def _create_db() -> DatabaseManager:
    db = DatabaseManager("sqlite:///:memory:")
    db.init_db()
    return db


def test_diff_engine_initial_scan_severity_classification() -> None:
    db = _create_db()
    engine = StateDiffEngine(sensitive_ports=[22, 6379, 3389])

    with db.get_session() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()

        run1 = ScanRun(target_id=target.id, started_at=utc_now(), status="RUNNING")
        session.add(run1)
        session.flush()

        dns_results = {
            "www.example.com": DNSResolutionResult(
                fqdn="www.example.com", a_records=["198.51.100.10"], is_resolving=True
            ),
            "redis.example.com": DNSResolutionResult(
                fqdn="redis.example.com", a_records=["198.51.100.20"], is_resolving=True
            ),
            "vuln.example.com": DNSResolutionResult(
                fqdn="vuln.example.com", a_records=["198.51.100.30"], is_resolving=True
            ),
            "dead.example.com": DNSResolutionResult(
                fqdn="dead.example.com", is_resolving=False
            ),
        }
        enrichments = {
            "198.51.100.10": InternetDBResult(
                ip_address="198.51.100.10", open_ports=[80, 443], found=True
            ),
            "198.51.100.20": InternetDBResult(
                ip_address="198.51.100.20", open_ports=[443, 6379], found=True
            ),
            "198.51.100.30": InternetDBResult(
                ip_address="198.51.100.30", open_ports=[443], cves=["CVE-2024-9999"], found=True
            ),
        }
        typosquats = [
            ActiveTyposquat(
                spoof_domain="examp1e.com",
                permutation_type="homoglyph",
                ip_address="198.51.100.42",
                has_mx_record=True,
                registrar="MockReg",
            )
        ]

        summary = engine.process_scan(
            session=session,
            target=target,
            current_run=run1,
            dns_results=dns_results,
            enrichments=enrichments,
            typosquats=typosquats,
        )
        session.commit()

        by_indicator = {(a.category, a.indicator): a.severity for a in summary.alerts}
        assert by_indicator[("NEW_SUBDOMAIN", "www.example.com")] == "MEDIUM"
        assert by_indicator[("NEW_SUBDOMAIN", "redis.example.com")] == "CRITICAL"
        assert by_indicator[("NEW_SUBDOMAIN", "vuln.example.com")] == "CRITICAL"
        assert by_indicator[("NEW_SUBDOMAIN", "dead.example.com")] == "LOW"
        assert by_indicator[("TYPOSQUAT_ACTIVE", "examp1e.com")] == "HIGH"
        assert run1.status == "COMPLETED"
        assert run1.new_findings_count == 5


def test_diff_engine_detects_new_ports_cves_ip_change_and_is_idempotent() -> None:
    db = _create_db()
    engine = StateDiffEngine(sensitive_ports=[22, 6379, 3389])

    with db.get_session() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()

        # Run 1 (Baseline)
        run1 = ScanRun(target_id=target.id, started_at=utc_now(), status="RUNNING")
        session.add(run1)
        session.flush()

        dns1 = {
            "api.example.com": DNSResolutionResult(
                fqdn="api.example.com", a_records=["203.0.113.10"], is_resolving=True
            ),
            "app.example.com": DNSResolutionResult(
                fqdn="app.example.com", a_records=["203.0.113.20"], is_resolving=True
            ),
        }
        enrich1 = {
            "203.0.113.10": InternetDBResult(
                ip_address="203.0.113.10", open_ports=[443], cves=[], found=True
            ),
            "203.0.113.20": InternetDBResult(
                ip_address="203.0.113.20", open_ports=[80, 443], cves=[], found=True
            ),
        }
        engine.process_scan(session, target, run1, dns1, enrich1, [])
        session.commit()

        # Run 2 (Identical data -> MUST be idempotent: 0 new alerts, no duplicate rows)
        run2 = ScanRun(target_id=target.id, started_at=utc_now(), status="RUNNING")
        session.add(run2)
        session.flush()
        summary2 = engine.process_scan(session, target, run2, dns1, enrich1, [])
        session.commit()

        assert summary2.alerts == []
        assert run2.new_findings_count == 0
        assert len(session.scalars(select(Subdomain)).all()) == 2

        # Run 3 (Deltas: api gains port 6379 + CVE; app changes IP; new typosquat)
        run3 = ScanRun(target_id=target.id, started_at=utc_now(), status="RUNNING")
        session.add(run3)
        session.flush()

        dns3 = {
            "api.example.com": DNSResolutionResult(
                fqdn="api.example.com", a_records=["203.0.113.10"], is_resolving=True
            ),
            "app.example.com": DNSResolutionResult(
                fqdn="app.example.com", a_records=["203.0.113.99"], is_resolving=True
            ),
        }
        enrich3 = {
            "203.0.113.10": InternetDBResult(
                ip_address="203.0.113.10",
                open_ports=[443, 6379],
                cves=["CVE-2025-1234"],
                found=True,
            ),
            "203.0.113.99": InternetDBResult(
                ip_address="203.0.113.99", open_ports=[443, 8443], cves=[], found=True
            ),
        }
        typos3 = [
            ActiveTyposquat(
                spoof_domain="exmple.com",
                permutation_type="omission",
                ip_address="198.51.100.77",
                has_mx_record=False,
            )
        ]

        summary3 = engine.process_scan(session, target, run3, dns3, enrich3, typos3)
        session.commit()

        alert_map = {(a.category, a.indicator): a.severity for a in summary3.alerts}
        assert alert_map[("NEW_PORT", "203.0.113.10")] == "CRITICAL"
        assert alert_map[("NEW_CVE", "203.0.113.10")] == "CRITICAL"
        assert alert_map[("IP_CHANGE", "app.example.com")] == "MEDIUM"
        assert alert_map[("NEW_PORT", "203.0.113.99")] == "HIGH"
        assert alert_map[("TYPOSQUAT_ACTIVE", "exmple.com")] == "MEDIUM"
        assert len(session.scalars(select(TyposquatDomain)).all()) == 1
        assert len(session.scalars(select(Alert)).all()) == 7


def test_dynamic_typosquat_severity_scoring_rules() -> None:
    ref_now = datetime(2026, 11, 26, 0, 0, 0, tzinfo=timezone.utc)

    # CRITICAL: Registered within 90 days AND has active MX
    assert (
        score_typosquat(
            has_a_record=True,
            has_mx_record=True,
            registration_date="2026-10-15T00:00:00Z",
            now=ref_now,
        )
        == "CRITICAL"
    )
    # HIGH: Active MX, registered > 90 days ago
    assert (
        score_typosquat(
            has_a_record=True,
            has_mx_record=True,
            registration_date="2024-01-01T00:00:00Z",
            now=ref_now,
        )
        == "HIGH"
    )
    # MEDIUM: Active A/AAAA web IP without MX
    assert (
        score_typosquat(
            has_a_record=True,
            has_mx_record=False,
            registration_date="2026-11-01T00:00:00Z",
            now=ref_now,
        )
        == "MEDIUM"
    )
    # LOW: Registered > 5 years ago with no active web IP or MX
    assert (
        score_typosquat(
            has_a_record=False,
            has_mx_record=False,
            registration_date="2018-01-01T00:00:00Z",
            now=ref_now,
        )
        == "LOW"
    )
