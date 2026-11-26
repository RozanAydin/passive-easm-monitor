"""End-to-end integration tests with temporary SQLite DB and mocked passive sources."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml

from src.collectors.crtsh_collector import CrtShCollector
from src.collectors.dns_resolver import DNSResolutionResult
from src.collectors.typosquat import TyposquatCollector
from src.config_loader import load_config
from src.enrichment.internetdb import InternetDBClient
from src.main import run_pipeline
from src.outputs.notifier import WebhookNotifier
from src.outputs.reporter import IntelligenceReporter


class _MockDNSResolver:
    async def resolve_many(self, fqdns: list[str]) -> dict[str, DNSResolutionResult]:
        out: dict[str, DNSResolutionResult] = {}
        for fqdn in fqdns:
            if fqdn == "staging-api.example.com":
                out[fqdn] = DNSResolutionResult(
                    fqdn=fqdn, a_records=["203.0.113.88"], is_resolving=True
                )
            elif fqdn == "example.com":
                out[fqdn] = DNSResolutionResult(
                    fqdn=fqdn, a_records=["93.184.216.34"], is_resolving=True
                )
            elif fqdn == "examp1e.com":
                out[fqdn] = DNSResolutionResult(
                    fqdn=fqdn,
                    a_records=["198.51.100.42"],
                    mx_records=["mail.examp1e.com"],
                    is_resolving=True,
                )
            else:
                out[fqdn] = DNSResolutionResult(fqdn=fqdn, is_resolving=False)
        return out


@pytest.mark.asyncio
async def test_full_end_to_end_pipeline_creates_reports_and_notifies(tmp_path: Path) -> None:
    db_path = tmp_path / "test_intel.db"
    reports_dir = tmp_path / "reports"
    config_file = tmp_path / "config.yaml"
    env_file = tmp_path / ".env"

    config_data = {
        "project": {"name": "Test EASM", "environment": "development"},
        "database": {"url": f"sqlite:///{db_path}"},
        "authorized_scope": ["example.com"],
        "targets": [
            {
                "domain": "example.com",
                "enable_easm": True,
                "enable_typosquat": True,
                "exclude_subdomains": ["dev-sandbox.example.com"],
            }
        ],
        "collector_settings": {
            "dns_concurrency": 10,
            "request_timeout_sec": 5,
            "rate_limit_delay_sec": 0.0,
            "sensitive_ports": [22, 6379, 3389],
        },
        "alerting": {
            "enabled": True,
            "min_severity": "HIGH",
            "webhook_provider": "telegram",
        },
        "reporting": {
            "output_dir": str(reports_dir),
            "export_formats": ["markdown", "json", "csv"],
        },
    }
    config_file.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    env_file.write_text(
        "TELEGRAM_BOT_TOKEN=test-token\nTELEGRAM_CHAT_ID=123456\n",
        encoding="utf-8",
    )

    app_config, secrets = load_config(config_path=config_file, env_path=env_file)

    sent_webhooks: list[dict] = []

    def _mock_http(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "crt.sh" in url:
            return httpx.Response(
                200,
                json=[
                    {"name_value": "*.example.com\nstaging-api.example.com"},
                    {"name_value": "dev-sandbox.example.com"},
                    {"name_value": "orphan.example.com"},
                ],
            )
        if "internetdb.shodan.io/203.0.113.88" in url:
            return httpx.Response(
                200,
                json={
                    "ip": "203.0.113.88",
                    "ports": [443, 6379],
                    "vulns": [],
                    "cpes": ["cpe:/a:redis:redis:7.0"],
                    "tags": ["database"],
                    "hostnames": ["staging-api.example.com"],
                },
            )
        if "internetdb.shodan.io/" in url:
            return httpx.Response(404)
        if "rdap.org/domain/examp1e.com" in url:
            return httpx.Response(
                200,
                json={
                    "events": [{"eventAction": "registration", "eventDate": "2026-11-20T00:00:00Z"}],
                    "entities": [
                        {
                            "roles": ["registrar"],
                            "vcardArray": ["vcard", [["fn", {}, "text", "TestRegistrar"]]],
                        }
                    ],
                },
            )
        if "api.telegram.org" in url:
            sent_webhooks.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    transport = httpx.MockTransport(_mock_http)
    async with httpx.AsyncClient(transport=transport) as client:
        mock_dns = _MockDNSResolver()
        summaries = await run_pipeline(
            app_config=app_config,
            secrets=secrets,
            crtsh_collector=CrtShCollector(rate_limit_delay_sec=0.0, client=client),
            dns_resolver=mock_dns,  # type: ignore[arg-type]
            typosquat_collector=TyposquatCollector(
                dns_resolver=mock_dns,  # type: ignore[arg-type]
                rate_limit_delay_sec=0.0,
                http_client=client,
            ),
            internetdb_client=InternetDBClient(rate_limit_delay_sec=0.0, client=client),
            notifier=WebhookNotifier(app_config.alerting, secrets, client=client),
            reporter=IntelligenceReporter(
                output_dir=reports_dir,
                template_dir=Path("templates"),
                sensitive_ports=app_config.collector_settings.sensitive_ports,
            ),
        )

    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.total_subdomains == 3  # example.com, orphan.example.com, staging-api.example.com (dev-sandbox excluded)

    md_report = reports_dir / "executive_report.md"
    ioc_json_file = reports_dir / "ioc_feed.json"
    ioc_csv_file = reports_dir / "ioc_feed.csv"

    assert md_report.exists()
    assert ioc_json_file.exists()
    assert ioc_csv_file.exists()

    md_text = md_report.read_text(encoding="utf-8")
    assert "staging-api.example.com" in md_text
    assert "examp1e.com" in md_text
    assert "dev-sandbox.example.com" not in md_text

    ioc_data = json.loads(ioc_json_file.read_text(encoding="utf-8"))
    assert ioc_data["metadata"]["target_domain"] == "example.com"
    assert ioc_data["metadata"]["scan_run_id"] == summary.scan_run_id
    assert ioc_data["metadata"]["total_new_findings"] == 4

    indicators = {i["indicator_value"]: i for i in ioc_data["indicators"]}
    assert indicators["staging-api.example.com"]["severity"] == "CRITICAL"
    assert indicators["examp1e.com"]["category"] == "TYPOSQUAT_ACTIVE"
    assert indicators["examp1e.com"]["severity"] == "HIGH"
    assert indicators["orphan.example.com"]["severity"] == "LOW"

    # Only HIGH & CRITICAL alerts (staging-api.example.com & examp1e.com) trigger Telegram
    assert len(sent_webhooks) == 2


def test_config_rejects_out_of_scope_target_and_invalid_domain(tmp_path: Path) -> None:
    bad_scope = tmp_path / "bad_scope.yaml"
    bad_scope.write_text(
        yaml.safe_dump(
            {
                "authorized_scope": ["authorized.com"],
                "targets": [{"domain": "unauthorized.com"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="authorized_scope"):
        load_config(config_path=bad_scope, env_path=None)

    bad_domain = tmp_path / "bad_domain.yaml"
    bad_domain.write_text(
        yaml.safe_dump({"targets": [{"domain": "https://not-a-domain/path"}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid domain format"):
        load_config(config_path=bad_domain, env_path=None)


@pytest.mark.asyncio
async def test_crtsh_retries_on_429_and_cleans_wildcards(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0

    async def _no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("src.collectors.crtsh_collector.asyncio.sleep", _no_sleep)

    def _handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429)
        return httpx.Response(
            200,
            json=[
                {"name_value": "*.api.example.com\napi.example.com"},
                {"name_value": "excluded.example.com"},
            ],
        )

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        collector = CrtShCollector(rate_limit_delay_sec=0.0, client=client)
        subs = await collector.collect("example.com", exclude_subdomains=["excluded.example.com"])

    assert attempts == 2
    assert subs == ["api.example.com", "example.com"]
