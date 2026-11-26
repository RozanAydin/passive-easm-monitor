# Automated External Attack Surface & Brand Threat Intelligence Monitor

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)
![Architecture](https://img.shields.io/badge/OSINT-100%25%20Passive-green)
![Database](https://img.shields.io/badge/Database-SQLite%20%7C%20PostgreSQL-informational)
![Container](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)

An automated, **100% passive** OSINT & Cyber Threat Intelligence (CTI) monitoring engine built with Python (`asyncio`, `httpx`, `dnspython`, `SQLAlchemy`, `Pydantic`, `Jinja2`). It continuously inventories external attack surfaces, detects active typosquatting/phishing infrastructure, enriches exposed IPs passively, tracks state deltas across scans, dispatches real-time webhook alerts, and exports executive reports and structured IoC feeds.

---

## Key Features

- **Passive EASM Collection (`src/collectors/crtsh_collector.py`, `dns_resolver.py`):** Harvests subdomains from Certificate Transparency logs (`crt.sh`), strips wildcards, enforces exclusions, and performs rate-limited async DNS resolution (`A`, `AAAA`, `CNAME`, `MX`).
- **Brand & Typosquatting Detection (`src/collectors/typosquat.py`):** Generates domain permutations (*omission*, *repetition*, *transposition*, *hyphenation*, *TLD swap*, *homoglyph*), filters for actively resolving domains (`A`/`MX`), and fetches RDAP registration metadata.
- **Passive IP Enrichment & PII Redaction (`src/enrichment/internetdb.py`, `sanitizer.py`):** Queries Shodan InternetDB (`ports`, `cpes`, `tags`, `vulns`/CVEs) without sending intrusive packets, and masks emails, phone numbers, and personal contact fields from WHOIS/RDAP payloads.
- **Stateful Diffing & Idempotency (`src/core/diff_engine.py`, `risk_scorer.py`):** Compares current scan run ($T_n$) against the latest completed scan run ($T_{n-1}$) to flag only new subdomains, IP changes, newly exposed ports, new CVEs, and active spoof domains without duplicate rows or repeat alerts.
- **Real-Time Alerting & Intelligence Reporting (`src/outputs/notifier.py`, `reporter.py`):** Dispatches severity-filtered alerts to Telegram, Slack, or Discord webhooks and generates `executive_report.md` (optional HTML), `ioc_feed.json`, and `ioc_feed.csv`.

---

## System Architecture

```text
+-------------------+      +-------------------------------------------+
|   config.yaml     | ---> |           Orchestrator (main.py)          |
|  & .env Secrets   |      +-------------------------------------------+
+-------------------+                            |
                                                 v
                    +----------------------------+----------------------------+
                    |                                                         |
                    v                                                         v
    +-------------------------------+                         +-------------------------------+
    |    Module 1: EASM Collector   |                         | Module 2: Typosquat Collector |
    | - crt.sh (CT Logs)            |                         | - Domain Permutations         |
    | - Async DNS (A/AAAA/CNAME/MX) |                         | - Async DNS (A / MX)          |
    | - Scope & Exclusion Filter    |                         | - Public RDAP Metadata        |
    +-------------------------------+                         +-------------------------------+
                    |                                                         |
                    +----------------------------+----------------------------+
                                                 |
                                                 v
                    +---------------------------------------------------------+
                    |              Module 3: Enrichment Engine                |
                    | - Shodan InternetDB (Passive Ports, CPEs, Tags, CVEs)   |
                    | - WHOIS / RDAP PII Redaction Filter                     |
                    +---------------------------------------------------------+
                                                 |
                                                 v
                    +---------------------------------------------------------+
                    |           Module 4: Storage & State Diff Engine         |
                    | - SQLite / PostgreSQL (SQLAlchemy ORM)                  |
                    | - Delta Comparison (T_n vs T_{n-1}) & Idempotency       |
                    | - Risk Scoring Engine (LOW -> CRITICAL)                 |
                    +---------------------------------------------------------+
                                                 |
                                                 v
                    +---------------------------------------------------------+
                    |          Module 5: Alerting & Reporting Engine          |
                    | - Real-Time Webhook (Telegram / Slack / Discord)        |
                    | - Jinja2 Executive Summary Report (Markdown / HTML)     |
                    | - Structured IoC Export (JSON / CSV)                    |
                    +---------------------------------------------------------+
```

---

## Ethical & Legal Guardrails (Rules of Engagement)

1. **100% Passive Reconnaissance:** Never sends active port-scan packets (e.g., Nmap SYN scans) or directory/credential brute-force traffic to target infrastructure.
2. **Authorized Scope Only:** Only test against domains you own, lab infrastructure, or public Bug Bounty targets explicitly permitting passive OSINT. Target domains and exclusions are strictly validated via `authorized_scope` and `exclude_subdomains` in `config/config.yaml`.
3. **Rate Limiting & Exponential Backoff:** All external HTTP/DNS queries enforce concurrency semaphores, configurable rate delays, and exponential backoff (`2s`, `4s`, `8s`) on HTTP `429`/`503`.
4. **PII Redaction:** Registrant emails, phone numbers, and personal contact attributes from WHOIS/RDAP responses are redacted (`[REDACTED_EMAIL]`, `[REDACTED_PHONE]`, `[REDACTED_PII]`) before storage or reporting.

---

## Risk Scoring Rules

| Severity | Trigger Conditions |
| --- | --- |
| **CRITICAL** | New resolving subdomain with sensitive open port(s) (e.g., `21`, `22`, `23`, `25`, `445`, `1433`, `3306`, `3389`, `5432`, `6379`, `9200`, `27017`) or known `CVE`; new `CVE` or new sensitive port on an existing asset. |
| **HIGH** | Newly detected active typosquatting domain (`A` or `MX` record); new non-sensitive open port on an existing asset. |
| **MEDIUM** | New active subdomain with standard/non-sensitive ports and no CVEs; DNS IP address change (`IP_CHANGE`) on an existing subdomain. |
| **LOW** | New subdomain discovered in Certificate Transparency logs without active DNS resolution (`NXDOMAIN`). |

---

## Database Schema

Defined via SQLAlchemy ORM in `src/core/database.py` (compatible with SQLite and PostgreSQL):

- `targets` — Monitored root domains.
- `scan_runs` — Execution history (`RUNNING`, `COMPLETED`, `FAILED`), subdomain totals, and new finding counts.
- `subdomains` — Deduplicated subdomain inventory (`UNIQUE(target_id, fqdn)`) tracking `first_seen_run_id` and `last_seen_run_id`.
- `ip_enrichments` — Per-run Shodan InternetDB snapshots (`open_ports`, `cves`, `cpes`, `tags`).
- `typosquat_domains` — Verified active spoof domains (`UNIQUE(target_id, spoof_domain)`) with sanitized RDAP registrar/date metadata.
- `alerts` — Classified security deltas (`NEW_SUBDOMAIN`, `NEW_PORT`, `NEW_CVE`, `IP_CHANGE`, `TYPOSQUAT_ACTIVE`) and webhook notification status.

---

## Project Structure

```text
.
├── config/
│   └── config.yaml              # Target domains, alert thresholds, & collector settings
├── src/
│   ├── __init__.py
│   ├── main.py                  # CLI entry point & pipeline orchestrator
│   ├── config_loader.py         # Pydantic config validation & .env secret loader
│   ├── logger.py                # Structured logging ([TIMESTAMP] [LEVEL] [MODULE] Message)
│   ├── collectors/
│   │   ├── crtsh_collector.py   # Passive Certificate Transparency collector
│   │   ├── dns_resolver.py      # Async DNS resolver (A, AAAA, CNAME, MX)
│   │   └── typosquat.py         # Permutation generator, DNS verifier, & RDAP collector
│   ├── enrichment/
│   │   ├── internetdb.py        # Passive Shodan InternetDB API client
│   │   └── sanitizer.py         # PII redaction filter for WHOIS/RDAP
│   ├── core/
│   │   ├── database.py          # SQLAlchemy ORM models & session manager
│   │   ├── diff_engine.py       # State comparison (T_n vs T_{n-1})
│   │   └── risk_scorer.py       # Severity classification & remediation recommendations
│   └── outputs/
│       ├── notifier.py          # Telegram / Slack / Discord webhook dispatcher
│       └── reporter.py          # Jinja2 report generator & JSON/CSV IoC exporter
├── templates/
│   └── executive_report.md.j2   # Markdown executive summary template
├── tests/
│   ├── test_diff_engine.py      # Diffing, severity rules, & idempotency unit tests
│   ├── test_integration.py      # End-to-end mocked pipeline + SQLite integration tests
│   ├── test_sanitizer.py        # PII redaction tests
│   └── test_typosquat.py        # Permutation & RDAP collector tests
├── .env.example                 # Environment variable template for secrets
├── .gitignore
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Configuration

### 1. Environment Secrets (`.env`)

Copy `.env.example` to `.env` and populate only the notification provider(s) you use. Secrets are loaded exclusively from environment variables and are rejected if placed inside `config/config.yaml`.

```bash
cp .env.example .env
```

Available variables:
- `TELEGRAM_BOT_TOKEN` & `TELEGRAM_CHAT_ID`
- `SLACK_WEBHOOK_URL`
- `DISCORD_WEBHOOK_URL`
- `DATABASE_URL` (optional override, e.g., for PostgreSQL)

### 2. Target & Pipeline Settings (`config/config.yaml`)

Configure target domains, `exclude_subdomains`, optional `authorized_scope`, collector concurrency/timeouts, `sensitive_ports`, `alerting`, and `reporting`.

---

## Quick Start

### Local Execution (Python 3.11+)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

python -m src.main --config config/config.yaml
```

#### CLI Options

| Flag | Default | Description |
| --- | --- | --- |
| `--config` | `config/config.yaml` | Path to YAML configuration file |
| `--env` | `.env` | Path to `.env` secrets file |
| `--target` | `None` | Run only a specific configured domain |
| `--skip-notify` | `False` | Skip webhook alert delivery (dry run) |
| `--log-file` | `logs/monitor.log` | Structured log output file path |
| `--verbose` | `False` | Enable `DEBUG` log verbosity |

### Containerized Execution (Docker)

```bash
cp .env.example .env
docker compose up --build
```

Persistent outputs are mounted to `./data/`, `./logs/`, and `./reports/`.

---

## Outputs

After a scan finishes, the following artifacts are generated under `./reports/`:

- `executive_report.md` (and `executive_report.html` if `"html"` is enabled in `export_formats`): Executive summary with severity counts, delta findings, subdomain inventory, typosquatting table, and remediation actions.
- `ioc_feed.json`: Structured IoC feed for automation/SOAR ingestion:

```json
{
  "metadata": {
    "generated_at": "2026-11-26T01:30:00Z",
    "target_domain": "example.com",
    "scan_run_id": 14,
    "total_new_findings": 2
  },
  "indicators": [
    {
      "indicator_type": "domain-name",
      "indicator_value": "examp1e.com",
      "category": "TYPOSQUAT_ACTIVE",
      "severity": "HIGH",
      "attributes": {
        "permutation_type": "homoglyph",
        "resolved_ip": "198.51.100.42",
        "has_mx_record": true
      },
      "recommended_action": "Ajukan takedown domain examp1e.com dan blokir domain pengirim pada Secure Email Gateway."
    }
  ]
}
```

- `ioc_feed.csv`: Tabular IoC export for spreadsheet or SIEM ingestion.
- `logs/monitor.log`: Timestamped execution logs.

---

## Running Tests

Run all unit and end-to-end integration tests with `pytest`:

```bash
pytest -v
```
