# Automated External Attack Surface & Brand Threat Intelligence Monitor

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)
![Architecture](https://img.shields.io/badge/OSINT-100%25%20Passive-green)
![Database](https://img.shields.io/badge/Database-SQLite%20WAL%20%7C%20PostgreSQL-informational)
![Web](https://img.shields.io/badge/Web-FastAPI%20%2B%20Tailwind-009688)
![Container](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)

An automated, **100% passive** OSINT & Cyber Threat Intelligence (CTI) monitoring platform built with a **Hybrid Architecture**:
1. **SQLite WAL-backed Target Management** for safe concurrent CLI + Web UI access (`PRAGMA journal_mode=WAL`, `timeout=30`).
2. **Flexible CLI Worker** (`--target`, `--all`, `--list-targets`, `--remove-target`) for automation and cron jobs.
3. **Lightweight SOC Web Dashboard** (`FastAPI` + `Jinja2` + `Tailwind CSS`) for managing targets, launching asynchronous background scans, inspecting scan histories, and downloading reports.

---

## Ethical & Legal Guardrails (Passive OSINT Disclaimer)

> **Important:** This software is designed strictly for **authorized defensive security monitoring and passive OSINT research**.

1. **100% Passive Reconnaissance:** Never sends active port-scan packets (e.g., Nmap SYN scans) or directory/credential brute-force traffic to target infrastructure. All exposure intelligence is collected from passive public repositories (Certificate Transparency via `crt.sh`, public DNS/RDAP, Shodan InternetDB).
2. **Authorized Scope Only:** Only monitor domains you own, authorized lab environments, or public Bug Bounty targets whose Rules of Engagement explicitly permit passive OSINT.
3. **Strict Input & SSRF Validation (`src/utils/validators.py`):** Rejects IP addresses, `localhost`, `.local`, `.internal`, wildcards, and shell metacharacters across both CLI and Web API inputs.
4. **Rate Limiting & Exponential Backoff:** All external HTTP/DNS queries enforce concurrency limits, polite rate delays, and exponential backoff (`2s`, `4s`, `8s`) on HTTP `429`/`503`.
5. **PII Redaction:** Registrant emails, phone numbers, and personal contact fields from WHOIS/RDAP responses are automatically masked (`[REDACTED_EMAIL]`, `[REDACTED_PHONE]`, `[REDACTED_PII]`) before storage or reporting.

---

## System Architecture

```text
+--------------------+     +-------------------------------+
| config/targets.yaml| --> | SQLite (WAL Mode) / PostgreSQL|
| & config.yaml/.env |     | (targets, scan_runs, alerts)  |
+--------------------+     +-------------------------------+
                                    ^             ^
                    +---------------+             +---------------+
                    |                                             |
        +-----------------------+                     +-----------------------+
        |  CLI Worker (main.py) |                     | FastAPI Web Dashboard |
        | --target / --all      |                     | (uvicorn :8000)       |
        +-----------------------+                     +-----------------------+
                    |                                             |
                    +---------------+-------------+---------------+
                                    |
                                    v
        +---------------------------------------------------------+
        | Shared Scan Pipeline (src/core/scanner.py)              |
        | 1. crt.sh CT Logs + Async DNS (A/AAAA/CNAME/MX)         |
        | 2. Typosquatting Permutations + Allowlist + RDAP        |
        | 3. Shodan InternetDB Passive Enrichment + PII Sanitizer |
        | 4. Stateful Diff Engine (T_n vs T_{n-1}) & Risk Scorer  |
        | 5. Telegram/Slack/Discord Alerts + Per-Run Reports      |
        +---------------------------------------------------------+
```

---

## Dynamic Risk Scoring Rules

| Severity | Trigger Conditions |
| --- | --- |
| **CRITICAL** | New resolving subdomain with sensitive open port(s) (`21`, `22`, `23`, `25`, `445`, `1433`, `3306`, `3389`, `5432`, `6379`, `9200`, `27017`) or known `CVE`; new `CVE` or sensitive port on an existing asset; active typosquatting domain registered **within the last 90 days AND with active `MX` records**. |
| **HIGH** | Active typosquatting domain with `MX` records (phishing/BEC risk); new non-sensitive open port on an existing asset. |
| **MEDIUM** | New active subdomain with standard/non-sensitive ports and no CVEs; DNS IP change (`IP_CHANGE`); active typosquatting domain with `A`/`AAAA` web IP without `MX`. |
| **LOW** | Non-resolving subdomain (`NXDOMAIN`) in CT logs; inactive typosquatting domain registered > 5 years ago without web IP or `MX`. |

---

## Project Structure

```text
.
├── config/
│   ├── config.yaml              # Pipeline settings, timeouts, sensitive ports, alerting
│   └── targets.yaml             # Initial seed targets (imported if DB targets table is empty)
├── src/
│   ├── main.py                  # CLI entry point (--target, --all, --list-targets, --remove-target)
│   ├── config_loader.py         # Pydantic config validation & .env secret loader
│   ├── logger.py                # Structured logging ([TIMESTAMP] [LEVEL] [MODULE] Message)
│   ├── utils/
│   │   └── validators.py        # Strict FQDN normalization & SSRF/injection validation
│   ├── collectors/
│   │   ├── crtsh_collector.py   # Passive CT log collector (40s timeout, params encoding)
│   │   ├── dns_resolver.py      # Async DNS resolver (A, AAAA, CNAME, MX)
│   │   └── typosquat.py         # Permutation generator, DNS verifier, allowlist & RDAP
│   ├── enrichment/
│   │   ├── internetdb.py        # Passive Shodan InternetDB client
│   │   └── sanitizer.py         # PII redaction filter for WHOIS/RDAP
│   ├── core/
│   │   ├── database.py          # SQLAlchemy ORM models, SQLite WAL mode & seeding
│   │   ├── scanner.py           # Shared async scan orchestrator (CLI + Web)
│   │   ├── diff_engine.py       # Stateful delta comparison & idempotency
│   │   └── risk_scorer.py       # Dynamic severity scoring & English recommendations
│   ├── outputs/
│   │   ├── notifier.py          # Telegram / Slack / Discord webhook dispatcher
│   │   └── reporter.py          # Per-run & latest Markdown/HTML/JSON/CSV report exporter
│   └── web/
│       ├── app.py               # FastAPI Web UI & REST API
│       └── templates/           # Dark-mode SOC Jinja2 + Tailwind templates
├── templates/
│   └── executive_report.md.j2   # Markdown executive summary template
├── tests/                       # Pytest unit & integration suite
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Quick Start

### 1. Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 2. CLI Mode (Automation & Cron Jobs)

```bash
# List registered targets in SQLite (auto-seeds from config/targets.yaml if empty)
python -m src.main --list-targets

# Upsert and scan a single authorized domain immediately
python -m src.main --target owasp.org

# Scan all active targets in SQLite (default when no flags are provided)
python -m src.main --all

# Remove a target from the database
python -m src.main --remove-target example.com
```

### 3. Web Dashboard Mode (`http://localhost:8000`)

Start the FastAPI dashboard locally:

```bash
uvicorn src.web.app:app --host 127.0.0.1 --port 8000
```

Then open **http://localhost:8000** in your browser to:
- Add root domains with optional comma-separated allowlists and trigger background scans (`202 Accepted`).
- Monitor live `scan_status` (`idle`, `running`, `completed`, `failed`) with automatic polling.
- Inspect historical `Scan Run ID`s, severity KPI cards, Delta Alerts, Subdomain Inventory, and Typosquatting/RDAP tables.
- Download per-run `executive_report.md`, `ioc_feed.json`, and `ioc_feed.csv`.

---

## Docker Usage

Build and start the Web Dashboard (`easm-web` bound to `127.0.0.1:8000`):

```bash
cp .env.example .env
docker compose --profile cli build
docker compose up -d easm-web
```

Run an ad-hoc or cron CLI scan sharing the same SQLite WAL database and reports volume:

```bash
docker compose run --rm easm-monitor --target owasp.org
docker compose run --rm easm-monitor --list-targets
```

---

## Output Reports

Reports are persisted per target/run under `./reports/{domain}/run_{run_id}_*` and also mirrored to `./reports/` for the latest run:
- `executive_report.md`
- `ioc_feed.json`
- `ioc_feed.csv`
- `logs/monitor.log`

---

## Testing

```bash
pytest -v
```
