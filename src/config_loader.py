"""Configuration loader and Pydantic validation for config.yaml and .env secrets."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator, model_validator

from src.utils.validators import (
    is_domain_allowlisted,
    validate_allowlist_entry,
    validate_and_normalize_domain,
)


def validate_domain_name(value: str, allow_wildcard: bool = False) -> str:
    """Normalize and validate a domain name string (delegating to src.utils.validators)."""
    if allow_wildcard:
        return validate_allowlist_entry(value, allow_wildcard=True)
    return validate_and_normalize_domain(value)


class ProjectConfig(BaseModel):
    name: str = "Passive EASM & Brand Threat Intelligence Monitor"
    environment: Literal["development", "staging", "production"] = "development"


class DatabaseConfig(BaseModel):
    url: str = "sqlite:///data/threat_intel.db"


class TargetConfig(BaseModel):
    domain: str
    enable_easm: bool = True
    enable_typosquat: bool = True
    exclude_subdomains: list[str] = Field(default_factory=list)

    @field_validator("domain")
    @classmethod
    def check_domain(cls, v: str) -> str:
        return validate_and_normalize_domain(v)

    @field_validator("exclude_subdomains")
    @classmethod
    def check_exclude_subdomains(cls, values: list[str]) -> list[str]:
        return [validate_allowlist_entry(item, allow_wildcard=True) for item in values]

    @model_validator(mode="after")
    def validate_scope_consistency(self) -> "TargetConfig":
        if self.domain in self.exclude_subdomains:
            raise ValueError(
                f"Target domain '{self.domain}' cannot be in its own exclude_subdomains list."
            )
        return self


class CollectorSettings(BaseModel):
    dns_concurrency: int = Field(default=20, ge=1, le=100)
    request_timeout_sec: int = Field(default=10, ge=1, le=120)
    crtsh_timeout_sec: int = Field(default=40, ge=5, le=180)
    rate_limit_delay_sec: float = Field(default=0.5, ge=0.0, le=60.0)
    sensitive_ports: list[int] = Field(
        default_factory=lambda: [21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017]
    )

    @field_validator("sensitive_ports")
    @classmethod
    def check_ports(cls, ports: list[int]) -> list[int]:
        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid port number in sensitive_ports: {port}")
        return sorted(set(ports))


class AlertingConfig(BaseModel):
    enabled: bool = True
    min_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    webhook_provider: Literal["telegram", "slack", "discord"] = "telegram"


class ReportingConfig(BaseModel):
    output_dir: str = "./reports"
    export_formats: list[Literal["markdown", "html", "json", "csv"]] = Field(
        default_factory=lambda: ["markdown", "json", "csv"]
    )


class SecretsConfig(BaseModel):
    """Secrets loaded strictly from environment variables (.env)."""

    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None

    @classmethod
    def from_env(cls) -> "SecretsConfig":
        return cls(
            telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN") or None,
            telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID") or None,
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL") or None,
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL") or None,
        )


class AppConfig(BaseModel):
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    targets: list[TargetConfig] = Field(default_factory=list)
    authorized_scope: list[str] | None = None
    collector_settings: CollectorSettings = Field(default_factory=CollectorSettings)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    @field_validator("authorized_scope")
    @classmethod
    def check_authorized_scope(cls, scope: list[str] | None) -> list[str] | None:
        if scope is None:
            return None
        return [validate_and_normalize_domain(d) for d in scope]

    @model_validator(mode="after")
    def enforce_authorized_scope(self) -> "AppConfig":
        if self.authorized_scope is not None:
            allowed = set(self.authorized_scope)
            for target in self.targets:
                if target.domain not in allowed:
                    raise ValueError(
                        f"Target domain '{target.domain}' is outside authorized_scope: {sorted(allowed)}"
                    )
        return self


def is_subdomain_excluded(fqdn: str, exclude_patterns: list[str]) -> bool:
    """Return True if fqdn matches an exact or wildcard exclusion entry."""
    return is_domain_allowlisted(fqdn, exclude_patterns)


def load_config(
    config_path: str | Path = "config/config.yaml",
    env_path: str | Path | None = ".env",
) -> tuple[AppConfig, SecretsConfig]:
    """Load and validate config.yaml and .env secrets."""
    if env_path is not None and Path(env_path).exists():
        load_dotenv(dotenv_path=env_path, override=False)
    else:
        load_dotenv(override=False)

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f) or {}

    forbidden_keys = {
        "telegram_bot_token",
        "telegram_chat_id",
        "slack_webhook_url",
        "discord_webhook_url",
    }
    alerting_raw = raw_data.get("alerting", {})
    if isinstance(alerting_raw, dict) and any(k in alerting_raw for k in forbidden_keys):
        raise ValueError(
            "Secrets (tokens/webhooks) must not be placed in config.yaml; use .env instead."
        )

    app_config = AppConfig.model_validate(raw_data)

    env_db_url = os.getenv("DATABASE_URL")
    if env_db_url:
        app_config.database.url = env_db_url

    secrets = SecretsConfig.from_env()
    return app_config, secrets
