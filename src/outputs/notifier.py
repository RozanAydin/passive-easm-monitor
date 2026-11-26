"""Real-time webhook notification engine for Telegram, Slack, and Discord."""

from __future__ import annotations

import asyncio
from typing import Sequence

import httpx

from src.config_loader import AlertingConfig, SecretsConfig
from src.core.database import Alert
from src.core.risk_scorer import meets_severity_threshold
from src.logger import get_logger

logger = get_logger("outputs.notifier")

RETRY_DELAYS = (2, 4, 8)


def format_alert_message(alert: Alert, target_domain: str) -> str:
    """Format an alert into a clear, structured security notification message."""
    return (
        f"[{alert.severity}] {alert.category} - {target_domain}\n"
        f"Indicator: {alert.indicator}\n"
        f"Details: {alert.description}\n"
        f"Scan Run ID: {alert.scan_run_id}"
    )


class WebhookNotifier:
    """Dispatches filtered security alerts to configured webhook providers."""

    def __init__(
        self,
        alerting_config: AlertingConfig,
        secrets: SecretsConfig,
        timeout_sec: int = 10,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = alerting_config
        self.secrets = secrets
        self.timeout_sec = timeout_sec
        self._external_client = client

    def _build_request(self, message: str) -> tuple[str, dict] | None:
        provider = self.config.webhook_provider
        if provider == "telegram":
            token = self.secrets.telegram_bot_token
            chat_id = self.secrets.telegram_chat_id
            if not token or not chat_id:
                logger.warning(
                    "Telegram credentials missing in environment; skipping notification."
                )
                return None
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            return url, {"chat_id": chat_id, "text": message}

        if provider == "slack":
            url = self.secrets.slack_webhook_url
            if not url:
                logger.warning("SLACK_WEBHOOK_URL missing in environment; skipping notification.")
                return None
            return url, {"text": message}

        if provider == "discord":
            url = self.secrets.discord_webhook_url
            if not url:
                logger.warning("DISCORD_WEBHOOK_URL missing in environment; skipping notification.")
                return None
            return url, {"content": message}

        logger.warning("Unsupported webhook provider: %s", provider)
        return None

    async def _post_with_retry(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: dict,
    ) -> bool:
        for attempt in range(len(RETRY_DELAYS) + 1):
            try:
                response = await client.post(url, json=payload)
                if 200 <= response.status_code < 300:
                    return True
                if response.status_code in (429, 503) and attempt < len(RETRY_DELAYS):
                    delay = RETRY_DELAYS[attempt]
                    logger.warning(
                        "Webhook returned HTTP %d; retrying in %ds",
                        response.status_code,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.error("Webhook delivery failed with HTTP %d", response.status_code)
                return False
            except httpx.RequestError as exc:
                if attempt < len(RETRY_DELAYS):
                    await asyncio.sleep(RETRY_DELAYS[attempt])
                    continue
                logger.error("Webhook request error: %s", exc)
                return False
        return False

    async def notify_alerts(
        self,
        alerts: Sequence[Alert],
        target_domain: str,
    ) -> int:
        """Send webhook notifications for unnotified alerts meeting min_severity."""
        if not self.config.enabled:
            logger.info("Alerting disabled in configuration; skipping webhook dispatch.")
            return 0

        eligible = [
            alert
            for alert in alerts
            if not alert.is_notified
            and meets_severity_threshold(alert.severity, self.config.min_severity)
        ]
        if not eligible:
            logger.info(
                "No unnotified alerts meet minimum severity '%s' for %s.",
                self.config.min_severity,
                target_domain,
            )
            return 0

        active_client = self._external_client
        owns_client = active_client is None
        if owns_client:
            active_client = httpx.AsyncClient(timeout=self.timeout_sec)

        sent_count = 0
        try:
            for alert in eligible:
                message = format_alert_message(alert, target_domain)
                req = self._build_request(message)
                if req is None:
                    break
                url, payload = req
                ok = await self._post_with_retry(active_client, url, payload)
                if ok:
                    alert.is_notified = True
                    sent_count += 1
                    await asyncio.sleep(0.2)
        finally:
            if owns_client and active_client is not None:
                await active_client.aclose()

        logger.info(
            "Dispatched %d/%d eligible webhook alert(s) for %s via %s",
            sent_count,
            len(eligible),
            target_domain,
            self.config.webhook_provider,
        )
        return sent_count
