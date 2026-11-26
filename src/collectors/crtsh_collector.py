"""Certificate Transparency (crt.sh) passive subdomain collector."""

from __future__ import annotations

import asyncio
from typing import Iterable

import httpx

from src.config_loader import is_subdomain_excluded
from src.logger import get_logger

logger = get_logger("collectors.crtsh")

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
RETRY_DELAYS = (2, 4, 8)


def extract_subdomains_from_crtsh_entries(
    entries: Iterable[dict],
    root_domain: str,
    exclude_subdomains: list[str] | None = None,
) -> list[str]:
    """Normalize, strip wildcards, deduplicate, and filter CT log entries."""
    root = root_domain.strip().lower().rstrip(".")
    exclusions = exclude_subdomains or []
    found: set[str] = set()

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw_names: list[str] = []
        name_value = entry.get("name_value")
        if isinstance(name_value, str):
            raw_names.extend(name_value.splitlines())
        common_name = entry.get("common_name")
        if isinstance(common_name, str):
            raw_names.append(common_name)

        for raw in raw_names:
            candidate = raw.strip().lower().rstrip(".")
            if not candidate:
                continue
            # Clean wildcard entries (*.example.com -> example.com, *.sub.example.com -> sub.example.com)
            while candidate.startswith("*."):
                candidate = candidate[2:]
            if not candidate or "*" in candidate or " " in candidate:
                continue
            if candidate != root and not candidate.endswith(f".{root}"):
                continue
            if is_subdomain_excluded(candidate, exclusions):
                continue
            found.add(candidate)

    return sorted(found)


class CrtShCollector:
    """Async collector for Certificate Transparency logs via crt.sh."""

    def __init__(
        self,
        timeout_sec: int = 10,
        rate_limit_delay_sec: float = 0.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.rate_limit_delay_sec = rate_limit_delay_sec
        self._external_client = client

    async def collect(
        self,
        domain: str,
        exclude_subdomains: list[str] | None = None,
    ) -> list[str]:
        """Fetch and clean subdomains for a root domain from crt.sh."""
        root = domain.strip().lower().rstrip(".")
        url = CRTSH_URL.format(domain=root)
        active_client = self._external_client
        owns_client = active_client is None
        if owns_client:
            active_client = httpx.AsyncClient(
                timeout=self.timeout_sec,
                headers={"User-Agent": "Passive-EASM-Threat-Monitor/1.0"},
            )

        try:
            for attempt in range(len(RETRY_DELAYS) + 1):
                try:
                    if self.rate_limit_delay_sec > 0:
                        await asyncio.sleep(self.rate_limit_delay_sec)
                    logger.info("Querying crt.sh for domain %s (attempt %d)", root, attempt + 1)
                    response = await active_client.get(url)
                    if response.status_code == 200:
                        try:
                            data = response.json()
                        except ValueError as exc:
                            logger.error("Invalid JSON returned by crt.sh for %s: %s", root, exc)
                            return [root] if not is_subdomain_excluded(root, exclude_subdomains or []) else []
                        if not isinstance(data, list):
                            logger.warning("Unexpected crt.sh response shape for %s", root)
                            return [root]
                        subdomains = extract_subdomains_from_crtsh_entries(
                            data, root, exclude_subdomains
                        )
                        if root not in subdomains and not is_subdomain_excluded(
                            root, exclude_subdomains or []
                        ):
                            subdomains = sorted(set(subdomains) | {root})
                        logger.info(
                            "Collected %d unique subdomain(s) for %s from crt.sh",
                            len(subdomains),
                            root,
                        )
                        return subdomains

                    if response.status_code in (429, 503) and attempt < len(RETRY_DELAYS):
                        delay = RETRY_DELAYS[attempt]
                        logger.warning(
                            "crt.sh returned HTTP %d for %s; retrying in %ds",
                            response.status_code,
                            root,
                            delay,
                        )
                        await asyncio.sleep(delay)
                        continue

                    logger.error(
                        "crt.sh returned HTTP %d for %s; aborting CT collection",
                        response.status_code,
                        root,
                    )
                    break
                except httpx.RequestError as exc:
                    if attempt < len(RETRY_DELAYS):
                        delay = RETRY_DELAYS[attempt]
                        logger.warning(
                            "crt.sh request error for %s (%s); retrying in %ds",
                            root,
                            exc,
                            delay,
                        )
                        await asyncio.sleep(delay)
                        continue
                    logger.error("crt.sh request failed for %s: %s", root, exc)
                    break
        finally:
            if owns_client and active_client is not None:
                await active_client.aclose()

        return []
