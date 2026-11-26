"""Passive IP enrichment client using Shodan InternetDB API."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from src.logger import get_logger

logger = get_logger("enrichment.internetdb")

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
RETRY_DELAYS = (2, 4, 8)


@dataclass
class InternetDBResult:
    """Structured passive enrichment result for an IP address."""

    ip_address: str
    open_ports: list[int] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    found: bool = False


class InternetDBClient:
    """Async rate-limited client for Shodan's passive InternetDB API."""

    def __init__(
        self,
        timeout_sec: int = 10,
        rate_limit_delay_sec: float = 0.5,
        concurrency: int = 5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.rate_limit_delay_sec = rate_limit_delay_sec
        self.semaphore = asyncio.Semaphore(concurrency)
        self._external_client = client

    async def enrich_ip(
        self,
        ip_address: str,
        client: httpx.AsyncClient | None = None,
    ) -> InternetDBResult:
        """Query InternetDB for a single IP with exponential backoff on 429/503."""
        active_client = client or self._external_client
        owns_client = active_client is None
        if owns_client:
            active_client = httpx.AsyncClient(
                timeout=self.timeout_sec,
                headers={"User-Agent": "Passive-EASM-Threat-Monitor/1.0"},
            )

        url = INTERNETDB_URL.format(ip=ip_address)
        try:
            async with self.semaphore:
                for attempt in range(len(RETRY_DELAYS) + 1):
                    try:
                        if self.rate_limit_delay_sec > 0:
                            await asyncio.sleep(self.rate_limit_delay_sec)
                        response = await active_client.get(url)
                        if response.status_code == 200:
                            payload = response.json()
                            return InternetDBResult(
                                ip_address=ip_address,
                                open_ports=sorted(int(p) for p in payload.get("ports", [])),
                                cves=sorted(set(payload.get("vulns", []))),
                                cpes=sorted(set(payload.get("cpes", []))),
                                tags=sorted(set(payload.get("tags", []))),
                                hostnames=sorted(set(payload.get("hostnames", []))),
                                found=True,
                            )
                        if response.status_code == 404:
                            logger.debug("No InternetDB record found for IP %s", ip_address)
                            return InternetDBResult(ip_address=ip_address, found=False)
                        if response.status_code in (429, 503) and attempt < len(RETRY_DELAYS):
                            delay = RETRY_DELAYS[attempt]
                            logger.warning(
                                "InternetDB HTTP %d for %s; retrying in %ds (attempt %d/%d)",
                                response.status_code,
                                ip_address,
                                delay,
                                attempt + 1,
                                len(RETRY_DELAYS),
                            )
                            await asyncio.sleep(delay)
                            continue
                        logger.warning(
                            "Unexpected InternetDB status %d for %s",
                            response.status_code,
                            ip_address,
                        )
                        return InternetDBResult(ip_address=ip_address, found=False)
                    except httpx.RequestError as exc:
                        if attempt < len(RETRY_DELAYS):
                            delay = RETRY_DELAYS[attempt]
                            logger.warning(
                                "InternetDB request error for %s (%s); retrying in %ds",
                                ip_address,
                                exc,
                                delay,
                            )
                            await asyncio.sleep(delay)
                            continue
                        logger.error("InternetDB failed for %s: %s", ip_address, exc)
                        return InternetDBResult(ip_address=ip_address, found=False)
        finally:
            if owns_client and active_client is not None:
                await active_client.aclose()

        return InternetDBResult(ip_address=ip_address, found=False)

    async def enrich_ips(self, ip_addresses: list[str]) -> dict[str, InternetDBResult]:
        """Enrich a deduplicated list of IP addresses concurrently."""
        unique_ips = sorted({ip.strip() for ip in ip_addresses if ip and ip.strip()})
        if not unique_ips:
            return {}

        logger.info("Enriching %d unique IP address(es) via Shodan InternetDB", len(unique_ips))
        if self._external_client is not None:
            results = await asyncio.gather(
                *(self.enrich_ip(ip, client=self._external_client) for ip in unique_ips)
            )
        else:
            async with httpx.AsyncClient(
                timeout=self.timeout_sec,
                headers={"User-Agent": "Passive-EASM-Threat-Monitor/1.0"},
            ) as client:
                results = await asyncio.gather(
                    *(self.enrich_ip(ip, client=client) for ip in unique_ips)
                )

        return {res.ip_address: res for res in results}
