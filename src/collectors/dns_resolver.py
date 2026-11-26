"""Asynchronous passive DNS resolver using dnspython."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

from src.logger import get_logger

logger = get_logger("collectors.dns_resolver")


@dataclass
class DNSResolutionResult:
    """Resolved DNS records for a single FQDN."""

    fqdn: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_record: str | None = None
    mx_records: list[str] = field(default_factory=list)
    is_resolving: bool = False

    @property
    def primary_ip(self) -> str | None:
        if self.a_records:
            return self.a_records[0]
        if self.aaaa_records:
            return self.aaaa_records[0]
        return None


class AsyncDNSResolver:
    """Rate-limited async DNS resolver for A, AAAA, CNAME, and MX records."""

    def __init__(
        self,
        concurrency: int = 20,
        timeout_sec: int = 10,
        nameservers: list[str] | None = None,
    ) -> None:
        self.semaphore = asyncio.Semaphore(concurrency)
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.timeout = float(timeout_sec)
        self.resolver.lifetime = float(timeout_sec)
        if nameservers:
            self.resolver.nameservers = nameservers

    async def _query_record(self, fqdn: str, rdtype: str) -> list[str]:
        try:
            answer = await self.resolver.resolve(fqdn, rdtype)
            results: list[str] = []
            for rdata in answer:
                if rdtype == "MX":
                    results.append(str(rdata.exchange).rstrip(".").lower())
                elif rdtype == "CNAME":
                    results.append(str(rdata.target).rstrip(".").lower())
                else:
                    results.append(str(rdata).strip())
            return sorted(set(results))
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            return []

    async def resolve_fqdn(self, fqdn: str) -> DNSResolutionResult:
        """Resolve A, AAAA, CNAME, and MX records for a single FQDN."""
        normalized = fqdn.strip().lower().rstrip(".")
        async with self.semaphore:
            a_task = self._query_record(normalized, "A")
            aaaa_task = self._query_record(normalized, "AAAA")
            cname_task = self._query_record(normalized, "CNAME")
            mx_task = self._query_record(normalized, "MX")
            a_records, aaaa_records, cname_records, mx_records = await asyncio.gather(
                a_task, aaaa_task, cname_task, mx_task
            )

        cname_record = cname_records[0] if cname_records else None
        is_resolving = bool(a_records or aaaa_records or cname_record or mx_records)
        return DNSResolutionResult(
            fqdn=normalized,
            a_records=a_records,
            aaaa_records=aaaa_records,
            cname_record=cname_record,
            mx_records=mx_records,
            is_resolving=is_resolving,
        )

    async def resolve_many(self, fqdns: list[str]) -> dict[str, DNSResolutionResult]:
        """Resolve a list of FQDNs concurrently respecting the semaphore."""
        unique_fqdns = sorted({f.strip().lower().rstrip(".") for f in fqdns if f and f.strip()})
        if not unique_fqdns:
            return {}
        logger.info("Resolving DNS records for %d FQDN(s)", len(unique_fqdns))
        results = await asyncio.gather(*(self.resolve_fqdn(fqdn) for fqdn in unique_fqdns))
        return {res.fqdn: res for res in results}
