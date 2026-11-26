"""Typosquatting permutation generator, DNS verifier, and RDAP metadata collector."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

import httpx

from src.collectors.dns_resolver import AsyncDNSResolver, DNSResolutionResult
from src.enrichment.sanitizer import redact_text, sanitize_rdap_data
from src.logger import get_logger
from src.utils.validators import is_domain_allowlisted

logger = get_logger("collectors.typosquat")

COMMON_TLDS = ("net", "org", "co", "id", "xyz")
ASCII_HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "a": ("4",),
    "e": ("3",),
    "i": ("1", "l"),
    "l": ("1", "i"),
    "o": ("0",),
    "s": ("5",),
    "g": ("9",),
    "m": ("rn",),
    "w": ("vv",),
    "0": ("o",),
    "1": ("l", "i"),
}
RDAP_URL = "https://rdap.org/domain/{domain}"
RETRY_DELAYS = (2, 4, 8)
LABEL_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class PermutationCandidate:
    """A single generated typosquatting domain candidate."""

    domain: str
    permutation_type: str


@dataclass
class ActiveTyposquat:
    """Verified active typosquatting domain with DNS and sanitized RDAP metadata."""

    spoof_domain: str
    permutation_type: str
    ip_address: str | None
    has_mx_record: bool
    registrar: str | None = None
    registration_date: str | None = None


def _split_domain(domain: str) -> tuple[str, str]:
    """Split a domain into its primary label and TLD/suffix (supports multi-part SLDs)."""
    normalized = domain.strip().lower().rstrip(".")
    parts = normalized.split(".")
    if len(parts) < 2:
        raise ValueError(f"Domain must contain at least one dot: '{domain}'")
    return parts[0], ".".join(parts[1:])


def _is_valid_label(label: str) -> bool:
    return bool(label and len(label) <= 63 and LABEL_REGEX.match(label))


def generate_permutations(domain: str) -> list[PermutationCandidate]:
    """Generate unique, DNS-valid typosquatting permutations for a target domain."""
    normalized_target = domain.strip().lower().rstrip(".")
    label, tld = _split_domain(normalized_target)

    seen: dict[str, str] = {}

    def _add(cand_label: str, cand_tld: str, ptype: str) -> None:
        if not _is_valid_label(cand_label):
            return
        candidate = f"{cand_label}.{cand_tld}".lower()
        if candidate == normalized_target:
            return
        if candidate not in seen:
            seen[candidate] = ptype

    # 1. Character omission
    if len(label) > 1:
        for idx in range(len(label)):
            _add(label[:idx] + label[idx + 1 :], tld, "omission")

    # 2. Character repetition
    for idx, ch in enumerate(label):
        if ch.isalnum():
            _add(label[: idx + 1] + ch + label[idx + 1 :], tld, "repetition")

    # 3. Adjacent character transposition
    for idx in range(len(label) - 1):
        if label[idx] != label[idx + 1]:
            swapped = label[:idx] + label[idx + 1] + label[idx] + label[idx + 2 :]
            _add(swapped, tld, "transposition")

    # 4. Hyphenation
    for idx in range(1, len(label)):
        if label[idx - 1] != "-" and label[idx] != "-":
            _add(label[:idx] + "-" + label[idx:], tld, "hyphenation")

    # 5. Common TLD swap
    for alt_tld in COMMON_TLDS:
        if alt_tld != tld:
            _add(label, alt_tld, "tld_swap")

    # 6. ASCII Homoglyph substitution
    for idx, ch in enumerate(label):
        for replacement in ASCII_HOMOGLYPHS.get(ch, ()):
            _add(label[:idx] + replacement + label[idx + 1 :], tld, "homoglyph")

    return [
        PermutationCandidate(domain=cand, permutation_type=ptype)
        for cand, ptype in sorted(seen.items())
    ]


def extract_rdap_metadata(rdap_payload: dict) -> tuple[str | None, str | None]:
    """Extract sanitized registrar name and registration date from RDAP JSON."""
    cleaned = sanitize_rdap_data(rdap_payload)

    registrar: str | None = None
    for entity in cleaned.get("entities", []):
        if not isinstance(entity, dict):
            continue
        roles = [str(r).lower() for r in entity.get("roles", [])]
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    if isinstance(prop, list) and len(prop) >= 4 and str(prop[0]).lower() in {"fn", "org"}:
                        candidate_name = redact_text(str(prop[3])).strip()
                        if candidate_name and "REDACTED" not in candidate_name:
                            registrar = candidate_name[:255]
                            break
            if not registrar and entity.get("handle"):
                registrar = redact_text(str(entity["handle"]))[:255]
        if registrar:
            break

    registration_date: str | None = None
    for event in cleaned.get("events", []):
        if isinstance(event, dict) and str(event.get("eventAction", "")).lower() == "registration":
            raw_date = event.get("eventDate")
            if raw_date:
                registration_date = str(raw_date)[:50]
                break

    return registrar, registration_date


class TyposquatCollector:
    """Generates typosquatting candidates, verifies DNS resolution, and enriches via RDAP."""

    def __init__(
        self,
        dns_resolver: AsyncDNSResolver | None = None,
        timeout_sec: int = 10,
        rate_limit_delay_sec: float = 0.5,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.dns_resolver = dns_resolver or AsyncDNSResolver(timeout_sec=timeout_sec)
        self.timeout_sec = timeout_sec
        self.rate_limit_delay_sec = rate_limit_delay_sec
        self._external_client = http_client

    async def _fetch_rdap(
        self,
        domain: str,
        client: httpx.AsyncClient,
    ) -> tuple[str | None, str | None]:
        url = RDAP_URL.format(domain=domain)
        for attempt in range(len(RETRY_DELAYS) + 1):
            try:
                if self.rate_limit_delay_sec > 0:
                    await asyncio.sleep(self.rate_limit_delay_sec)
                response = await client.get(url, follow_redirects=True)
                if response.status_code == 200:
                    return extract_rdap_metadata(response.json())
                if response.status_code in (429, 503) and attempt < len(RETRY_DELAYS):
                    await asyncio.sleep(RETRY_DELAYS[attempt])
                    continue
                return None, None
            except (httpx.RequestError, ValueError) as exc:
                if attempt < len(RETRY_DELAYS):
                    await asyncio.sleep(RETRY_DELAYS[attempt])
                    continue
                logger.debug(
                    "RDAP lookup failed for %s (%s: %s)",
                    domain,
                    type(exc).__name__,
                    exc,
                )
                return None, None
        return None, None

    async def collect(
        self,
        target_domain: str,
        allowlist: list[str] | None = None,
    ) -> list[ActiveTyposquat]:
        """Generate permutations, filter allowlist, check DNS A/AAAA/MX, and retrieve RDAP metadata."""
        exclusions = allowlist or []
        candidates = [
            cand
            for cand in generate_permutations(target_domain)
            if not is_domain_allowlisted(cand.domain, exclusions)
        ]
        if not candidates:
            return []

        logger.info(
            "Checking %d typosquatting permutation(s) for %s",
            len(candidates),
            target_domain,
        )
        candidate_domains = [c.domain for c in candidates]
        dns_results: dict[str, DNSResolutionResult] = await self.dns_resolver.resolve_many(
            candidate_domains
        )

        active_candidates: list[tuple[PermutationCandidate, DNSResolutionResult]] = []
        for cand in candidates:
            dns_res = dns_results.get(cand.domain)
            if dns_res and (dns_res.a_records or dns_res.aaaa_records or dns_res.mx_records):
                active_candidates.append((cand, dns_res))

        if not active_candidates:
            logger.info("No active typosquatting domains resolved for %s", target_domain)
            return []

        logger.info(
            "Found %d active typosquatting domain(s) for %s; querying RDAP",
            len(active_candidates),
            target_domain,
        )

        active_client = self._external_client
        owns_client = active_client is None
        if owns_client:
            active_client = httpx.AsyncClient(
                timeout=self.timeout_sec,
                headers={"User-Agent": "Passive-EASM-Threat-Monitor/1.0"},
            )

        results: list[ActiveTyposquat] = []
        try:
            rdap_semaphore = asyncio.Semaphore(5)

            async def _build(
                cand: PermutationCandidate, dns_res: DNSResolutionResult
            ) -> ActiveTyposquat:
                async with rdap_semaphore:
                    registrar, reg_date = await self._fetch_rdap(cand.domain, active_client)
                return ActiveTyposquat(
                    spoof_domain=cand.domain,
                    permutation_type=cand.permutation_type,
                    ip_address=dns_res.primary_ip,
                    has_mx_record=bool(dns_res.mx_records),
                    registrar=registrar,
                    registration_date=reg_date,
                )

            results = await asyncio.gather(
                *(_build(cand, dns_res) for cand, dns_res in active_candidates)
            )
        finally:
            if owns_client and active_client is not None:
                await active_client.aclose()

        return sorted(results, key=lambda item: item.spoof_domain)
