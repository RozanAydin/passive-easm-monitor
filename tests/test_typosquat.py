"""Unit tests for typosquatting generator and collector."""

from __future__ import annotations

import httpx
import pytest

from src.collectors.dns_resolver import DNSResolutionResult
from src.collectors.typosquat import (
    TyposquatCollector,
    extract_rdap_metadata,
    generate_permutations,
)


def test_generate_permutations_accuracy_and_uniqueness() -> None:
    candidates = generate_permutations("example.com")
    domains = [c.domain for c in candidates]
    by_domain = {c.domain: c.permutation_type for c in candidates}

    # No duplicates and never includes original domain
    assert len(domains) == len(set(domains))
    assert "example.com" not in by_domain

    # Expected permutation families from PRD Section 5.2 & 7.2
    assert by_domain["exmple.com"] == "omission"
    assert by_domain["exampple.com"] == "repetition"
    assert by_domain["examlpe.com"] == "transposition"
    assert by_domain["ex-ample.com"] == "hyphenation"
    assert by_domain["example.net"] == "tld_swap"
    assert by_domain["example.org"] == "tld_swap"
    assert by_domain["example.co"] == "tld_swap"
    assert by_domain["example.id"] == "tld_swap"
    assert by_domain["example.xyz"] == "tld_swap"
    assert by_domain["examp1e.com"] == "homoglyph"


def test_extract_rdap_metadata_preserves_registrar_and_redacts_pii() -> None:
    sample_rdap = {
        "ldhName": "examp1e.com",
        "events": [
            {"eventAction": "registration", "eventDate": "2026-10-01T12:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-10-01T12:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Example Registrar Inc."],
                        ["email", {}, "text", "abuse@registrar.example"],
                    ],
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "John Doe"],
                        ["email", {}, "text", "john.doe@attacker.invalid"],
                        ["tel", {}, "uri", "tel:+1-555-234-5678"],
                    ],
                ],
            },
        ],
    }

    registrar, reg_date = extract_rdap_metadata(sample_rdap)
    assert registrar == "Example Registrar Inc."
    assert reg_date == "2026-10-01T12:00:00Z"


class _StubDNSResolver:
    async def resolve_many(self, fqdns: list[str]) -> dict[str, DNSResolutionResult]:
        results: dict[str, DNSResolutionResult] = {}
        for fqdn in fqdns:
            if fqdn == "examp1e.com":
                results[fqdn] = DNSResolutionResult(
                    fqdn=fqdn,
                    a_records=["198.51.100.42"],
                    mx_records=["mail.examp1e.com"],
                    is_resolving=True,
                )
            else:
                results[fqdn] = DNSResolutionResult(fqdn=fqdn, is_resolving=False)
        return results


@pytest.mark.asyncio
async def test_typosquat_collector_filters_only_active_domains() -> None:
    def _mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "events": [{"eventAction": "registration", "eventDate": "2026-11-01T00:00:00Z"}],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "MockRegistrar Ltd"]]],
                    }
                ],
            },
        )

    transport = httpx.MockTransport(_mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        collector = TyposquatCollector(
            dns_resolver=_StubDNSResolver(),  # type: ignore[arg-type]
            rate_limit_delay_sec=0.0,
            http_client=client,
        )
        active = await collector.collect("example.com")

    assert len(active) == 1
    assert active[0].spoof_domain == "examp1e.com"
    assert active[0].permutation_type == "homoglyph"
    assert active[0].ip_address == "198.51.100.42"
    assert active[0].has_mx_record is True
    assert active[0].registrar == "MockRegistrar Ltd"
    assert active[0].registration_date == "2026-11-01T00:00:00Z"
