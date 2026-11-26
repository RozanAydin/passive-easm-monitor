"""Unit tests for PII redaction and WHOIS/RDAP sanitization."""

from __future__ import annotations

from src.enrichment.sanitizer import redact_text, sanitize_rdap_data


def test_redact_text_masks_emails_phones_and_whois_fields() -> None:
    raw_whois = (
        "Domain Name: EXAMP1E.COM\n"
        "Registrar: Example Registrar LLC\n"
        "Creation Date: 2026-11-01T00:00:00Z\n"
        "Registrant Name: Budi Santoso\n"
        "Registrant Street: Jl. Sudirman No. 10\n"
        "Registrant Phone: +62-812-3456-7890\n"
        "Registrant Email: budi.santoso@private-mail.id\n"
        "Admin Phone: (555) 123-4567\n"
        "Name Server: 198.51.100.42\n"
    )

    cleaned = redact_text(raw_whois)
    assert "budi.santoso@private-mail.id" not in cleaned
    assert "+62-812-3456-7890" not in cleaned
    assert "(555) 123-4567" not in cleaned
    assert "Budi Santoso" not in cleaned
    assert "Jl. Sudirman No. 10" not in cleaned
    assert "[REDACTED_EMAIL]" in cleaned
    assert "[REDACTED_PHONE]" in cleaned
    assert "[REDACTED_PII]" in cleaned

    # Non-PII fields like IP addresses, registrar, and ISO dates remain intact
    assert "198.51.100.42" in cleaned
    assert "2026-11-01T00:00:00Z" in cleaned
    assert "Example Registrar LLC" in cleaned


def test_sanitize_rdap_data_redacts_registrant_vcard_pii() -> None:
    rdap = {
        "ldhName": "examp1e.com",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Alice ThreatActor"],
                        ["adr", {}, "text", ["", "", "123 Hidden St", "Jakarta", "", "10110", "ID"]],
                        ["tel", {}, "uri", "tel:+62-811-9988-7766"],
                        ["email", {}, "text", "alice@evil-domain.xyz"],
                    ],
                ],
            },
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Safe Registrar Corp"],
                        ["email", {}, "text", "registrar-contact@safe.example"],
                    ],
                ],
            },
        ],
    }

    sanitized = sanitize_rdap_data(rdap)
    registrant_vcard = sanitized["entities"][0]["vcardArray"][1]
    assert registrant_vcard[1][3] == "[REDACTED_PII]"
    assert registrant_vcard[2][3] == ["[REDACTED_PII]"] * 7
    assert registrant_vcard[3][3] == "[REDACTED_PHONE]"
    assert registrant_vcard[4][3] == "[REDACTED_EMAIL]"

    registrar_vcard = sanitized["entities"][1]["vcardArray"][1]
    assert registrar_vcard[0][3] == "Safe Registrar Corp"
    assert registrar_vcard[1][3] == "[REDACTED_EMAIL]"
