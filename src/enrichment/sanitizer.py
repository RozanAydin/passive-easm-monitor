"""PII redaction and sanitization filter for WHOIS/RDAP and public records."""

from __future__ import annotations

import copy
import re
from typing import Any

EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# Matches international/regional phone numbers while avoiding IPv4s and ISO dates
PHONE_REGEX = re.compile(
    r"(?:tel:)?(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\b\d{3,4}[\s.-])\d{3,4}[\s.-]\d{3,4}(?:[\s.-]\d{1,4})?\b"
    r"|(?<=[\s:])\+\d{1,3}\.\d{6,14}\b"
)

WHOIS_PII_KEY_REGEX = re.compile(
    r"(?im)^((?:registrant|admin|tech|billing)\s+(?:name|organization|street|city|state/province|postal\s+code|phone(?:\s+ext)?|fax(?:\s+ext)?|email))\s*:\s*(.+)$"
)

SENSITIVE_VCARD_PROPS = {"fn", "n", "adr", "tel", "email", "contact-uri"}


def redact_text(text: str | None) -> str:
    """Redact emails, phone numbers, and WHOIS personal contact lines from text."""
    if not text:
        return ""

    sanitized = EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
    sanitized = PHONE_REGEX.sub("[REDACTED_PHONE]", sanitized)

    def _replace_whois_line(match: re.Match[str]) -> str:
        key = match.group(1)
        val = match.group(2).strip()
        if not val or val.upper().startswith("REDACTED"):
            return match.group(0)
        if "email" in key.lower():
            return f"{key}: [REDACTED_EMAIL]"
        if "phone" in key.lower() or "fax" in key.lower():
            return f"{key}: [REDACTED_PHONE]"
        return f"{key}: [REDACTED_PII]"

    sanitized = WHOIS_PII_KEY_REGEX.sub(_replace_whois_line, sanitized)
    return sanitized


def _sanitize_vcard_array(vcard: Any, preserve_org_name: bool = False) -> Any:
    """Sanitize jCard / vCard structures found inside RDAP entity objects."""
    if not isinstance(vcard, list):
        return vcard
    # jCard format: ["vcard", [ [prop_name, params, type, value], ... ]]
    if len(vcard) == 2 and vcard[0] == "vcard" and isinstance(vcard[1], list):
        cleaned_props = []
        for prop in vcard[1]:
            if isinstance(prop, list) and len(prop) >= 4:
                prop_name = str(prop[0]).lower()
                if prop_name == "email":
                    cleaned_props.append([prop[0], prop[1], prop[2], "[REDACTED_EMAIL]"])
                elif prop_name == "tel":
                    cleaned_props.append([prop[0], prop[1], prop[2], "[REDACTED_PHONE]"])
                elif preserve_org_name and prop_name in {"fn", "org"}:
                    cleaned_props.append([prop[0], prop[1], prop[2], redact_text(str(prop[3]))])
                elif prop_name in SENSITIVE_VCARD_PROPS:
                    replacement = ["[REDACTED_PII]"] * len(prop[3]) if isinstance(prop[3], list) else "[REDACTED_PII]"
                    cleaned_props.append([prop[0], prop[1], prop[2], replacement])
                else:
                    cleaned_props.append(sanitize_rdap_data(prop))
            else:
                cleaned_props.append(sanitize_rdap_data(prop))
        return ["vcard", cleaned_props]
    return [sanitize_rdap_data(item) for item in vcard]


def sanitize_rdap_data(data: Any) -> Any:
    """Recursively sanitize RDAP JSON objects, preserving non-PII registrar metadata."""
    if isinstance(data, str):
        return redact_text(data)
    if isinstance(data, list):
        return [sanitize_rdap_data(item) for item in data]
    if isinstance(data, dict):
        result: dict[str, Any] = {}
        roles = [str(r).lower() for r in data.get("roles", [])] if isinstance(data.get("roles"), list) else []
        is_registrar_only = "registrar" in roles and not any(
            r in roles for r in ("registrant", "administrative", "technical", "billing")
        )
        for key, value in data.items():
            lower_key = key.lower()
            if lower_key == "vcardarray":
                result[key] = _sanitize_vcard_array(value, preserve_org_name=is_registrar_only)
            elif lower_key in {"email", "emails"}:
                result[key] = "[REDACTED_EMAIL]"
            elif lower_key in {"phone", "telephone", "tel", "fax"}:
                result[key] = "[REDACTED_PHONE]"
            elif lower_key == "entities" and isinstance(value, list):
                result[key] = [sanitize_rdap_data(entity) for entity in value]
            else:
                result[key] = sanitize_rdap_data(value)
        return result
    return copy.deepcopy(data)
