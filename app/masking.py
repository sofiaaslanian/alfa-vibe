"""Mask strategies: dev_redact_v1 (autotest) and scoped proxy tokens."""

from __future__ import annotations

import re
import secrets
from app.pii.detect import Finding, maskable

# Map baseline canonical names <-> our detector types
TYPE_ALIASES = {
    "PERSON_NAME": "PERSON",
    "PERSON": "PERSON",
    "INN_PERSON": "INN",
    "INN": "INN",
    "PASSPORT_NUMBER": "PASSPORT",
    "PASSPORT": "PASSPORT",
    "DRIVER_LICENSE_NUMBER": "DRIVER_LICENSE",
    "DRIVER_LICENSE": "DRIVER_LICENSE",
    "CARD_PIN": "PIN",
    "PIN": "PIN",
    "PLACE_OF_BIRTH": "PLACE_OF_BIRTH",
    "CITIZENSHIP": "CITIZENSHIP",
    "PASSPORT_ISSUER": "PASSPORT_ISSUER",
    "CARDHOLDER_NAME": "CARDHOLDER_NAME",
    "ADDRESS": "ADDRESS",
    "BIRTH_DATE": "BIRTH_DATE",
    "PASSPORT_ISSUE_DATE": "PASSPORT_ISSUE_DATE",
    "SUBDIVISION_CODE": "SUBDIVISION_CODE",
    "CVV": "CVV",
    "EMAIL": "EMAIL",
    "PHONE": "PHONE",
    "PAYMENT_CARD": "PAYMENT_CARD",
}


def canonical(t: str) -> str:
    return TYPE_ALIASES.get(t, t)


def redact_chars(value: str) -> str:
    """dev_redact_v1: letters/digits -> *, keep punctuation/spaces."""
    out: list[str] = []
    for ch in value:
        out.append("*" if ch.isalnum() else ch)
    return "".join(out)


def _expand_document_label_spans(text: str, findings: list[Finding]) -> list[Finding]:
    """For passport/VU series+number pairs, include explicit service labels in the redacted span.

    Detection stays unchanged. We only widen an already-confirmed document pair such as
    «серия 45 11, номер 123456» so /process masks the whole logical fragment.
    """
    items = sorted(findings, key=lambda f: (f.start, f.end))
    used: set[int] = set()
    out: list[Finding] = []

    for i, first in enumerate(items):
        if i in used:
            continue
        if first.type not in {"PASSPORT", "DRIVER_LICENSE"} or getattr(first, "part", "") != "series":
            out.append(first)
            continue

        pair_idx = None
        for j in range(i + 1, len(items)):
            second = items[j]
            if second.start - first.end > 32:
                break
            if (
                second.type == first.type
                and getattr(second, "part", "") == "number"
                and re.fullmatch(r"\s*,?\s*(?:номер|№)\s*", text[first.end:second.start], re.IGNORECASE)
            ):
                pair_idx = j
                break

        if pair_idx is None:
            out.append(first)
            continue

        second = items[pair_idx]
        start = first.start
        left_start = max(0, first.start - 16)
        left = text[left_start:first.start]
        m = re.search(r"(?i)серия\s*$", left)
        if m:
            start = left_start + m.start()

        out.append(
            Finding(
                first.type,
                start,
                second.end,
                min(first.score, second.score),
                "document_full_span_v1",
                part="full",
            )
        )
        used.add(pair_idx)

    for i, item in enumerate(items):
        if i in used:
            continue
        if item not in out and not (
            item.type in {"PASSPORT", "DRIVER_LICENSE"}
            and getattr(item, "part", "") == "series"
        ):
            out.append(item)

    return sorted(out, key=lambda f: (f.start, f.end))


def apply_dev_redact(text: str, findings: list[Finding]) -> str:
    findings = _expand_document_label_spans(text, maskable(findings))
    if not findings:
        return text
    result = text
    for f in sorted(findings, key=lambda x: x.start, reverse=True):
        original = text[f.start : f.end]
        result = result[: f.start] + redact_chars(original) + result[f.end :]
    return result


def make_scoped_token(pii_type: str) -> str:
    # ⟦PII_TYPE_<32 hex>⟧ — ≥128 bits
    return f"⟦PII_{canonical(pii_type)}_{secrets.token_hex(16)}⟧"


def apply_scoped_tokens(text: str, findings: list[Finding]) -> tuple[str, dict[str, str]]:
    """Returns masked text and token->original map."""
    findings = maskable(findings)
    mapping: dict[str, str] = {}
    if not findings:
        return text, mapping
    result = text
    for f in sorted(findings, key=lambda x: x.start, reverse=True):
        original = text[f.start : f.end]
        token = make_scoped_token(f.type)
        while token in text or token in mapping:
            token = make_scoped_token(f.type)
        mapping[token] = original
        result = result[: f.start] + token + result[f.end :]
    return result, mapping


def restore_scoped_tokens(text: str, mapping: dict[str, str]) -> str:
    # one-pass exact tokens only; longest first to avoid partial issues
    result = text
    for token in sorted(mapping.keys(), key=len, reverse=True):
        if token in result:
            result = result.replace(token, mapping[token])
    return result
