"""PII detection: findings, rules+NER pipeline, eligibility, resolve, apply masks."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

log = logging.getLogger("alfa.pii")


@dataclass(frozen=True)
class Finding:
    type: str
    start: int
    end: int
    score: float
    detector: str

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "score": self.score,
            "detector": self.detector,
        }


PRIORITY = {
    "PASSPORT_ISSUER": 100,
    "CARDHOLDER_NAME": 95,
    "PLACE_OF_BIRTH": 90,
    "CITIZENSHIP": 85,
    "PASSPORT": 80,
    "DRIVER_LICENSE": 78,
    "SUBDIVISION_CODE": 75,
    "BIRTH_DATE": 70,
    "PASSPORT_ISSUE_DATE": 68,
    "PAYMENT_CARD": 65,
    "INN": 60,
    "EMAIL": 55,
    "PHONE": 55,
    "CVV": 50,
    "PIN": 48,
    "ADDRESS": 40,
    "PERSON": 30,
}

FIXED_TOKENS = {"PERSON", "ADDRESS", "PLACE_OF_BIRTH", "CITIZENSHIP", "PASSPORT_ISSUER", "CARDHOLDER_NAME"}
DEFAULT_MASKS = {
    "PHONE": "+7 XXX XXX-XX-XX",
    "INN": "XXXXXXXXXXXX",
    "PAYMENT_CARD": "XXXX XXXX XXXX XXXX",
    "PERSON": "[PERSON]",
    "ADDRESS": "[ADDRESS]",
    "PLACE_OF_BIRTH": "[PLACE_OF_BIRTH]",
    "CITIZENSHIP": "[CITIZENSHIP]",
    "PASSPORT_ISSUER": "[PASSPORT_ISSUER]",
    "CARDHOLDER_NAME": "[CARDHOLDER_NAME]",
    "BIRTH_DATE": "XX.XX.XXXX",
    "PASSPORT_ISSUE_DATE": "XX.XX.XXXX",
    "PASSPORT": "XXXX XXXXXX",
    "DRIVER_LICENSE": "XX XX XXXXXX",
    "SUBDIVISION_CODE": "XXX-XXX",
    "CVV": "XXX",
    "PIN": "XXXX",
}

PUBLIC_PERSON = re.compile(
    r"(пушкин|лермонтов|толстой|достоевский|есенин)",
    re.IGNORECASE,
)


def _window(text: str, start: int, end: int, size: int = 40) -> str:
    return text[max(0, start - size) : min(len(text), end + size)]


def filter_findings(text: str, findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        ctx = _window(text, f.start, f.end)
        if f.type == "PERSON" and PUBLIC_PERSON.search(ctx):
            if re.search(r"поэт|писател|роман|стих", ctx, re.IGNORECASE):
                continue
        out.append(f)
    return out


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    if not findings:
        return []
    ordered = sorted(
        findings,
        key=lambda f: (-PRIORITY.get(f.type, 0), -(f.end - f.start), f.start),
    )
    accepted: list[Finding] = []
    for cand in ordered:
        if any(not (cand.end <= k.start or cand.start >= k.end) for k in accepted):
            continue
        accepted.append(cand)
    return sorted(accepted, key=lambda f: f.start)


def apply_masks(text: str, findings: list[Finding], token_style: bool = False) -> str:
    if not findings:
        return text
    result = text
    counters: dict[str, int] = {}
    for f in sorted(findings, key=lambda x: x.start, reverse=True):
        original = text[f.start : f.end]
        if token_style:
            counters[f.type] = counters.get(f.type, 0) + 1
            replacement = f"<{f.type}_{counters[f.type]}>"
        elif f.type in FIXED_TOKENS:
            replacement = DEFAULT_MASKS[f.type]
        else:
            template = DEFAULT_MASKS.get(f.type) or ("X" * len(original))
            if len(template) >= len(original):
                replacement = template[: len(original)]
            else:
                replacement = (template * ((len(original) // len(template)) + 1))[: len(original)]
        result = result[: f.start] + replacement + result[f.end :]
    return result


_ner = None


def get_ner():
    global _ner
    if _ner is None:
        from app.pii.ner import NerClient

        _ner = NerClient()
    return _ner


def detect_pii(
    text: str,
    *,
    enable_ner: bool | None = None,
    fail_closed_on_ner_error: bool | None = None,
) -> list[Finding]:
    from app.pii.rules import detect_all_rules

    findings = detect_all_rules(text)
    ner = get_ner()
    use_ner = ner.enabled if enable_ner is None else enable_ner
    if use_ner:
        fail_closed = (
            os.getenv("NER_FAIL_CLOSED", "0") == "1"
            if fail_closed_on_ner_error is None
            else fail_closed_on_ner_error
        )
        try:
            if enable_ner is True and not ner.enabled:
                ner.enabled = True
                ner.use_local = True
            findings.extend(ner.detect(text))
        except Exception:
            log.exception("NER detection failed")
            if fail_closed:
                raise
    return resolve_overlaps(filter_findings(text, findings))
