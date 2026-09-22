"""Date detectors: birth date and passport issue date."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import has_any, window

DATE_RE = re.compile(
    r"(?<!\d)(?:0?[1-9]|[12]\d|3[01])[./](?:0?[1-9]|1[0-2])[./](?:19|20)\d{2}(?!\d)"
)

BIRTH_POS = [r"дат[аы]\s+рожден", r"родил(?:ся|ась)", r"\bдр\b"]
BIRTH_NEG = [r"заседани", r"опубликован", r"срок", r"встреч"]

ISSUE_POS = [r"выдан", r"дата\s+выдач", r"дата\s+выдачи\s+паспорт"]
ISSUE_NEG = [r"опубликован", r"заседани"]


def _detect_with_context(
    text: str,
    *,
    pii_type: str,
    detector: str,
    positive: list[str],
    negative: list[str],
) -> list[Finding]:
    out: list[Finding] = []
    for m in DATE_RE.finditer(text):
        ctx = window(text, m.start(), m.end(), size=50)
        if not has_any(ctx, positive):
            continue
        if has_any(ctx, negative):
            continue
        out.append(
            Finding(
                type=pii_type,
                start=m.start(),
                end=m.end(),
                score=0.95,
                detector=detector,
            )
        )
    return out


def detect_birth_date(text: str) -> list[Finding]:
    return _detect_with_context(
        text,
        pii_type="BIRTH_DATE",
        detector="birth_date_rule_v1",
        positive=BIRTH_POS,
        negative=BIRTH_NEG,
    )


def detect_passport_issue_date(text: str) -> list[Finding]:
    return _detect_with_context(
        text,
        pii_type="PASSPORT_ISSUE_DATE",
        detector="passport_issue_date_rule_v1",
        positive=ISSUE_POS,
        negative=ISSUE_NEG,
    )
