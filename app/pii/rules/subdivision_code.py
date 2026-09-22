"""Subdivision code detector (NNN-NNN) with required anchor."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import has_any, window

CODE_RE = re.compile(r"(?<!\d)\d{3}-\d{3}(?!\d)")
POS = [r"код\s+подраздел", r"подраздел"]


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CODE_RE.finditer(text):
        ctx = window(text, m.start(), m.end())
        if not has_any(ctx, POS):
            continue
        out.append(
            Finding(
                type="SUBDIVISION_CODE",
                start=m.start(),
                end=m.end(),
                score=0.97,
                detector="subdivision_code_rule_v1",
            )
        )
    return out
