"""Eligibility / hard-negative filter (not a detector)."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import window

PUBLIC_PERSON = re.compile(
    r"(пушкин|лермонтов|толстой|достоевский|есенин)",
    re.IGNORECASE,
)


def filter_findings(text: str, findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        ctx = window(text, f.start, f.end, size=40)
        if f.type == "PERSON" and PUBLIC_PERSON.search(ctx):
            # poet / historical mention
            if re.search(r"поэт|писател|роман|стих", ctx, re.IGNORECASE):
                continue
        out.append(f)
    return out
