"""INN (12-digit individual) with checksum validation."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import digits_only

INN_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")


def _inn12_valid(inn: str) -> bool:
    if len(inn) != 12 or not inn.isdigit():
        return False
    coeffs1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    coeffs2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    n = [int(c) for c in inn]
    d11 = sum(c * n[i] for i, c in enumerate(coeffs1)) % 11 % 10
    d12 = sum(c * n[i] for i, c in enumerate(coeffs2)) % 11 % 10
    return d11 == n[10] and d12 == n[11]


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in INN_RE.finditer(text):
        inn = digits_only(m.group(1))
        if not _inn12_valid(inn):
            continue
        out.append(
            Finding(
                type="INN",
                start=m.start(),
                end=m.end(),
                score=0.99,
                detector="inn_rule_v1",
            )
        )
    return out
