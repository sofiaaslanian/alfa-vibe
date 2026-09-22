"""Address rule detector (component heuristics, not NER)."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import has_any, window

# Compact address-like spans with street markers
ADDRESS_RE = re.compile(
    r"(?:"
    r"(?:г\.|город)\s*[А-Яа-яЁёA-Za-z\-]+"
    r"(?:\s*,\s*)?"
    r")?"
    r"(?:ул\.|улица|пр\.|проспект|пер\.|переулок)\s*"
    r"[А-Яа-яЁёA-Za-z0-9\-\.\s]+?"
    r"(?:\s*,\s*|\s+)"
    r"(?:д\.|дом)\s*\d+[А-Яа-яA-Za-z]?"
    r"(?:(?:\s*,\s*|\s+)(?:кв\.|квартира)\s*\d+)?"
    ,
    re.IGNORECASE,
)

NEGATIVE = [
    r"отделен\w*\s+банк",
    r"филиал",
    r"офис\s+банк",
    r"адрес\s+отделен",
    r"адрес\s+банк",
]


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in ADDRESS_RE.finditer(text):
        ctx = window(text, m.start(), m.end(), size=80)
        if has_any(ctx, NEGATIVE):
            continue
        out.append(
            Finding(
                type="ADDRESS",
                start=m.start(),
                end=m.end(),
                score=0.9,
                detector="address_rule_v1",
            )
        )
    return out
