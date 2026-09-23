"""Map raw ML entities to the six context-defined business PII types.

The NER model detects generic semantic entities. This layer assigns business
roles from local context. It deliberately does not handle format-defined or
format-context PII.
"""

from __future__ import annotations

import re
from typing import Any

from app.pii.detect import Finding


_NAME_LABELS = {"FIRST_NAME", "LAST_NAME", "MIDDLE_NAME", "PER", "PERSON"}
_LOCATION_LABELS = {"COUNTRY", "REGION", "DISTRICT", "CITY", "LOC", "LOCATION"}
_ADDRESS_LABELS = {"ADDRESS", "REGION", "DISTRICT", "CITY", "STREET", "HOUSE", "LOC", "LOCATION"}
_ORG_LABELS = {"ORG", "ORGANIZATION"}

# redmadrobot-rnd/rubert-base-pii-ner has name + address hierarchy labels,
# but no ORG label. PASSPORT_ISSUER therefore stays an explicit migration
# fallback until the context model is replaced/extended.
ML_COVERED_CONTEXT_TYPES = frozenset({
    "PERSON",
    "PLACE_OF_BIRTH",
    "CITIZENSHIP",
    "ADDRESS",
    "CARDHOLDER_NAME",
})

_BIRTH_ROLE_RE = re.compile(
    r"(?i)(?:место\s+рожден|родил(?:ся|ась)|place\s+of\s+birth|birth\s*place)"
)
_CITIZEN_ROLE_RE = re.compile(
    r"(?i)(?:гражданств|гражданин(?:ка)?|citizen(?:ship)?)"
)
_CARDHOLDER_ROLE_RE = re.compile(
    r"(?i)(?:имя\s+держателя\s+карты|держател\w*\s+карты|имя\s+на\s+карт|"
    r"embossed\s+name|name\s+on\s+card|cardholder(?:\s+name)?)"
)
_ISSUER_ROLE_RE = re.compile(
    r"(?i)(?:кем\s+выдан\s+паспорт|паспорт\s+выдан|"
    r"орган(?:ом)?\s+выдач\w*(?:\s+паспорт\w*)?|выдавш\w*\s+орган)"
)


def _label(entity: dict[str, Any]) -> str:
    raw = entity.get("entity_group") or entity.get("entity") or entity.get("label") or entity.get("type") or ""
    value = str(raw).strip()
    if value.startswith(("B-", "I-", "S-", "E-")):
        value = value.split("-", 1)[1]
    return value.upper().replace(" ", "_")


def _span(entity: dict[str, Any]) -> tuple[int, int] | None:
    try:
        start = int(entity["start"])
        end = int(entity["end"])
    except (KeyError, TypeError, ValueError):
        return None
    if start < 0 or end <= start:
        return None
    return start, end


def _score(entity: dict[str, Any]) -> float:
    try:
        return float(entity.get("score", 0.0))
    except (TypeError, ValueError):
        return 0.0


def _ctx(text: str, start: int, end: int, size: int = 100) -> str:
    return text[max(0, start - size): min(len(text), end + size)]


def raw_entities_to_context_findings(
    text: str,
    entities: list[dict[str, Any]],
) -> list[Finding]:
    """Convert raw NER entities into candidates for context-defined PII."""

    out: list[Finding] = []
    seen: set[tuple[str, int, int, str]] = set()

    def add(typ: str, start: int, end: int, score: float, part: str = "") -> None:
        key = (typ, start, end, part)
        if key in seen:
            return
        seen.add(key)
        out.append(Finding(typ, start, end, score, "context_ml_v1", part=part))

    for entity in entities:
        label = _label(entity)
        span = _span(entity)
        if span is None:
            continue
        start, end = span
        score = _score(entity)
        if label in _NAME_LABELS:
            from app.pii.ner import expand_span_to_word
            start, end = expand_span_to_word(text, start, end)
        ctx = _ctx(text, start, end)

        # Generic PERSON candidate.
        if label in _NAME_LABELS:
            part = {
                "FIRST_NAME": "first",
                "LAST_NAME": "last",
                "MIDDLE_NAME": "middle",
            }.get(label, "")
            add("PERSON", start, end, score, part)

            # Same name may have the specific role "cardholder".
            if _CARDHOLDER_ROLE_RE.search(ctx):
                add("CARDHOLDER_NAME", start, end, score, part)

        # Generic location/address components.
        if label in _ADDRESS_LABELS:
            part = {
                "REGION": "region",
                "DISTRICT": "district",
                "CITY": "city",
                "STREET": "street",
                "HOUSE": "house",
            }.get(label, "")
            add("ADDRESS", start, end, score, part)

        # Business role: place of birth.
        if label in _LOCATION_LABELS and _BIRTH_ROLE_RE.search(ctx):
            add("PLACE_OF_BIRTH", start, end, score)

        # Business role: citizenship. COUNTRY is strongest; LOC/LOCATION are
        # accepted only with an explicit citizenship cue.
        if label in {"COUNTRY", "LOC", "LOCATION"} and _CITIZEN_ROLE_RE.search(ctx):
            add("CITIZENSHIP", start, end, score)

        # Business role: organisation that issued the passport.
        if label in _ORG_LABELS and _ISSUER_ROLE_RE.search(ctx):
            add("PASSPORT_ISSUER", start, end, score)

    return out
