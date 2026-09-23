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
_ADDRESS_LABELS = {
    "ADDRESS",
    "REGION",
    "DISTRICT",
    "CITY",
    "STREET",
    "HOUSE",
    "LOC",
    "LOCATION",
}
_ORG_LABELS = {"ORG", "ORGANIZATION"}
_NAME_PART = {
    "FIRST_NAME": "first",
    "LAST_NAME": "last",
    "MIDDLE_NAME": "middle",
}
_ADDRESS_PART = {
    "REGION": "region",
    "DISTRICT": "district",
    "CITY": "city",
    "STREET": "street",
    "HOUSE": "house",
}

ML_COVERED_CONTEXT_TYPES = frozenset({
    "PERSON",
    "PLACE_OF_BIRTH",
    "CITIZENSHIP",
    "ADDRESS",
    "CARDHOLDER_NAME",
    "PASSPORT_ISSUER",
})

_BIRTH_ROLE_RE = re.compile(
    r"(?i)(?:место\s+рожден|родил(?:ся|ась)|place\s+of\s+birth|birth\s*place)"
)
_CITIZEN_ROLE_RE = re.compile(
    r"(?i)(?:гражданств|граждан(?:ин\w*|к\w*)|citizen(?:ship)?)"
)
_CARDHOLDER_ROLE_RE = re.compile(
    r"(?i)(?:имя\s+держателя\s+карты|держател\w*\s+карты|имя\s+на\s+карт|"
    r"карт\w*.{0,50}имя\s+держател\w*|имя\s+держател\w*.{0,50}карт\w*|"
    r"embossed\s+name|name\s+on\s+card|cardholder(?:\s+name)?)"
)
_ISSUER_ROLE_RE = re.compile(
    r"(?i)(?:кем\s+выдан\s+паспорт|паспорт\s+выдан|"
    r"орган(?:ом)?\s+выдач\w*(?:\s+паспорт\w*)?|выдавш\w*\s+орган)"
)
_ADDRESS_ROLE_RE = re.compile(
    r"(?i)(?:мой\s+адрес|домашн\w*\s+адрес|адрес\s+(?:проживани|регистрац|"
    r"клиента|доставк|для\s+корреспонденц)|живу|прожива|прописан|"
    r"зарегистрирован|улиц|ул\.|проспект|пр\.|переулок|пер\.|"
    r"шоссе|\bд\.|дом\s+\d|кв\.|квартира)"
)


def _label(entity: dict[str, Any]) -> str:
    raw = (
        entity.get("entity_group")
        or entity.get("entity")
        or entity.get("label")
        or entity.get("type")
        or ""
    )
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


def _append_unique(
    out: list[Finding],
    seen: set[tuple[str, int, int, str]],
    typ: str,
    start: int,
    end: int,
    score: float,
    part: str = "",
) -> None:
    key = (typ, start, end, part)
    if key in seen:
        return
    seen.add(key)
    out.append(Finding(typ, start, end, score, "context_ml_v1", part=part))


def _expand_name_span(text: str, label: str, start: int, end: int) -> tuple[int, int]:
    if label not in _NAME_LABELS:
        return start, end
    from app.pii.ner import expand_span_to_word

    return expand_span_to_word(text, start, end)


def _add_name_roles(
    out: list[Finding],
    seen: set[tuple[str, int, int, str]],
    label: str,
    start: int,
    end: int,
    score: float,
    ctx: str,
) -> None:
    if label not in _NAME_LABELS:
        return
    part = _NAME_PART.get(label, "")
    _append_unique(out, seen, "PERSON", start, end, score, part)
    if _CARDHOLDER_ROLE_RE.search(ctx):
        _append_unique(out, seen, "CARDHOLDER_NAME", start, end, score, part)


def _add_address_role(
    out: list[Finding],
    seen: set[tuple[str, int, int, str]],
    label: str,
    start: int,
    end: int,
    score: float,
    ctx: str,
) -> None:
    if label not in _ADDRESS_LABELS:
        return
    is_specific_address = label in {"ADDRESS", "STREET", "HOUSE"}
    if not is_specific_address and not _ADDRESS_ROLE_RE.search(ctx):
        return
    _append_unique(out, seen, "ADDRESS", start, end, score, _ADDRESS_PART.get(label, ""))


def _add_location_roles(
    out: list[Finding],
    seen: set[tuple[str, int, int, str]],
    label: str,
    start: int,
    end: int,
    score: float,
    ctx: str,
) -> None:
    if label in _LOCATION_LABELS and _BIRTH_ROLE_RE.search(ctx):
        _append_unique(out, seen, "PLACE_OF_BIRTH", start, end, score)
    if label in {"COUNTRY", "LOC", "LOCATION"} and _CITIZEN_ROLE_RE.search(ctx):
        _append_unique(out, seen, "CITIZENSHIP", start, end, score)


def _add_issuer_role(
    out: list[Finding],
    seen: set[tuple[str, int, int, str]],
    label: str,
    start: int,
    end: int,
    score: float,
    ctx: str,
) -> None:
    if label in _ORG_LABELS and _ISSUER_ROLE_RE.search(ctx):
        _append_unique(out, seen, "PASSPORT_ISSUER", start, end, score)


def _convert_entity(
    text: str,
    entity: dict[str, Any],
    out: list[Finding],
    seen: set[tuple[str, int, int, str]],
) -> None:
    span = _span(entity)
    if span is None:
        return
    label = _label(entity)
    start, end = _expand_name_span(text, label, *span)
    score = _score(entity)
    ctx = _ctx(text, start, end)

    _add_name_roles(out, seen, label, start, end, score, ctx)
    _add_address_role(out, seen, label, start, end, score, ctx)
    _add_location_roles(out, seen, label, start, end, score, ctx)
    _add_issuer_role(out, seen, label, start, end, score, ctx)


def raw_entities_to_context_findings(
    text: str,
    entities: list[dict[str, Any]],
) -> list[Finding]:
    """Convert raw NER entities into candidates for context-defined PII."""
    out: list[Finding] = []
    seen: set[tuple[str, int, int, str]] = set()
    for entity in entities:
        _convert_entity(text, entity, out, seen)
    return out
