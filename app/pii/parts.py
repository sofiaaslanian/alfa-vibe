"""Split composite PII into structural parts (DETECTION.md + jury table).

Composite → several findings of the same type with ``part=…``.
Atomic types stay a single span (no part).
"""

from __future__ import annotations

import re

from app.pii.detect import Finding

_PATRONYMIC_RE = re.compile(
    r"(?i)(?:ич|ича|ичу|ичем|иче|вна|вны|вне|вну|вной|ична|ичны|ичне|ичну|ичной)$"
)
_FIO_TOKEN_RE = re.compile(r"[А-ЯЁA-Z][А-Яа-яЁёA-Za-z\-]*")
_LAT_TOKEN_RE = re.compile(r"[A-Z][A-Za-z\-]*")

# Address component extractors (inside an already-validated ADDRESS span).
_ADDR_INDEX_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
_ADDR_CITY_RE = re.compile(
    r"(?i)(?:(?:г\.|город)\s*)?([А-ЯЁ][А-Яа-яЁё\-]+)"
)
_ADDR_STREET_RE = re.compile(
    r"(?i)("
    r"(?:ул\.|улица|пр\.|пр\-т|проспект|пер\.|переулок|ш\.|шоссе|б\-р|бульвар|наб\.|пл\.|площадь)"
    r"\s+[А-ЯЁа-яёA-Za-z0-9\-\.]+"
    r"|"
    r"[А-ЯЁ][А-Яа-яЁёA-Za-z0-9\-\.]+\s+"
    r"(?:ул\.|улица|пр\.|пр\-т|проспект|пер\.|переулок|ш\.|шоссе|б\-р|бульвар|наб\.|пл\.|площадь)"
    r")"
)
# Include role prefixes in house/flat spans so redact matches full-address baselines.
_ADDR_HOUSE_RE = re.compile(r"(?i)((?:д\.|дом)\s*\d+[А-Яа-яA-Za-z]?)")
_ADDR_FLAT_RE = re.compile(r"(?i)((?:кв\.|квартира)\s*\d+)")
_ADDR_CORP_RE = re.compile(r"(?i)((?:корп\.|корпус|стр\.|строен\w*)\s*\d+[А-Яа-яA-Za-z]?)")


def classify_fio_parts(tokens: list[str]) -> list[str]:
    """Return part labels aligned with tokens (Russian order heuristics)."""
    n = len(tokens)
    if n == 0:
        return []
    if n == 1:
        return ["last"]
    if n == 2:
        # «Иван Петров» / «Иванов Иван»
        if _PATRONYMIC_RE.search(tokens[1]):
            return ["first", "middle"]
        return ["first", "last"]
    toks = tokens[:3]
    if _PATRONYMIC_RE.search(toks[1]):
        # Иван Иванович Петров
        return ["first", "middle", "last"]
    if _PATRONYMIC_RE.search(toks[2]):
        # Иванов Иван Иванович
        return ["last", "first", "middle"]
    # Official form without clear patronymic cue
    return ["last", "first", "middle"]


def split_person_span(
    text: str,
    start: int,
    end: int,
    score: float,
    detector: str,
    *,
    decision: str = "mask",
    reason: str = "",
) -> list[Finding]:
    """Split a FIO span into first / middle / last findings."""
    chunk = text[start:end]
    matches = list(_FIO_TOKEN_RE.finditer(chunk))
    if not matches:
        return [
            Finding("PERSON", start, end, score, detector, decision, reason, part="")
        ]
    tokens = [m.group(0) for m in matches]
    parts = classify_fio_parts(tokens)
    out: list[Finding] = []
    for m, part in zip(matches, parts):
        out.append(
            Finding(
                "PERSON",
                start + m.start(),
                start + m.end(),
                score,
                detector,
                decision,
                reason,
                part=part,
            )
        )
    return out


def split_cardholder_span(
    text: str,
    start: int,
    end: int,
    score: float,
    detector: str,
) -> list[Finding]:
    chunk = text[start:end]
    matches = list(_LAT_TOKEN_RE.finditer(chunk)) or list(_FIO_TOKEN_RE.finditer(chunk))
    if len(matches) <= 1:
        return [Finding("CARDHOLDER_NAME", start, end, score, detector, part="full")]
    # Latin card face: GIVEN FAMILY (sometimes FAMILY/GIVEN)
    if len(matches) == 2:
        labels = ["first", "last"]
    else:
        labels = classify_fio_parts([m.group(0) for m in matches])
    return [
        Finding(
            "CARDHOLDER_NAME",
            start + m.start(),
            start + m.end(),
            score,
            detector,
            part=lab,
        )
        for m, lab in zip(matches, labels)
    ]


def split_address_span(
    text: str,
    start: int,
    end: int,
    score: float,
    detector: str,
    *,
    decision: str = "mask",
    reason: str = "",
) -> list[Finding]:
    """Emit city / street / house / flat (and index) inside an ADDRESS span."""
    chunk = text[start:end]
    found: list[Finding] = []
    covered: list[tuple[int, int]] = []

    def _add(rel_s: int, rel_e: int, part: str) -> None:
        s, e = start + rel_s, start + rel_e
        if any(not (e <= a or s >= b) for a, b in covered):
            return
        covered.append((s, e))
        found.append(
            Finding("ADDRESS", s, e, score, detector, decision, reason, part=part)
        )

    for m in _ADDR_INDEX_RE.finditer(chunk):
        _add(m.start(1), m.end(1), "index")
    for m in _ADDR_STREET_RE.finditer(chunk):
        _add(m.start(1), m.end(1), "street")
    for m in _ADDR_HOUSE_RE.finditer(chunk):
        _add(m.start(1), m.end(1), "house")
    for m in _ADDR_FLAT_RE.finditer(chunk):
        _add(m.start(1), m.end(1), "flat")
    for m in _ADDR_CORP_RE.finditer(chunk):
        _add(m.start(1), m.end(1), "building")
    # City: first capital token before street, if not already covered
    for m in _ADDR_CITY_RE.finditer(chunk):
        s, e = start + m.start(1), start + m.end(1)
        if any(not (e <= a or s >= b) for a, b in covered):
            continue
        _add(m.start(1), m.end(1), "city")
        break

    if not found:
        return [Finding("ADDRESS", start, end, score, detector, decision, reason, part="")]

    # If parts leave alphanumeric gaps inside the original span, keep the whole
    # span so mask baselines (full-address redact) stay exact.
    covered_alnum = set()
    for f in found:
        for i in range(f.start, f.end):
            if text[i].isalnum():
                covered_alnum.add(i)
    gap = any(
        text[i].isalnum() and i not in covered_alnum for i in range(start, end)
    )
    if gap:
        return [Finding("ADDRESS", start, end, score, detector, decision, reason, part="")]
    return found
