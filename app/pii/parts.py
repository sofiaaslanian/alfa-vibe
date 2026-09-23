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
# These regexes locate complete components; semantic span normalization below
# removes role labels such as "ул.", "д.", "кв." from the protected value.
_ADDR_INDEX_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
_ADDR_CITY_RE = re.compile(
    r"(?i)(?:(?:г\.|город)\s*)?([А-ЯЁ][А-Яа-яЁё\-]+)"
)
_ADDR_STREET_TYPE = (
    r"(?:ул\.|улиц(?:а|е|у)|пр\.|пр\-т|проспект(?:е|у)?|просп\.|"
    r"пер\.|переулок(?:е)?|ш\.|шоссе|б\-р|бульвар(?:е)?|"
    r"наб\.|набережн(?:ая|ой)|пл\.|площад(?:ь|и))"
)
_ADDR_STREET_RE = re.compile(
    rf"(?i)("
    rf"{_ADDR_STREET_TYPE}\s+[А-ЯЁа-яёA-Za-z0-9\-\.]+"
    rf"|"
    rf"[А-ЯЁ][А-Яа-яЁёA-Za-z0-9\-\.]+\s+{_ADDR_STREET_TYPE}"
    rf")"
)
_ADDR_HOUSE_RE = re.compile(r"(?i)((?:д\.|дом)\s*\d+[А-ЯA-Z]?)")
_ADDR_FLAT_RE = re.compile(r"(?i)((?:кв\.|квартира)\s*\d+)")
_ADDR_CORP_RE = re.compile(r"(?i)((?:корп\.|корпус|стр\.|строен\w*)\s*\d+[А-ЯA-Z]?)")

_ADDRESS_PREFIX_BY_PART = {
    "street": re.compile(rf"(?i)^{_ADDR_STREET_TYPE}\s+"),
    "house": re.compile(r"(?i)^(?:д\.|дом)\s*"),
    "flat": re.compile(r"(?i)^(?:кв\.|квартира)\s*"),
    "building": re.compile(r"(?i)^(?:корп\.|корпус|стр\.|строен\w*)\s*"),
}
_ADDRESS_SERVICE_RESIDUAL_RE = re.compile(
    r"(?i)(?:^|\W)(?:на|г|город|ул|улица|улице|улицу|пр|пр-т|просп|"
    r"проспект|проспекте|проспекту|пер|переулок|переулке|ш|шоссе|"
    r"б-р|бульвар|бульваре|наб|набережная|набережной|пл|площадь|площади|"
    r"д|дом|кв|квартира|корп|корпус|стр|строение)(?:\.|\W|$)"
)


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


def _append_address_part(
    found: list[Finding],
    covered: list[tuple[int, int]],
    *,
    start: int,
    rel_start: int,
    rel_end: int,
    part: str,
    score: float,
    detector: str,
    decision: str,
    reason: str,
) -> None:
    span_start, span_end = start + rel_start, start + rel_end
    overlaps = any(
        not (span_end <= old_start or span_start >= old_end)
        for old_start, old_end in covered
    )
    if overlaps:
        return
    covered.append((span_start, span_end))
    found.append(
        Finding(
            "ADDRESS",
            span_start,
            span_end,
            score,
            detector,
            decision,
            reason,
            part=part,
        )
    )


def _collect_address_parts(
    text: str,
    start: int,
    end: int,
    score: float,
    detector: str,
    decision: str,
    reason: str,
) -> list[Finding]:
    chunk = text[start:end]
    found: list[Finding] = []
    covered: list[tuple[int, int]] = []
    patterns = (
        (_ADDR_INDEX_RE, "index"),
        (_ADDR_STREET_RE, "street"),
        (_ADDR_HOUSE_RE, "house"),
        (_ADDR_FLAT_RE, "flat"),
        (_ADDR_CORP_RE, "building"),
    )
    for regex, part in patterns:
        for match in regex.finditer(chunk):
            rel_start, rel_end = match.start(1), match.end(1)
            prefix_re = _ADDRESS_PREFIX_BY_PART.get(part)
            if prefix_re is not None:
                prefix = prefix_re.match(chunk[rel_start:rel_end])
                if prefix:
                    rel_start += prefix.end()
            _append_address_part(
                found,
                covered,
                start=start,
                rel_start=rel_start,
                rel_end=rel_end,
                part=part,
                score=score,
                detector=detector,
                decision=decision,
                reason=reason,
            )

    for match in _ADDR_CITY_RE.finditer(chunk):
        before = len(found)
        _append_address_part(
            found,
            covered,
            start=start,
            rel_start=match.start(1),
            rel_end=match.end(1),
            part="city",
            score=score,
            detector=detector,
            decision=decision,
            reason=reason,
        )
        if len(found) > before:
            break
    return found


def _address_parts_cover_alnum(
    text: str,
    start: int,
    end: int,
    findings: list[Finding],
) -> bool:
    """All semantic values must be covered; address role words may remain open."""
    covered = {
        index
        for finding in findings
        for index in range(finding.start, finding.end)
    }
    residual = "".join(
        " " if index in covered else text[index]
        for index in range(start, end)
    )
    residual = _ADDRESS_SERVICE_RESIDUAL_RE.sub(" ", residual)
    return not any(char.isalnum() for char in residual)


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
    """Emit semantic address parts when they fully cover the original value."""
    found = _collect_address_parts(
        text,
        start,
        end,
        score,
        detector,
        decision,
        reason,
    )
    fallback = Finding(
        "ADDRESS",
        start,
        end,
        score,
        detector,
        decision,
        reason,
        part="",
    )
    if not found or not _address_parts_cover_alnum(text, start, end, found):
        return [fallback]
    return found


