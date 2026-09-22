"""Map RuBERT PII labels to canonical types + PERSON merge."""

from __future__ import annotations

from app.pii.contract import Finding

LABEL_MAP = {
    "FIRST_NAME": "PERSON",
    "LAST_NAME": "PERSON",
    "MIDDLE_NAME": "PERSON",
}

ML_ALLOWED_TYPES = set(LABEL_MAP.keys())


def map_entity(entity: dict) -> Finding | None:
    label = entity.get("entity_group") or entity.get("type")
    if label not in LABEL_MAP:
        return None
    return Finding(
        type=LABEL_MAP[label],
        start=int(entity["start"]),
        end=int(entity["end"]),
        score=float(entity.get("score", 0.0)),
        detector="ml",
    )


def merge_adjacent_person(findings: list[Finding], max_gap: int = 2) -> list[Finding]:
    """Merge neighboring PERSON spans (FIRST+LAST+MIDDLE) into one."""
    persons = sorted(
        [f for f in findings if f.type == "PERSON"],
        key=lambda f: f.start,
    )
    others = [f for f in findings if f.type != "PERSON"]
    if not persons:
        return findings

    merged: list[Finding] = []
    cur = persons[0]
    for nxt in persons[1:]:
        if nxt.start <= cur.end + max_gap:
            cur = Finding(
                type="PERSON",
                start=cur.start,
                end=max(cur.end, nxt.end),
                score=min(cur.score, nxt.score),
                detector="ml",
            )
        else:
            merged.append(cur)
            cur = nxt
    merged.append(cur)
    return others + merged
