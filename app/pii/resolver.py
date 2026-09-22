"""Resolve overlaps: keep higher-priority / longer spans."""

from __future__ import annotations

from app.pii.contract import Finding

# Higher number = higher priority when overlapping
PRIORITY: dict[str, int] = {
    "PAYMENT_CARD": 100,
    "INN": 95,
    "PASSPORT": 90,
    "DRIVER_LICENSE": 88,
    "CVV": 85,
    "PIN": 84,
    "SUBDIVISION_CODE": 80,
    "PHONE": 70,
    "EMAIL": 70,
    "BIRTH_DATE": 60,
    "PASSPORT_ISSUE_DATE": 60,
    "ADDRESS": 50,
    "PERSON": 40,
}


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    if not findings:
        return []

    ordered = sorted(
        findings,
        key=lambda f: (
            -PRIORITY.get(f.type, 0),
            -(f.end - f.start),
            f.start,
        ),
    )
    accepted: list[Finding] = []
    for cand in ordered:
        clash = False
        for kept in accepted:
            if not (cand.end <= kept.start or cand.start >= kept.end):
                clash = True
                break
        if not clash:
            accepted.append(cand)
    return sorted(accepted, key=lambda f: f.start)
