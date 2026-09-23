"""Single structural post-processing layer.

Type detection answers WHAT the PII is.
This module answers WHICH semantic spans of a confirmed composite object
should be masked.
"""

from __future__ import annotations

from app.pii.catalog import BY_TYPE, StructureKind
from app.pii.detect import Finding


def _split_series_number(text: str, finding: Finding) -> list[Finding]:
    positions = [i for i in range(finding.start, finding.end) if text[i].isdigit()]
    if len(positions) != 10:
        return [finding]

    return [
        Finding(
            finding.type,
            positions[0],
            positions[3] + 1,
            finding.score,
            finding.detector,
            getattr(finding, "decision", "mask"),
            getattr(finding, "reason", "") or "",
            part="series",
        ),
        Finding(
            finding.type,
            positions[4],
            positions[9] + 1,
            finding.score,
            finding.detector,
            getattr(finding, "decision", "mask"),
            getattr(finding, "reason", "") or "",
            part="number",
        ),
    ]


def _split_person(text: str, finding: Finding) -> list[Finding]:
    from app.pii.parts import split_person_span

    return split_person_span(
        text,
        finding.start,
        finding.end,
        finding.score,
        finding.detector,
        decision=getattr(finding, "decision", "mask"),
        reason=getattr(finding, "reason", "") or "",
    )


def _split_address(text: str, finding: Finding) -> list[Finding]:
    from app.pii.parts import split_address_span

    return split_address_span(
        text,
        finding.start,
        finding.end,
        finding.score,
        finding.detector,
        decision=getattr(finding, "decision", "mask"),
        reason=getattr(finding, "reason", "") or "",
    )


def _split_cardholder(text: str, finding: Finding) -> list[Finding]:
    from app.pii.parts import split_cardholder_span

    return split_cardholder_span(
        text,
        finding.start,
        finding.end,
        finding.score,
        finding.detector,
    )


def _normalize_composite(text: str, finding: Finding) -> list[Finding]:
    # ADDRESS has one structural authority regardless of detector source.
    # ML may already classify a candidate as street/house, but its raw entity
    # span can still include role labels ("ул.", "д.", "кв."). Always pass
    # ADDRESS through the shared value-span normalizer before masking.
    if finding.type == "ADDRESS":
        return _split_address(text, finding)

    if getattr(finding, "part", ""):
        return [finding]

    splitters = {
        "PERSON": _split_person,
        "CARDHOLDER_NAME": _split_cardholder,
        "PASSPORT": _split_series_number,
        "DRIVER_LICENSE": _split_series_number,
    }
    splitter = splitters.get(finding.type)
    return splitter(text, finding) if splitter else [finding]


def _normalize_one(text: str, finding: Finding) -> list[Finding]:
    spec = BY_TYPE.get(finding.type)
    if spec is None or spec.structure == StructureKind.ATOMIC:
        return [finding]
    return _normalize_composite(text, finding)


def normalize_structures(text: str, findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for finding in findings:
        out.extend(_normalize_one(text, finding))
    return out
