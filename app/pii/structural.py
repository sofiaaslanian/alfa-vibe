"""Single structural post-processing layer.

Type detection answers WHAT the PII is.
This module answers WHICH semantic spans of a confirmed composite object
should be masked.
"""

from __future__ import annotations

from app.pii.catalog import BY_TYPE, StructureKind
from app.pii.detect import Finding


def _split_series_number(
    text: str,
    finding: Finding,
) -> list[Finding]:
    """Split a confirmed 10-digit document number into 4-digit series + 6-digit number.

    Non-digits between the first four digits stay outside the semantic value
    except separators inside the series itself (e.g. "45 11").
    """
    positions = [
        i for i in range(finding.start, finding.end)
        if text[i].isdigit()
    ]
    if len(positions) != 10:
        return [finding]

    series_start = positions[0]
    series_end = positions[3] + 1
    number_start = positions[4]
    number_end = positions[9] + 1

    return [
        Finding(
            finding.type,
            series_start,
            series_end,
            finding.score,
            finding.detector,
            getattr(finding, "decision", "mask"),
            getattr(finding, "reason", "") or "",
            part="series",
        ),
        Finding(
            finding.type,
            number_start,
            number_end,
            finding.score,
            finding.detector,
            getattr(finding, "decision", "mask"),
            getattr(finding, "reason", "") or "",
            part="number",
        ),
    ]


def normalize_structures(text: str, findings: list[Finding]) -> list[Finding]:
    from app.pii.parts import split_address_span, split_person_span, split_cardholder_span

    out: list[Finding] = []
    for finding in findings:
        spec = BY_TYPE.get(finding.type)
        if spec is None or spec.structure == StructureKind.ATOMIC:
            out.append(finding)
            continue

        # Already structurally decomposed by a legacy detector.
        # Keep it unchanged during migration; detector-specific splitting will
        # be removed only after output-equivalence is proven.
        if getattr(finding, "part", ""):
            out.append(finding)
            continue

        if finding.type == "PERSON":
            out.extend(
                split_person_span(
                    text,
                    finding.start,
                    finding.end,
                    finding.score,
                    finding.detector,
                    decision=getattr(finding, "decision", "mask"),
                    reason=getattr(finding, "reason", "") or "",
                )
            )
            continue

        if finding.type == "ADDRESS":
            out.extend(
                split_address_span(
                    text,
                    finding.start,
                    finding.end,
                    finding.score,
                    finding.detector,
                    decision=getattr(finding, "decision", "mask"),
                    reason=getattr(finding, "reason", "") or "",
                )
            )
            continue

        if finding.type == "CARDHOLDER_NAME":
            out.extend(
                split_cardholder_span(
                    text,
                    finding.start,
                    finding.end,
                    finding.score,
                    finding.detector,
                )
            )
            continue

        if finding.type in {"PASSPORT", "DRIVER_LICENSE"}:
            out.extend(_split_series_number(text, finding))
            continue

        out.append(finding)

    return out
