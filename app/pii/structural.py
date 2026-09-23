"""Single structural post-processing layer.

Type detection answers WHAT the PII is.
This module answers WHICH semantic spans of a confirmed composite object
should be masked.
"""

from __future__ import annotations

from app.pii.catalog import BY_TYPE, StructureKind
from app.pii.detect import Finding


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

        # PASSPORT / DRIVER_LICENSE are still emitted with explicit parts by
        # legacy candidate rules. Until those detectors are migrated, an
        # unsplit candidate is kept intact rather than guessed here.
        out.append(finding)

    return out
