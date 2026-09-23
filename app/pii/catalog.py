"""Canonical 17-type PII catalog.

Detection group and structure are orthogonal:
- FORMAT: format-defined, rules-based.
- FORMAT_CONTEXT: format candidate + contextual rule.
- CONTEXT: context-defined, ML-first.
- ATOMIC/COMPOSITE: structural post-processing after type confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DetectionGroup(str, Enum):
    FORMAT = "format"
    FORMAT_CONTEXT = "format_context"
    CONTEXT = "context"


class StructureKind(str, Enum):
    ATOMIC = "atomic"
    COMPOSITE = "composite"


@dataclass(frozen=True)
class PiiSpec:
    type: str
    group: DetectionGroup
    structure: StructureKind


PII_CATALOG: tuple[PiiSpec, ...] = (
    # Context-defined → ML-first
    PiiSpec("PERSON", DetectionGroup.CONTEXT, StructureKind.COMPOSITE),
    PiiSpec("PLACE_OF_BIRTH", DetectionGroup.CONTEXT, StructureKind.ATOMIC),
    PiiSpec("CITIZENSHIP", DetectionGroup.CONTEXT, StructureKind.ATOMIC),
    PiiSpec("PASSPORT_ISSUER", DetectionGroup.CONTEXT, StructureKind.ATOMIC),
    PiiSpec("ADDRESS", DetectionGroup.CONTEXT, StructureKind.COMPOSITE),
    PiiSpec("CARDHOLDER_NAME", DetectionGroup.CONTEXT, StructureKind.COMPOSITE),
    # Format + context → rules-based
    PiiSpec("BIRTH_DATE", DetectionGroup.FORMAT_CONTEXT, StructureKind.ATOMIC),
    PiiSpec("PASSPORT", DetectionGroup.FORMAT_CONTEXT, StructureKind.COMPOSITE),
    PiiSpec("SUBDIVISION_CODE", DetectionGroup.FORMAT_CONTEXT, StructureKind.ATOMIC),
    PiiSpec("PASSPORT_ISSUE_DATE", DetectionGroup.FORMAT_CONTEXT, StructureKind.ATOMIC),
    PiiSpec("DRIVER_LICENSE", DetectionGroup.FORMAT_CONTEXT, StructureKind.COMPOSITE),
    PiiSpec("CVV", DetectionGroup.FORMAT_CONTEXT, StructureKind.ATOMIC),
    PiiSpec("PIN", DetectionGroup.FORMAT_CONTEXT, StructureKind.ATOMIC),
    # Format-defined → rules-based
    PiiSpec("EMAIL", DetectionGroup.FORMAT, StructureKind.ATOMIC),
    PiiSpec("PHONE", DetectionGroup.FORMAT, StructureKind.ATOMIC),
    PiiSpec("INN", DetectionGroup.FORMAT, StructureKind.ATOMIC),
    PiiSpec("PAYMENT_CARD", DetectionGroup.FORMAT, StructureKind.ATOMIC),
)

BY_TYPE = {spec.type: spec for spec in PII_CATALOG}
CORE_TYPES = frozenset(BY_TYPE)
