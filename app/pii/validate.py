"""Post-filters for non-group-1 ML format spans.

The group-1 experiment intentionally leaves EMAIL, PHONE, INN and
PAYMENT_CARD exactly as they behaved before the latest group-1 changes.
"""

from __future__ import annotations

from app.pii.detect import Finding


def _digits(value: str) -> str:
    return "".join(char for char in value if char.isdigit())


def accept_format_finding(text: str, finding: Finding) -> bool:
    """Validate ML spans outside experimental group 1."""
    value = text[finding.start : finding.end]

    if finding.type == "CVV":
        digits = _digits(value)
        return len(digits) in {3, 4} and digits == value.strip()

    if finding.type == "PIN":
        digits = _digits(value)
        return 4 <= len(digits) <= 6 and digits == value.strip()

    return True


def sanitize_format_findings(
    text: str,
    findings: list[Finding],
) -> list[Finding]:
    """Drop invalid ML CVV/PIN; leave group-1 spans untouched."""
    out: list[Finding] = []
    for finding in findings:
        detector = (finding.detector or "").lower()
        is_ml = (
            detector == "ml"
            or detector.startswith("ml")
            or "ner" in detector
            or "rubert" in detector
        )
        if not is_ml or accept_format_finding(text, finding):
            out.append(finding)
    return out
