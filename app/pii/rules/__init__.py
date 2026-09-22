"""Rule-based detectors for format and format-context PII."""

from __future__ import annotations

from app.pii.contract import Finding
from app.pii.rules import address, card, cvv, dates, driver_license, email, inn, passport, phone, pin, subdivision_code

RULE_DETECTORS = [
    email.detect,
    phone.detect,
    inn.detect,
    card.detect,
    address.detect,
    dates.detect_birth_date,
    dates.detect_passport_issue_date,
    passport.detect,
    subdivision_code.detect,
    driver_license.detect,
    cvv.detect,
    pin.detect,
]


def detect_all_rules(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for detector in RULE_DETECTORS:
        findings.extend(detector(text))
    return findings
