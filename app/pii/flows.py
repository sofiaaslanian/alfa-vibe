"""Three explicit detection flows for the canonical PII groups."""

from __future__ import annotations

from dataclasses import dataclass

from app.pii.detect import Finding


@dataclass(frozen=True)
class FlowResult:
    findings: list[Finding]
    source: str


class FormatFlow:
    """Format-defined: candidate format/validator first, protect by default."""

    @staticmethod
    def detect(text: str) -> FlowResult:
        from app.pii.rules import detect_email, detect_phone, detect_inn, detect_card

        findings: list[Finding] = []
        for detector in (detect_email, detect_phone, detect_inn, detect_card):
            findings.extend(detector(text))
        return FlowResult(findings, "format_rules")


class FormatContextFlow:
    """Format candidate → entity-specific context confirmation."""

    @staticmethod
    def detect(text: str) -> FlowResult:
        from app.pii.rules import (
            detect_birth_date,
            detect_passport,
            detect_subdivision,
            detect_passport_issue_date,
            detect_driver_license,
            detect_cvv,
            detect_pin,
        )

        findings: list[Finding] = []
        for detector in (
            detect_birth_date,
            detect_passport,
            detect_subdivision,
            detect_passport_issue_date,
            detect_driver_license,
            detect_cvv,
            detect_pin,
        ):
            findings.extend(detector(text))
        return FlowResult(findings, "format_context_rules")


class ContextFlow:
    """Context-defined PII.

    Target architecture: ML candidate extraction first, then role/context
    classification. During migration, labelled rules remain as explicit
    fallback candidates so the refactor can be validated independently from
    the later model swap.
    """

    @staticmethod
    def _rule_candidates(text: str) -> list[Finding]:
        from app.pii.rules import (
            detect_address,
            detect_place_of_birth,
            detect_citizenship,
            detect_passport_issuer,
            detect_cardholder_name,
            detect_person_labelled,
            detect_person_patronymic,
        )

        findings: list[Finding] = []
        for detector in (
            detect_address,
            detect_place_of_birth,
            detect_citizenship,
            detect_passport_issuer,
            detect_cardholder_name,
            detect_person_labelled,
            detect_person_patronymic,
        ):
            findings.extend(detector(text))
        return findings

    @staticmethod
    def detect(
        text: str,
        *,
        ml_findings: list[Finding] | None = None,
    ) -> FlowResult:
        findings = ContextFlow._rule_candidates(text)
        if ml_findings:
            # Only context-group outputs enter this flow. Format and
            # format-context types stay owned by their rule pipelines.
            findings.extend(
                f
                for f in ml_findings
                if f.type in {
                    "PERSON",
                    "ADDRESS",
                    "PLACE_OF_BIRTH",
                    "CITIZENSHIP",
                    "PASSPORT_ISSUER",
                    "CARDHOLDER_NAME",
                }
            )
        return FlowResult(findings, "context_ml" if ml_findings else "context_rules_fallback")


def run_detection_flows(
    text: str,
    *,
    context_ml_findings: list[Finding] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(FormatFlow.detect(text).findings)
    findings.extend(FormatContextFlow.detect(text).findings)
    findings.extend(ContextFlow.detect(text, ml_findings=context_ml_findings).findings)
    return findings
