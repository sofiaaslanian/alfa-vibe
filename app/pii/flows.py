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
            _detect_passport_candidate,
            detect_subdivision,
            detect_passport_issue_date,
            _detect_driver_license_candidate,
            detect_cvv,
            detect_pin,
        )

        findings: list[Finding] = []
        for detector in (
            detect_birth_date,
            _detect_passport_candidate,
            detect_subdivision,
            detect_passport_issue_date,
            _detect_driver_license_candidate,
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
            _detect_address_candidate,
            detect_place_of_birth,
            detect_citizenship,
            detect_passport_issuer,
            _detect_cardholder_name_candidate,
            _detect_person_labelled_candidate,
            _detect_person_patronymic_candidate,
        )

        findings: list[Finding] = []
        for detector in (
            _detect_address_candidate,
            detect_place_of_birth,
            detect_citizenship,
            detect_passport_issuer,
            _detect_cardholder_name_candidate,
            _detect_person_labelled_candidate,
            _detect_person_patronymic_candidate,
        ):
            findings.extend(detector(text))
        return findings

    @staticmethod
    def detect(
        text: str,
        *,
        ml_findings: list[Finding] | None = None,
    ) -> FlowResult:
        # None means ML is disabled for this request: use the compatibility
        # fallback while migrating from baseline 9465.
        if ml_findings is None:
            return FlowResult(ContextFlow._rule_candidates(text), "context_rules_fallback")

        # ML adds candidates, but a model miss must not suppress a precise
        # labelled/role rule. Downstream overlap resolution removes duplicates.
        from app.pii.context_ml import ML_COVERED_CONTEXT_TYPES

        findings = [
            f
            for f in ml_findings
            if f.type in ML_COVERED_CONTEXT_TYPES
        ]
        findings.extend(ContextFlow._rule_candidates(text))
        return FlowResult(findings, "context_ml_union_rules")


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
