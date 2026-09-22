"""Email rule detector."""

from __future__ import annotations

import re

from app.pii.contract import Finding

EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"(?![A-Za-z0-9._%+-])"
)

SERVICE_DOMAINS = {
    "bank.ru",
    "support.bank.ru",
    "alfabank.ru",
    "example.com",
}

SERVICE_LOCAL = {"support", "noreply", "no-reply", "info", "help", "admin"}


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in EMAIL_RE.finditer(text):
        value = m.group(0)
        local, _, domain = value.partition("@")
        domain_l = domain.lower()
        local_l = local.lower()
        if domain_l in SERVICE_DOMAINS or local_l in SERVICE_LOCAL:
            continue
        out.append(
            Finding(
                type="EMAIL",
                start=m.start(),
                end=m.end(),
                score=0.99,
                detector="email_rule_v1",
            )
        )
    return out
