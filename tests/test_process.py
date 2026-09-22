from __future__ import annotations

import pytest

from app.config import load_config
from app.masking import apply_dev_redact, redact_chars
from app.pii.detect import Finding, detect_pii
from app.process import ProcessError, ProcessService
from app.state import MemoryStateStore


def test_dev_redact_preserves_separators():
    assert redact_chars("Иванов Иван") == "****** ****"
    assert redact_chars("12.03.2001") == "**.**.****"
    assert redact_chars("+7 999") == "+* ***"


def test_dev_redact_on_findings():
    text = "Email: ivan@mail.ru"
    findings = [Finding("EMAIL", 7, 19, 1.0, "t")]
    assert apply_dev_redact(text, findings) == "Email: ****@****.**"


def test_process_roundtrip_and_retry():
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())
    original = "Клиент ivan@mail.ru"
    masked = svc.process(original, "id-1")
    assert "*" in masked
    assert "@" in masked
    # retry original → same mask
    assert svc.process(original, "id-1") == masked
    # demask
    assert svc.process(masked, "id-1") == original


def test_process_conflict_409():
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())
    svc.process("Клиент a@b.ru", "id-2")
    with pytest.raises(ProcessError) as ei:
        svc.process("Другой текст", "id-2")
    assert ei.value.status == 409


def test_acceptance_email_redact_shape():
    # smoke against acceptance style
    text = "Клиент: ivanov@mail.ru"
    findings = detect_pii(text, enable_ner=False)
    emails = [f for f in findings if f.type == "EMAIL"]
    assert emails
    masked = apply_dev_redact(text, emails)
    assert "ivanov" not in masked
    assert "@" in masked
