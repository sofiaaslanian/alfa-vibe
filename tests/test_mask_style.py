from __future__ import annotations

import pytest

from app.config import load_config
from app.process import ProcessError, ProcessService
from app.state import MemoryStateStore


def test_proxy_mask_style_is_config_driven():
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())

    original = "Контакт клиента: ivan@example.ru"

    tokenized, token_state = svc.proxy_protect(
        original,
        consumer_id="demo-consumer",
        operation_id="demo-token",
        system="demo",
    )
    assert "ivan@example.ru" not in tokenized
    assert "⟦PII_EMAIL_" in tokenized
    assert token_state.mask_strategy == "scoped_tokens_v1"
    assert (
        svc.proxy_restore(
            tokenized,
            consumer_id="demo-consumer",
            operation_id="demo-token",
            system="demo",
        )
        == original
    )

    redacted, redact_state = svc.proxy_protect(
        original,
        consumer_id="load-consumer",
        operation_id="load-redact",
        system="high_rps",
    )
    assert "ivan@example.ru" not in redacted
    assert "****@" in redacted
    assert "⟦PII_" not in redacted
    assert redact_state.mask_strategy == "dev_redact_v1"
    assert (
        svc.proxy_restore(
            redacted,
            consumer_id="load-consumer",
            operation_id="load-redact",
            system="high_rps",
        )
        == original
    )


def test_dev_redact_cannot_restore_modified_llm_output():
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())
    original = "Контакт клиента: ivan@example.ru"
    redacted, _ = svc.proxy_protect(
        original,
        consumer_id="load-consumer",
        operation_id="modified-redact",
        system="high_rps",
    )

    with pytest.raises(ProcessError) as exc:
        svc.proxy_restore(
            "Префикс " + redacted,
            consumer_id="load-consumer",
            operation_id="modified-redact",
            system="high_rps",
        )
    assert exc.value.status == 422
