from __future__ import annotations

import asyncio
import logging

from fastapi.testclient import TestClient

import app.api as api


def test_process_overload_returns_429_with_retry_after(monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "memory")
    api._process_sem = asyncio.Semaphore(0)
    try:
        with TestClient(api.app) as client:
            r = client.post(
                "/process",
                json={"payload": "Клиент ivan@example.ru", "payload_id": "overload-1"},
            )
        assert r.status_code == 429
        assert r.headers["Retry-After"] == "1"
    finally:
        api._process_sem = None


def test_process_log_has_types_and_timings_without_raw_pii(monkeypatch, caplog):
    monkeypatch.setenv("STORAGE_BACKEND", "memory")
    api._process_sem = None
    caplog.set_level(logging.INFO, logger="alfa.api")

    with TestClient(api.app) as client:
        r = client.post(
            "/process",
            json={"payload": "Email клиента: ivan@example.ru", "payload_id": "log-1"},
        )

    assert r.status_code == 200
    log_text = caplog.text
    assert "ivan@example.ru" not in log_text
    assert '"types":["EMAIL"]' in log_text
    assert '"detect_ms":' in log_text
    assert '"mask_ms":' in log_text
    assert '"state_ms":' in log_text
    assert '"payload_id":"log-1"' not in log_text
    assert '"payload_id_hash":' in log_text
