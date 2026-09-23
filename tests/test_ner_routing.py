"""Context-ML routing by system and PII group."""

from __future__ import annotations

from app.config import load_config
from app.process import ProcessService
from app.state import MemoryStateStore


def test_context_ml_routing_by_system(monkeypatch):
    monkeypatch.setenv("CONTEXT_ML_ENABLED", "1")
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())

    assert svc._context_ml_for_system("demo", need_context_ml=True) is True
    assert svc._context_ml_for_system("autotest", need_context_ml=True) is False
    assert svc._context_ml_for_system("high_rps", need_context_ml=True) is False
    assert svc._context_ml_for_system("format_only", need_context_ml=False) is False
    assert svc._context_ml_for_system(None, need_context_ml=True) is False


def test_context_ml_master_switch_off(monkeypatch):
    monkeypatch.setenv("CONTEXT_ML_ENABLED", "0")
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())
    assert svc._context_ml_for_system("demo", need_context_ml=True) is False


def test_context_group_not_just_person(monkeypatch):
    monkeypatch.setenv("CONTEXT_ML_ENABLED", "1")
    cfg = load_config("config.yaml")
    cfg.systems["demo"].pd_types = ["ADDRESS"]
    svc = ProcessService(cfg, MemoryStateStore())

    allowed = svc._allowed_types("demo")
    assert allowed == {"ADDRESS"}
    assert svc._context_ml_for_system("demo", bool(allowed & {"ADDRESS"})) is True
