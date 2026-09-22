"""NER on for demo, off for autotest load path."""

from __future__ import annotations

import os

from app.config import load_config
from app.process import ProcessService
from app.state import MemoryStateStore


def test_ner_routing_by_system(monkeypatch):
    monkeypatch.setenv("NER_ENABLED", "1")
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())
    assert svc._ner_for_system("demo", need_person=True) is True
    assert svc._ner_for_system("autotest", need_person=True) is False
    assert svc._ner_for_system("high_rps", need_person=True) is False
    assert svc._ner_for_system("format_only", need_person=False) is False
    assert svc._ner_for_system(None, need_person=True) is False
    assert svc._ner_for_system("", need_person=True) is False


def test_ner_master_switch_off(monkeypatch):
    monkeypatch.setenv("NER_ENABLED", "0")
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())
    assert svc._ner_for_system("demo", need_person=True) is False
