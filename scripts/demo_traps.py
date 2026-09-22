#!/usr/bin/env python3
"""Demo traps for jury: Pushkin / bank office / manager vs client / combo.

Run: NER_ENABLED=1 python scripts/demo_traps.py
(Load/autotest stays rules-only via config use_ner: false.)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("NER_ENABLED", "1")
os.environ.setdefault("STORAGE_BACKEND", "memory")

from app.config import load_config
from app.masking import apply_dev_redact
from app.process import ProcessService
from app.state import MemoryStateStore

TRAPS = [
    (
        "cultural_pushkin",
        "Поэт Александр Пушкин родился в Москве.",
        "не маскировать ФИО / место рождения знаменитости",
    ),
    (
        "client_named_pushkin",
        "Клиент Александр Пушкин хочет оформить карту.",
        "маскировать ФИО клиента даже если имя историческое",
    ),
    (
        "bank_office_address",
        "Адрес отделения Банка: Москва, ул. Каланчёвская, д. 27.",
        "адрес офиса ≠ клиентский ADDRESS",
    ),
    (
        "home_address",
        "Адрес проживания: Москва, ул. Арбат, д. 10, кв. 2.",
        "домашний адрес — ПД",
    ),
    (
        "manager_vs_client",
        "Менеджер Анна Смирнова оформила заявку. Клиент Иван Петров подтвердил данные.",
        "только клиент",
    ),
    (
        "combo_pin_alone",
        "PIN-код карты: 4321",
        "demo combo: PIN без карты не маскируем",
    ),
    (
        "combo_pin_with_card",
        "Карта 4111 1111 1111 1111, PIN-код карты: 4321",
        "demo combo: PIN+карта — маскируем оба",
    ),
    (
        "snils_bonus",
        "СНИЛС клиента: 112-233-445 95",
        "бонус УЛ кроме паспорта",
    ),
]


def main() -> None:
    cfg = load_config(str(ROOT / "config.yaml"))
    svc = ProcessService(cfg, MemoryStateStore())
    print("=== Jury trap demo (system=demo) ===\n")
    for tid, text, note in TRAPS:
        findings = svc.detect(text, system="demo")
        masked = apply_dev_redact(text, findings)
        types = ", ".join(sorted({f.type for f in findings})) or "—"
        print(f"[{tid}] {note}")
        print(f"  in:  {text}")
        print(f"  out: {masked}")
        print(f"  types: {types}\n")


if __name__ == "__main__":
    main()
