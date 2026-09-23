"""Tests for MIT checksums + reused public RU PII patterns."""

from __future__ import annotations

from app.config import load_config
from app.pii import checksums, rules
from app.pii.detect import detect_pii
from app.pii.structural import normalize_structures
from app.process import ProcessService
from app.state import MemoryStateStore


def test_checksums_inn_snils_luhn():
    assert checksums.inn12("500100732259")
    assert not checksums.inn12("500100732258")
    assert checksums.inn10("7707083893")
    assert checksums.snils("112-233-445 95")
    assert not checksums.snils("112-233-445 00")
    assert checksums.luhn("4111111111111111")


def test_snils_requires_label():
    assert rules.detect_snils("Код 112-233-445 95") == []
    f = rules.detect_snils("СНИЛС клиента: 112-233-445 95")
    assert len(f) == 1 and f[0].type == "SNILS"


def test_zagran_and_oms():
    z = rules.detect_international_passport("Загранпаспорт: 75 1234567")
    assert len(z) == 1 and z[0].type == "INTERNATIONAL_PASSPORT"
    o = rules.detect_oms("Полис ОМС 1234567890123456")
    assert len(o) == 1 and o[0].type == "OMS"


def test_cvv_oborote_phrase():
    f = rules.detect_cvv("Три цифры на обороте карты 321")
    assert len(f) == 1 and f[0].type == "CVV"
    assert rules.detect_cvv("код 321") == []


def test_passport_filler_words():
    # Cloud.ru-style filler between keyword and number → series + number spans
    text = "С моим паспортом данные 45 11 123456 уже внесены"
    f = normalize_structures(text, rules.detect_passport(text))
    assert len(f) >= 2
    digits = "".join(c for x in f for c in text[x.start : x.end] if c.isdigit())
    assert digits == "4511123456"
    assert all("номер" not in text[x.start : x.end].lower() for x in f)


def test_person_patronymic_candidate():
    text = "Вчера Петров Иван Сергеевич пришёл в банк"
    raw = normalize_structures(text, rules.detect_person_patronymic(text))
    assert len(raw) == 3
    assert {x.part for x in raw} == {"last", "first", "middle"}
    # Without personal claim discourse drops it
    kept = detect_pii("Вчера Петров Иван Сергеевич пришёл в банк", enable_ner=False)
    assert not any(f.type == "PERSON" and getattr(f, "decision", "mask") == "mask" for f in kept)
    kept2 = detect_pii("Клиент Петров Иван Сергеевич подтвердил данные", enable_ner=False)
    assert any(f.type == "PERSON" and getattr(f, "decision", "mask") == "mask" for f in kept2)


def test_combo_policy_demo_system():
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())
    # autotest (no combo): PIN alone masks
    pin_only = svc.detect("PIN-код карты: 4321", system="autotest")
    assert any(f.type == "PIN" for f in pin_only)
    # demo combo: PIN alone dropped
    pin_demo = svc.detect("PIN-код карты: 4321", system="demo")
    assert not any(f.type == "PIN" for f in pin_demo)
    # demo combo: PIN + card kept
    both = svc.detect(
        "Карта 4111 1111 1111 1111, PIN-код карты: 4321", system="demo"
    )
    types = {f.type for f in both}
    assert "PAYMENT_CARD" in types and "PIN" in types
