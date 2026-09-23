"""Discourse gate: self/KYC claim vs third-party mention — no celebrity lexicon."""

from __future__ import annotations

import pytest

from app.pii.detect import detect_pii
from app.pii.discourse import is_personal_person_mention, should_skip_person
from tests.conftest import joined_mask_vals

ALEXANDER = "Александр"


def _persons(text: str) -> list[str]:
    return joined_mask_vals(text, "PERSON")


# ── keep: personal claims ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("меня зовут Соня Асланян", "Соня Асланян"),
        ("мое имя Иван Петров", "Иван Петров"),
        ("Ваня Дмитриенко меня зовут", "Ваня Дмитриенко"),
        ("ФИО клиента: Иванов Иван Иванович", "Иванов Иван Иванович"),
        ("Клиент Петрова Анна просит ответить.", "Петрова Анна"),
        # Self-ID wins even if the name «looks famous» — KYC-safe
        ("меня зовут Илон Маск", "Илон Маск"),
        # Holdout: client + banking action
        ("Клиент Александр Пушкин просит перевыпуск карты", "Александр Пушкин"),
        ("я Соня Асланян", "Соня Асланян"),
        ("я соня асланян", "соня асланян"),
        ("Я София Асланян", "София Асланян"),
        ("Иван Петров хочет оформить карту", "Иван Петров"),
        ("свяжитесь с Иваном", "Иваном"),
    ],
)
def test_personal_claims_masked(text, expected):
    assert expected in _persons(text)


def test_ner_mid_sentence_banking(monkeypatch):
    """Discourse policy is tested with deterministic NER findings, without ML deps."""
    from app.pii.detect import Finding, get_ner

    ner = get_ner()
    ner.enabled = True
    ner.use_local = False

    def fake_detect(text: str) -> list[Finding]:
        full_name = "Дмитрий Орлов" if "Дмитрий Орлов" in text else "Александр Пушкин"
        first, last = full_name.split()
        start = text.index(full_name)
        return [
            Finding("PERSON", start, start + len(first), 0.99, "ml", part="first"),
            Finding(
                "PERSON",
                start + len(first) + 1,
                start + len(full_name),
                0.99,
                "ml",
                part="last",
            ),
        ]

    monkeypatch.setattr(ner, "detect", fake_detect)

    keep = "Заявку на кредит подал Дмитрий Орлов, паспорт уже в системе."
    drop = "Поэт Александр Пушкин родился в Москве."
    kept_fs = sorted(
        [
            f
            for f in detect_pii(keep, enable_ner=True)
            if f.type == "PERSON" and getattr(f, "decision", "mask") == "mask"
        ],
        key=lambda f: f.start,
    )
    assert kept_fs
    kept = keep[kept_fs[0].start : kept_fs[-1].end]
    assert "Дмитрий" in kept
    assert "Орлов" in kept
    poet = [f for f in detect_pii(drop, enable_ner=True) if f.type == "PERSON"]
    assert poet
    assert all(getattr(f, "decision", "") == "allow" for f in poet)
    assert any("Пушкин" in drop[f.start : f.end] or ALEXANDER in drop[f.start : f.end] for f in poet)


def test_famous_name_allow_not_masked(monkeypatch):
    from app.pii.detect import Finding, get_ner
    from app.masking import apply_dev_redact

    ner = get_ner()
    ner.enabled = True
    ner.use_local = False

    def fake_detect(text: str) -> list[Finding]:
        tokens = ["Владимир", "владимирович", "Жириновский"]
        parts = ["first", "middle", "last"]
        findings = []
        search_from = 0
        for token, part in zip(tokens, parts):
            start = text.index(token, search_from)
            findings.append(
                Finding("PERSON", start, start + len(token), 0.99, "ml", part=part)
            )
            search_from = start + len(token)
        return findings

    monkeypatch.setattr(ner, "detect", fake_detect)
    text = "Владимир владимирович Жириновский любит кофе"
    fs = detect_pii(text, enable_ner=True)
    persons = [f for f in fs if f.type == "PERSON"]
    assert persons
    assert all(f.decision == "allow" for f in persons)
    joined = text[min(f.start for f in persons) : max(f.end for f in persons)]
    assert "Жириновский" in joined
    assert apply_dev_redact(text, fs) == text


# ── drop: third-party / bare mentions ──────────────────────────────────────


@pytest.mark.parametrize(
    "text",
    [
        "Илон Маск",
        "Илон Маск купил Twitter",
        "Elon Musk founded SpaceX and Tesla",
        "Александр Пушкин — русский поэт",
        "В тексте указан роман «Евгений Онегин».",
        "Павел Дуров основал Telegram",
        "Билл Гейтс заявил о новых инвестициях",
    ],
)
def test_third_party_not_masked(text):
    assert _persons(text) == []


def test_discourse_helpers():
    t = "Александр Пушкин — русский поэт"
    # No PERSON span from rules; helper on hypothetical offsets
    s, e = t.index(ALEXANDER), t.index(ALEXANDER) + len("Александр Пушкин")
    assert is_personal_person_mention(t, s, e) is False
    assert should_skip_person(t, s, e) is True

    t2 = "меня зовут Соня Асланян"
    s2, e2 = t2.index("Соня"), t2.index("Соня") + len("Соня Асланян")
    assert is_personal_person_mention(t2, s2, e2) is True


# ── phone: personal vs Alfa support ────────────────────────────────────────


def _phones(text: str) -> list[str]:
    return [
        text[f.start : f.end]
        for f in detect_pii(text, enable_ner=False)
        if f.type == "PHONE"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "мой телефон +7 916 123-45-67",
        "Перезвоните мне на 89161234567",
        "номер клиента: 8 (916) 123-45-67",
    ],
)
def test_personal_phone_kept(text):
    assert _phones(text)


@pytest.mark.parametrize(
    "text",
    [
        "Телефон поддержки Альфа-Банка: 8 800 200-00-00",
        "Горячая линия: 8 800 200 00 00",
        "Звоните в колл-центр: +7 495 788-88-78",
        "Контакт-центр Альфа-Банка 88002000000",
    ],
)
def test_alfa_support_phone_dropped(text):
    assert _phones(text) == []


# ── birth date vs holiday ──────────────────────────────────────────────────


def _birth_dates(text: str) -> list[str]:
    return [
        text[f.start : f.end]
        for f in detect_pii(text, enable_ner=False)
        if f.type == "BIRTH_DATE"
    ]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("дата рождения 15.03.1990", "15.03.1990"),
        ("я родился 01.01.2000", "01.01.2000"),
        ("день рождения клиента 12.05.1988", "12.05.1988"),
    ],
)
def test_personal_birth_date_kept(text, expected):
    assert expected in _birth_dates(text)


@pytest.mark.parametrize(
    "text",
    [
        "Новый год отмечаем 01.01.2025",
        "Корпоратив 8 марта 08.03.2024",
        "дедлайн отчёта 31.12.2024",
        "праздник 9 мая 09.05.2025",
    ],
)
def test_holiday_or_event_date_not_birth(text):
    assert _birth_dates(text) == []


def test_celebrity_birth_date_dropped():
    text = "День рождения Пушкина — 26.05.1799, великий поэт"
    assert _birth_dates(text) == []


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Дата рождения: 02.01.1990", "02.01.1990"),
        ("Дата рождения: 02-01-1990", "02-01-1990"),
        ("Дата рождения: 1990.02.01", "1990.02.01"),
        ("Дата рождения: 1990-02-01", "1990-02-01"),
        ("Дата рождения: 02/01/1990", "02/01/1990"),
        ("Дата рождения: 1990/02/01", "1990/02/01"),
    ],
)
def test_birth_date_order_variants(text, expected):
    assert expected in _birth_dates(text)
