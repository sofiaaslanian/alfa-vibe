from app.pii import rules


def _vals(text):
    return [text[f.start:f.end] for f in rules.detect_passport_issue_date(text)]


def test_p5_issue_date_requires_passport_context():
    assert _vals("Кредит выдан 03.04.2015.") == []
    assert _vals("Документ выдан 03.04.2015.") == []


def test_p5_issue_date_keeps_explicit_passport_context():
    assert _vals("Паспорт выдан 03.04.2015.") == ["03.04.2015"]
    assert _vals("Дата выдачи паспорта: 03.04.2015.") == ["03.04.2015"]


def test_p5_issue_date_keeps_passport_bundle_context():
    text = "Паспорт: серия 45 11, номер 123456; код подразделения 770-002; выдан 03.04.2015 ОМВД России."
    assert _vals(text) == ["03.04.2015"]
