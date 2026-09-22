from app.masking import apply_dev_redact
from app.pii import rules


def test_p4b_passport_expands_only_labelled_pair():
    text = "Паспорт: серия 45 11, номер 123456."
    masked = apply_dev_redact(text, rules.detect_passport(text))
    assert masked == "Паспорт: ***** ** **, ***** ******."

    plain = "Паспорт: 45 11 123456."
    plain_masked = apply_dev_redact(plain, rules.detect_passport(plain))
    assert plain_masked == "Паспорт: ** ** ******."


def test_p4b_driver_license_expands_labelled_pair():
    text = "Водительское удостоверение: серия 77 11, номер 123456."
    masked = apply_dev_redact(text, rules.detect_driver_license(text))
    assert masked == "Водительское удостоверение: ***** ** **, ***** ******."
