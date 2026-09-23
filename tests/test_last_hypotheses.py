from app.pii.detect import Finding, detect_pii
from app.pii.flows import ContextFlow


def _masked(findings, typ):
    return [f for f in findings if f.type == typ and getattr(f, "decision", "mask") == "mask"]


def test_ml_union_recovers_labelled_person_when_ml_misses():
    text = "ФИО клиента: Иванов Иван"
    result = ContextFlow.detect(text, ml_findings=[])
    assert any(f.type == "PERSON" for f in result.findings)


def test_ml_union_keeps_ml_person_candidate():
    text = "Клиент Иванов Иван"
    start = text.index("Иванов")
    ml = [Finding("PERSON", start, len(text), 0.99, "synthetic_ml")]
    result = ContextFlow.detect(text, ml_findings=ml)
    assert any(f.detector == "synthetic_ml" for f in result.findings)


def test_patronymic_fio_next_to_contact_is_personal():
    text = "Иванов Иван Иванович, тел. +7 (999) 123-45-67"
    findings = detect_pii(text, enable_ner=False)
    persons = _masked(findings, "PERSON")
    assert persons
    assert min(f.start for f in persons) == 0
    assert max(f.end for f in persons) == len("Иванов Иван Иванович")


def test_patronymic_fio_cultural_context_stays_allowed():
    text = "Иванов Иван Иванович, известный поэт, выступил на сцене"
    findings = detect_pii(text, enable_ner=False)
    assert not _masked(findings, "PERSON")


def test_personal_spoken_address_includes_city():
    text = "Живу в Самаре на улице Ленина 5"
    findings = detect_pii(text, enable_ner=False)
    addresses = _masked(findings, "ADDRESS")
    city_start = text.index("Самаре")
    city_end = city_start + len("Самаре")
    assert any(f.start <= city_start and city_end <= f.end for f in addresses)


def test_meeting_city_and_street_is_not_personal_address():
    text = "Встреча в Самаре на улице Ленина 5"
    findings = detect_pii(text, enable_ner=False)
    assert not _masked(findings, "ADDRESS")
