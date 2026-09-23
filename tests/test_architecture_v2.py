from app.pii.catalog import BY_TYPE, DetectionGroup, StructureKind
from app.pii.context_ml import raw_entities_to_context_findings
from app.pii.detect import Finding
from app.pii.structural import normalize_structures


def test_canonical_catalog_is_exactly_17_types():
    assert len(BY_TYPE) == 17
    assert sum(s.group == DetectionGroup.CONTEXT for s in BY_TYPE.values()) == 6
    assert sum(s.group == DetectionGroup.FORMAT_CONTEXT for s in BY_TYPE.values()) == 7
    assert sum(s.group == DetectionGroup.FORMAT for s in BY_TYPE.values()) == 4


def test_structure_is_orthogonal_to_detection_group():
    assert BY_TYPE["PERSON"].structure == StructureKind.COMPOSITE
    assert BY_TYPE["PASSPORT"].structure == StructureKind.COMPOSITE
    assert BY_TYPE["EMAIL"].structure == StructureKind.ATOMIC


def test_raw_ml_location_gets_business_role_from_context():
    text = "Место рождения: Самара"
    start = text.index("Самара")
    raw = [{"entity_group": "CITY", "start": start, "end": start + len("Самара"), "score": 0.9}]
    out = raw_entities_to_context_findings(text, raw)
    assert any(f.type == "PLACE_OF_BIRTH" for f in out)


def test_raw_country_becomes_citizenship_only_in_role_context():
    text = "Гражданство: Россия"
    start = text.index("Россия")
    raw = [{"entity_group": "COUNTRY", "start": start, "end": start + len("Россия"), "score": 0.9}]
    out = raw_entities_to_context_findings(text, raw)
    assert any(f.type == "CITIZENSHIP" for f in out)

    neutral = "Поездка в Россию"
    start = neutral.index("Россию")
    raw = [{"entity_group": "COUNTRY", "start": start, "end": start + len("Россию"), "score": 0.9}]
    out = raw_entities_to_context_findings(neutral, raw)
    assert not any(f.type == "CITIZENSHIP" for f in out)


def test_document_structure_is_centralized():
    text = "45 11 123456"
    f = Finding("PASSPORT", 0, len(text), 0.9, "test")
    parts = normalize_structures(text, [f])
    assert [(p.part, text[p.start:p.end]) for p in parts] == [
        ("series", "45 11"),
        ("number", "123456"),
    ]
