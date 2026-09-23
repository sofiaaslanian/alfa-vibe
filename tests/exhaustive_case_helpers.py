"""Helpers for the exhaustive 360-case PII contract.

This suite is intentionally recall-first for hackathon scoring:
false negatives are treated as more severe than conservative masking.
Do not edit expected answers to make production code green.
"""

from __future__ import annotations


def pos(case_id: str, typ: str, text: str, *values: str, must_not: tuple[str, ...] = ()) -> dict:
    case = {
        "id": case_id,
        "text": text,
        "enabled_types": [typ],
        "expected": [
            {"type": typ, "value": value, "match": "exact"} for value in values
        ],
    }
    if must_not:
        case["must_not_cover_values"] = list(must_not)
    return case


def neg(case_id: str, typ: str, text: str) -> dict:
    return {
        "id": case_id,
        "text": text,
        "enabled_types": [typ],
        "expected": [],
        "forbidden_types": [typ],
    }


def mixed(case_id: str, text: str, enabled_types: list[str], expected: list[tuple[str, str]], must_not: tuple[str, ...] = ()) -> dict:
    case = {
        "id": case_id,
        "text": text,
        "enabled_types": enabled_types,
        "expected": [
            {"type": typ, "value": value, "match": "exact"}
            for typ, value in expected
        ],
    }
    if must_not:
        case["must_not_cover_values"] = list(must_not)
    return case
