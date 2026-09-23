"""RuBERT NER for FIO: local model + optional HTTP client."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

from app.pii.detect import Finding

log = logging.getLogger("alfa.ner")

DEFAULT_MODEL = "redmadrobot-rnd/rubert-base-pii-ner"
MAX_LENGTH = int(os.getenv("NER_MAX_LENGTH", "512"))
STRIDE = int(os.getenv("NER_STRIDE", "128"))

# RuBERT label → (our type, structural part for composite types)
LABEL_MAP = {
    "FIRST_NAME": ("PERSON", "first"),
    "LAST_NAME": ("PERSON", "last"),
    "MIDDLE_NAME": ("PERSON", "middle"),
    "PER": ("PERSON", "last"),
    "PERSON": ("PERSON", ""),
    "PHONE": ("PHONE", ""),
    "EMAIL": ("EMAIL", ""),
    "INN": ("INN", ""),
    "CREDIT_CARD": ("PAYMENT_CARD", ""),
    "PASSPORT": ("PASSPORT", ""),
    "DRIVER_LICENSE": ("DRIVER_LICENSE", ""),
    "STREET": ("ADDRESS", "street"),
    "HOUSE": ("ADDRESS", "house"),
    "CITY": ("ADDRESS", "city"),
    "DISTRICT": ("ADDRESS", "district"),
    "REGION": ("ADDRESS", "region"),
}


def _normalize_label(label: str) -> str:
    label = (label or "").strip()
    if label.startswith(("B-", "I-", "S-", "E-")):
        label = label.split("-", 1)[1]
    return label.upper().replace(" ", "_")


def map_entity(entity: dict) -> Finding | None:
    raw = entity.get("entity_group") or entity.get("entity") or entity.get("type")
    label = _normalize_label(str(raw))
    if label not in LABEL_MAP:
        return None
    typ, part = LABEL_MAP[label]
    return Finding(
        type=typ,
        start=int(entity["start"]),
        end=int(entity["end"]),
        score=float(entity.get("score", 0.0)),
        detector="ml",
        part=part,
    )


# Letters / hyphen inside a name token — RuBERT often stops mid-subword (Пу|пкие).
_WORD_CHAR_RE = re.compile(r"[0-9A-Za-zА-Яа-яЁёІіЇїЄєҐґ'\-]")
# Next Capitalized token after a single-name NER hit («Александр» + «Пушкин»).
_NEXT_CYR_NAME_RE = re.compile(
    r"^(\s+)([А-ЯЁ][а-яё]*(?:-[А-ЯЁа-яё]+)?)\b"
)
_NEXT_LAT_NAME_RE = re.compile(
    r"^(\s+)([A-Z][a-z]+(?:-[A-Za-z]+)?)\b"
)


def _next_name_match(text: str):
    return _NEXT_CYR_NAME_RE.match(text) or _NEXT_LAT_NAME_RE.match(text)
_NOT_NAME_FOLLOW = frozenset(
    {
        "русский",
        "русская",
        "поэт",
        "писатель",
        "романист",
        "родился",
        "родилась",
        "умер",
        "умерла",
        "хочет",
        "просил",
        "просила",
        "клиент",
        "менеджер",
        "москва",
        "москве",
        "санкт",
        "россия",
        "рф",
    }
)


def expand_span_to_word(text: str, start: int, end: int) -> tuple[int, int]:
    """Snap NER offsets to Unicode word boundaries so surnames aren't clipped."""
    n = len(text)
    start = max(0, min(start, n))
    end = max(start, min(end, n))
    while start > 0 and _WORD_CHAR_RE.match(text[start - 1]):
        start -= 1
    while end < n and _WORD_CHAR_RE.match(text[end]):
        end += 1
    return start, end


def expand_findings_to_words(text: str, findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        if f.type not in {"PERSON", "CARDHOLDER_NAME", "ADDRESS"}:
            out.append(f)
            continue
        s, e = expand_span_to_word(text, f.start, f.end)
        if s == f.start and e == f.end:
            out.append(f)
        else:
            out.append(
                Finding(
                    f.type,
                    s,
                    e,
                    f.score,
                    f.detector,
                    getattr(f, "decision", "mask"),
                    getattr(f, "reason", ""),
                    getattr(f, "part", ""),
                )
            )
    return out


def _base_person_finding(finding: Finding, part: str) -> Finding:
    return Finding(
        "PERSON",
        finding.start,
        finding.end,
        finding.score,
        finding.detector,
        getattr(finding, "decision", "mask"),
        getattr(finding, "reason", ""),
        part=part,
    )


def _following_name_candidates(
    text: str,
    finding: Finding,
    max_extra: int,
) -> list[Finding]:
    pending: list[Finding] = []
    cursor = finding.end
    while len(pending) < max_extra:
        match = _next_name_match(text[cursor:])
        if not match:
            break
        token = match.group(2)
        if token.casefold() in _NOT_NAME_FOLLOW:
            break
        start = cursor + match.start(2)
        end = cursor + match.end(2)
        cursor += match.end()
        pending.append(
            Finding(
                "PERSON",
                start,
                end,
                finding.score * 0.95,
                finding.detector,
                getattr(finding, "decision", "mask"),
                getattr(finding, "reason", ""),
                part="",
            )
        )
    return pending


def _expanded_person_sequence(
    text: str,
    finding: Finding,
    max_extra: int,
) -> list[Finding]:
    part = getattr(finding, "part", "") or "first"
    if part not in {"", "first"}:
        return [finding]
    if re.search(r"\s", text[finding.start : finding.end].strip()):
        return [finding]

    base = _base_person_finding(finding, part or "first")
    pending = _following_name_candidates(text, finding, max_extra)
    if not pending:
        return [base]

    from app.pii.parts import classify_fio_parts

    tokens = [text[base.start : base.end]] + [
        text[item.start : item.end] for item in pending
    ]
    labels = classify_fio_parts(tokens)
    relabeled = [_base_person_finding(base, labels[0])]
    relabeled.extend(
        Finding(
            "PERSON",
            item.start,
            item.end,
            item.score,
            item.detector,
            item.decision,
            item.reason,
            part=label,
        )
        for item, label in zip(pending, labels[1:])
    )
    return relabeled


def attach_following_name_tokens(
    text: str,
    findings: list[Finding],
    *,
    max_extra: int = 2,
) -> list[Finding]:
    """If RuBERT tagged only first name, emit following Capital tokens."""
    out: list[Finding] = []
    for finding in findings:
        if finding.type == "PERSON":
            out.extend(_expanded_person_sequence(text, finding, max_extra))
        else:
            out.append(finding)
    return out


def merge_adjacent_person(findings: list[Finding], max_gap: int = 3) -> list[Finding]:
    """Merge only subword pieces of the *same* part (e.g. Пу + пкин)."""
    persons = sorted([f for f in findings if f.type == "PERSON"], key=lambda f: f.start)
    others = [f for f in findings if f.type != "PERSON"]
    if not persons:
        return findings
    merged: list[Finding] = []
    cur = persons[0]
    for nxt in persons[1:]:
        same_part = (getattr(cur, "part", "") or "") == (getattr(nxt, "part", "") or "")
        if same_part and nxt.start - cur.end <= max_gap:
            cur = Finding(
                "PERSON",
                cur.start,
                max(cur.end, nxt.end),
                min(cur.score, nxt.score),
                "ml",
                getattr(cur, "decision", "mask"),
                getattr(cur, "reason", "") or getattr(nxt, "reason", ""),
                getattr(cur, "part", ""),
            )
        else:
            merged.append(cur)
            cur = nxt
    merged.append(cur)
    return others + merged


class PiiNerModel:
    def __init__(self, model_name: str | None = None):
        from transformers import (
            AutoModelForTokenClassification,
            AutoTokenizer,
            pipeline,
        )

        name = model_name or os.getenv("NER_MODEL", DEFAULT_MODEL)
        log.info("Loading NER model %s", name)
        device = int(os.getenv("NER_DEVICE", "-1"))
        self.model_name = name
        offline = os.getenv("HF_HUB_OFFLINE", "0") == "1" or os.getenv("TRANSFORMERS_OFFLINE", "0") == "1"
        # Prefer cached weights (RU servers often have no HF access).
        # local_files_only belongs on from_pretrained — not on pipeline(...).
        load_kw: dict[str, Any] = {"local_files_only": True} if offline else {}
        try:
            tokenizer = AutoTokenizer.from_pretrained(name, **load_kw)
            model = AutoModelForTokenClassification.from_pretrained(name, **load_kw)
        except Exception:
            if offline:
                raise
            log.warning("NER cache miss — downloading %s", name)
            tokenizer = AutoTokenizer.from_pretrained(name)
            model = AutoModelForTokenClassification.from_pretrained(name)
        self._pipe = pipeline(
            "token-classification",
            model=model,
            tokenizer=tokenizer,
            aggregation_strategy="simple",
            device=device,
        )

    def predict(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        if len(text) < MAX_LENGTH * 3:
            return list(self._pipe(text))
        entities: list[dict[str, Any]] = []
        step = max(MAX_LENGTH - STRIDE, 1) * 2
        window = MAX_LENGTH * 3
        start = 0
        while start < len(text):
            chunk = text[start : start + window]
            for e in self._pipe(chunk):
                entities.append(
                    {
                        "entity_group": e["entity_group"],
                        "start": int(e["start"]) + start,
                        "end": int(e["end"]) + start,
                        "score": float(e["score"]),
                    }
                )
            if start + window >= len(text):
                break
            start += step
        seen: set[tuple] = set()
        unique = []
        for e in entities:
            key = (e["entity_group"], e["start"], e["end"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(e)
        return unique


class NerClient:
    """NER_ENABLED=1; NER_URL for remote, else local RuBERT."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 30.0,
        enabled: bool | None = None,
    ):
        self.base_url = (base_url if base_url is not None else os.getenv("NER_URL", "")).rstrip("/")
        self.timeout = float(os.getenv("NER_TIMEOUT", str(timeout)))
        env_enabled = os.getenv("NER_ENABLED", "0") == "1"
        self.enabled = env_enabled if enabled is None else enabled
        local_default = "1" if self.enabled and not self.base_url else "0"
        self.use_local = os.getenv("NER_LOCAL", local_default) == "1"
        self._local: PiiNerModel | None = None

    def _ensure_local(self):
        if self._local is None:
            self._local = PiiNerModel()

    def detect_raw(self, text: str) -> list[dict[str, Any]]:
        """Return raw NER entities before mapping them to business PII types."""
        if not self.enabled:
            return []
        if self.base_url:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/detect", json={"text": text})
                resp.raise_for_status()
                data = resp.json()
                raw = data.get("entities", data if isinstance(data, list) else [])
            return list(raw)
        if not self.use_local:
            return []
        self._ensure_local()
        return list(self._local.predict(text))

    @staticmethod
    def _map_remote_entity(entity: dict) -> Finding | None:
        if entity.get("type") == "PERSON" and "start" in entity:
            return Finding(
                "PERSON",
                int(entity["start"]),
                int(entity["end"]),
                float(entity.get("score", 0)),
                "ml",
            )
        return map_entity(entity)

    def _detect_remote(self, text: str) -> list[Finding]:
        raw = self.detect_raw(text)
        findings = [
            mapped
            for entity in raw
            if (mapped := self._map_remote_entity(entity)) is not None
        ]
        return self._finalize_person_spans(text, findings)

    def _detect_local(self, text: str) -> list[Finding]:
        self._ensure_local()
        raw = self._local.predict(text)
        findings = [mapped for entity in raw if (mapped := map_entity(entity))]
        return self._finalize_person_spans(text, findings)

    def detect(self, text: str) -> list[Finding]:
        if not self.enabled:
            return []
        if self.base_url:
            return self._detect_remote(text)
        if not self.use_local:
            return []
        return self._detect_local(text)

    @staticmethod
    def _finalize_person_spans(text: str, findings: list[Finding]) -> list[Finding]:
        merged = merge_adjacent_person(findings)
        expanded = expand_findings_to_words(text, merged)
        glued = attach_following_name_tokens(text, expanded)
        glued = merge_adjacent_person(glued)
        from app.pii.parts import split_person_span

        out: list[Finding] = []
        for f in glued:
            if f.type == "PERSON" and re.search(r"\s", text[f.start : f.end]):
                out.extend(
                    split_person_span(
                        text,
                        f.start,
                        f.end,
                        f.score,
                        f.detector,
                        decision=getattr(f, "decision", "mask"),
                        reason=getattr(f, "reason", "") or "",
                    )
                )
            else:
                out.append(f)
        return out
