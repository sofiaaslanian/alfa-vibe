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
_NEXT_NAME_TOKEN_RE = re.compile(
    r"^(\s+)([А-ЯЁ][а-яё]*(?:-[А-ЯЁа-яё]+)?|[A-Z][a-z]+(?:-[A-Za-z]+)?)\b"
)
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


def attach_following_name_tokens(
    text: str, findings: list[Finding], *, max_extra: int = 2
) -> list[Finding]:
    """If RuBERT tagged only first name, emit following Capital tokens as last/middle."""
    out: list[Finding] = []
    for f in findings:
        if f.type != "PERSON":
            out.append(f)
            continue
        part = getattr(f, "part", "") or "first"
        if part not in {"", "first"}:
            out.append(f)
            continue
        # Already multi-token in one span — split later via parts.split_person_span
        if re.search(r"\s", text[f.start : f.end].strip()):
            out.append(f)
            continue
        out.append(
            Finding(
                "PERSON",
                f.start,
                f.end,
                f.score,
                f.detector,
                getattr(f, "decision", "mask"),
                getattr(f, "reason", ""),
                part="first" if not part else part,
            )
        )
        end = f.end
        extras = 0
        labels_queue = ["last"] if max_extra == 1 else ["last", "middle"]
        # Prefer: first + last; if two extras, first + middle + last (swap)
        pending: list[Finding] = []
        while extras < max_extra:
            m = _NEXT_NAME_TOKEN_RE.match(text[end:])
            if not m:
                break
            token = m.group(2)
            if token.casefold() in _NOT_NAME_FOLLOW:
                break
            tok_start = end + m.start(2)
            tok_end = end + m.end(2)
            end = end + m.end()
            pending.append(
                Finding(
                    "PERSON",
                    tok_start,
                    tok_end,
                    f.score * 0.95,
                    f.detector,
                    getattr(f, "decision", "mask"),
                    getattr(f, "reason", ""),
                    part="",  # classify below
                )
            )
            extras += 1
        if not pending:
            continue
        tokens = [text[f.start : f.end]] + [text[p.start : p.end] for p in pending]
        from app.pii.parts import classify_fio_parts

        labels = classify_fio_parts(tokens)
        # Relabel the already-appended first finding
        out[-1] = Finding(
            "PERSON",
            out[-1].start,
            out[-1].end,
            out[-1].score,
            out[-1].detector,
            out[-1].decision,
            out[-1].reason,
            part=labels[0],
        )
        for p, lab in zip(pending, labels[1:]):
            out.append(
                Finding(
                    "PERSON",
                    p.start,
                    p.end,
                    p.score,
                    p.detector,
                    p.decision,
                    p.reason,
                    part=lab,
                )
            )
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

    def detect(self, text: str) -> list[Finding]:
        if not self.enabled:
            return []
        if self.base_url:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/detect", json={"text": text})
                resp.raise_for_status()
                data = resp.json()
                raw = data.get("entities", data if isinstance(data, list) else [])
            out: list[Finding] = []
            for e in raw:
                if e.get("type") == "PERSON" and "start" in e:
                    out.append(
                        Finding("PERSON", int(e["start"]), int(e["end"]), float(e.get("score", 0)), "ml")
                    )
                else:
                    mapped = map_entity(e)
                    if mapped:
                        out.append(mapped)
            return self._finalize_person_spans(text, out)
        if not self.use_local:
            return []
        self._ensure_local()
        raw = self._local.predict(text)
        return self._finalize_person_spans(
            text, [m for e in raw if (m := map_entity(e))]
        )

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
