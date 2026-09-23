"""Dedicated raw-NER service for the context-defined PII flow."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from app.pii.ner import PiiNerModel

app = FastAPI(title="alfa-vibe-context-ner")
_model: PiiNerModel | None = None


class DetectRequest(BaseModel):
    text: str


def _get_model() -> PiiNerModel:
    global _model
    if _model is None:
        _model = PiiNerModel()
    return _model


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/detect")
def detect(body: DetectRequest) -> dict:
    return {"entities": _get_model().predict(body.text)}
