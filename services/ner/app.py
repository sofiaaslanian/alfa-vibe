"""Minimal FastAPI NER service for redmadrobot-rnd/rubert-base-pii-ner."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.pii.ner.mapper import map_entity, merge_adjacent_person
from app.pii.ner.model import DEFAULT_MODEL, PiiNerModel

_model: PiiNerModel | None = None


def get_model() -> PiiNerModel:
    global _model
    if _model is None:
        _model = PiiNerModel()
    return _model


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("NER_PRELOAD", "1") == "1":
        get_model()
    yield


app = FastAPI(title="Alfa PII NER", version="0.1.0", lifespan=lifespan)


class DetectRequest(BaseModel):
    text: str = Field(..., min_length=1)


@app.get("/health")
def health():
    return {"status": "ok", "model": os.getenv("NER_MODEL", DEFAULT_MODEL)}


@app.post("/detect")
def detect(body: DetectRequest):
    raw = get_model().predict(body.text)
    mapped = [m for e in raw if (m := map_entity(e)) is not None]
    merged = merge_adjacent_person(mapped)
    return {"entities": [f.to_dict() for f in merged]}
