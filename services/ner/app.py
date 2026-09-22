"""Minimal FastAPI NER service for redmadrobot-rnd/rubert-base-pii-ner."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.pii.ner.mapper import map_entity, merge_adjacent_person

MODEL_NAME = os.getenv("NER_MODEL", "redmadrobot-rnd/rubert-base-pii-ner")
_pipeline = None


def get_pipeline():
    global _pipeline
    if _pipeline is None:
        from transformers import pipeline

        _pipeline = pipeline(
            "token-classification",
            model=MODEL_NAME,
            aggregation_strategy="simple",
        )
    return _pipeline


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("NER_PRELOAD", "1") == "1":
        get_pipeline()
    yield


app = FastAPI(title="Alfa PII NER", version="0.1.0", lifespan=lifespan)


class DetectRequest(BaseModel):
    text: str = Field(..., min_length=1)


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_NAME}


@app.post("/detect")
def detect(body: DetectRequest):
    ner = get_pipeline()
    raw = ner(body.text)
    mapped = []
    for entity in raw:
        finding = map_entity(
            {
                "entity_group": entity["entity_group"],
                "start": entity["start"],
                "end": entity["end"],
                "score": float(entity["score"]),
            }
        )
        if finding is not None:
            mapped.append(finding)
    merged = merge_adjacent_person(mapped)
    return {"entities": [f.to_dict() for f in merged]}
