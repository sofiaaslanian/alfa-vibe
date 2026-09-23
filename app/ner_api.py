"""Dedicated raw-NER service for the context-defined PII flow."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from app.pii.ner import PiiNerModel

_model: PiiNerModel | None = None


def _get_model() -> PiiNerModel:
    global _model
    if _model is None:
        _model = PiiNerModel()
    return _model


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load before the service becomes healthy. The API proxy depends on this
    # health check, so evaluator traffic never pays first-request model load.
    _get_model()
    yield


app = FastAPI(title="alfa-vibe-context-ner", lifespan=lifespan)


class DetectRequest(BaseModel):
    text: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "model": "loaded" if _model is not None else "loading"}


def _jsonable(value):
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    item = getattr(value, "item", None)
    if callable(item) and type(value).__module__ == "numpy":
        return item()
    return value


@app.post("/detect")
def detect(body: DetectRequest) -> dict:
    return {"entities": _jsonable(_get_model().predict(body.text))}
