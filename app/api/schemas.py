"""Схемы данных для API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ProcessRequest(BaseModel):
    payload: str = Field(..., description="Текст запроса или уже замаскированная строка")
    payload_id: str = Field(..., description="Ключ корреляции mask -> demask")


class ProcessResponse(BaseModel):
    result: str


class HealthResponse(BaseModel):
    status: str
    systems: int
    pd_types: int