"""Конфигурация: allowlist систем, типы ПД, правила маскирования."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class PDRule:
    """Правило для одного типа персональных данных."""

    id: str                    # например "passport_series_number"
    name: str                  # человекочитаемое название
    patterns: list[str]        # regex-шаблоны (регистронезависимо)
    mask: str                  # маска, напр. "XXXX ######"
    requires_context: bool = False
    context_patterns: list[str] = field(default_factory=list)


@dataclass
class SystemConfig:
    """Настройки для одной системы-потребителя."""

    name: str
    enabled: bool = True
    pd_types: list[str] = field(default_factory=list)   # id типов ПД; пусто = все
    allow_demask: bool = True
    mask_style: str = "default"  # default | token | synthetic


@dataclass
class Config:
    systems: dict[str, SystemConfig]
    pd_rules: dict[str, PDRule]
    default_pd_types: list[str]
    storage_backend: str = "memory"


def _rule_from_dict(data: dict[str, Any]) -> PDRule:
    return PDRule(
        id=data["id"],
        name=data.get("name", data["id"]),
        patterns=data.get("patterns", []),
        mask=data.get("mask", "XXXX"),
        requires_context=data.get("requires_context", False),
        context_patterns=data.get("context_patterns", []),
    )


def _system_from_dict(name: str, data: dict[str, Any]) -> SystemConfig:
    return SystemConfig(
        name=name,
        enabled=data.get("enabled", True),
        pd_types=data.get("pd_types", []),
        allow_demask=data.get("allow_demask", True),
        mask_style=data.get("mask_style", "default"),
    )


def load_config(path: str = "config.yaml") -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    systems = {n: _system_from_dict(n, d) for n, d in (raw.get("systems") or {}).items()}
    rules = {r["id"]: _rule_from_dict(r) for r in (raw.get("pd_rules") or [])}
    return Config(
        systems=systems,
        pd_rules=rules,
        default_pd_types=raw.get("default_pd_types", list(rules.keys())),
        storage_backend=raw.get("storage_backend", "memory"),
    )