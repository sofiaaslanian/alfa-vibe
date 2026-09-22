"""Движок идентификации персональных данных.

Регистронезависимый поиск по regex-шаблонам с контекстными проверками.
Ловушки: «пушкин» ≠ ФИО, «адрес отделения банка» ≠ адрес клиента.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from app.core.config import Config, PDRule


@dataclass
class Match:
    pd_type: str
    start: int
    end: int
    value: str
    confidence: float = 1.0


# Контекстные слова, указывающие на НЕ-ПД (ловушки)
TRAP_WORDS = [
    r"\bпушкин\b", r"\bсергей\b", r"\bантон\b", r"\bиван\b",
    r"\bотделение\s+банка\b", r"\bофис\b", r"\bфилиал\b",
    r"\bадрес\s+отделения\b", r"\bадрес\b\s*(?:отделения|банка|офиса)",
    r"\bдом\b\s*(?: культуры| отдыха| творчества)",
]


def _compile_rule(rule: PDRule) -> list[re.Pattern]:
    compiled = []
    for pat in rule.patterns:
        try:
            compiled.append(re.compile(pat, re.IGNORECASE | re.VERBOSE))
        except re.error:
            pass
    return compiled


def _is_trap_context(text: str, start: int, end: int, window: int = 60) -> bool:
    """Проверяет, не находится ли совпадение в ловушечном контексте."""
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    ctx = text[ctx_start:ctx_end]
    for tw in TRAP_WORDS:
        if re.search(tw, ctx, re.IGNORECASE):
            return True
    return False


def _is_name_trap(text: str, start: int, end: int) -> bool:
    """ФИО может быть именем поэта/персонажа — проверяем окружение."""
    value = text[start:end].strip()
    # Известные имена-ловушки
    known_traps = {"Пушкин", "Сергей", "Иван", "Антон", "Александр", "Мария"}
    parts = value.split()
    if parts and parts[0] in known_traps:
        # Проверяем, есть ли перед/после указание на ПД (паспорт, клиент, т.п.)
        ctx_start = max(0, start - 120)
        ctx_end = min(len(text), end + 120)
        ctx = text[ctx_start:ctx_end].lower()
        pd_indicators = ["паспорт", "клиент", "гражданин", "водитель", "карта", "данные", "персональные"]
        if not any(ind in ctx for ind in pd_indicators):
            return True
    return False


def identify(text: str, config: Config, system_name: Optional[str] = None) -> list[Match]:
    """Находит все ПД в тексте.

    Args:
        text: исходный текст
        config: конфигурация
        system_name: система-потребитель; если None — используются все правила

    Returns:
        Список найденных совпадений (без пересечений, по приоритету).
    """
    if system_name and system_name in config.systems:
        sys_cfg = config.systems[system_name]
        if not sys_cfg.enabled:
            return []
        active_ids = sys_cfg.pd_types if sys_cfg.pd_types else config.default_pd_types
    else:
        active_ids = config.default_pd_types

    matches: list[Match] = []
    compiled_cache: dict[str, list[re.Pattern]] = {}

    for pid in active_ids:
        rule = config.pd_rules.get(pid)
        if not rule:
            continue
        if pid not in compiled_cache:
            compiled_cache[pid] = _compile_rule(rule)
        for pat in compiled_cache[pid]:
            for m in pat.finditer(text):
                s, e = m.start(), m.end()
                # Ловушки
                if _is_trap_context(text, s, e):
                    continue
                if pid == "full_name" and _is_name_trap(text, s, e):
                    continue
                matches.append(Match(
                    pd_type=pid,
                    start=s,
                    end=e,
                    value=text[s:e],
                ))

    # Убираем пересечения: оставляем более длинное/раннее совпадение
    matches.sort(key=lambda x: (x.start, -(x.end - x.start)))
    filtered: list[Match] = []
    last_end = 0
    for m in matches:
        if m.start >= last_end:
            filtered.append(m)
            last_end = m.end
    return filtered