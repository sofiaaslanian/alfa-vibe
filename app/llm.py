"""Клиент для работы с AlfaGen LLM-провайдером."""

from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

log = logging.getLogger("alfa.llm")


class AlfaGenClient:
    """Обёртка над API AlfaGen (совместимо с OpenAI-контрактом)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "deepseek-v.4-flash",
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("ALFAGEN_API_KEY", "")
        self.base_url = (base_url or os.getenv("ALFAGEN_BASE_URL", "https://alfagen.alfabank.ru/continue-dev/")).rstrip("/")
        self.model = model or os.getenv("ALFAGEN_MODEL", "deepseek-v.4-flash")
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def chat(self, prompt: str, system: Optional[str] = None) -> str:
        """Отправляет замаскированный промпт в LLM, возвращает ответ."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
        }

        log.debug("AlfaGen chat request: model=%s", self.model)
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
        return data["choices"][0]["message"]["content"]

    def is_available(self) -> bool:
        """Проверяет доступность AlfaGen."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{self.base_url}/models", headers=self._headers())
                return resp.status_code == 200
        except Exception:
            return False