from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import LLMConfig


class DeepSeekAPIError(RuntimeError):
    """Raised when the GLM-compatible API request fails."""


class DeepSeekClient:
    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    def chat_completion(
        self,
        *,
        messages: list[dict[str, str]],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": self.config.temperature if temperature is None else temperature,
            "max_tokens": self.config.max_tokens if max_tokens is None else max_tokens,
        }
        if response_format is not None:
            payload["response_format"] = response_format

        url = self.config.base_url.rstrip("/") + "/chat/completions"
        request = Request(
            url=url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise DeepSeekAPIError(f"GLM HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise DeepSeekAPIError(f"GLM network error: {exc}") from exc

    def chat_text(
        self,
        *,
        messages: list[dict[str, str]],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> str:
        response = self.chat_completion(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
        )
        try:
            message = response["choices"][0]["message"]
            content = message.get("content", "")
        except (KeyError, IndexError, TypeError) as exc:
            raise DeepSeekAPIError(f"Unexpected GLM response: {response}") from exc

        if not isinstance(content, str):
            raise DeepSeekAPIError(f"Unexpected content type from GLM: {type(content).__name__}")
        return content.strip()

    def chat_json(
        self,
        *,
        messages: list[dict[str, str]],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        content = self.chat_text(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        return self._parse_json(content)

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any]:
        text = content.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) >= 3:
                text = "\n".join(lines[1:-1]).strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DeepSeekAPIError(f"GLM JSON parse failed: {text}") from exc
        if not isinstance(parsed, dict):
            raise DeepSeekAPIError("GLM JSON response must be an object")
        return parsed
