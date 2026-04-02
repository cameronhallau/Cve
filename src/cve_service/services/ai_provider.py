from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from cve_service.core.config import Settings
from cve_service.services.ai_review import AIProviderRequest, AIProviderResponse


@dataclass
class InlinePayloadProvider:
    payload: dict[str, Any] | str
    model_name: str = "inline-worker-provider"

    def review(self, request: AIProviderRequest) -> AIProviderResponse:  # pragma: no cover - exercised in integration tests
        return AIProviderResponse(model_name=self.model_name, payload=self.payload)


@dataclass
class OpenRouterProvider:
    api_key: str
    model: str
    base_url: str
    timeout_seconds: float
    max_completion_tokens: int
    temperature: float
    http_referer: str | None = None
    title: str | None = None
    client: httpx.Client | None = None

    def review(self, request: AIProviderRequest) -> AIProviderResponse:
        payload = {
            "model": self.model,
            "messages": _build_messages(request),
            "temperature": self.temperature,
            "max_completion_tokens": self.max_completion_tokens,
        }
        response_data = self._client.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers=self._headers,
            json=payload,
        )
        response_data.raise_for_status()
        body = response_data.json()
        try:
            choice = body["choices"][0]["message"]
            content = choice["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("OpenRouter response did not contain a chat completion message") from exc

        return AIProviderResponse(
            model_name=str(body.get("model") or self.model),
            payload=_extract_message_content(content),
            prompt_version=request.prompt_version,
        )

    @property
    def _client(self) -> httpx.Client:
        if self.client is not None:
            return self.client
        return httpx.Client(timeout=self.timeout_seconds)

    @property
    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.http_referer:
            headers["HTTP-Referer"] = self.http_referer
        if self.title:
            headers["X-Title"] = self.title
        return headers


def build_ai_review_provider(
    settings: Settings,
    *,
    ai_payload: dict[str, Any] | str | None = None,
    ai_model_name: str | None = None,
    client: httpx.Client | None = None,
):
    if ai_payload is not None:
        return InlinePayloadProvider(ai_payload, model_name=ai_model_name or "inline-worker-provider")

    provider_name = settings.ai_provider.strip().lower()
    if provider_name == "openrouter":
        if not settings.openrouter_api_key:
            raise ValueError("CVE AI provider is openrouter but OPENROUTER_API_KEY is not configured")
        return OpenRouterProvider(
            api_key=settings.openrouter_api_key,
            model=ai_model_name or settings.ai_model,
            base_url=settings.openrouter_base_url,
            timeout_seconds=settings.ai_timeout_seconds,
            max_completion_tokens=settings.ai_max_completion_tokens,
            temperature=settings.ai_temperature,
            http_referer=settings.openrouter_http_referer,
            title=settings.openrouter_title,
            client=client,
        )

    raise ValueError(f"unsupported AI provider: {settings.ai_provider}")


def _build_messages(request: AIProviderRequest) -> list[dict[str, str]]:
    system_prompt = (
        "You are reviewing ambiguous CVEs for enterprise relevance. "
        "Rules-first, AI-second. AI is advisory only. "
        "Hard deterministic denies remain absolute. "
        "Return only JSON that matches the provided response schema."
    )
    user_prompt = json.dumps(
        {
            "request_payload": request.request_payload,
            "response_schema": request.response_schema,
            "constraints": [
                "Use only the requested output fields.",
                "Treat PoC and ITW as separate signals.",
                "Prefer uncertainty over invention.",
            ],
        },
        sort_keys=True,
    )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def _extract_message_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    text_parts.append(item["text"])
                    continue
                if item.get("type") == "text" and isinstance(item.get("content"), str):
                    text_parts.append(item["content"])
                    continue
            if isinstance(item, str):
                text_parts.append(item)
        if text_parts:
            return "".join(text_parts)
    raise ValueError("OpenRouter response content was empty or unsupported")
