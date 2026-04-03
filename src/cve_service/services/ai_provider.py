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
    reasoning_enabled: bool = False
    http_referer: str | None = None
    title: str | None = None
    client: httpx.Client | None = None

    def review(self, request: AIProviderRequest) -> AIProviderResponse:
        payload = {
            "model": self.model,
            "messages": _build_messages(request),
            "temperature": self.temperature,
            "max_completion_tokens": self.max_completion_tokens,
            # Ask OpenRouter to keep reasoning out of the assistant message and
            # enforce a JSON response shape when the model supports it.
            "reasoning": {"enabled": self.reasoning_enabled, "exclude": True},
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "ai_review_response",
                    "strict": True,
                    "schema": request.response_schema,
                },
            },
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

        extracted_content = _extract_message_content(content)
        return AIProviderResponse(
            model_name=str(body.get("model") or self.model),
            payload=extracted_content,
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
            reasoning_enabled=False,
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
    if isinstance(content, dict):
        extracted = _extract_dict_content(content)
        if extracted:
            return extracted
    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            extracted = _extract_message_content_part(item)
            if extracted:
                text_parts.append(extracted)
        if text_parts:
            return "".join(text_parts)
    raise ValueError("OpenRouter response content was empty or unsupported")


def _extract_message_content_part(item: Any) -> str | None:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return _extract_dict_content(item)
    return None


def _extract_dict_content(item: dict[str, Any]) -> str | None:
    if isinstance(item.get("text"), str):
        return item["text"]
    if isinstance(item.get("content"), str):
        return item["content"]
    if isinstance(item.get("output_text"), str):
        return item["output_text"]

    nested_content = item.get("content")
    if isinstance(nested_content, list):
        nested_text = "".join(
            extracted
            for part in nested_content
            if (extracted := _extract_message_content_part(part))
        )
        if nested_text:
            return nested_text

    nested_text = item.get("text")
    if isinstance(nested_text, list):
        joined = "".join(
            extracted
            for part in nested_text
            if (extracted := _extract_message_content_part(part))
        )
        if joined:
            return joined

    return None
