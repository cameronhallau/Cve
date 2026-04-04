from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from cve_service.core.config import Settings

PROMPT_VERSION = "phase8-description-compression.v1"
DESCRIPTION_COMPRESSION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "compressed_description": {
            "type": "string",
            "minLength": 1,
            "maxLength": 280,
        }
    },
    "required": ["compressed_description"],
}


@dataclass(frozen=True, slots=True)
class DescriptionCompressionRequest:
    cve_id: str
    title: str | None
    description: str | None
    severity: str | None
    canonical_name: str | None
    canonical_vendor_name: str | None
    canonical_product_name: str | None


@dataclass(frozen=True, slots=True)
class DescriptionCompressionResult:
    compressed_description: str
    source: str
    model_name: str | None = None
    prompt_version: str | None = None


class DescriptionCompressor(Protocol):
    def compress(self, request: DescriptionCompressionRequest) -> DescriptionCompressionResult:
        """Return a concise description tailored for a public feed post."""


@dataclass
class OpenRouterDescriptionCompressor:
    api_key: str
    model: str
    base_url: str
    timeout_seconds: float
    max_completion_tokens: int
    temperature: float
    http_referer: str | None = None
    title: str | None = None
    client: httpx.Client | None = None

    def compress(self, request: DescriptionCompressionRequest) -> DescriptionCompressionResult:
        payload = {
            "model": self.model,
            "messages": _build_messages(request),
            "temperature": self.temperature,
            "max_completion_tokens": self.max_completion_tokens,
            "reasoning": {"enabled": False, "exclude": True},
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "description_compression_response",
                    "strict": True,
                    "schema": DESCRIPTION_COMPRESSION_SCHEMA,
                },
            },
        }
        response = self._client.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers=self._headers,
            json=payload,
        )
        response.raise_for_status()
        body = response.json()
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("OpenRouter description compression response was missing content") from exc

        raw_text = _extract_message_content(content)
        parsed = json.loads(raw_text)
        compressed_description = str(parsed["compressed_description"]).strip()
        if not compressed_description:
            raise ValueError("OpenRouter description compression returned an empty description")

        return DescriptionCompressionResult(
            compressed_description=compressed_description,
            source="llm",
            model_name=str(body.get("model") or self.model),
            prompt_version=PROMPT_VERSION,
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


def build_description_compressor(
    settings: Settings,
    *,
    model_name: str | None = None,
    client: httpx.Client | None = None,
) -> DescriptionCompressor | None:
    if settings.ai_provider.strip().lower() != "openrouter":
        return None
    if not settings.openrouter_api_key:
        return None
    return OpenRouterDescriptionCompressor(
        api_key=settings.openrouter_api_key,
        model=model_name or settings.ai_model,
        base_url=settings.openrouter_base_url,
        timeout_seconds=settings.ai_timeout_seconds,
        max_completion_tokens=min(settings.ai_max_completion_tokens, 160),
        temperature=settings.ai_temperature,
        http_referer=settings.openrouter_http_referer,
        title=settings.openrouter_title,
        client=client,
    )


def fallback_description_brief(
    description: str | None,
    *,
    canonical_product_name: str | None,
    limit: int = 180,
) -> str:
    normalized = " ".join((description or "").split())
    if not normalized:
        return "No description provided."

    product_name = (canonical_product_name or "").strip()
    if product_name:
        for prefix in (
            f"A flaw was found in {product_name}. ",
            f"A vulnerability was found in {product_name}. ",
        ):
            if normalized.startswith(prefix):
                normalized = f"In {product_name}, {_lowercase_first_alpha(normalized[len(prefix):])}"
                break

    replacements = (
        ("unauthenticated attacker", "unauth attacker"),
        ("authenticated attacker", "auth'd attacker"),
        ("denial of service", "DoS"),
        ("Denial of Service", "DoS"),
        ("remote code execution", "RCE"),
        ("Remote code execution", "RCE"),
    )
    for source, target in replacements:
        normalized = normalized.replace(source, target)

    if len(normalized) <= limit:
        return normalized.rstrip(".") if normalized.endswith("..") else normalized

    truncated = normalized[:limit].rsplit(" ", 1)[0].rstrip(" ,;:")
    if not truncated:
        truncated = normalized[:limit].rstrip()
    if not truncated.endswith((".", "!", "?")):
        truncated += "..."
    return truncated


def _build_messages(request: DescriptionCompressionRequest) -> list[dict[str, str]]:
    system_prompt = (
        "You compress CVE descriptions for a public security feed. "
        "Return only JSON that matches the provided schema. "
        "Write one sentence in the format 'In <Product>, <how>, resulting in <impact>' when possible. "
        "Be succinct, prefer common abbreviations like unauth, auth'd, RCE, DoS, OIDC when accurate, "
        "and keep only product, attack method, and impact."
    )
    user_prompt = json.dumps(
        {
            "request": {
                "cve_id": request.cve_id,
                "title": request.title,
                "description": request.description,
                "severity": request.severity,
                "canonical_name": request.canonical_name,
                "canonical_vendor_name": request.canonical_vendor_name,
                "canonical_product_name": request.canonical_product_name,
            },
            "requirements": {
                "max_length_hint": 180,
                "must_include": ["product", "how", "impact"],
                "must_exclude": ["severity labels", "PoC/ITW status", "reason codes", "remediation"],
            },
            "response_schema": DESCRIPTION_COMPRESSION_SCHEMA,
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
    raise ValueError("OpenRouter description compression response content was empty or unsupported")


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


def _lowercase_first_alpha(text: str) -> str:
    for index, character in enumerate(text):
        if character.isalpha():
            return text[:index] + character.lower() + text[index + 1 :]
    return text
