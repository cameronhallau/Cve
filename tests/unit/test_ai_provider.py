from __future__ import annotations

import json

import httpx

from cve_service.core.config import Settings
from cve_service.services.ai_provider import OpenRouterProvider, build_ai_review_provider
from cve_service.services.ai_review import AIProviderRequest


def test_build_ai_review_provider_uses_openrouter_settings() -> None:
    settings = Settings(
        ai_provider="openrouter",
        ai_model="openai/gpt-5.2",
        openrouter_api_key="test-key",
    )

    provider = build_ai_review_provider(settings)

    assert isinstance(provider, OpenRouterProvider)
    assert provider.model == "openai/gpt-5.2"


def test_openrouter_provider_reviews_through_chat_completion_boundary() -> None:
    captured_request: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_request["url"] = str(request.url)
        captured_request["authorization"] = request.headers["Authorization"]
        payload = json.loads(request.content.decode("utf-8"))
        captured_request["model"] = payload["model"]
        captured_request["messages"] = payload["messages"]
        return httpx.Response(
            200,
            json={
                "model": "openai/gpt-5.2",
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "cve_id": "CVE-2026-0310",
                                    "enterprise_relevance_assessment": "enterprise_relevant",
                                    "exploit_path_assessment": "internet_exploitable",
                                    "confidence": 0.88,
                                    "reasoning_summary": "Enterprise edge exposure is plausible.",
                                }
                            )
                        }
                    }
                ],
            },
        )

    provider = OpenRouterProvider(
        api_key="test-key",
        model="openai/gpt-5.2",
        base_url="https://openrouter.ai/api/v1",
        timeout_seconds=30.0,
        max_completion_tokens=400,
        temperature=0.0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    response = provider.review(
        AIProviderRequest(
            request_payload={"cve_id": "CVE-2026-0310", "task": {"review_focus": "Assess enterprise relevance."}},
            request_schema={"type": "object"},
            response_schema={"type": "object"},
            prompt_version="phase3-ai-review.v1",
        )
    )

    assert captured_request["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert captured_request["authorization"] == "Bearer test-key"
    assert captured_request["model"] == "openai/gpt-5.2"
    assert len(captured_request["messages"]) == 2
    assert json.loads(response.payload)["cve_id"] == "CVE-2026-0310"
    assert response.model_name == "openai/gpt-5.2"
