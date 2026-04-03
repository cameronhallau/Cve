from __future__ import annotations

import json

import httpx

from cve_service.core.config import Settings
from cve_service.services.ai_provider import OpenRouterProvider, build_ai_review_provider
from cve_service.services.ai_review import AIProviderRequest


def test_build_ai_review_provider_uses_openrouter_settings() -> None:
    settings = Settings(
        ai_provider="openrouter",
        ai_model="deepseek/deepseek-v3.2",
        openrouter_api_key="test-key",
    )

    provider = build_ai_review_provider(settings)

    assert isinstance(provider, OpenRouterProvider)
    assert provider.model == "deepseek/deepseek-v3.2"


def test_openrouter_provider_reviews_through_chat_completion_boundary() -> None:
    captured_request: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_request["url"] = str(request.url)
        captured_request["authorization"] = request.headers["Authorization"]
        payload = json.loads(request.content.decode("utf-8"))
        captured_request["model"] = payload["model"]
        captured_request["messages"] = payload["messages"]
        captured_request["reasoning"] = payload["reasoning"]
        captured_request["response_format"] = payload["response_format"]
        return httpx.Response(
            200,
            json={
                "model": "deepseek/deepseek-v3.2",
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
        model="deepseek/deepseek-v3.2",
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
    assert captured_request["model"] == "deepseek/deepseek-v3.2"
    assert len(captured_request["messages"]) == 2
    assert captured_request["reasoning"] == {"enabled": False, "exclude": True}
    assert captured_request["response_format"]["type"] == "json_schema"
    assert json.loads(response.payload)["cve_id"] == "CVE-2026-0310"
    assert response.model_name == "deepseek/deepseek-v3.2"


def test_openrouter_provider_extracts_text_from_content_parts() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "minimax/minimax-m2.7",
                "choices": [
                    {
                        "message": {
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": '{"cve_id":"CVE-2026-0310","enterprise_relevance_assessment":"enterprise_relevant","exploit_path_assessment":"internet_exploitable","confidence":0.88,"reasoning_summary":"Enterprise edge exposure is plausible."}',
                                }
                            ]
                        }
                    }
                ],
            },
        )

    provider = OpenRouterProvider(
        api_key="test-key",
        model="minimax/minimax-m2.7",
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

    assert json.loads(response.payload)["cve_id"] == "CVE-2026-0310"
