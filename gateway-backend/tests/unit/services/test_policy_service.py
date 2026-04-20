"""PolicyService 테스트."""

import json
import logging

import httpx
import pytest

from app.models.policy import GuardrailPolicy
from app.services.policy_service import PolicyService
from app.services.request_verifier import VerifiedHeaders

_ADMIN_URL = "http://admin-backend.test"
_VERIFY_URL = f"{_ADMIN_URL}/api/v1/gateway/verify"

_SAMPLE_RESPONSE = {
    "isUse": True,
    "createdAt": "2026-04-15T06:37:51.766295Z",
    "l1Enabled": True,
    "name": "테스트 정책 1",
    "l4Enabled": True,
    "description": "테스트 정책 입니다.",
    "l3Enabled": True,
    "id": 10,
    "l2Enabled": True,
    "l5Enabled": True,
    "l6Enabled": True,
    "updatedAt": "2026-04-15T07:43:48.397550Z",
}

_SAMPLE_HEADERS = VerifiedHeaders(
    api_key="uak_user",
    timestamp="1700000000",
    nonce="nonce-abc",
    signature="a" * 64,
)
_SAMPLE_BODY_HASH = "deadbeef" * 8


def _make_service(
    handler, *, admin_api_key: str | None = None
) -> PolicyService:
    """핸들러를 탑재한 MockTransport 기반 PolicyService 를 생성한다."""
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    return PolicyService(
        admin_backend_url=_ADMIN_URL,
        http_client=client,
        admin_api_key=admin_api_key,
    )


async def test_verify_and_fetch_policy_posts_to_verify_endpoint():
    """verify_and_fetch_policy 는 POST /api/v1/gateway/verify 로 호출한다."""
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        return httpx.Response(200, json=_SAMPLE_RESPONSE)

    service = _make_service(handler)
    await service.verify_and_fetch_policy(
        session_id="s",
        headers=_SAMPLE_HEADERS,
        body_hash=_SAMPLE_BODY_HASH,
    )
    assert captured["method"] == "POST"
    assert captured["url"] == _VERIFY_URL


async def test_verify_and_fetch_policy_sends_full_body():
    """요청 body 에 apiKey/timestamp/nonce/bodyHash/signature 필드가 실린다."""
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json=_SAMPLE_RESPONSE)

    service = _make_service(handler)
    await service.verify_and_fetch_policy(
        session_id="s",
        headers=_SAMPLE_HEADERS,
        body_hash=_SAMPLE_BODY_HASH,
    )
    assert captured["body"] == {
        "apiKey": "uak_user",
        "timestamp": "1700000000",
        "nonce": "nonce-abc",
        "bodyHash": _SAMPLE_BODY_HASH,
        "signature": "a" * 64,
    }


async def test_verify_and_fetch_policy_attaches_admin_api_key_header():
    """admin_api_key 가 있으면 X-API-Key 헤더로 전송된다."""
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["x_api_key"] = request.headers.get("x-api-key")
        return httpx.Response(200, json=_SAMPLE_RESPONSE)

    service = _make_service(handler, admin_api_key="iak_gateway_key")
    await service.verify_and_fetch_policy(
        session_id="s",
        headers=_SAMPLE_HEADERS,
        body_hash=_SAMPLE_BODY_HASH,
    )
    assert captured["x_api_key"] == "iak_gateway_key"


async def test_verify_and_fetch_policy_omits_header_when_api_key_none():
    """admin_api_key 가 None 이면 X-API-Key 헤더를 싣지 않는다."""
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["x_api_key"] = request.headers.get("x-api-key")
        return httpx.Response(200, json=_SAMPLE_RESPONSE)

    service = _make_service(handler, admin_api_key=None)
    await service.verify_and_fetch_policy(
        session_id="s",
        headers=_SAMPLE_HEADERS,
        body_hash=_SAMPLE_BODY_HASH,
    )
    assert captured["x_api_key"] is None


async def test_verify_and_fetch_policy_returns_guardrail_policy():
    """ADMIN 응답에서 GuardrailPolicy 를 파싱한다."""
    service = _make_service(
        lambda _req: httpx.Response(200, json=_SAMPLE_RESPONSE)
    )
    policy = await service.verify_and_fetch_policy(
        session_id="s",
        headers=_SAMPLE_HEADERS,
        body_hash=_SAMPLE_BODY_HASH,
    )
    assert isinstance(policy, GuardrailPolicy)
    assert policy.enabled_layers() == [1, 2, 3, 4, 5, 6]


async def test_verify_and_fetch_policy_respects_disabled_flags():
    """l3Enabled=false 등 비활성 플래그가 반영된다."""
    payload = {**_SAMPLE_RESPONSE, "l3Enabled": False, "l5Enabled": False}
    service = _make_service(lambda _req: httpx.Response(200, json=payload))
    policy = await service.verify_and_fetch_policy(
        session_id="s",
        headers=_SAMPLE_HEADERS,
        body_hash=_SAMPLE_BODY_HASH,
    )
    assert policy.l3 is False
    assert policy.l5 is False
    assert policy.enabled_layers() == [1, 2, 4, 6]


async def test_verify_and_fetch_policy_raises_on_http_error():
    """ADMIN 이 5xx 를 반환하면 예외가 전파된다."""
    service = _make_service(lambda _req: httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        await service.verify_and_fetch_policy(
            session_id="s",
            headers=_SAMPLE_HEADERS,
            body_hash=_SAMPLE_BODY_HASH,
        )


async def test_verify_and_fetch_policy_logs_session_id(caplog):
    """세션 ID 가 로그에 기록된다."""
    service = _make_service(
        lambda _req: httpx.Response(200, json=_SAMPLE_RESPONSE)
    )
    with caplog.at_level(logging.INFO):
        await service.verify_and_fetch_policy(
            session_id="my-session-123",
            headers=_SAMPLE_HEADERS,
            body_hash=_SAMPLE_BODY_HASH,
        )
    assert "my-session-123" in caplog.text
