"""PolicyService 테스트."""

import logging

import httpx
import pytest

from app.models.policy import GuardrailPolicy
from app.services.policy_service import PolicyService

_ADMIN_URL = "http://admin-backend.test"
_POLICY_URL = f"{_ADMIN_URL}/api/v1/policies/active"

_SAMPLE_RESPONSE = {
    "isUse": True,
    "createdAt": "2026-04-15T06:37:51.766295Z",
    "l0Enabled": True,
    "name": "테스트 정책 1",
    "l3Enabled": True,
    "description": "테스트 정책 입니다.",
    "l2Enabled": True,
    "id": 10,
    "l1Enabled": True,
    "l4Enabled": True,
    "l5Enabled": True,
    "updatedAt": "2026-04-15T07:43:48.397550Z",
}


def _make_service(handler) -> PolicyService:
    """핸들러를 탑재한 MockTransport 기반 PolicyService 를 생성한다."""
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    return PolicyService(admin_backend_url=_ADMIN_URL, http_client=client)


async def test_fetch_policy_returns_guardrail_policy():
    """fetch_policy()가 GuardrailPolicy 인스턴스를 반환한다."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == _POLICY_URL
        return httpx.Response(200, json=_SAMPLE_RESPONSE)

    service = _make_service(handler)
    result = await service.fetch_policy(session_id="test-session")
    assert isinstance(result, GuardrailPolicy)


async def test_fetch_policy_all_layers_enabled():
    """모든 l*Enabled=true 응답은 6개 레이어를 전부 활성으로 파싱한다."""
    service = _make_service(
        lambda _req: httpx.Response(200, json=_SAMPLE_RESPONSE)
    )
    policy = await service.fetch_policy(session_id="test-session")
    assert policy.l0 is True
    assert policy.l1 is True
    assert policy.l2 is True
    assert policy.l3 is True
    assert policy.l4 is True
    assert policy.l5 is True
    assert policy.enabled_layers() == [0, 1, 2, 3, 4, 5]


async def test_fetch_policy_respects_disabled_flags():
    """l2Enabled=false 는 policy.l2=False 로 반영된다."""
    payload = {**_SAMPLE_RESPONSE, "l2Enabled": False, "l4Enabled": False}
    service = _make_service(lambda _req: httpx.Response(200, json=payload))
    policy = await service.fetch_policy(session_id="s")
    assert policy.l2 is False
    assert policy.l4 is False
    assert policy.enabled_layers() == [0, 1, 3, 5]


async def test_fetch_policy_raises_on_http_error():
    """admin-backend 가 5xx 를 반환하면 예외가 전파된다."""
    service = _make_service(lambda _req: httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        await service.fetch_policy(session_id="s")


async def test_fetch_policy_logs_session_id(caplog):
    """fetch_policy()가 session_id 를 로그에 기록한다."""
    service = _make_service(
        lambda _req: httpx.Response(200, json=_SAMPLE_RESPONSE)
    )
    with caplog.at_level(logging.INFO):
        await service.fetch_policy(session_id="my-session-123")
    assert "my-session-123" in caplog.text
