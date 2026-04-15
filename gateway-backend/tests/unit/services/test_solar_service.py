"""SolarService 테스트 (openai 클라이언트 mock)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.solar_service import SolarService


@pytest.fixture
def mock_settings():
    """테스트용 더미 Settings."""
    settings = MagicMock()
    settings.upstage_api_key.get_secret_value.return_value = "test-key"
    settings.llm_base_url = "https://api.upstage.ai/v1"
    settings.llm_model = "solar-pro"
    return settings


@pytest.fixture
def service(mock_settings, mocker):
    """AsyncOpenAI 클라이언트가 mock된 SolarService."""
    mock_client = MagicMock()
    mocker.patch(
        "app.services.solar_service.AsyncOpenAI",
        return_value=mock_client,
    )
    return SolarService(settings=mock_settings), mock_client


async def test_chat_calls_completions_create(service):
    """chat()이 올바른 파라미터로 completions.create를 호출한다."""
    svc, mock_client = service

    mock_response = MagicMock()
    mock_response.choices[0].message.content = "안녕하세요!"
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    messages = [{"role": "user", "content": "안녕"}]
    await svc.chat(messages=messages)

    mock_client.chat.completions.create.assert_called_once_with(
        model="solar-pro",
        messages=messages,
        stream=False,
    )


async def test_chat_returns_content_string(service):
    """chat()이 응답 내용 문자열을 반환한다."""
    svc, mock_client = service

    mock_response = MagicMock()
    mock_response.choices[0].message.content = "응답 텍스트"
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    result = await svc.chat(messages=[{"role": "user", "content": "질문"}])
    assert result == "응답 텍스트"


async def test_stream_chat_yields_chunks(service):
    """stream_chat()이 delta 콘텐츠 청크를 yield한다."""
    svc, mock_client = service

    async def fake_stream():
        for text in ["안녕", "하세요", "!"]:
            chunk = MagicMock()
            chunk.choices[0].delta.content = text
            yield chunk

    mock_client.chat.completions.create = AsyncMock(return_value=fake_stream())

    chunks = []
    async for chunk in svc.stream_chat(
        messages=[{"role": "user", "content": "hi"}]
    ):
        chunks.append(chunk)

    assert chunks == ["안녕", "하세요", "!"]


async def test_stream_chat_skips_none_delta(service):
    """stream_chat()은 delta.content가 None인 청크를 yield하지 않는다."""
    svc, mock_client = service

    async def fake_stream():
        for text in [None, "텍스트", None]:
            chunk = MagicMock()
            chunk.choices[0].delta.content = text
            yield chunk

    mock_client.chat.completions.create = AsyncMock(return_value=fake_stream())

    chunks = []
    async for chunk in svc.stream_chat(
        messages=[{"role": "user", "content": "hi"}]
    ):
        chunks.append(chunk)

    assert chunks == ["텍스트"]
