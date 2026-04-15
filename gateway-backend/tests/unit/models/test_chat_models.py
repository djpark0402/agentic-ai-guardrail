"""Chat 모델 테스트."""

import pytest
from app.models.chat import ChatRequest, Message
from pydantic import ValidationError


def test_chat_request_valid():
    """유효한 딕셔너리로 ChatRequest가 생성된다."""
    req = ChatRequest(
        model="solar-pro",
        messages=[{"role": "user", "content": "안녕"}],
    )
    assert req.model == "solar-pro"
    assert len(req.messages) == 1


def test_chat_request_extra_fields_allowed():
    """extra 필드(temperature 등)가 허용된다."""
    req = ChatRequest(
        model="solar-pro",
        messages=[{"role": "user", "content": "test"}],
        temperature=0.7,
    )
    assert req.model == "solar-pro"


def test_chat_request_stream_defaults_false():
    """stream 필드를 생략하면 기본값이 False다."""
    req = ChatRequest(
        model="solar-pro",
        messages=[{"role": "user", "content": "test"}],
    )
    assert req.stream is False


def test_chat_request_stream_true():
    """stream=True로 설정할 수 있다."""
    req = ChatRequest(
        model="solar-pro",
        messages=[{"role": "user", "content": "test"}],
        stream=True,
    )
    assert req.stream is True


def test_message_role_required():
    """role 필드 누락 시 ValidationError가 발생한다."""
    with pytest.raises(ValidationError):
        Message(content="내용만 있고 role 없음")


def test_message_content_required():
    """content 필드 누락 시 ValidationError가 발생한다."""
    with pytest.raises(ValidationError):
        Message(role="user")
