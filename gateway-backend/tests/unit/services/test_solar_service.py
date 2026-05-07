"""SolarService 래퍼 테스트 — LLMService 위임 확인."""

from unittest.mock import MagicMock

from app.services.llm_service import LLMService
from app.services.solar_service import SolarService


def test_solar_service_is_llm_service_subclass():
    """SolarService 가 LLMService 를 상속한다."""
    assert issubclass(SolarService, LLMService)


def test_solar_service_sets_provider_name():
    """SolarService 의 provider_name 이 'solar' 이다."""
    settings = MagicMock()
    settings.upstage_api_key.get_secret_value.return_value = "test-key"
    settings.llm_base_url = "https://api.upstage.ai/v1"
    settings.llm_model = "solar-pro"

    svc = SolarService(settings=settings)
    assert svc.provider_name == "solar"


def test_solar_service_does_not_expose_stream_chat():
    """SolarService는 stream_chat을 노출하지 않는다."""
    settings = MagicMock()
    settings.upstage_api_key.get_secret_value.return_value = "test-key"
    settings.llm_base_url = "https://api.upstage.ai/v1"
    settings.llm_model = "solar-pro"

    svc = SolarService(settings=settings)
    assert not hasattr(svc, "stream_chat")
