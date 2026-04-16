"""ProviderRouter 테스트."""

from unittest.mock import MagicMock

import pytest

from app.services.provider_router import ProviderRouter


def _make_settings(*, openai_key=None):
    """테스트용 더미 Settings."""
    settings = MagicMock()
    settings.upstage_api_key.get_secret_value.return_value = "solar-key"
    settings.llm_base_url = "https://api.upstage.ai/v1"
    settings.llm_model = "solar-pro"

    if openai_key:
        settings.openai_api_key.get_secret_value.return_value = openai_key
        settings.openai_base_url = "https://api.openai.com/v1"
        settings.openai_model = "gpt-4o"
    else:
        settings.openai_api_key = None
        settings.openai_base_url = "https://api.openai.com/v1"
        settings.openai_model = "gpt-4o"

    return settings


class TestDetectProvider:
    """모델명 → provider 감지 테스트."""

    def test_gpt_model_detected_as_openai(self):
        assert ProviderRouter.detect_provider("gpt-4o") == "openai"

    def test_gpt_35_detected_as_openai(self):
        assert ProviderRouter.detect_provider("gpt-3.5-turbo") == "openai"

    def test_o1_model_detected_as_openai(self):
        assert ProviderRouter.detect_provider("o1-preview") == "openai"

    def test_o3_model_detected_as_openai(self):
        assert ProviderRouter.detect_provider("o3-mini") == "openai"

    def test_ft_gpt_detected_as_openai(self):
        assert (
            ProviderRouter.detect_provider("ft:gpt-4o:org:custom") == "openai"
        )

    def test_chatgpt_detected_as_openai(self):
        assert ProviderRouter.detect_provider("chatgpt-4o-latest") == "openai"

    def test_solar_model_detected_as_solar(self):
        assert ProviderRouter.detect_provider("solar-pro") == "solar"

    def test_unknown_model_defaults_to_solar(self):
        assert ProviderRouter.detect_provider("some-custom-model") == "solar"

    def test_case_insensitive(self):
        assert ProviderRouter.detect_provider("GPT-4o") == "openai"


class TestGetService:
    """서비스 생성 및 캐싱 테스트."""

    def test_get_solar_service(self, mocker):
        mocker.patch("app.services.llm_service.ChatOpenAI")
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        svc = router.get_service("solar")
        assert svc.provider_name == "solar"

    def test_get_openai_service(self, mocker):
        mocker.patch("app.services.llm_service.ChatOpenAI")
        settings = _make_settings(openai_key="sk-test")
        router = ProviderRouter(settings=settings)
        svc = router.get_service("openai")
        assert svc.provider_name == "openai"

    def test_get_openai_without_key_raises(self):
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            router.get_service("openai")

    def test_unknown_provider_raises(self, mocker):
        mocker.patch("app.services.llm_service.ChatOpenAI")
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        with pytest.raises(ValueError, match="지원하지 않는 provider"):
            router.get_service("anthropic")

    def test_service_is_cached(self, mocker):
        mocker.patch("app.services.llm_service.ChatOpenAI")
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        svc1 = router.get_service("solar")
        svc2 = router.get_service("solar")
        assert svc1 is svc2


class TestResolve:
    """resolve() 통합 테스트."""

    def test_resolve_gpt_model(self, mocker):
        mocker.patch("app.services.llm_service.ChatOpenAI")
        settings = _make_settings(openai_key="sk-test")
        router = ProviderRouter(settings=settings)
        svc = router.resolve("gpt-4o")
        assert svc.provider_name == "openai"

    def test_resolve_solar_model(self, mocker):
        mocker.patch("app.services.llm_service.ChatOpenAI")
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        svc = router.resolve("solar-pro")
        assert svc.provider_name == "solar"


class TestAvailableProviders:
    """available_providers() 테스트."""

    def test_only_solar_when_no_openai_key(self):
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        providers = router.available_providers()
        assert len(providers) == 1
        assert providers[0]["provider"] == "solar"

    def test_both_when_openai_configured(self):
        settings = _make_settings(openai_key="sk-test")
        router = ProviderRouter(settings=settings)
        providers = router.available_providers()
        assert len(providers) == 2
        names = {p["provider"] for p in providers}
        assert names == {"solar", "openai"}
