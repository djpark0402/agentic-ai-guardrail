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
    settings.ollama_base_url = "http://localhost:11434/v1"

    if openai_key:
        settings.openai_api_key.get_secret_value.return_value = openai_key
        settings.openai_base_url = "https://api.openai.com/v1"
        settings.openai_model = "gpt-4o"
    else:
        settings.openai_api_key = None
        settings.openai_base_url = "https://api.openai.com/v1"
        settings.openai_model = "gpt-4o"

    return settings


class TestParseModel:
    """모델명 파싱 테스트."""

    def test_gpt_model_detected_as_openai(self):
        assert ProviderRouter.parse_model("gpt-4o") == (
            "openai",
            "gpt-4o",
        )

    def test_gpt_35_detected_as_openai(self):
        p, m = ProviderRouter.parse_model("gpt-3.5-turbo")
        assert p == "openai"
        assert m == "gpt-3.5-turbo"

    def test_o1_model_detected_as_openai(self):
        p, _ = ProviderRouter.parse_model("o1-preview")
        assert p == "openai"

    def test_o3_model_detected_as_openai(self):
        p, _ = ProviderRouter.parse_model("o3-mini")
        assert p == "openai"

    def test_ft_gpt_detected_as_openai(self):
        p, m = ProviderRouter.parse_model("ft:gpt-4o:org:custom")
        assert p == "openai"
        assert m == "ft:gpt-4o:org:custom"

    def test_chatgpt_detected_as_openai(self):
        p, _ = ProviderRouter.parse_model("chatgpt-4o-latest")
        assert p == "openai"

    def test_solar_model_detected_as_solar(self):
        assert ProviderRouter.parse_model("solar-pro") == (
            "solar",
            "solar-pro",
        )

    def test_unknown_model_defaults_to_solar(self):
        p, _ = ProviderRouter.parse_model("some-custom-model")
        assert p == "solar"

    def test_case_insensitive(self):
        p, _ = ProviderRouter.parse_model("GPT-4o")
        assert p == "openai"

    def test_ollama_prefix_detected(self):
        p, m = ProviderRouter.parse_model("ollama/llama3")
        assert p == "ollama"
        assert m == "llama3"

    def test_ollama_prefix_case_insensitive(self):
        p, m = ProviderRouter.parse_model("Ollama/mistral")
        assert p == "ollama"
        assert m == "mistral"

    def test_non_explicit_prefix_not_split(self):
        """알 수 없는 접두사는 분리하지 않고 Solar로 라우팅."""
        p, m = ProviderRouter.parse_model("unknown/model")
        assert p == "solar"
        assert m == "unknown/model"


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

    def test_get_ollama_service(self, mocker):
        mocker.patch("app.services.llm_service.ChatOpenAI")
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        svc = router.get_service("ollama")
        assert svc.provider_name == "ollama"

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
        svc, model = router.resolve("gpt-4o")
        assert svc.provider_name == "openai"
        assert model == "gpt-4o"

    def test_resolve_solar_model(self, mocker):
        mocker.patch("app.services.llm_service.ChatOpenAI")
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        svc, model = router.resolve("solar-pro")
        assert svc.provider_name == "solar"
        assert model == "solar-pro"

    def test_resolve_ollama_strips_prefix(self, mocker):
        mocker.patch("app.services.llm_service.ChatOpenAI")
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        svc, model = router.resolve("ollama/llama3")
        assert svc.provider_name == "ollama"
        assert model == "llama3"


class TestAvailableProviders:
    """available_providers() 테스트."""

    def test_solar_and_ollama_always_present(self):
        settings = _make_settings()
        router = ProviderRouter(settings=settings)
        providers = router.available_providers()
        names = {p["provider"] for p in providers}
        assert "solar" in names
        assert "ollama" in names

    def test_openai_included_when_configured(self):
        settings = _make_settings(openai_key="sk-test")
        router = ProviderRouter(settings=settings)
        providers = router.available_providers()
        names = {p["provider"] for p in providers}
        assert names == {"solar", "openai", "ollama"}
