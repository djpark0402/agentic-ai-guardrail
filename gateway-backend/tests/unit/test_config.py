"""Settings 설정 테스트."""

import pytest
from pydantic import ValidationError


def test_settings_loads_from_env(monkeypatch):
    """환경 변수가 주입되면 Settings 필드가 정상적으로 로딩된다."""
    monkeypatch.setenv("LLM_BASE_URL", "https://api.upstage.ai/v1")
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("ADMIN_BACKEND_URL", "http://localhost:8001")

    from app.config import Settings

    settings = Settings()
    assert settings.llm_base_url == "https://api.upstage.ai/v1"
    assert settings.llm_model == "solar-pro"
    assert settings.upstage_api_key.get_secret_value() == "test-key"
    assert settings.admin_backend_url == "http://localhost:8001"


def test_settings_missing_api_key_raises(monkeypatch):
    """UPSTAGE_API_KEY 없으면 ValidationError가 발생한다."""
    monkeypatch.delenv("UPSTAGE_API_KEY", raising=False)
    monkeypatch.setenv("LLM_MODEL", "solar-pro")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_get_settings_is_cached(monkeypatch):
    """get_settings()는 lru_cache로 동일 인스턴스를 반환한다."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")

    from app.config import get_settings

    get_settings.cache_clear()
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
    get_settings.cache_clear()
