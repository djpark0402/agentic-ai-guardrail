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


def test_continue_on_layer_failure_defaults_to_false(monkeypatch):
    """CONTINUE_ON_LAYER_FAILURE 미설정 시 기본값은 False 여야 한다."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.delenv("CONTINUE_ON_LAYER_FAILURE", raising=False)

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.continue_on_layer_failure is False


def test_continue_on_layer_failure_reads_env(monkeypatch):
    """CONTINUE_ON_LAYER_FAILURE=true 이면 플래그가 켜진다 (dev 환경 필요)."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("CONTINUE_ON_LAYER_FAILURE", "true")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.continue_on_layer_failure is True


def test_admin_api_key_empty_string_is_none(monkeypatch):
    """빈 문자열 ADMIN_API_KEY 는 None 으로 정규화된다."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("ADMIN_API_KEY", "")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.admin_api_key is None


def test_admin_api_key_preserves_non_empty(monkeypatch):
    """비어있지 않은 ADMIN_API_KEY 는 SecretStr 로 보존된다."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("ADMIN_API_KEY", "iak_test_value")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.admin_api_key is not None
    assert settings.admin_api_key.get_secret_value() == "iak_test_value"


def test_request_timestamp_skew_sec_default(monkeypatch):
    """REQUEST_TIMESTAMP_SKEW_SEC 기본값은 300 (5분)."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.delenv("REQUEST_TIMESTAMP_SKEW_SEC", raising=False)

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.request_timestamp_skew_sec == 300


def test_skip_header_verification_defaults_false(monkeypatch):
    """SKIP_HEADER_VERIFICATION 미설정 시 기본 False."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.delenv("SKIP_HEADER_VERIFICATION", raising=False)

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.skip_header_verification is False


def test_skip_header_verification_reads_env(monkeypatch):
    """SKIP_HEADER_VERIFICATION=true 이면 플래그가 켜진다."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("SKIP_HEADER_VERIFICATION", "true")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.skip_header_verification is True


def test_app_env_defaults_to_prod(monkeypatch):
    """APP_ENV 미설정 시 기본값은 'prod' (safe-by-default)."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.delenv("APP_ENV", raising=False)

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.app_env == "prod"


def test_app_env_reads_dev(monkeypatch):
    """APP_ENV=dev 로 설정되면 값이 보존된다."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("APP_ENV", "dev")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.app_env == "dev"


def test_app_env_unknown_value_rejected(monkeypatch):
    """알 수 없는 APP_ENV 값은 ValidationError."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("APP_ENV", "staging")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_observe_mode_allowed_when_app_env_dev(monkeypatch):
    """APP_ENV=dev 이면 관찰 모드(CONTINUE_ON_LAYER_FAILURE=true) 정상 로드."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("CONTINUE_ON_LAYER_FAILURE", "true")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.app_env == "dev"
    assert settings.continue_on_layer_failure is True


def test_observe_mode_rejected_when_app_env_prod(monkeypatch):
    """APP_ENV=prod + CONTINUE_ON_LAYER_FAILURE=true 는 기동 실패해야 한다."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("CONTINUE_ON_LAYER_FAILURE", "true")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_observe_mode_rejected_when_app_env_missing(monkeypatch):
    """APP_ENV 미설정(기본 prod) + 관찰 모드 true 도 기동 실패."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("CONTINUE_ON_LAYER_FAILURE", "true")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_observe_mode_off_in_prod_ok(monkeypatch):
    """APP_ENV=prod + CONTINUE_ON_LAYER_FAILURE=false 는 정상 로드."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("CONTINUE_ON_LAYER_FAILURE", "false")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.app_env == "prod"
    assert settings.continue_on_layer_failure is False
