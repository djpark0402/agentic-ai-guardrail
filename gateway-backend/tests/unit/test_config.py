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


# ---------------------------------------------------------------------------
# SKIP_POLICY_FETCH 보조 환경변수 — 입력/출력 레이어 선택
# ---------------------------------------------------------------------------


def _base_env(monkeypatch, *, app_env: str = "dev") -> None:
    """SKIP_POLICY_FETCH_* 테스트용 최소 env 세팅."""
    monkeypatch.setenv("LLM_MODEL", "solar-pro")
    monkeypatch.setenv("UPSTAGE_API_KEY", "test-key")
    monkeypatch.setenv("APP_ENV", app_env)


def test_skip_policy_fetch_layers_default_is_all_six(monkeypatch):
    """미설정 시 입력/출력 모두 L1~L6 전체."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.delenv("SKIP_POLICY_FETCH_INPUT_LAYERS", raising=False)
    monkeypatch.delenv("SKIP_POLICY_FETCH_OUTPUT_LAYERS", raising=False)

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.input_layer_indices == frozenset({1, 2, 3, 4, 5, 6})
    assert settings.output_layer_indices == frozenset({1, 2, 3, 4, 5, 6})


def test_skip_policy_fetch_input_layers_csv_parsed(monkeypatch):
    """CSV 토큰을 정규화해 frozenset[int] 로 노출한다."""
    _base_env(monkeypatch, app_env="dev")
    monkeypatch.setenv("SKIP_POLICY_FETCH_INPUT_LAYERS", "L1, l3 ,L6")
    monkeypatch.setenv("SKIP_POLICY_FETCH_OUTPUT_LAYERS", "L1,L2,L3,L4,L5,L6")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.input_layer_indices == frozenset({1, 3, 6})
    assert settings.output_layer_indices == frozenset({1, 2, 3, 4, 5, 6})


def test_skip_policy_fetch_output_layers_empty_string_disables_all(
    monkeypatch,
):
    """빈 문자열은 출력 레이어를 빈 셋으로 둔다 (outbound 비활성 의도)."""
    _base_env(monkeypatch, app_env="dev")
    monkeypatch.setenv("SKIP_POLICY_FETCH_INPUT_LAYERS", "L1,L2,L3,L4,L5,L6")
    monkeypatch.setenv("SKIP_POLICY_FETCH_OUTPUT_LAYERS", "")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.output_layer_indices == frozenset()


def test_skip_policy_fetch_invalid_token_rejected(monkeypatch):
    """L7 같은 범위 외 토큰은 기동 실패."""
    _base_env(monkeypatch, app_env="dev")
    monkeypatch.setenv("SKIP_POLICY_FETCH_INPUT_LAYERS", "L1,L7")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_skip_policy_fetch_unknown_token_rejected(monkeypatch):
    """`foo` 같은 비정형 토큰도 기동 실패."""
    _base_env(monkeypatch, app_env="dev")
    monkeypatch.setenv("SKIP_POLICY_FETCH_INPUT_LAYERS", "L1,foo")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_skip_policy_fetch_custom_layers_allowed_in_dev(monkeypatch):
    """APP_ENV=dev 면 비기본 레이어 셋 허용."""
    _base_env(monkeypatch, app_env="dev")
    monkeypatch.setenv("SKIP_POLICY_FETCH_INPUT_LAYERS", "L4")
    monkeypatch.setenv("SKIP_POLICY_FETCH_OUTPUT_LAYERS", "")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.input_layer_indices == frozenset({4})
    assert settings.output_layer_indices == frozenset()


def test_skip_policy_fetch_custom_layers_rejected_in_prod(monkeypatch):
    """APP_ENV=prod 에서 비기본 레이어 셋은 기동 실패."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.setenv("SKIP_POLICY_FETCH_INPUT_LAYERS", "L4")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_skip_policy_fetch_custom_output_layers_rejected_in_prod(
    monkeypatch,
):
    """APP_ENV=prod 에서 출력 레이어 비기본값도 기동 실패."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.setenv("SKIP_POLICY_FETCH_OUTPUT_LAYERS", "")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_skip_policy_fetch_default_layers_allowed_in_prod(monkeypatch):
    """APP_ENV=prod 라도 명시 기본값(L1~L6)은 기동 가능."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.setenv("SKIP_POLICY_FETCH_INPUT_LAYERS", "L1,L2,L3,L4,L5,L6")
    monkeypatch.setenv("SKIP_POLICY_FETCH_OUTPUT_LAYERS", "L1,L2,L3,L4,L5,L6")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.input_layer_indices == frozenset({1, 2, 3, 4, 5, 6})
    assert settings.output_layer_indices == frozenset({1, 2, 3, 4, 5, 6})


def test_skip_policy_fetch_l5_setting_default_is_none(monkeypatch):
    """L5 보조 환경변수 미설정 시 기본 L5 설정을 사용한다."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.delenv("SKIP_POLICY_FETCH_L5_MODEL", raising=False)
    monkeypatch.delenv("SKIP_POLICY_FETCH_L5_THRESHOLD", raising=False)

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.skip_policy_fetch_l5_setting is None


def test_skip_policy_fetch_l5_setting_parsed_in_dev(monkeypatch):
    """APP_ENV=dev 에서는 환경변수로 L5 model/threshold 를 지정할 수 있다."""
    _base_env(monkeypatch, app_env="dev")
    monkeypatch.setenv("SKIP_POLICY_FETCH_L5_MODEL", "pii_model_v11")
    monkeypatch.setenv("SKIP_POLICY_FETCH_L5_THRESHOLD", "0.82")

    from app.config import Settings

    settings = Settings(_env_file=None)
    l5_setting = settings.skip_policy_fetch_l5_setting
    assert l5_setting is not None
    assert l5_setting.model == "pii_model_v11"
    assert l5_setting.threshold == 0.82


def test_skip_policy_fetch_l5_threshold_empty_string_is_none(monkeypatch):
    """빈 threshold 는 None 으로 정규화된다."""
    _base_env(monkeypatch, app_env="dev")
    monkeypatch.setenv("SKIP_POLICY_FETCH_L5_MODEL", "pii_model_v11")
    monkeypatch.setenv("SKIP_POLICY_FETCH_L5_THRESHOLD", "")

    from app.config import Settings

    settings = Settings(_env_file=None)
    l5_setting = settings.skip_policy_fetch_l5_setting
    assert l5_setting is not None
    assert l5_setting.model == "pii_model_v11"
    assert l5_setting.threshold is None


@pytest.mark.parametrize("threshold", ["-0.01", "1.01"])
def test_skip_policy_fetch_l5_threshold_out_of_range_rejected(
    monkeypatch,
    threshold: str,
):
    """L5 threshold 보조 환경변수도 0.0~1.0 범위만 허용한다."""
    _base_env(monkeypatch, app_env="dev")
    monkeypatch.setenv("SKIP_POLICY_FETCH_L5_THRESHOLD", threshold)

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_skip_policy_fetch_l5_model_rejected_in_prod(monkeypatch):
    """APP_ENV=prod 에서 L5 model 비기본값은 기동 실패."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.setenv("SKIP_POLICY_FETCH_L5_MODEL", "pii_model_v11")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_skip_policy_fetch_l5_threshold_rejected_in_prod(monkeypatch):
    """APP_ENV=prod 에서 L5 threshold 비기본값은 기동 실패."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.setenv("SKIP_POLICY_FETCH_L5_THRESHOLD", "0.82")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


# ---------------------------------------------------------------------------
# LLM 레이어 대체 옵션
# ---------------------------------------------------------------------------


def test_llm_layer_replacement_defaults_to_empty(monkeypatch):
    """미설정 시 LLM 대체 레이어는 없다."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.delenv("LLM_LAYER_REPLACEMENT_LAYERS", raising=False)

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.llm_layer_replacement_indices == frozenset()


def test_llm_layer_replacement_layers_csv_parsed(monkeypatch):
    """LLM 대체 레이어 CSV 토큰을 frozenset[int] 로 노출한다."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.setenv("LLM_LAYER_REPLACEMENT_LAYERS", "L1, l4 ,L6")
    monkeypatch.setenv("LLM_LAYER_BASE_URL", "http://localhost:4000/v1")
    monkeypatch.setenv("LLM_LAYER_API_KEY", "test-layer-key")
    monkeypatch.setenv("LLM_LAYER_MODEL", "guard-model")

    from app.config import Settings

    settings = Settings(_env_file=None)
    assert settings.llm_layer_replacement_indices == frozenset({1, 4, 6})
    assert settings.llm_layer_api_key is not None
    assert settings.llm_layer_api_key.get_secret_value() == "test-layer-key"


def test_llm_layer_replacement_invalid_token_rejected(monkeypatch):
    """L1~L6 밖의 LLM 대체 토큰은 기동 실패."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.setenv("LLM_LAYER_REPLACEMENT_LAYERS", "L1,L7")
    monkeypatch.setenv("LLM_LAYER_BASE_URL", "http://localhost:4000/v1")
    monkeypatch.setenv("LLM_LAYER_API_KEY", "test-layer-key")
    monkeypatch.setenv("LLM_LAYER_MODEL", "guard-model")

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_llm_layer_replacement_requires_endpoint_settings(monkeypatch):
    """대체 레이어가 있으면 LLM endpoint/model/key 설정이 필수다."""
    _base_env(monkeypatch, app_env="prod")
    monkeypatch.setenv("LLM_LAYER_REPLACEMENT_LAYERS", "L4")
    monkeypatch.delenv("LLM_LAYER_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_LAYER_API_KEY", raising=False)
    monkeypatch.delenv("LLM_LAYER_MODEL", raising=False)

    from app.config import Settings

    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None)
    assert "LLM_LAYER_BASE_URL" in str(exc.value)
    assert "LLM_LAYER_API_KEY" in str(exc.value)
    assert "LLM_LAYER_MODEL" in str(exc.value)
