"""애플리케이션 설정 모듈."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Literal

from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.models.policy import L5Setting

AppEnv = Literal["dev", "prod"]

_LAYER_TOKEN_RE = re.compile(r"^[Ll]([1-6])$")
_DEFAULT_LAYER_INDICES: frozenset[int] = frozenset({1, 2, 3, 4, 5, 6})


def _parse_layer_csv(value: str) -> frozenset[int]:
    """`L1, l3 ,L6` 형태의 CSV 토큰을 정규화한 frozenset[int] 로 변환한다.

    Args:
        value: 환경변수 원문. 빈 문자열이거나 공백뿐이면 빈 셋 반환.

    Returns:
        활성 레이어 인덱스 frozenset (예: {1, 3, 6}).

    Raises:
        ValueError: `L1`~`L6` 외 토큰이 포함된 경우.
    """
    if not value or not value.strip():
        return frozenset()
    indices: set[int] = set()
    for raw in value.split(","):
        token = raw.strip()
        if not token:
            continue
        match = _LAYER_TOKEN_RE.match(token)
        if not match:
            raise ValueError(
                "SKIP_POLICY_FETCH_CONFIG__*_LAYERS 토큰은 'L1'~'L6' 만 "
                f"허용됩니다. 잘못된 토큰: {token!r}"
            )
        indices.add(int(match.group(1)))
    return frozenset(indices)


class SkipPolicyFetchSettings(BaseModel):
    """SKIP_POLICY_FETCH=true 일 때 적용할 dev 전용 레이어 오버라이드.

    환경변수는 `SKIP_POLICY_FETCH_CONFIG__INPUT_LAYERS` 처럼 nested
    delimiter `__` 를 사용한다.

    Attributes:
        input_layers: 입력 가드레일에서 실행할 레이어 CSV. 예: 'L1,L4'.
            빈 문자열이면 입력 측 가드레일이 비어 모든 입력이 통과한다.
        output_layers: 출력 가드레일에서 실행할 레이어 CSV. 빈 문자열이면
            outbound 파이프라인 전체가 생략된다.
        l5_model: ADMIN 의 `l5Setting.model` 과 같은 역할. 빈 문자열이면
            기본 L5 모델 설정을 사용한다.
        l5_threshold: ADMIN 의 `l5Setting.threshold` 와 같은 역할. 빈 값이면
            기본 L5 threshold. 값은 0.0~1.0 범위만 허용.
    """

    input_layers: str = "L1,L2,L3,L4,L5,L6"
    output_layers: str = "L1,L2,L3,L4,L5,L6"
    l5_model: str = ""
    l5_threshold: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("l5_threshold", mode="before")
    @classmethod
    def _empty_l5_threshold_is_none(cls, value: object) -> object:
        """빈 L5 threshold 문자열은 None 으로 정규화한다."""
        if isinstance(value, str) and value.strip() == "":
            return None
        return value

    @field_validator("input_layers", "output_layers", mode="after")
    @classmethod
    def _validate_layer_csv(cls, value: str) -> str:
        """CSV 토큰 형식만 검증하고 원문 문자열을 그대로 보존한다."""
        _parse_layer_csv(value)
        return value

    @property
    def input_layer_indices(self) -> frozenset[int]:
        """입력 가드레일에서 실행할 레이어 셋."""
        return _parse_layer_csv(self.input_layers)

    @property
    def output_layer_indices(self) -> frozenset[int]:
        """출력 가드레일에서 실행할 레이어 셋. 빈 셋이면 outbound 생략."""
        return _parse_layer_csv(self.output_layers)

    @property
    def l5_setting(self) -> L5Setting | None:
        """정책 조회 생략 시 환경변수로 주입할 L5 설정."""
        model_name = self.l5_model.strip() or None
        threshold = self.l5_threshold
        if model_name is None and threshold is None:
            return None
        return L5Setting(model=model_name, threshold=threshold)


class LlmLayerSettings(BaseModel):
    """정책 기반 `useLlm=true` 경로의 LLM 엔드포인트 설정.

    환경변수는 `LLM_LAYER__BASE_URL` 처럼 nested delimiter `__` 를 사용한다.
    BASE_URL+API_KEY 는 짝으로 설정돼야 하며, 한쪽만 설정된 채로 기동되면
    `_endpoint_pair_required` 가 기동을 거부한다.

    Attributes:
        base_url: OpenAI 호환 LLM 엔드포인트 URL.
        api_key: OpenAI 호환 LLM 인증 키. 빈 문자열은 None 으로 정규화.
        timeout_seconds: LLM 호출 타임아웃(초). 0보다 큰 값만 허용.
    """

    base_url: str = ""
    api_key: SecretStr | None = None
    timeout_seconds: float = Field(default=15.0, gt=0.0)

    @field_validator("api_key", mode="before")
    @classmethod
    def _empty_api_key_is_none(cls, value: object) -> object:
        """빈 문자열 API_KEY 는 None 으로 정규화한다."""
        if isinstance(value, str) and value.strip() == "":
            return None
        return value

    @model_validator(mode="after")
    def _endpoint_pair_required(self) -> LlmLayerSettings:
        """BASE_URL/API_KEY 가 짝으로 설정돼야 한다."""
        url_set = bool(self.base_url.strip())
        key_set = self.api_key is not None
        if url_set and not key_set:
            raise ValueError(
                "LLM_LAYER__BASE_URL 가 설정되면 LLM_LAYER__API_KEY 도 "
                "필요합니다."
            )
        if key_set and not url_set:
            raise ValueError(
                "LLM_LAYER__API_KEY 가 설정되면 LLM_LAYER__BASE_URL 도 "
                "필요합니다."
            )
        return self

    @property
    def has_endpoint(self) -> bool:
        """OpenAI 호환 LLM 엔드포인트(URL+API key)가 모두 설정됐는지."""
        return bool(self.base_url.strip() and self.api_key is not None)


class PlaygroundSettings(BaseModel):
    """Playground 페이지 dev 자동 채움 시크릿.

    환경변수는 `PLAYGROUND__DEFAULT_API_KEY` 처럼 nested delimiter
    `__` 를 사용한다. `app_env="dev"` 일 때만 `/v1/playground/defaults`
    응답에 노출되고, 그 외 환경에서는 빈 문자열로 대체된다.

    Attributes:
        default_api_key: `/playground/` 페이지의 `X-API-Key` 입력 칸에
            자동 채워질 데모용 키.
        default_hmac_secret: `/playground/` 페이지의 `HMAC SECRET` 입력
            칸에 자동 채워질 데모용 서명 시크릿.
    """

    default_api_key: str = ""
    default_hmac_secret: SecretStr = SecretStr("")


class Settings(BaseSettings):
    """환경 변수 기반 애플리케이션 설정.

    Attributes:
        llm_base_url: Upstage AI API 베이스 URL.
        llm_model: 사용할 LLM 모델 이름.
        upstage_api_key: Upstage API 인증 키.
        admin_backend_url: 정책 조회를 위한 admin-backend URL.
        admin_api_key: admin-backend `/api/v1/gateway/verify` 호출 시
            `X-API-Key` 헤더에 실리는 게이트웨이 키. 빈 값은 None 으로 정규화.
        request_timestamp_skew_sec: `X-Timestamp` 헤더와 서버 시각의 허용
            오차(초). 기본 5분(300).
        skip_header_verification: True 면 사용자 4개 헤더 검증을 건너뛴다.
            `skip_policy_fetch` 와 독립 동작하는 로컬/데모용 플래그.
        app_env: 실행 환경. `"dev"` 또는 `"prod"` 만 허용. 기본값
            `"prod"` (safe-by-default). 관찰 모드는 `"dev"` 에서만 허용.
        continue_on_layer_failure: 데모/개발용 관찰 모드 플래그. True 면
            레이어가 BLOCK 을 내려도 파이프라인을 끝까지 실행하고 응답에
            `guardrail_reports` 를 첨부한다. `app_env="dev"` 일 때만
            True 허용 — 그 외 환경에서 True 는 ValidationError.
        skip_policy_fetch_config: SKIP_POLICY_FETCH=true 일 때만 의미를
            가지는 dev 전용 레이어 오버라이드 그룹.
        llm_layer: 정책 기반 `useLlm=true` 경로의 LLM 엔드포인트 그룹.
        playground: Playground 페이지 dev 자동 채움 시크릿 그룹.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Solar (Upstage)
    llm_base_url: str = "https://api.upstage.ai/v1"
    llm_model: str
    upstage_api_key: SecretStr

    # OpenAI (optional — 미설정 시 OpenAI 모델 요청은 에러)
    openai_api_key: SecretStr | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o"

    # Ollama (optional — 로컬 LLM, API 키 불필요)
    ollama_base_url: str = "http://localhost:11434/v1"

    # 공통
    admin_backend_url: str = "http://localhost:8001"
    admin_api_key: SecretStr | None = None
    request_timestamp_skew_sec: int = 300
    skip_header_verification: bool = False
    skip_policy_fetch: bool = False
    # 실행 환경. 기본 "prod" 는 safe-by-default — 명시하지 않으면 관찰
    # 모드 등 개발 전용 기능이 활성화되지 않도록 잠근다.
    app_env: AppEnv = "prod"
    # 데모용 관찰 모드 — True 면 레이어가 BLOCK 판정을 내려도 파이프라인을
    # 끝까지 진행하고, 응답에 `guardrail_reports` 블록으로 각 레이어 판정을
    # 첨부한다. False (기본) 면 기존 동작 유지(첫 BLOCK 시 즉시 차단 응답).
    # `app_env="dev"` 일 때만 True 허용 (model_validator 로 강제).
    continue_on_layer_failure: bool = False

    # 그룹별 nested settings — 환경변수는 `SKIP_POLICY_FETCH_CONFIG__*`,
    # `LLM_LAYER__*`, `PLAYGROUND__*` 처럼 nested delimiter `__` 사용.
    skip_policy_fetch_config: SkipPolicyFetchSettings = Field(
        default_factory=SkipPolicyFetchSettings
    )
    llm_layer: LlmLayerSettings = Field(default_factory=LlmLayerSettings)
    playground: PlaygroundSettings = Field(default_factory=PlaygroundSettings)

    @field_validator("admin_api_key", mode="before")
    @classmethod
    def _empty_admin_api_key_is_none(cls, value: object) -> object:
        """빈 문자열 `ADMIN_API_KEY` 는 None 으로 정규화한다."""
        if isinstance(value, str) and value.strip() == "":
            return None
        return value

    @property
    def input_layer_indices(self) -> frozenset[int]:
        """`SKIP_POLICY_FETCH=true` 시 입력 가드레일에서 실행할 레이어 셋."""
        return self.skip_policy_fetch_config.input_layer_indices

    @property
    def output_layer_indices(self) -> frozenset[int]:
        """`SKIP_POLICY_FETCH=true` 시 출력 가드레일에서 실행할 레이어 셋.

        빈 셋이면 출력 파이프라인 전체가 생략된다 (outbound=False 동등).
        """
        return self.skip_policy_fetch_config.output_layer_indices

    @property
    def has_llm_layer_endpoint(self) -> bool:
        """OpenAI 호환 LLM 엔드포인트 (URL + API key) 가 모두 설정됐는지.

        정책 기반 `useLlm=True` 경로를 활성화하기 위해 DI 팩토리가 참조한다.
        """
        return self.llm_layer.has_endpoint

    @property
    def skip_policy_fetch_l5_setting(self) -> L5Setting | None:
        """정책 조회 생략 시 환경변수로 주입할 L5 설정."""
        return self.skip_policy_fetch_config.l5_setting

    @model_validator(mode="after")
    def _observe_mode_requires_dev(self) -> Settings:
        """관찰 모드는 `app_env="dev"` 에서만 허용.

        프로덕션/스테이징에서 `CONTINUE_ON_LAYER_FAILURE=true` 가 실수로
        설정되어도 BLOCK 판정이 무시되는 사고를 막기 위한 기동 시 가드.
        """
        if self.continue_on_layer_failure and self.app_env != "dev":
            raise ValueError(
                "CONTINUE_ON_LAYER_FAILURE=true 는 APP_ENV='dev' 에서만 "
                f"허용됩니다. 현재 APP_ENV={self.app_env!r}."
            )
        return self

    @model_validator(mode="after")
    def _skip_policy_fetch_layers_require_dev(self) -> Settings:
        """SKIP_POLICY_FETCH 보조 변수의 비기본값은 dev 에서만 허용.

        SKIP_POLICY_FETCH 자체가 dev 전용 토글이지만, 보조 변수가 prod
        환경 파일에 잔존해 운영 트래픽에 영향을 주는 사고를 방지하기 위해
        SKIP_POLICY_FETCH 값과 무관하게 기동 시 가드한다.
        """
        if self.app_env == "dev":
            return self
        cfg = self.skip_policy_fetch_config
        if (
            cfg.input_layer_indices != _DEFAULT_LAYER_INDICES
            or cfg.output_layer_indices != _DEFAULT_LAYER_INDICES
            or cfg.l5_setting is not None
        ):
            raise ValueError(
                "SKIP_POLICY_FETCH_CONFIG__INPUT_LAYERS / "
                "SKIP_POLICY_FETCH_CONFIG__OUTPUT_LAYERS / "
                "SKIP_POLICY_FETCH_CONFIG__L5_MODEL / "
                "SKIP_POLICY_FETCH_CONFIG__L5_THRESHOLD 의 비기본값은 "
                "APP_ENV='dev' 에서만 허용됩니다. "
                f"현재 APP_ENV={self.app_env!r}."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    """캐시된 Settings 인스턴스를 반환한다.

    Returns:
        싱글턴 Settings 인스턴스.
    """
    return Settings()
