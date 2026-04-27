"""애플리케이션 설정 모듈."""

import re
from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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
                "SKIP_POLICY_FETCH_*_LAYERS 토큰은 'L1'~'L6' 만 허용됩니다. "
                f"잘못된 토큰: {token!r}"
            )
        indices.add(int(match.group(1)))
    return frozenset(indices)


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
        playground_default_api_key: `/playground/` 페이지의 `X-API-Key`
            입력 칸에 자동 채워질 데모용 키. `app_env="dev"` 에서만
            응답에 노출되며, `prod` 에서는 값이 있어도 빈 문자열로
            대체된다 (시크릿이 브라우저로 새지 않게 차단).
        playground_default_hmac_secret: `/playground/` 페이지의
            `HMAC SECRET` 입력 칸에 자동 채워질 데모용 서명 시크릿.
            동일하게 `app_env="dev"` 에서만 노출. SecretStr 로 보관해
            로그·repr 에 노출되지 않게 한다.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
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

    # SKIP_POLICY_FETCH=true 일 때만 의미가 있는 보조 토글.
    # CSV 형식 `L1,L4` 처럼 활성 레이어를 지정한다. 기본값은 `L1~L6` 전체로
    # 기존 동작과 동일. 빈 문자열은 해당 방향 가드레일을 빈 셋으로 두며,
    # 출력 측이 빈 셋이면 outbound 파이프라인 전체가 생략된다.
    # APP_ENV='dev' 가 아닌데 비기본값을 지정하면 model_validator 가
    # 기동을 거부한다 (테스트용 환경변수가 prod 로 새지 않게 차단).
    skip_policy_fetch_input_layers: str = "L1,L2,L3,L4,L5,L6"
    skip_policy_fetch_output_layers: str = "L1,L2,L3,L4,L5,L6"

    # Playground (/playground/) 기본 입력값 — APP_ENV=dev 에서만 노출.
    # prod 환경에서 값이 설정되어 있어도 /v1/playground/defaults 응답은
    # 빈 문자열로 대체되어 시크릿이 브라우저로 새지 않는다.
    playground_default_api_key: str = ""
    playground_default_hmac_secret: SecretStr = SecretStr("")

    @field_validator("admin_api_key", mode="before")
    @classmethod
    def _empty_admin_api_key_is_none(cls, value: object) -> object:
        """빈 문자열 `ADMIN_API_KEY` 는 None 으로 정규화한다."""
        if isinstance(value, str) and value.strip() == "":
            return None
        return value

    @field_validator(
        "skip_policy_fetch_input_layers",
        "skip_policy_fetch_output_layers",
        mode="after",
    )
    @classmethod
    def _validate_layer_csv(cls, value: str) -> str:
        """CSV 토큰 형식만 검증하고 원문 문자열을 그대로 보존한다."""
        _parse_layer_csv(value)
        return value

    @property
    def input_layer_indices(self) -> frozenset[int]:
        """`SKIP_POLICY_FETCH=true` 시 입력 가드레일에서 실행할 레이어 셋."""
        return _parse_layer_csv(self.skip_policy_fetch_input_layers)

    @property
    def output_layer_indices(self) -> frozenset[int]:
        """`SKIP_POLICY_FETCH=true` 시 출력 가드레일에서 실행할 레이어 셋.

        빈 셋이면 출력 파이프라인 전체가 생략된다 (outbound=False 동등).
        """
        return _parse_layer_csv(self.skip_policy_fetch_output_layers)

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
        if (
            self.input_layer_indices != _DEFAULT_LAYER_INDICES
            or self.output_layer_indices != _DEFAULT_LAYER_INDICES
        ):
            raise ValueError(
                "SKIP_POLICY_FETCH_INPUT_LAYERS / "
                "SKIP_POLICY_FETCH_OUTPUT_LAYERS 의 비기본값은 "
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
