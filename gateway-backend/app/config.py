"""애플리케이션 설정 모듈."""

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnv = Literal["dev", "prod"]


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


@lru_cache
def get_settings() -> Settings:
    """캐시된 Settings 인스턴스를 반환한다.

    Returns:
        싱글턴 Settings 인스턴스.
    """
    return Settings()
