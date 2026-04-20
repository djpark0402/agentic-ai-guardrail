"""애플리케이션 설정 모듈."""

from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    # 데모용 관찰 모드 — True 면 레이어가 BLOCK 판정을 내려도 파이프라인을
    # 끝까지 진행하고, 응답에 `guardrail_reports` 블록으로 각 레이어 판정을
    # 첨부한다. False (기본) 면 기존 동작 유지(첫 BLOCK 시 즉시 차단 응답).
    continue_on_layer_failure: bool = False

    @field_validator("admin_api_key", mode="before")
    @classmethod
    def _empty_admin_api_key_is_none(cls, value: object) -> object:
        """빈 문자열 `ADMIN_API_KEY` 는 None 으로 정규화한다."""
        if isinstance(value, str) and value.strip() == "":
            return None
        return value


@lru_cache
def get_settings() -> Settings:
    """캐시된 Settings 인스턴스를 반환한다.

    Returns:
        싱글턴 Settings 인스턴스.
    """
    return Settings()
