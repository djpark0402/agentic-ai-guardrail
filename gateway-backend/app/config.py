"""애플리케이션 설정 모듈."""

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """환경 변수 기반 애플리케이션 설정.

    Attributes:
        llm_base_url: Upstage AI API 베이스 URL.
        llm_model: 사용할 LLM 모델 이름.
        upstage_api_key: Upstage API 인증 키.
        admin_backend_url: 정책 조회를 위한 admin-backend URL.
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
    skip_policy_fetch: bool = False
    # 데모용 관찰 모드 — True 면 레이어가 BLOCK 판정을 내려도 파이프라인을
    # 끝까지 진행하고, 응답에 `guardrail_reports` 블록으로 각 레이어 판정을
    # 첨부한다. False (기본) 면 기존 동작 유지(첫 BLOCK 시 즉시 차단 응답).
    continue_on_layer_failure: bool = False


@lru_cache
def get_settings() -> Settings:
    """캐시된 Settings 인스턴스를 반환한다.

    Returns:
        싱글턴 Settings 인스턴스.
    """
    return Settings()
