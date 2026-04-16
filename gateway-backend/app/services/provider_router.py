"""모델명 기반 LLM provider 라우터.

요청의 model 필드를 분석하여 적절한 LLMService 인스턴스로 라우팅한다.
provider 별 서비스 인스턴스는 최초 요청 시 생성되어 캐싱된다.
"""

from typing import Any

from app.config import Settings
from app.services.llm_service import LLMService

# OpenAI 모델명 접두사 패턴.
_OPENAI_PREFIXES: tuple[str, ...] = (
    "gpt-",
    "o1-",
    "o3-",
    "ft:gpt-",
    "chatgpt-",
)

# 명시적 provider 접두사 (예: "ollama/llama3").
# 자동 감지가 어려운 provider 는 "provider/model" 형식으로 라우팅한다.
_EXPLICIT_PROVIDERS: frozenset[str] = frozenset({"ollama"})


class ProviderRouter:
    """모델명으로 LLM provider를 감지하고 서비스를 반환한다.

    Attributes:
        _settings: 애플리케이션 설정.
        _services: provider 별 캐싱된 LLMService 인스턴스.
    """

    def __init__(self, settings: Settings) -> None:
        """ProviderRouter를 초기화한다.

        Args:
            settings: 애플리케이션 설정 인스턴스.
        """
        self._settings = settings
        self._services: dict[str, LLMService] = {}

    @staticmethod
    def parse_model(model: str) -> tuple[str, str]:
        """모델명에서 provider와 실제 모델명을 분리한다.

        "ollama/llama3" → ("ollama", "llama3")
        "gpt-4o" → ("openai", "gpt-4o")  (자동 감지)
        "solar-pro" → ("solar", "solar-pro")  (기본값)

        Args:
            model: 요청의 모델명.

        Returns:
            (provider, 실제 모델명) 튜플.
        """
        # 명시적 접두사 확인 (예: "ollama/llama3").
        if "/" in model:
            prefix, _, model_name = model.partition("/")
            if prefix.lower() in _EXPLICIT_PROVIDERS:
                return prefix.lower(), model_name

        # OpenAI 패턴 자동 감지.
        model_lower = model.lower()
        for pattern in _OPENAI_PREFIXES:
            if model_lower.startswith(pattern):
                return "openai", model

        # 기본값: Solar.
        return "solar", model

    def get_service(self, provider: str) -> LLMService:
        """provider에 해당하는 LLMService를 반환한다.

        최초 호출 시 인스턴스를 생성하고, 이후에는 캐싱된 인스턴스를
        반환한다.

        Args:
            provider: provider 식별자.

        Returns:
            LLMService 인스턴스.

        Raises:
            ValueError: 알 수 없는 provider이거나 API 키 미설정 시.
        """
        if provider in self._services:
            return self._services[provider]

        service = self._create_service(provider)
        self._services[provider] = service
        return service

    def _create_service(self, provider: str) -> LLMService:
        """Provider 설정으로 LLMService를 생성한다.

        Args:
            provider: provider 식별자.

        Returns:
            새 LLMService 인스턴스.

        Raises:
            ValueError: 알 수 없는 provider이거나 API 키 미설정 시.
        """
        s = self._settings

        if provider == "solar":
            return LLMService(
                api_key=s.upstage_api_key.get_secret_value(),
                base_url=s.llm_base_url,
                model=s.llm_model,
                provider_name="solar",
            )

        if provider == "openai":
            if s.openai_api_key is None:
                msg = "OPENAI_API_KEY 환경변수가 설정되지 않았습니다"
                raise ValueError(msg)
            return LLMService(
                api_key=s.openai_api_key.get_secret_value(),
                base_url=s.openai_base_url,
                model=s.openai_model,
                provider_name="openai",
            )

        if provider == "ollama":
            return LLMService(
                api_key="ollama",
                base_url=s.ollama_base_url,
                model="llama3",
                provider_name="ollama",
            )

        msg = f"지원하지 않는 provider: {provider}"
        raise ValueError(msg)

    def resolve(self, model: str) -> LLMService:
        """모델명을 분석하여 적절한 LLMService를 반환한다.

        Args:
            model: 요청의 모델명.

        Returns:
            라우팅된 LLMService 인스턴스.

        Raises:
            ValueError: provider가 미설정이거나 알 수 없을 때.
        """
        provider, _model_name = self.parse_model(model)
        return self.get_service(provider)

    def available_providers(self) -> list[dict[str, Any]]:
        """설정된 provider 목록을 반환한다.

        Returns:
            사용 가능한 provider 정보 목록.
        """
        s = self._settings
        providers: list[dict[str, Any]] = [
            {
                "provider": "solar",
                "default_model": s.llm_model,
            }
        ]
        if s.openai_api_key is not None:
            providers.append(
                {
                    "provider": "openai",
                    "default_model": s.openai_model,
                }
            )
        providers.append(
            {
                "provider": "ollama",
                "default_model": "llama3",
                "note": "ollama/모델명 형식으로 요청",
            }
        )
        return providers
