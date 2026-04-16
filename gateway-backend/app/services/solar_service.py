"""Solar API 클라이언트 서비스 (LLMService 래퍼).

Upstage Solar 전용 설정을 주입하여 LLMService 를 초기화하는
하위 호환 래퍼 클래스.
"""

from app.config import Settings
from app.services.llm_service import LLMService


class SolarService(LLMService):
    """Upstage Solar API를 호출하는 서비스.

    LLMService 를 상속하여 Solar 전용 설정(API 키, 엔드포인트)을
    자동으로 주입한다.
    """

    def __init__(self, settings: Settings) -> None:
        """SolarService를 초기화한다.

        Args:
            settings: 애플리케이션 설정 인스턴스.
        """
        super().__init__(
            api_key=settings.upstage_api_key.get_secret_value(),
            base_url=settings.llm_base_url,
            model=settings.llm_model,
            provider_name="solar",
        )
