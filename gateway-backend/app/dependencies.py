"""FastAPI Depends() 팩토리 함수 모음."""

from typing import Annotated

from fastapi import Depends

from app.config import Settings, get_settings
from app.services.policy_service import PolicyService
from app.services.security_layer_service import SecurityLayerService
from app.services.solar_service import SolarService


def get_policy_service() -> PolicyService:
    """PolicyService 인스턴스를 반환한다.

    Returns:
        PolicyService 인스턴스.
    """
    return PolicyService()


def get_security_service() -> SecurityLayerService:
    """SecurityLayerService 인스턴스를 반환한다.

    Returns:
        SecurityLayerService 인스턴스.
    """
    return SecurityLayerService()


def get_solar_service(
    settings: Annotated[Settings, Depends(get_settings)],
) -> SolarService:
    """SolarService 인스턴스를 반환한다.

    Args:
        settings: 주입된 애플리케이션 설정.

    Returns:
        SolarService 인스턴스.
    """
    return SolarService(settings=settings)
