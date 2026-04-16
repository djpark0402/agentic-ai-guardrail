"""FastAPI Depends() 팩토리 함수 모음."""

from functools import lru_cache
from typing import Annotated

import httpx
from fastapi import Depends

from app.config import Settings, get_settings
from app.services.policy_service import PolicyService
from app.services.provider_router import ProviderRouter
from app.services.security_layer_service import SecurityLayerService
from app.services.solar_service import SolarService

# ProviderRouter 는 요청마다 생성하지 않고 싱글턴으로 캐싱한다.
_provider_router: ProviderRouter | None = None


@lru_cache
def get_http_client() -> httpx.AsyncClient:
    """앱 수명주기 동안 재사용되는 httpx AsyncClient 를 반환한다.

    Returns:
        싱글턴 httpx.AsyncClient 인스턴스.
    """
    return httpx.AsyncClient()


def get_policy_service(
    settings: Annotated[Settings, Depends(get_settings)],
    http_client: Annotated[httpx.AsyncClient, Depends(get_http_client)],
) -> PolicyService:
    """admin-backend 와 연계된 PolicyService 인스턴스를 반환한다.

    Args:
        settings: 주입된 애플리케이션 설정.
        http_client: 주입된 httpx AsyncClient.

    Returns:
        PolicyService 인스턴스.
    """
    return PolicyService(
        admin_backend_url=settings.admin_backend_url,
        http_client=http_client,
    )


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


def get_provider_router(
    settings: Annotated[Settings, Depends(get_settings)],
) -> ProviderRouter:
    """ProviderRouter 싱글턴 인스턴스를 반환한다.

    Args:
        settings: 주입된 애플리케이션 설정.

    Returns:
        ProviderRouter 인스턴스.
    """
    global _provider_router
    if _provider_router is None:
        _provider_router = ProviderRouter(settings=settings)
    return _provider_router
