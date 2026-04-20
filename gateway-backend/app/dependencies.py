"""FastAPI Depends() 팩토리 함수 모음."""

from functools import lru_cache
from typing import Annotated

import httpx
from fastapi import Depends

from app.config import Settings, get_settings
from app.services.policy_service import PolicyService
from app.services.provider_router import ProviderRouter
from app.services.request_verifier import NonceStore
from app.services.security_layer_service import SecurityLayerService
from app.services.solar_service import SolarService

# ProviderRouter 는 요청마다 생성하지 않고 싱글턴으로 캐싱한다.
_provider_router: ProviderRouter | None = None

# NonceStore 싱글턴 — 프로세스 전체에서 공유되어야 재연 방지가 유효하다.
_nonce_store: NonceStore | None = None


@lru_cache
def get_http_client() -> httpx.AsyncClient:
    """앱 수명주기 동안 재사용되는 httpx AsyncClient 를 반환한다.

    Returns:
        싱글턴 httpx.AsyncClient 인스턴스.
    """
    return httpx.AsyncClient()


def get_nonce_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> NonceStore:
    """프로세스 전역에서 공유되는 NonceStore 싱글턴을 반환한다.

    TTL 은 `request_timestamp_skew_sec * 2` 로 두어 timestamp 검증을
    통과한 nonce 가 만료 전에 재연되지 못하도록 한다.

    Args:
        settings: 주입된 애플리케이션 설정.

    Returns:
        공유 NonceStore 인스턴스.
    """
    global _nonce_store
    if _nonce_store is None:
        _nonce_store = NonceStore(
            ttl_sec=settings.request_timestamp_skew_sec * 2
        )
    return _nonce_store


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
    admin_api_key = (
        settings.admin_api_key.get_secret_value()
        if settings.admin_api_key is not None
        else None
    )
    return PolicyService(
        admin_backend_url=settings.admin_backend_url,
        http_client=http_client,
        admin_api_key=admin_api_key,
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
