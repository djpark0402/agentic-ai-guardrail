"""레이어 진단 라우터.

``GET /v1/layers/status`` — 각 가드레일 레이어(L1~L6)의 모델 로드
상태를 JSON 으로 반환한다. docker 컨테이너 안에서 모델이 정상 로드
되었는지 외부에서 바로 확인할 수 있게 한다.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.layer_diagnostics import collect_layer_statuses

router = APIRouter()


class LayerStatusItem(BaseModel):
    """단일 레이어 로드 상태 응답 모델."""

    index: int = Field(
        ...,
        description="정책 레이어 인덱스 (1~6).",
        examples=[1],
    )
    name: str = Field(..., description="레이어 이름. 예: L1.", examples=["L1"])
    class_name: str = Field(
        ...,
        description="core-secure-layer 클래스 이름.",
        examples=["L1Layer"],
    )
    model_loaded: bool = Field(
        ...,
        description=(
            "모델이 정상 로드되었는지 여부. L1 은 규칙 기반이라 항상 True."
        ),
    )
    model_paths: list[str] = Field(
        default_factory=list,
        description="모델이 있을 것으로 예상되는 디렉터리 경로(진단용).",
    )
    detail: str | None = Field(
        default=None,
        description="loaded=False 일 때 이유 요약. 성공 시 null.",
    )


class LayersStatusResponse(BaseModel):
    """``/v1/layers/status`` 응답 모델."""

    all_loaded: bool = Field(
        ...,
        description=(
            "모든 레이어가 정상 로드되었을 때만 True. 하나라도"
            " loaded=False 면 False."
        ),
    )
    layers: list[LayerStatusItem] = Field(
        ...,
        description="정책 인덱스 오름차순 레이어 상태 배열.",
    )


@router.get(
    "/layers/status",
    tags=["meta"],
    summary="가드레일 레이어 모델 로드 상태 조회",
    response_model=LayersStatusResponse,
)
async def layers_status() -> LayersStatusResponse:
    """각 레이어의 모델 로드 상태를 진단해 반환한다.

    fail-open 정책 유지 — 로드 실패 레이어가 있어도 서비스는 정상
    동작하며 이 엔드포인트는 진단 정보만 제공한다. 로드 실패 라인은
    앱 기동 시점의 로그에도 WARNING 레벨로 남는다.

    Returns:
        레이어별 로드 상태와 전체 요약(``all_loaded``) 을 담은 응답.
    """
    statuses = collect_layer_statuses()
    items = [
        LayerStatusItem(
            index=s.index,
            name=s.name,
            class_name=s.class_name,
            model_loaded=s.model_loaded,
            model_paths=s.model_paths,
            detail=s.detail,
        )
        for s in statuses
    ]
    all_loaded = all(item.model_loaded for item in items) if items else False
    return LayersStatusResponse(all_loaded=all_loaded, layers=items)
