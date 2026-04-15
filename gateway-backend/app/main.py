"""Gateway Backend FastAPI 애플리케이션 진입점."""

from fastapi import FastAPI

app = FastAPI(title="Gateway Backend")


@app.get("/health")
async def health_check() -> dict[str, str]:
    """서비스 헬스체크 엔드포인트.

    Returns:
        서비스 상태를 담은 딕셔너리.
    """
    return {"status": "ok"}
