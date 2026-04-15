"""헬스체크 엔드포인트 테스트."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_check_returns_ok() -> None:
    """GET /health가 200과 status:ok를 반환해야 한다."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
