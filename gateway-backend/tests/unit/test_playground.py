"""플레이그라운드 정적 페이지 테스트."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_playground_page_is_served_with_core_sections() -> None:
    """GET /playground/가 정적 페이지와 핵심 섹션을 반환해야 한다."""
    response = client.get("/playground/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Gateway Backend" in response.text
    assert "Playground" in response.text
    assert "POST /v1/chat/completions" in response.text
    assert "응답" in response.text
