"""CORS 미들웨어 동작 테스트."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_cors_preflight_allows_any_origin():
    """OPTIONS preflight 요청이 와일드카드 오리진을 허용한다."""
    response = client.options(
        "/v1/chat/completions",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"
    assert "POST" in response.headers["access-control-allow-methods"]


def test_cors_header_on_actual_request():
    """실제 요청 응답에 access-control-allow-origin 헤더가 붙는다."""
    response = client.get("/health", headers={"Origin": "https://example.com"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"
