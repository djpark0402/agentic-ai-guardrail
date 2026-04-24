"""커스텀 Swagger UI 테스트."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_docs_page_uses_custom_swagger_shell() -> None:
    """GET /docs 가 기본 Swagger UI 셸에 개발 편의 옵션을 포함해야 한다."""
    response = client.get("/docs")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Agentic AI Guardrail Gateway - Swagger UI" in response.text
    assert "swagger-ui-bundle.js" in response.text
    assert "persistAuthorization" in response.text
    assert "displayRequestDuration" in response.text
    assert "gateway-swagger-topbar" in response.text
    assert "Supported by SmartBear" in response.text


def test_docs_page_accepts_alternate_spec_url() -> None:
    """GET /docs 는 topbar Explore 입력값을 위해 url 쿼리를 반영해야 한다."""
    response = client.get("/docs?url=/custom-openapi.json")

    assert response.status_code == 200
    assert "/custom-openapi.json" in response.text
