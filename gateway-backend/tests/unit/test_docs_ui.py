"""LiteLLM 번들 Swagger UI 자산 기반 /docs 테스트."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_docs_page_renders_swagger_ui_with_litellm_assets() -> None:
    """GET /docs 가 LiteLLM 번들 자산을 가리키는 Swagger UI 를 반환한다."""
    response = client.get("/docs")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Agentic AI Guardrail Gateway - Swagger UI" in response.text
    # LiteLLM 번들 자산이 /swagger 마운트 경로로 노출돼야 한다.
    assert "/swagger/swagger-ui-bundle.js" in response.text
    assert "/swagger/swagger-ui.css" in response.text
    # 외부 CDN(jsdelivr) 의존이 남아 있으면 안 된다.
    assert "cdn.jsdelivr.net" not in response.text
    # 개발 편의 옵션은 유지.
    assert "persistAuthorization" in response.text
    assert "displayRequestDuration" in response.text


def test_swagger_static_assets_are_served_from_litellm_bundle() -> None:
    """LiteLLM 번들 자산이 /swagger/* 로 200 응답돼야 한다."""
    js = client.get("/swagger/swagger-ui-bundle.js")
    assert js.status_code == 200
    assert len(js.content) > 0

    css = client.get("/swagger/swagger-ui.css")
    assert css.status_code == 200
    assert len(css.content) > 0

    favicon = client.get("/swagger/favicon.png")
    assert favicon.status_code == 200
    assert len(favicon.content) > 0
