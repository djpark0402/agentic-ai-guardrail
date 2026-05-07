"""LiteLLM 번들 Swagger UI 자산 + /swagger-ui 진입 라우팅 테스트."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_legacy_docs_path_is_removed() -> None:
    """기존 /docs 진입점은 제거되어 404 가 떠야 한다."""
    response = client.get("/docs", follow_redirects=False)
    assert response.status_code == 404


def test_swagger_ui_index_renders_with_litellm_assets() -> None:
    """/swagger-ui/index.html 이 LiteLLM 번들 자산을 가리키는 UI 를 반환한다."""
    response = client.get("/swagger-ui/index.html")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Agentic AI Guardrail Gateway - Swagger UI" in response.text
    assert "/swagger/swagger-ui-bundle.js" in response.text
    assert "/swagger/swagger-ui.css" in response.text
    # 외부 CDN 의존이 남아 있으면 안 된다.
    assert "cdn.jsdelivr.net" not in response.text
    # 개발 편의 옵션 유지.
    assert "persistAuthorization" in response.text
    assert "displayRequestDuration" in response.text


def test_swagger_ui_bare_paths_redirect_to_index() -> None:
    """/swagger-ui 와 /swagger-ui/ 는 index.html 로 리디렉트한다."""
    bare = client.get("/swagger-ui", follow_redirects=False)
    assert bare.status_code in (307, 308)
    assert bare.headers["location"].endswith("/swagger-ui/index.html")

    slash = client.get("/swagger-ui/", follow_redirects=False)
    assert slash.status_code in (307, 308)
    assert slash.headers["location"].endswith("/swagger-ui/index.html")


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
