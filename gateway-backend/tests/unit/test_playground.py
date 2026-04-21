"""플레이그라운드 정적 페이지 테스트."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_playground_page_is_served_with_core_sections() -> None:
    """GET /playground/가 정적 페이지와 핵심 섹션을 반환해야 한다."""
    response = client.get("/playground/")
    interactive_index = response.text.index("Interactive Test")
    api_surface_index = response.text.index("API Surface")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Gateway Backend" in response.text
    assert "Playground" in response.text
    assert "POST /v1/chat/completions" in response.text
    assert "Interactive Test" in response.text
    assert "API Surface" in response.text
    assert "응답" in response.text
    assert interactive_index < api_surface_index


def test_playground_helper_copy_uses_body_text_style() -> None:
    """긴 보조 설명은 배지 스타일이 아닌 본문 스타일로 렌더링해야 한다."""
    response = client.get("/playground/")

    assert '<p class="helper-text">' in response.text
    assert '<p class="card-kicker" style="margin-top:6px">' not in response.text
