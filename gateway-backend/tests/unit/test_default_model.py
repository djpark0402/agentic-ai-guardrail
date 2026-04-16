"""기본 모델명 엔드포인트 테스트."""

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_default_model_returns_llm_model_value() -> None:
    """GET /v1/models/default가 LLM_MODEL 환경 변수 값을 반환해야 한다."""
    with patch(
        "app.config.get_settings",
    ) as mock_settings:
        mock_settings.return_value.llm_model = "solar-pro"
        response = client.get("/v1/models/default")

    assert response.status_code == 200
    assert response.json() == {"default_model": "solar-pro"}
