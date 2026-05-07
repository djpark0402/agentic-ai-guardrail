"""Playground 기본 입력값 엔드포인트 테스트."""

from unittest.mock import patch

from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.main import app

client = TestClient(app)


def test_playground_defaults_dev_returns_values() -> None:
    """APP_ENV=dev 면 환경변수 값을 그대로 반환해야 한다."""
    with patch("app.config.get_settings") as mock_settings:
        mock_settings.return_value.app_env = "dev"
        mock_settings.return_value.playground.default_api_key = "uak_demo"
        mock_settings.return_value.playground.default_hmac_secret = SecretStr(
            "s3cret"
        )
        response = client.get("/v1/playground/defaults")

    assert response.status_code == 200
    assert response.json() == {
        "api_key": "uak_demo",
        "hmac_secret": "s3cret",
    }


def test_playground_defaults_prod_returns_empty() -> None:
    """APP_ENV=prod 면 시크릿이 브라우저로 새면 안 되므로 빈 값 반환."""
    with patch("app.config.get_settings") as mock_settings:
        mock_settings.return_value.app_env = "prod"
        mock_settings.return_value.playground.default_api_key = "uak_demo"
        mock_settings.return_value.playground.default_hmac_secret = SecretStr(
            "s3cret"
        )
        response = client.get("/v1/playground/defaults")

    assert response.status_code == 200
    assert response.json() == {"api_key": "", "hmac_secret": ""}


def test_playground_defaults_unset_returns_empty() -> None:
    """환경변수 미설정 시 빈 값을 반환해야 한다 (기본 동작)."""
    with patch("app.config.get_settings") as mock_settings:
        mock_settings.return_value.app_env = "dev"
        mock_settings.return_value.playground.default_api_key = ""
        mock_settings.return_value.playground.default_hmac_secret = SecretStr(
            ""
        )
        response = client.get("/v1/playground/defaults")

    assert response.status_code == 200
    assert response.json() == {"api_key": "", "hmac_secret": ""}
