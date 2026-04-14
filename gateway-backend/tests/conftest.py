import hashlib
import hmac
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def api_key() -> str:
    return settings.TEST_API_KEY


@pytest.fixture
def api_secret() -> str:
    return settings.TEST_API_SECRET


def build_hmac_headers(api_key: str, api_secret: str, body: bytes) -> dict:
    nonce = uuid.uuid4().hex
    timestamp = str(int(time.time()))
    payload = f"{timestamp}.{nonce}.".encode() + body
    signature = hmac.new(
        api_secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return {
        "X-API-Key": api_key,
        "X-Nonce": nonce,
        "X-Timestamp": timestamp,
        "X-Signature": signature,
    }


@pytest.fixture
def sign_headers():
    return build_hmac_headers
