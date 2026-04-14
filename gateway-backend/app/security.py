import hashlib
import hmac
import time

from fastapi import HTTPException, Request

from app.config import settings

_KEY_SECRETS = {
    settings.TEST_API_KEY: settings.TEST_API_SECRET,
}

_seen_nonces: set[str] = set()


def reset_nonces() -> None:
    _seen_nonces.clear()


async def verify_request(request: Request) -> bytes:
    api_key = request.headers.get("X-API-Key")
    nonce = request.headers.get("X-Nonce")
    timestamp = request.headers.get("X-Timestamp")
    signature = request.headers.get("X-Signature")

    if not api_key or api_key not in _KEY_SECRETS:
        raise HTTPException(status_code=401, detail="invalid api key")
    if not nonce or not timestamp or not signature:
        raise HTTPException(status_code=401, detail="missing auth headers")

    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="bad timestamp")
    if abs(int(time.time()) - ts) > settings.NONCE_TTL_SECONDS:
        raise HTTPException(status_code=401, detail="expired timestamp")

    body = await request.body()
    secret = _KEY_SECRETS[api_key]
    payload = f"{timestamp}.{nonce}.".encode() + body
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="invalid signature")

    if nonce in _seen_nonces:
        raise HTTPException(status_code=409, detail="nonce replay")
    _seen_nonces.add(nonce)

    return body
