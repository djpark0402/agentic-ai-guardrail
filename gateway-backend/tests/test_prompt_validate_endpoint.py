import json


def test_validate_prompt_success(client, api_key, api_secret, sign_headers):
    body = json.dumps({"prompt": "Hello world", "model": "gpt-4"}).encode()
    headers = sign_headers(api_key, api_secret, body)
    res = client.post("/v1/prompt/validate", content=body, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is True
    assert "response" in data


def test_validate_prompt_missing_api_key(client, api_secret, sign_headers):
    body = json.dumps({"prompt": "hi"}).encode()
    headers = sign_headers("", api_secret, body)
    headers.pop("X-API-Key", None)
    res = client.post("/v1/prompt/validate", content=body, headers=headers)
    assert res.status_code == 401


def test_validate_prompt_invalid_hmac(client, api_key, sign_headers):
    body = json.dumps({"prompt": "hi"}).encode()
    headers = sign_headers(api_key, "WRONG_SECRET", body)
    res = client.post("/v1/prompt/validate", content=body, headers=headers)
    assert res.status_code == 401


def test_validate_prompt_nonce_replay(client, api_key, api_secret, sign_headers):
    body = json.dumps({"prompt": "hi"}).encode()
    headers = sign_headers(api_key, api_secret, body)
    r1 = client.post("/v1/prompt/validate", content=body, headers=headers)
    r2 = client.post("/v1/prompt/validate", content=body, headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 409
