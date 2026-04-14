import json

import pytest

from app.llm.router import LLMRouter


@pytest.mark.asyncio
async def test_router_selects_openai(mocker):
    mock_client = mocker.AsyncMock()
    mock_client.complete.return_value = {"text": "hi from gpt"}
    router = LLMRouter(clients={"openai": mock_client})
    result = await router.call(model="gpt-4", prompt="hello")
    assert result["text"] == "hi from gpt"
    mock_client.complete.assert_awaited_once()


@pytest.mark.asyncio
async def test_router_selects_anthropic(mocker):
    mock_client = mocker.AsyncMock()
    mock_client.complete.return_value = {"text": "hi from claude"}
    router = LLMRouter(clients={"anthropic": mock_client})
    result = await router.call(model="claude-opus-4-6", prompt="hello")
    assert result["text"] == "hi from claude"


@pytest.mark.asyncio
async def test_router_unknown_model_raises():
    router = LLMRouter(clients={})
    with pytest.raises(ValueError):
        await router.call(model="unknown-xyz", prompt="hi")


def test_validate_endpoint_routes_to_llm(
    client, api_key, api_secret, sign_headers, mocker
):
    mock_call = mocker.patch(
        "app.llm.router.LLMRouter.call",
        return_value={"text": "mocked llm response"},
    )
    body = json.dumps({"prompt": "hello", "model": "gpt-4"}).encode()
    headers = sign_headers(api_key, api_secret, body)
    res = client.post("/v1/prompt/validate", content=body, headers=headers)
    assert res.status_code == 200
    assert res.json()["response"]["text"] == "mocked llm response"
    mock_call.assert_called_once()
