import json

import pytest

from app.guardrail.chain import GuardrailChain
from app.guardrail.layers import L1InputLayer, L2PolicyLayer


@pytest.mark.asyncio
async def test_chain_runs_layers_in_order():
    chain = GuardrailChain(layers=[L1InputLayer(), L2PolicyLayer()])
    result = await chain.run({"prompt": "safe content"})
    assert result.allowed is True
    assert [r.name for r in result.trace] == ["L1", "L2"]


@pytest.mark.asyncio
async def test_chain_blocks_on_l1_violation():
    chain = GuardrailChain(layers=[L1InputLayer(), L2PolicyLayer()])
    result = await chain.run({"prompt": "<script>evil</script>"})
    assert result.allowed is False
    assert result.blocked_by == "L1"


@pytest.mark.asyncio
async def test_chain_blocks_on_l2_policy():
    chain = GuardrailChain(layers=[L1InputLayer(), L2PolicyLayer()])
    result = await chain.run({"prompt": "BLOCKED_POLICY_TOKEN"})
    assert result.allowed is False
    assert result.blocked_by == "L2"


def test_validate_triggers_full_chain(client, api_key, api_secret, sign_headers):
    body = json.dumps({"prompt": "<script>evil</script>"}).encode()
    headers = sign_headers(api_key, api_secret, body)
    res = client.post("/v1/prompt/validate", content=body, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is False
    assert data["blocked_by"] == "L1"
