import json

from fastapi import FastAPI, HTTPException, Request

from app.guardrail.chain import GuardrailChain
from app.guardrail.layers import L1InputLayer, L2PolicyLayer
from app.llm.router import LLMRouter
from app.security import verify_request

app = FastAPI(title="Gateway Backend")


def _build_chain() -> GuardrailChain:
    return GuardrailChain(layers=[L1InputLayer(), L2PolicyLayer()])


def _build_router() -> LLMRouter:
    return LLMRouter(clients={})


@app.post("/v1/prompt/validate")
async def validate_prompt(request: Request) -> dict:
    body = await verify_request(request)
    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid json")

    prompt = payload.get("prompt", "")
    model = payload.get("model", "gpt-4")

    chain = _build_chain()
    chain_result = await chain.run({"prompt": prompt})

    if not chain_result.allowed:
        return {
            "allowed": False,
            "blocked_by": chain_result.blocked_by,
            "reason": chain_result.reason,
            "response": None,
        }

    router = _build_router()
    try:
        llm_response = await router.call(model=model, prompt=prompt)
    except ValueError:
        llm_response = {"text": ""}

    return {
        "allowed": True,
        "blocked_by": None,
        "response": llm_response,
    }
