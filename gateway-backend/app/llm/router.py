from typing import Any


class LLMRouter:
    def __init__(self, clients: dict[str, Any] | None = None):
        self.clients = clients or {}

    def _resolve_provider(self, model: str) -> str:
        m = model.lower()
        if m.startswith("gpt") or "openai" in m:
            return "openai"
        if m.startswith("claude") or "anthropic" in m:
            return "anthropic"
        raise ValueError(f"Unknown model: {model}")

    async def call(self, model: str, prompt: str, **kwargs: Any) -> dict[str, Any]:
        provider = self._resolve_provider(model)
        client = self.clients.get(provider)
        if client is None:
            raise ValueError(f"No client configured for provider: {provider}")
        return await client.complete(model=model, prompt=prompt, **kwargs)
