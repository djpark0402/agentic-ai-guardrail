from pydantic import BaseModel


class Settings(BaseModel):
    TEST_API_KEY: str = "test-api-key"
    TEST_API_SECRET: str = "test-api-secret"
    NONCE_TTL_SECONDS: int = 300


settings = Settings()
