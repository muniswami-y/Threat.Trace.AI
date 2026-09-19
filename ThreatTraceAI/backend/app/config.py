from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache

class Settings(BaseSettings):
    APP_NAME: str = "THREAT TRACE AI"
    DEBUG: bool = True
    SECRET_KEY: str = "change-me"
    DATABASE_URL: str = "sqlite+aiosqlite:///./threattrace.db"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def sanitize_database_url(cls, v):
        if not v or not isinstance(v, str) or not (v.startswith("sqlite") or v.startswith("postgresql") or v.startswith("mysql")):
            return "sqlite+aiosqlite:///./threattrace.db"
        return v

    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/callback"

    PHISHTANK_API_KEY: str = ""
    OPENPHISH_ENABLED: bool = True
    IP_API_URL: str = "http://ip-api.com/json/"

    POLYGON_RPC_URL: str = "https://rpc-amoy.polygon.technology"
    PRIVATE_KEY: str = ""
    CONTRACT_ADDRESS: str = ""
    CHAIN_ID: int = 80002

    DEMO_MODE: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"

@lru_cache()
def get_settings() -> Settings:
    return Settings()
