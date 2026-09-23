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
        if not v or not isinstance(v, str):
            return "sqlite+aiosqlite:///./threattrace.db"
        v = str(v).split("#")[0].strip()
        if not v:
            return "sqlite+aiosqlite:///./threattrace.db"
        if v.startswith("file:"):
            db_path = v[5:].replace("\\", "/")
            return f"sqlite+aiosqlite:///{db_path}"
        if v.startswith("postgres://"):
            v = v.replace("postgres://", "postgresql+asyncpg://", 1)
        elif v.startswith("postgresql://") and not v.startswith("postgresql+asyncpg://"):
            v = v.replace("postgresql://", "postgresql+asyncpg://", 1)
        
        if "postgresql+asyncpg://" in v:
            import re
            v = re.sub(r'[\?\&]sslmode=[^&]+', '', v)
            v = re.sub(r'[\?\&]channel_binding=[^&]+', '', v)
            if '?' in v and v.endswith('?'):
                v = v[:-1]
            if '&' in v and '?' not in v:
                v = v.replace('&', '?', 1)

        if not (v.startswith("sqlite") or v.startswith("postgresql") or v.startswith("mysql")):
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
