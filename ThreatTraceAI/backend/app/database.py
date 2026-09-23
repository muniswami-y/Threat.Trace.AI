from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import text
from app.config import get_settings

settings = get_settings()

connect_args = {}
if "postgresql" in settings.DATABASE_URL:
    connect_args["ssl"] = "require"

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args=connect_args,
    future=True
)

AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def _run_migrations(conn):
    """Safe additive migrations: add any ORM columns missing from the live DB.

    Uses PRAGMA table_info so it never drops or alters existing columns.
    Only supports SQLite (aiosqlite). Postgres uses CREATE TABLE IF NOT EXISTS
    which handles new tables but not new columns — extend here if needed.
    """
    # Mapping: table_name -> [(column_name, column_type)]
    schema_additions = {
        "cases": [
            ("case_salt",     "VARCHAR(16)"),
            ("case_pepper",   "VARCHAR(16)"),
            ("canary_token",  "VARCHAR(64)"),
            ("canary_hits",   "JSON"),
            ("evidence_hash", "VARCHAR(64)"),
        ],
    }
    if "sqlite" in engine.url.drivername:
        for table, columns in schema_additions.items():
            result = await conn.execute(text(f"PRAGMA table_info({table})"))
            existing_cols = {row[1] for row in result.fetchall()}
            for col_name, col_type in columns:
                if col_name not in existing_cols:
                    await conn.execute(
                        text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                    )

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _run_migrations(conn)
