import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import get_settings
from app.database import init_db
from app.routes import analyze, cases, reports, intelligence, blockchain, crypto, soc, auth, canary, cybercrime

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Powered Email Threat Detection and Forensic Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(auth.router)
app.include_router(analyze.router)
app.include_router(cases.router)
app.include_router(reports.router)
app.include_router(intelligence.router)
app.include_router(blockchain.router)
app.include_router(crypto.router)
app.include_router(soc.router)
app.include_router(canary.router)
app.include_router(cybercrime.router)

@app.get("/")
async def root():
    return {
        "status": "online",
        "project": settings.APP_NAME,
        "version": "1.0.0",
        "message": "Threat Trace AI backend is running",
        "demo_mode": settings.DEMO_MODE
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "demo_mode": settings.DEMO_MODE}
