"""
ThreatTrace AI – Canary / Honeytoken API Routes
================================================
POST /api/canary/generate        → create canary token for a case
GET  /api/canary/ping/{token}    → beacon (GET with tracking pixel fallback)
POST /api/canary/ping/{token}    → beacon (POST from JS fetch/XHR/sendBeacon)
GET  /api/canary/hits/{case_id}  → all hits for a case
GET  /api/canary/tokens/{case_id}→ all tokens created for a case
"""

from fastapi import APIRouter, Request, HTTPException, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional

from app.services.canary_service import (
    generate_canary_token,
    record_canary_hit,
    get_canary_hits,
    get_hits_by_case,
    get_all_tokens_for_case,
)

router = APIRouter(prefix="/api/canary", tags=["Canary Traps"])


# ── Request models ────────────────────────────────────────────────────────────

class CanaryGenerateRequest(BaseModel):
    case_id: str
    analyst_email: Optional[str] = "analyst@threattrace.ai"


# ── 1. Generate canary token ─────────────────────────────────────────────────

@router.post("/generate")
async def generate_canary(payload: CanaryGenerateRequest):
    """
    Generates a canary/honeytoken for the given case.
    Returns the token, HTML bait page, email lure text, and instructions.
    """
    result = generate_canary_token(
        case_id=payload.case_id,
        analyst_email=payload.analyst_email or "analyst@threattrace.ai",
    )
    return {"ok": True, **result}


# ── 2a. Beacon – GET (tracking pixel / direct URL open) ──────────────────────

@router.get("/ping/{token}")
async def canary_ping_get(token: str, request: Request):
    """
    Called when attacker opens the bait URL or the tracking pixel fires.
    Captures server-side IP and records the hit.
    Returns a 1x1 transparent GIF to satisfy image requests.
    """
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP", "")
        or (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")

    hit_data = {
        "_server_ip": client_ip,
        "userAgent": ua,
        "geo_source": "not_attempted",
        "platform": "unknown",
        "os_family": _infer_os_from_ua(ua),
        "os_confidence": "LOW" if "Linux" not in ua else "HIGH",
        "screenWidth": None, "screenHeight": None,
    }
    record_canary_hit(token, hit_data)

    # Return 1x1 transparent GIF (for img-tag pixel requests)
    GIF_1X1 = (
        b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00"
        b"\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00"
        b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
    )
    return Response(content=GIF_1X1, media_type="image/gif")


# ── 2b. Beacon – POST (from JS fetch / XHR / sendBeacon) ─────────────────────

@router.post("/ping/{token}")
async def canary_ping_post(token: str, request: Request):
    """
    Called by the embedded JS beacon with full device/OS fingerprint data.
    This gives the most accurate OS detection.
    """
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP", "")
        or (request.client.host if request.client else "unknown")
    )

    try:
        body = await request.json()
    except Exception:
        body = {}

    # Inject the server-captured IP (attacker's real IP at packet level)
    body["_server_ip"] = client_ip

    hit = record_canary_hit(token, body)
    if hit is None:
        # Unknown token — still return 200 to avoid tipping off attacker
        return {"ok": False, "note": "token_not_found"}

    return {
        "ok": True,
        "hit_id": hit["hit_id"],
        "timestamp_utc": hit["timestamp_utc"],
        "os_detected": hit["os_family"],
        "os_confidence": hit["os_confidence"],
    }


# ── 3. Query hits by case ─────────────────────────────────────────────────────

@router.get("/hits/{case_id}")
async def get_case_hits(case_id: str):
    """Returns all canary hits recorded for a case (across all tokens)."""
    hits = get_hits_by_case(case_id)
    return {
        "case_id": case_id,
        "total_hits": len(hits),
        "hits": hits,
    }


# ── 4. List tokens for a case ─────────────────────────────────────────────────

@router.get("/tokens/{case_id}")
async def list_tokens_for_case(case_id: str):
    """Returns all canary tokens and their metadata for a given case."""
    tokens = get_all_tokens_for_case(case_id)
    return {
        "case_id": case_id,
        "token_count": len(tokens),
        "tokens": tokens,
    }


# ── Helper: fast UA-based OS inference (server side, as fallback) ─────────────

def _infer_os_from_ua(ua: str) -> str:
    ua_l = ua.lower()
    if "kali" in ua_l:
        return "Kali Linux (Confirmed via UA)"
    if "linux" in ua_l:
        if "android" in ua_l:
            return "Android (Linux Kernel)"
        if "debian" in ua_l:
            return "Debian Linux"
        if "ubuntu" in ua_l:
            return "Ubuntu Linux"
        return "Linux (Distro unknown)"
    if "windows nt 10" in ua_l:
        return "Windows 10/11"
    if "windows" in ua_l:
        return "Windows"
    if "mac os x" in ua_l or "macintosh" in ua_l:
        return "macOS"
    if "iphone" in ua_l or "ipad" in ua_l:
        return "iOS"
    return "Unknown OS"
