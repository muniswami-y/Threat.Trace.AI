from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List

from app.database import get_db
from app.models import Case
from app.services.subpoena_service import build_subpoena_package
from app.services.canary_service import get_hits_by_case

router = APIRouter(prefix="/api/cases", tags=["Cases"])

@router.get("/")
async def list_cases(limit: int = 50, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Case).where(
            ~Case.case_id.like("TT-DEMO%"),
            ~Case.case_id.like("INC-DEMO%"),
            ~Case.case_id.in_({"TT-2026-F80E1E7B", "TT-2026-B819A21C", "TT-2026-4401AA9F", "TT-2026-C90288EA", "TT-2026-9C44E109"})
        ).order_by(desc(Case.created_at)).limit(limit)
    )
    cases = result.scalars().all()
    return [
        {
            "case_id": c.case_id,
            "subject": c.subject,
            "sender": c.sender,
            "risk_score": c.risk_score,
            "risk_level": c.risk_level,
            "recommendation": c.recommendation,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "is_reported": c.is_reported,
            "blockchain_tx": c.blockchain_tx,
            "blockchain_hash": c.blockchain_hash
        }
        for c in cases
    ]

@router.post("/seed")
async def seed_demo_cases(db: AsyncSession = Depends(get_db)):
    """Seed the database with sample demo cases disabled."""
    return {"seeded_count": 0, "case_ids": []}

@router.get("/{case_id}")
async def get_case(case_id: str, db: AsyncSession = Depends(get_db)):
    import re
    # 1. Direct match
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    c = result.scalar_one_or_none()

    # 2. Extract standard pattern TT-2026-XXXXXXXX or INC-2026-XXXXXXXX
    if not c:
        match = re.search(r'(?:TT|INC)-\d{4}-[A-Fa-f0-9]{6,12}', case_id, re.IGNORECASE)
        if match:
            clean_id = match.group(0).upper()
            result = await db.execute(select(Case).where(Case.case_id.ilike(f"%{clean_id}%")))
            c = result.scalar_one_or_none()

    # 3. Extract any 8-char hex chunk
    if not c:
        hex_match = re.search(r'[A-Fa-f0-9]{8}', case_id)
        if hex_match:
            hex_part = hex_match.group(0).upper()
            result = await db.execute(select(Case).where(Case.case_id.ilike(f"%{hex_part}%")))
            c = result.scalar_one_or_none()

    # 4. Fallback search anywhere in string
    if not c:
        clean_str = re.sub(r'[^A-Za-z0-9]', '', case_id)
        if len(clean_str) >= 6:
            result = await db.execute(select(Case).where(Case.case_id.ilike(f"%{clean_str[:8]}%")))
            c = result.scalar_one_or_none()

    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    return {
        "case_id": c.case_id,
        "subject": c.subject,
        "sender": c.sender,
        "recipient": c.recipient,
        "body_text": c.body_text,
        "risk_score": c.risk_score,
        "risk_level": c.risk_level,
        "risk_factors": c.risk_factors,
        "urls": c.urls,
        "domains": c.domains,
        "ips": c.ips,
        "geo_locations": c.geo_locations,
        "recommendation": c.recommendation,
        "blockchain_tx": c.blockchain_tx,
        "blockchain_hash": c.blockchain_hash,
        "is_reported": c.is_reported,
        "report_id": c.report_id,
        "created_at": c.created_at.isoformat() if c.created_at else None
    }


@router.get("/{case_id}/subpoena")
async def get_subpoena_package(case_id: str, db: AsyncSession = Depends(get_db)):
    """
    Generates an ISP subpoena-ready evidence package for a case.

    Returns:
    - SHA-256 evidence hash (cryptographic seal)
    - All attacker IPs with exact UTC timestamps
    - ISP/ASN info for each IP
    - Canary hit data (accurate OS via JS probe, geolocation)
    - Human-readable formatted LE report text
    - Step-by-step ISP subpoena instructions
    """
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    c = result.scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    # Build case dict from DB record
    case_dict = {
        "case_id":      c.case_id,
        "subject":      c.subject,
        "sender":       c.sender,
        "body_text":    c.body_text or "",
        "risk_score":   c.risk_score,
        "risk_level":   c.risk_level,
        "ips":          c.ips or [],
        "geo_locations": c.geo_locations or [],
        "created_at":   c.created_at.isoformat() if c.created_at else "",
    }

    # Fetch any canary hits recorded for this case (in-memory store)
    canary_hits = get_hits_by_case(case_id)

    package = build_subpoena_package(case_dict, canary_hits=canary_hits)
    return {"ok": True, **package}


@router.delete("/reset-all")
@router.post("/reset-all")
async def reset_all_data(db: AsyncSession = Depends(get_db)):
    """Wipes all cases, intel caches, cybercrime store, and quarantine records."""
    from sqlalchemy import delete
    from app.models import ThreatIntelCache
    from app.routes.cybercrime import CYBER_STORE
    from app.routes.soc import QUARANTINE_STORE, DISMISSED_QUARANTINE_SENDERS

    await db.execute(delete(Case))
    await db.execute(delete(ThreatIntelCache))
    await db.commit()

    CYBER_STORE["cases"] = []
    QUARANTINE_STORE.clear()
    DISMISSED_QUARANTINE_SENDERS.clear()

    return {
        "success": True,
        "message": "All threat trace cases, intel cache, cybercrime queue, and quarantine data completely deleted."
    }

