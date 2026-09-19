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
        select(Case).order_by(desc(Case.created_at)).limit(limit)
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
    """Seed the database with sample demo cases if empty or requested."""
    from pathlib import Path
    from app.services.email_parser import parse_email_content
    from app.services.header_analyzer import analyze_headers
    from app.services.ioc_extractor import extract_iocs
    from app.services.risk_engine import score_content, combine_scores
    from app.services.blockchain_service import prepare_case_hash
    import uuid
    from datetime import datetime, timezone

    demo_dir = Path(__file__).resolve().parents[3] / "demo_data"
    created = []

    files = list(demo_dir.glob("*.eml")) if demo_dir.exists() else []
    for eml_file in files:
        raw_text = eml_file.read_text(encoding="utf-8")
        parsed = parse_email_content(raw_text)
        
        # Check if already seeded by subject (handle duplicates safely)
        existing = await db.execute(select(Case).where(Case.subject == parsed.get("subject")))
        if existing.scalars().first():
            continue
            
        header_factors, header_pts = analyze_headers(parsed.get("headers") or {}, parsed.get("sender_email") or "")
        iocs = extract_iocs(parsed.get("body_text") or "", parsed.get("headers"))
        content_factors, content_pts = score_content(parsed.get("body_text") or "", parsed.get("subject") or "")
        
        # Check if phishing file
        is_phish = "phish" in eml_file.name.lower()
        score, level, rec, extra = combine_scores(header_pts, content_pts, 1 if is_phish else 0)
        factors = header_factors + content_factors + extra
        
        case_id = f"TT-DEMO-{uuid.uuid4().hex[:6].upper()}"
        
        sample_geos = []
        if iocs.get("ips"):
            for ip in iocs["ips"]:
                sample_geos.append({
                    "ip": ip, "status": "success", "country": "United States",
                    "region": "California", "city": "San Jose", "lat": 37.3382, "lon": -121.8863,
                    "isp": "Cloudflare / CDN Relay"
                })
                
        new_case = Case(
            case_id=case_id,
            subject=parsed.get("subject") or eml_file.stem.replace("_", " ").title(),
            sender=parsed.get("sender_email") or parsed.get("from_header") or "unknown@demo.org",
            recipient=parsed.get("to_header") or "analyst@enterprise.local",
            raw_headers=str(parsed.get("headers")),
            body_text=parsed.get("body_text"),
            risk_score=score,
            risk_level=level,
            risk_factors=factors,
            urls=[{"original": u, "final": u, "redirect_count": 0, "status": 200} for u in iocs.get("urls", [])],
            domains=iocs.get("domains", []),
            ips=iocs.get("ips", []),
            geo_locations=sample_geos,
            recommendation=rec,
            is_reported=is_phish
        )
        case_dict = {
            "case_id": case_id, "subject": new_case.subject, "sender": new_case.sender,
            "risk_score": score, "risk_level": level, "urls": new_case.urls,
            "domains": new_case.domains, "ips": new_case.ips, "recommendation": rec,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        new_case.blockchain_hash = prepare_case_hash(case_dict)
        if is_phish:
            new_case.blockchain_tx = f"0x{uuid.uuid4().hex}{uuid.uuid4().hex}"[:66]
            new_case.report_id = f"RPT-DEMO-{uuid.uuid4().hex[:6].upper()}"
            
        db.add(new_case)
        created.append(case_id)

    await db.commit()
    return {"seeded_count": len(created), "case_ids": created}

@router.get("/{case_id}")
async def get_case(case_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.case_id == case_id))
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
