from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pathlib import Path
import uuid
from datetime import datetime, timezone

from app.database import get_db
from app.models import Case
from app.services.report_generator import generate_case_report
from app.services.blockchain_service import log_case_to_chain
from app.services.crypto_service import get_crypto_service
from app.utils.salting import apply_salt_pepper

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.post("/{case_id}/generate")
async def generate_report(case_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    c = result.scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    # Generate base report ID then wrap with cryptographic salt + pepper
    _base_report_id = f"RPT-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"
    report_id, _rpt_salt, _rpt_pepper = apply_salt_pepper(_base_report_id)
    c.report_id = report_id
    c.is_reported = True

    case_dict = {
        "case_id": c.case_id,
        "subject": c.subject,
        "sender": c.sender,
        "risk_score": c.risk_score,
        "risk_level": c.risk_level,
        "risk_factors": c.risk_factors,
        "urls": c.urls,
        "domains": c.domains,
        "ips": c.ips,
        "geo_locations": c.geo_locations,
        "recommendation": c.recommendation,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "report_id": report_id
    }

    # Cryptographic evidence sealing (ECDSA + Canonical SHA-256)
    crypto_service = get_crypto_service()
    crypto_seal = crypto_service.seal_case(case_dict)
    case_dict["canonical_hash"] = crypto_seal["canonical_hash"]
    case_dict["signature"] = crypto_seal["signature"]
    case_dict["public_key_fingerprint"] = crypto_seal["public_key_fingerprint"]
    case_dict["crypto_seal"] = crypto_seal

    # Blockchain chain-of-custody
    chain_result = await log_case_to_chain(case_dict)
    if chain_result.get("success") or chain_result.get("simulated"):
        c.blockchain_hash = crypto_seal["canonical_hash"]
        c.blockchain_tx = chain_result.get("tx_hash") or crypto_seal.get("blockchain_tx")

    await db.commit()

    report_meta = generate_case_report(case_dict)

    return {
        "success": True,
        "report_id": report_id,
        "case_id": case_id,
        "blockchain": chain_result,
        "crypto_seal": crypto_seal,
        "report": report_meta,
        "message": "Case reported. Cryptographically sealed with ECDSA & hash logged for chain-of-custody."
    }

@router.get("/{report_id}/download")
async def download_report(report_id: str, format: str = "json"):
    ext = "html" if format.lower() == "html" else "json"
    media_type = "text/html" if ext == "html" else "application/json"
    path = Path(__file__).resolve().parents[3] / "reports" / f"{report_id}.{ext}"
    if not path.exists():
        # Fallback check
        alt_path = Path(__file__).resolve().parents[3] / "reports" / f"{report_id}.json"
        if alt_path.exists():
            return FileResponse(alt_path, filename=f"{report_id}.json", media_type="application/json")
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(path, filename=f"{report_id}.{ext}", media_type=media_type)
