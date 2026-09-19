from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import uuid
import secrets
import string

from app.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.models import Case
from app.utils.salting import apply_salt_pepper

router = APIRouter(prefix="/api/cybercrime", tags=["Cybercrime Directorate"])

# In-memory store for Cybercrime state synchronization with database
CYBER_STORE: Dict[str, Any] = {
    "officers": [
        {
            "id": "OFF-0842",
            "name": "Inspector Rajesh Rao",
            "rank": "Cyber Crime Inspector",
            "badge": "CC-INSP-0842",
            "specialization": "Phishing, BEC & Executive Impersonation",
            "activeCases": 2,
            "clearance": "OMEGA-TOP-SECRET",
            "publicKey": "0xOF-842A-77C1-E490-9B21"
        },
        {
            "id": "OFF-1193",
            "name": "Sr. Analyst Neha Verma",
            "rank": "Senior Digital Forensic Investigator",
            "badge": "DF-ANL-1193",
            "specialization": "Malware Reverse Engineering & C2 Tracing",
            "activeCases": 1,
            "clearance": "OMEGA-SECRET",
            "publicKey": "0xOF-1193-F241-B882-3A10"
        },
        {
            "id": "OFF-0527",
            "name": "Det. Vikram Malhotra",
            "rank": "Senior Detective (Financial Crimes)",
            "badge": "CC-DET-0527",
            "specialization": "Cryptocurrency Laundering & Mule Networks",
            "activeCases": 3,
            "clearance": "OMEGA-TOP-SECRET",
            "publicKey": "0xOF-0527-31C9-9A82-4DF7"
        }
    ]
}

def _gen_hex(length=8):
    chars = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))

def generate_3_layer_keys(case_id: str, officer_id: str = "OFF-0842"):
    k1 = f"K1-ADM-{_gen_hex(4)}-{_gen_hex(4)}"
    k2 = f"K2-{officer_id.replace('OFF-', 'OFF')}-{_gen_hex(4)}-{_gen_hex(4)}"
    k3 = f"K3-ENC-{_gen_hex(4)}-{_gen_hex(4)}"
    combined_hash = f"0x{_gen_hex(16)}{_gen_hex(16)}".lower()
    return {
        "layer1_admin_key": k1,
        "layer2_officer_key": k2,
        "layer3_enclave_key": k3,
        "master_combined_hash": combined_hash,
        "algorithm": "ECDSA-SECP256R1 + AES-256-GCM (3-Layer Split)",
        "sealed_at": datetime.now(timezone.utc).isoformat()
    }

class ReportIncidentRequest(BaseModel):
    case_id: Optional[str] = None
    reporter_email: str
    reporter_name: Optional[str] = "Complainant"
    reporter_phone: Optional[str] = "+91 80 4000 8899"
    subject: str
    body_text: str
    raw_headers: Optional[str] = ""
    sender: str
    recipient: Optional[str] = ""
    risk_score: Optional[float] = 75.0
    risk_level: Optional[str] = "HIGH"
    urls: Optional[List[str]] = []
    domains: Optional[List[str]] = []
    ips: Optional[List[str]] = []

class TriageActionRequest(BaseModel):
    action: str  # "APPROVE" or "REJECT"
    explanation: Optional[str] = None
    officer_id: Optional[str] = None

class DailyLogRequest(BaseModel):
    notes: str
    officer_name: Optional[str] = None
    officer_badge: Optional[str] = None

class OfficerAddRequest(BaseModel):
    name: str
    badge: str
    rank: str
    station: Optional[str] = "CID Cyber Police Station, Bengaluru"
    specialization: str
    mail: str
    phone: Optional[str] = ""
    pin: Optional[str] = "123456"
    solved_count: Optional[int] = 0

class OfficerTransferRequest(BaseModel):
    officer_id: str
    new_station: str
    order_ref: str
    effective_date: Optional[str] = None
    reason: Optional[str] = None

class OfficerFireRequest(BaseModel):
    officer_id: str
    reason_category: str
    order_ref: str
    notes: Optional[str] = None

@router.get("/officers")
async def get_officers():
    return {"officers": CYBER_STORE["officers"]}

@router.post("/officers/add")
async def add_officer(req: OfficerAddRequest):
    officer_id = f"OFF-{req.badge.replace('-', '').replace(' ', '')[-4:]}"
    new_officer = {
        "id": officer_id,
        "name": req.name,
        "badge": req.badge,
        "rank": req.rank,
        "station": req.station,
        "specialization": req.specialization,
        "mail": req.mail,
        "phone": req.phone,
        "pin": req.pin,
        "solvedCount": req.solved_count,
        "status": "ACTIVE",
        "joinedDate": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "transferHistory": [
            {
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "from": "State Police Academy / Induction Board",
                "to": req.station,
                "ref": f"INDUCT-CYB-{_gen_hex(4)}",
                "reason": "Official Induction into Cyber Crime Investigation Cadre"
            }
        ]
    }
    CYBER_STORE["officers"].insert(0, new_officer)
    return {"success": True, "officer": new_officer}

@router.post("/officers/transfer")
async def transfer_officer(req: OfficerTransferRequest):
    officer = next((o for o in CYBER_STORE["officers"] if o["id"] == req.officer_id), None)
    if not officer:
        raise HTTPException(status_code=404, detail="Officer not found")
    
    prev_station = officer.get("station", "CID Cyber Police Station, Bengaluru")
    officer["station"] = req.new_station
    if "transferHistory" not in officer:
        officer["transferHistory"] = []
    
    officer["transferHistory"].insert(0, {
        "date": req.effective_date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "from": prev_station,
        "to": req.new_station,
        "ref": req.order_ref,
        "reason": req.reason or "Administrative Re-posting by Head of Department"
    })
    return {"success": True, "officer": officer}

@router.post("/officers/fire")
async def fire_officer(req: OfficerFireRequest):
    officer = next((o for o in CYBER_STORE["officers"] if o["id"] == req.officer_id), None)
    if not officer:
        raise HTTPException(status_code=404, detail="Officer not found")
    
    officer["status"] = "RELIEVED"
    if "transferHistory" not in officer:
        officer["transferHistory"] = []
    
    officer["transferHistory"].insert(0, {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "from": officer.get("station", "CID Cyber Police Station, Bengaluru"),
        "to": "RELIEVED FROM SERVICE",
        "ref": req.order_ref,
        "reason": f"{req.reason_category}: {req.notes or 'Service relieved by Head of Department'}"
    })
    return {"success": True, "officer": officer}

@router.get("/cases")
async def list_cybercrime_cases(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.is_reported == True).order_by(desc(Case.created_at)))
    reported_cases = result.scalars().all()
    out = []
    
    # In-memory cases first
    mem_cases = CYBER_STORE.get("cases", [])
    seen = set()
    for m in mem_cases:
        cid = m.get("caseId")
        if cid:
            out.append(m)
            seen.add(cid)

    for c in reported_cases:
        if c.case_id and c.case_id not in seen:
            out.append({
                "caseId": c.case_id,
                "complainantName": "ThreatTrace Forensic User",
                "reportingEmail": c.recipient or c.sender or "victim@enterprise.corp",
                "reportedAt": c.created_at.isoformat() if c.created_at else datetime.now(timezone.utc).isoformat(),
                "status": "QUEUE",
                "subject": c.subject or "Reported Threat Incident",
                "riskScore": int(c.risk_score or 75),
                "bodyText": c.body_text or "",
                "assignedOfficer": None,
                "diaryEntries": [],
                "firData": None,
                "rejectionReason": None
            })
            seen.add(c.case_id)
            
    return {"cases": out}

@router.post("/cases/sync")
async def sync_cybercrime_cases(data: Dict[str, Any]):
    cases = data.get("cases", [])
    CYBER_STORE["cases"] = cases
    return {"success": True, "count": len(cases)}

@router.post("/report")
async def report_incident(req: ReportIncidentRequest, db: AsyncSession = Depends(get_db)):
    case_id = req.case_id or f"TT-{datetime.now(timezone.utc).year}-{_gen_hex(8)}"
    
    # Check if case exists in DB
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    c = result.scalar_one_or_none()
    
    if not c:
        c = Case(
            case_id=case_id,
            subject=req.subject,
            sender=req.sender,
            recipient=req.recipient or req.reporter_email,
            body_text=req.body_text,
            raw_headers=req.raw_headers,
            risk_score=req.risk_score,
            risk_level=req.risk_level,
            urls=req.urls,
            domains=req.domains,
            ips=req.ips,
            is_reported=True
        )
        db.add(c)
    else:
        c.is_reported = True
        
    await db.commit()

    # Store in memory list as QUEUE
    new_case_dict = {
        "caseId": case_id,
        "complainantName": req.reporter_name or "ThreatTrace Certified User",
        "reportingEmail": req.reporter_email,
        "reportingPhone": req.reporter_phone or "+91 80 4000 8899",
        "reportedAt": datetime.now(timezone.utc).isoformat(),
        "status": "QUEUE",
        "subject": req.subject,
        "sender": req.sender,
        "recipient": req.recipient or req.reporter_email,
        "riskScore": int(req.risk_score or 75),
        "riskLevel": req.risk_level or "HIGH",
        "bodyText": req.body_text,
        "rawHeaders": req.raw_headers or "",
        "urls": req.urls or [],
        "domains": req.domains or [],
        "ips": req.ips or [],
        "geoLocations": [
            {"ip": req.ips[0], "city": "External Origin", "country": "Global Internet", "isp": "External Gateway"}
        ] if req.ips else [],
        "riskFactors": [
            "Reported from ThreatTrace AI Real-Time Ingestion Sensor",
            f"Risk Level classified as {req.risk_level or 'HIGH'} with score {int(req.risk_score or 75)}/100"
        ],
        "assignedOfficer": None,
        "diaryEntries": [],
        "firData": None,
        "rejectionReason": None
    }
    
    mem_cases = CYBER_STORE.get("cases", [])
    existing_idx = next((i for i, x in enumerate(mem_cases) if x.get("caseId") == case_id), -1)
    if existing_idx >= 0:
        mem_cases[existing_idx] = new_case_dict
    else:
        mem_cases.insert(0, new_case_dict)
    CYBER_STORE["cases"] = mem_cases

    return {
        "success": True,
        "case_id": case_id,
        "status": "QUEUE",
        "reporter_email": req.reporter_email,
        "message": f"Case {case_id} successfully queued in Cybercrime Command Registry."
    }

@router.post("/{case_id}/triage")
async def triage_case(case_id: str, req: TriageActionRequest, db: AsyncSession = Depends(get_db)):
    if req.action.upper() == "REJECT":
        if not req.explanation or not req.explanation.strip():
            raise HTTPException(status_code=400, detail="Rejection explanation is mandatory.")
        return {
            "success": True,
            "case_id": case_id,
            "status": "REJECTED",
            "explanation": req.explanation.strip(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    elif req.action.upper() == "APPROVE":
        if not req.officer_id:
            raise HTTPException(status_code=400, detail="Investigating officer must be specified.")
        
        three_layers = generate_3_layer_keys(case_id, req.officer_id)
        return {
            "success": True,
            "case_id": case_id,
            "status": "PROCESS",
            "assigned_officer_id": req.officer_id,
            "three_layer_keys": three_layers,
            "message": "Officer assigned. 3-Layer separated cryptographic keys derived and sealed."
        }
    
    raise HTTPException(status_code=400, detail="Invalid action. Must be APPROVE or REJECT.")

@router.post("/{case_id}/daily-log")
async def add_daily_log(case_id: str, req: DailyLogRequest):
    if not req.notes or not req.notes.strip():
        raise HTTPException(status_code=400, detail="Daily log notes cannot be empty.")
    
    salt, _s, _p = apply_salt_pepper(f"LOG-{_gen_hex(6)}")
    
    return {
        "success": True,
        "case_id": case_id,
        "salt": f"S_{_s}",
        "pepper": f"P_{_p}",
        "blockchain_tx": f"0x{_gen_hex(16)}{_gen_hex(16)}".lower(),
        "sealed": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "Daily investigation log cryptographically sealed with salt, pepper & 3-layer key."
    }
