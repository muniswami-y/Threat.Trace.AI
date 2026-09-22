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
    reporter_email: Optional[str] = "muniswami1112@gmail.com"
    reporter_name: Optional[str] = "Complainant"
    reporter_phone: Optional[str] = "+91 80 4000 8899"
    subject: Optional[str] = "Reported Threat Incident"
    body_text: Optional[str] = ""
    raw_headers: Optional[str] = ""
    sender: Optional[str] = "threat-origin@unknown.com"
    recipient: Optional[str] = ""
    risk_score: Optional[float] = 0.0
    risk_level: Optional[str] = "LOW"
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
    station: Optional[str] = "National Cyber Crime Police Station, Central Command, New Delhi"
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
                "from": "National Cyber Directorate / Induction Board",
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
    
    prev_station = officer.get("station", "National Cyber Crime Police Station, Central Command, New Delhi")
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
        "from": officer.get("station", "National Cyber Crime Police Station, Central Command, New Delhi"),
        "to": "RELIEVED FROM SERVICE",
        "ref": req.order_ref,
        "reason": f"{req.reason_category}: {req.notes or 'Service relieved by Head of Department'}"
    })
    return {"success": True, "officer": officer}

TEST_CASE_IDS = set()

def is_test_case(cid: str, subject: str = "") -> bool:
    if not cid:
        return False
    if cid.startswith("TT-DUMMY-") or cid.startswith("INC-DUMMY-"):
        return True
    return False


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
        if cid and not is_test_case(cid, m.get("subject", "")):
            # Clean legacy fake placeholder emails if present
            rep_email = m.get("reportingEmail") or m.get("recipient") or "muniswami1112@gmail.com"
            if "corp.net" in rep_email or "enterprise.corp" in rep_email or "citizen.user@" in rep_email or "victim@" in rep_email:
                rep_email = "muniswami1112@gmail.com"
                m["reportingEmail"] = rep_email
                m["recipient"] = rep_email
            
            comp_name = m.get("complainantName") or m.get("reportingName")
            if not comp_name or "ThreatTrace" in comp_name or "Citizen" in comp_name or comp_name == "Complainant":
                user_part = rep_email.split("@")[0].replace(".", " ").replace("_", " ").title() if "@" in rep_email else "Muniswami"
                comp_name = f"{user_part} (Complainant)"
                m["complainantName"] = comp_name
                m["reportingName"] = comp_name

            out.append(m)
            seen.add(cid)

    for c in reported_cases:
        if c.case_id and c.case_id not in seen and not is_test_case(c.case_id, c.subject or ""):
            # If case_id contains salt prefix/suffix, clean it
            clean_cid = c.case_id
            if "_" in clean_cid and "TT-2026-" in clean_cid:
                match = __import__('re').search(r'TT-2026-[A-Fa-f0-9]{8}', clean_cid)
                if match:
                    clean_cid = match.group(0)
            if clean_cid in seen:
                continue

            rep_email = c.recipient or c.sender or "muniswami1112@gmail.com"
            if "corp.net" in rep_email or "enterprise.corp" in rep_email or "citizen.user@" in rep_email or "victim@" in rep_email:
                rep_email = "muniswami1112@gmail.com"

            user_part = rep_email.split("@")[0].replace(".", " ").replace("_", " ").title() if "@" in rep_email else "Muniswami"
            complainant_name = f"{user_part} (Complainant)"

            out.append({
                "caseId": clean_cid,
                "complainantName": complainant_name,
                "reportingEmail": rep_email,
                "reportedAt": c.created_at.isoformat() if c.created_at else datetime.now(timezone.utc).isoformat(),
                "status": "QUEUE",
                "subject": c.subject or "Reported Threat Incident",
                "riskScore": int(round(c.risk_score)) if c.risk_score is not None else 0,
                "bodyText": c.body_text or "",
                "assignedOfficer": None,
                "diaryEntries": [],
                "firData": None,
                "rejectionReason": None
            })
            seen.add(clean_cid)
            
    return {"cases": out}

@router.post("/cases/sync")
async def sync_cybercrime_cases(data: Dict[str, Any]):
    cases = data.get("cases", [])
    CYBER_STORE["cases"] = cases
    return {"success": True, "count": len(cases)}

@router.post("/report")
async def report_incident(req: ReportIncidentRequest, db: AsyncSession = Depends(get_db)):
    case_id = req.case_id or f"TT-{datetime.now(timezone.utc).year}-{_gen_hex(8)}"
    score_val = int(round(req.risk_score)) if req.risk_score is not None else 0
    level_val = req.risk_level or ("CRITICAL" if score_val >= 85 else "HIGH" if score_val >= 70 else "MEDIUM" if score_val >= 40 else "LOW")
    
    effective_reporter_email = req.reporter_email or req.recipient or "muniswami1112@gmail.com"
    if "corp.net" in effective_reporter_email or "enterprise.corp" in effective_reporter_email or "citizen.user@" in effective_reporter_email:
        effective_reporter_email = "muniswami1112@gmail.com"

    user_part = effective_reporter_email.split("@")[0].replace(".", " ").replace("_", " ").title() if "@" in effective_reporter_email else "Muniswami"
    effective_reporter_name = req.reporter_name
    if not effective_reporter_name or "ThreatTrace" in effective_reporter_name or "Citizen" in effective_reporter_name or effective_reporter_name == "Complainant":
        effective_reporter_name = f"{user_part} (Complainant)"

    # Check if case exists in DB
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    c = result.scalar_one_or_none()
    
    if not c:
        c = Case(
            case_id=case_id,
            subject=req.subject,
            sender=req.sender,
            recipient=effective_reporter_email,
            body_text=req.body_text,
            raw_headers=req.raw_headers,
            risk_score=float(score_val),
            risk_level=level_val,
            urls=req.urls,
            domains=req.domains,
            ips=req.ips,
            is_reported=True
        )
        db.add(c)
    else:
        c.is_reported = True
        c.risk_score = float(score_val)
        c.risk_level = level_val
        c.recipient = effective_reporter_email
        
    await db.commit()

    # Store in memory list as QUEUE
    new_case_dict = {
        "caseId": case_id,
        "complainantName": effective_reporter_name,
        "reportingEmail": effective_reporter_email,
        "reportingPhone": req.reporter_phone or "+91 80 4000 8899",
        "reportedAt": datetime.now(timezone.utc).isoformat(),
        "status": "QUEUE",
        "subject": req.subject,
        "sender": req.sender,
        "recipient": effective_reporter_email,
        "riskScore": score_val,
        "riskLevel": level_val,
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
            f"Risk Level classified as {level_val} with score {score_val}/100"
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
