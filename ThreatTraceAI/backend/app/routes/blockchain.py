from fastapi import APIRouter
from pydantic import BaseModel
from app.services.blockchain_service import prepare_case_hash, log_case_to_chain

router = APIRouter(prefix="/api/blockchain", tags=["Blockchain"])

class HashRequest(BaseModel):
    case: dict

@router.post("/hash")
async def compute_hash(payload: HashRequest):
    h = prepare_case_hash(payload.case)
    return {"case_hash": h}

@router.post("/log")
async def log_hash(payload: HashRequest):
    result = await log_case_to_chain(payload.case)
    return result
