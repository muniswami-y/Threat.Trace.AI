from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from app.services.crypto_service import get_crypto_service, CryptoService

router = APIRouter(prefix="/api/crypto", tags=["Cryptography"])


class SealRequest(BaseModel):
    case: Dict[str, Any]


class VerifyRequest(BaseModel):
    case: Dict[str, Any]
    signature: str
    expected_hash: Optional[str] = None
    public_key_pem: Optional[str] = None


class EncryptRequest(BaseModel):
    dossier: Dict[str, Any]
    passphrase: str


class DecryptRequest(BaseModel):
    envelope: Dict[str, Any]
    passphrase: str


class HeaderCryptoRequest(BaseModel):
    raw_headers: str


@router.post("/seal")
async def seal_case_evidence(payload: SealRequest, cs: CryptoService = Depends(get_crypto_service)):
    """
    Cryptographically seals a forensic case with canonical SHA-256 and ECDSA signature.
    """
    try:
        seal = cs.seal_case(payload.case)
        return {
            "success": True,
            "seal": seal,
            "message": "Case cryptographically sealed with ECDSA digital signature and canonical hash."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to seal case: {str(e)}")


@router.post("/verify")
async def verify_case_integrity(payload: VerifyRequest, cs: CryptoService = Depends(get_crypto_service)):
    """
    Verifies that case evidence has not been tampered with since signing.
    """
    try:
        result = cs.verify_seal(
            current_case=payload.case,
            signature_hex=payload.signature,
            public_key_pem=payload.public_key_pem,
            expected_hash=payload.expected_hash
        )
        return {
            "success": True,
            "verification": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@router.post("/simulate-tamper")
async def simulate_tamper_attack(payload: SealRequest, cs: CryptoService = Depends(get_crypto_service)):
    """
    Demonstrates tamper-resistance by altering 1 byte/field and showing immediate failure.
    """
    try:
        report = cs.simulate_tamper_attack(payload.case)
        return {
            "success": True,
            "simulation": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")


@router.post("/encrypt")
async def encrypt_evidence_vault(payload: EncryptRequest, cs: CryptoService = Depends(get_crypto_service)):
    """
    End-to-End encrypts a forensic incident report using AES-256-GCM + PBKDF2.
    """
    try:
        envelope = cs.encrypt_dossier(payload.dossier, payload.passphrase)
        return {
            "success": True,
            "envelope": envelope,
            "message": "Forensic evidence package successfully encrypted with AES-256-GCM."
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Encryption failed: {str(e)}")


@router.post("/decrypt")
async def decrypt_evidence_vault(payload: DecryptRequest, cs: CryptoService = Depends(get_crypto_service)):
    """
    Decrypts an AES-256-GCM encrypted forensic envelope using the passphrase.
    """
    try:
        decrypted = cs.decrypt_dossier(payload.envelope, payload.passphrase)
        return {
            "success": True,
            "dossier": decrypted,
            "message": "Authentication tag verified. Evidence decrypted successfully."
        }
    except ValueError as ve:
        raise HTTPException(status_code=401, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")


@router.get("/keys")
async def get_authority_keys(cs: CryptoService = Depends(get_crypto_service)):
    """
    Returns the public key and fingerprint of the ThreatTrace Forensic Authority.
    """
    return {
        "public_key_pem": cs.get_public_key_pem(),
        "key_fingerprint": cs.get_key_fingerprint(),
        "algorithm": "ECDSA SECP256R1 with SHA-256",
        "jurisdiction": "ThreatTrace AI Cyber Forensic Authority",
        "standard": "FIPS 186-4 ECDSA Digital Signature Standard"
    }


@router.post("/inspect-headers")
async def inspect_header_cryptography(payload: HeaderCryptoRequest, cs: CryptoService = Depends(get_crypto_service)):
    """
    Inspects raw email headers for DKIM cryptographic signatures and key alignment.
    """
    result = cs.inspect_dkim_cryptography(payload.raw_headers)
    return {
        "success": True,
        "dkim_cryptography": result
    }
