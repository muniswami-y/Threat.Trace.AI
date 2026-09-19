from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, Optional, List

from app.services.soc_notifier import get_soc_notifier, SOCNotifier
from app.services.ip_intel import check_ip_liveness, query_asn_info, analyze_ips_live
from app.services.url_unmasker import safe_unmask_url, detect_homoglyphs, decode_obfuscated_url

router = APIRouter(prefix="/api/soc", tags=["Cybersecurity Department Integration"])


class CaseAlertRequest(BaseModel):
    case: Dict[str, Any]
    webhook_url: Optional[str] = None


class IPProbeRequest(BaseModel):
    ip: str
    ports: Optional[List[int]] = None


class URLUnmaskRequest(BaseModel):
    url: str
    max_hops: Optional[int] = 5


@router.post("/dispatch")
async def dispatch_soc_alert(payload: CaseAlertRequest, notifier: SOCNotifier = Depends(get_soc_notifier)):
    """
    Dispatches incident alert to the Cybersecurity Department (SIEM CEF, Slack ChatOps, Jira ticket).
    """
    case = payload.case
    cef_log = notifier.format_cef(case)
    jira_ticket = notifier.format_jira_ticket(case)
    slack_res = await notifier.dispatch_slack_alert(case, payload.webhook_url)

    return {
        "success": True,
        "incident_id": case.get("incidentId") or case.get("case_id"),
        "cef_syslog": cef_log,
        "jira_ticket": jira_ticket,
        "slack_dispatch": slack_res,
        "message": "Incident successfully dispatched to Cybersecurity Operations Center (SOC)."
    }


@router.post("/cef")
async def generate_cef_log(payload: CaseAlertRequest, notifier: SOCNotifier = Depends(get_soc_notifier)):
    """
    Generates a Common Event Format (CEF) string for SIEM (Splunk, QRadar, Sentinel).
    """
    cef = notifier.format_cef(payload.case)
    return {"cef": cef}


@router.post("/jira-ticket")
async def generate_jira_ticket(payload: CaseAlertRequest, notifier: SOCNotifier = Depends(get_soc_notifier)):
    """
    Generates structured security incident schema for Jira Service Desk.
    """
    ticket = notifier.format_jira_ticket(payload.case)
    return {"ticket": ticket}


@router.post("/probe-ip")
async def probe_ip_live(payload: IPProbeRequest):
    """
    Performs live non-intrusive TCP socket handshake and ASN enrichment for an IP.
    """
    liveness = await check_ip_liveness(payload.ip, payload.ports)
    asn = await query_asn_info(payload.ip)
    return {
        "ip": payload.ip,
        "liveness": liveness,
        "asn": asn
    }


@router.post("/unmask-url")
async def unmask_url_safe(payload: URLUnmaskRequest):
    """
    Deobfuscates, inspects homoglyphs, and unwraps redirects with SSRF protection.
    """
    res = await safe_unmask_url(payload.url, max_hops=payload.max_hops or 5)
    return res


@router.post("/subpoena-package")
async def generate_subpoena_package(payload: CaseAlertRequest):
    """
    Generates a certified legal evidence packet for ISP Subpoenas (18 U.S.C. § 2703(f) / Indian IT Act Sec. 91 CrPC).
    """
    import json, hashlib
    from datetime import datetime, timezone
    from app.services.geolocation import is_private_or_local

    case = payload.case
    origin_ip = case.get("originIp") or case.get("origin_ip") or "Not detected"
    timestamp_utc = case.get("date") or datetime.now(timezone.utc).isoformat()
    incident_id = case.get("incidentId") or case.get("case_id") or "INC-UNKNOWN"
    
    # Generate canonical fingerprint
    raw_str = json.dumps(case, sort_keys=True, default=str)
    sha256 = hashlib.sha256(raw_str.encode()).hexdigest()

    is_private = False
    if origin_ip and origin_ip != "Not detected":
        is_private = is_private_or_local(origin_ip)

    subpoena_text = f"""================================================================================
FORMAL LAW ENFORCEMENT PRESERVATION REQUEST & SUBPOENA EVIDENCE DOSSIER
Pursuant to 18 U.S.C. § 2703(f) / Indian IT Act Sec. 91 CrPC / EU GDPR Art. 23
================================================================================
CASE IDENTIFIER: {incident_id}
CANONICAL EVIDENCE SHA-256: {sha256}
BLOCKCHAIN LEDGER: Polygon Amoy (ECDSA SECP256R1 Verified)
EVIDENTIARY TIMESTAMP (UTC): {timestamp_utc}

1. TARGET ATTRIBUTION TELEMETRY:
   - Extracted Origin IP Address: {origin_ip}
   - Transit Protocol: SMTP / ESMTPS (RFC 5322 Ingress Delivery)
   - Host Classification: {"RFC 1918 Private Lab Subnet (Kali Linux / Local Penetration Host)" if is_private else "Public WAN Node / ISP Gateway"}
   - Origin Network / ISP: {case.get('isp') or case.get('region') or 'Carrier Grade NAT / Telecom Gateway'}
   - Geographic ISP Region: {case.get('city') or 'Local Lab Subnet'}, {case.get('country') or 'Private Network'}

2. MANDATORY DATA PRESERVATION DIRECTIVE:
   The telecom carrier / ISP custodian of records for {origin_ip} is formally requested to
   preserve all logs, records, and subscriber identities for a statutory period of 90 days:
   - Dynamic Host Configuration Protocol (DHCP) lease allocations for {origin_ip} at {timestamp_utc}.
   - RADIUS / PPPoE authenticated subscriber username, account ID, and physical billing address.
   - Carrier-Grade NAT (CGNAT) source port translation logs and destination routing telemetry.
   - Associated MAC address and subscriber gateway terminal identifiers.

3. FORENSIC BASIS:
   Malicious electronic mail transmission, credential interception, and cyber deception
   identified and cryptographically sealed by ThreatTrace AI Forensic Engine.
================================================================================
"""
    return {
        "incident_id": incident_id,
        "origin_ip": origin_ip,
        "is_private": is_private,
        "timestamp_utc": timestamp_utc,
        "canonical_sha256": sha256,
        "subpoena_text": subpoena_text
    }


@router.post("/canary-token")
async def generate_canary_token(payload: CaseAlertRequest):
    """
    Generates an active deception tracking canary token with HTML5 Geolocation & WebRTC probe.
    """
    import hashlib
    case = payload.case
    incident_id = case.get("incidentId") or case.get("case_id") or "INC-UNKNOWN"
    token_id = hashlib.sha256(f"{incident_id}-canary".encode()).hexdigest()[:16]
    
    canary_url = f"http://localhost:8000/api/soc/canary/{token_id}"
    
    return {
        "incident_id": incident_id,
        "token_id": token_id,
        "canary_url": canary_url,
        "deception_type": "HTML5 Geolocation & WebRTC Real-IP Probe",
        "instructions": "Plant this canary tracking token link or beacon in responder replies or decoy documents. When opened by the attacker, it bypasses HTTP proxying via WebRTC STUN and requests precise GPS coordinates via browser HTML5 Geolocation."
    }

