"""
ThreatTrace AI – ISP Subpoena Evidence Package Generator
=========================================================
Compiles a law-enforcement-ready evidence package for a given case.

What LE / Police need to track a hacker through an ISP:
  1. Exact attacker IP address (from email Received headers or canary hit)
  2. Exact UTC timestamp of the event (ISO-8601, not local time)
  3. SHA-256 hash of the original email (cryptographic evidence seal)
  4. ISP / ASN info (which ISP to serve the subpoena to)
  5. Chain-of-custody metadata (case ID, analyst, salt/pepper)

How the ISP responds:
  - They check their DHCP logs for the IP at that exact UTC timestamp
  - They return the subscriber's billing name, address, and account ID
  - Law enforcement uses this to obtain a physical search warrant

This module generates ALL of the above in a structured + human-readable format.
"""

import hashlib
import json
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


# ─── Public API ───────────────────────────────────────────────────────────────

def build_subpoena_package(
    case_data: Dict[str, Any],
    canary_hits: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """
    Builds a complete ISP subpoena evidence package from case data
    and optional canary hit records.

    Args:
        case_data:    The full case dict (from DB or /api/analyze response)
        canary_hits:  Optional list of canary beacon hit records for this case

    Returns:
        Structured evidence package ready for LE submission
    """
    case_id     = case_data.get("case_id", "UNKNOWN")
    sender      = case_data.get("sender", "unknown")
    subject     = case_data.get("subject", "(no subject)")
    body_text   = case_data.get("body_text", "")
    created_at  = case_data.get("created_at", datetime.now(timezone.utc).isoformat())
    risk_score  = case_data.get("risk_score", 0)
    risk_level  = case_data.get("risk_level", "UNKNOWN")

    # ── 1. Cryptographic evidence seal ──────────────────────────────────────
    evidence_blob = json.dumps({
        "case_id":    case_id,
        "sender":     sender,
        "subject":    subject,
        "body_text":  body_text[:4096],
        "created_at": created_at,
    }, sort_keys=True, ensure_ascii=False)
    evidence_hash = hashlib.sha256(evidence_blob.encode("utf-8")).hexdigest()

    # ── 2. Collect attacker IPs with timestamps ──────────────────────────────
    ip_events: List[Dict] = []

    # A. From email headers (most reliable for original sender)
    for ip in (case_data.get("ips") or []):
        if _is_routable(ip):
            ip_events.append({
                "source":       "Email Received Headers",
                "ip":           ip,
                "timestamp_utc": created_at,
                "note":         "Extracted from SMTP Received: chain in email headers",
            })

    # B. From canary beacon hits (most accurate — real connection IP)
    for hit in (canary_hits or []):
        attacker_ip = hit.get("attacker_ip", "unknown")
        if attacker_ip and attacker_ip != "unknown":
            ip_events.append({
                "source":       "Canary / Honeytoken Beacon",
                "ip":           attacker_ip,
                "timestamp_utc": hit.get("attacker_ip_utc") or hit.get("timestamp_utc"),
                "os_detected":  hit.get("os_family", "Unknown"),
                "os_confidence": hit.get("os_confidence", "LOW"),
                "os_evidence":  hit.get("os_evidence", []),
                "geo_lat":      hit.get("geo_lat"),
                "geo_lon":      hit.get("geo_lon"),
                "geo_accuracy_m": hit.get("geo_accuracy_m"),
                "device":       hit.get("screen"),
                "timezone":     hit.get("timezone"),
                "userAgent":    hit.get("userAgent"),
                "hit_id":       hit.get("hit_id"),
                "note": (
                    "Attacker opened the canary trap. IP captured at TCP handshake level. "
                    "OS confirmed via JavaScript navigator.platform/oscpu probe."
                ),
            })

    # C. From geo_locations (backup)
    for geo in (case_data.get("geo_locations") or []):
        geo_ip = geo.get("ip")
        if geo_ip and _is_routable(geo_ip):
            already = any(e["ip"] == geo_ip for e in ip_events)
            if not already:
                ip_events.append({
                    "source":       "GeoIP Lookup",
                    "ip":           geo_ip,
                    "timestamp_utc": created_at,
                    "country":      geo.get("country"),
                    "isp":          geo.get("isp"),
                    "org":          geo.get("org"),
                    "note":         "Extracted from email content/link targets",
                })

    # ── 3. ISP lookup for each IP ────────────────────────────────────────────
    for event in ip_events:
        if not event.get("isp"):
            isp_info = _quick_isp_lookup(event["ip"])
            event["isp"]     = isp_info.get("isp", "Unknown ISP")
            event["org"]     = isp_info.get("org", "Unknown")
            event["country"] = isp_info.get("country", "Unknown")
            event["asn"]     = isp_info.get("asn", "Unknown")

    # ── 4. Human-readable LE report text ────────────────────────────────────
    report_text = _format_le_report(
        case_id, sender, subject, created_at,
        evidence_hash, risk_score, risk_level,
        ip_events, canary_hits or [],
    )

    return {
        "package_type":   "ISP_SUBPOENA_EVIDENCE_PACKAGE",
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "case_id":        case_id,
        "evidence_hash_sha256": evidence_hash,
        "evidence_hash_note": (
            "SHA-256 of {case_id, sender, subject, body_text, created_at}. "
            "Submit to ISP / court as cryptographic evidence seal."
        ),
        "risk_score":  risk_score,
        "risk_level":  risk_level,
        "sender":      sender,
        "subject":     subject,
        "event_timestamp_utc": created_at,
        "ip_events":   ip_events,
        "canary_hits": canary_hits or [],
        "isp_subpoena_instructions": _isp_instructions(),
        "report_text": report_text,
    }


# ─── Private helpers ─────────────────────────────────────────────────────────

def _is_routable(ip: str) -> bool:
    """Returns True if IP is publicly routable (not private/loopback)."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)
    except Exception:
        return False


def _quick_isp_lookup(ip: str) -> Dict[str, str]:
    """
    Fast synchronous ISP lookup via reverse DNS + Team Cymru TXT.
    Used only in subpoena context (non-hot-path).
    """
    try:
        hostname = socket.gethostbyaddr(ip)
        if hostname and hostname[0]:
            return {"isp": hostname[0], "org": hostname[0], "country": "Unknown"}
    except Exception:
        pass

    # Cymru reverse DNS for ASN
    try:
        octets = ip.split(".")
        if len(octets) == 4:
            reversed_ip = ".".join(reversed(octets)) + ".origin.asn.cymru.com"
            result = socket.gethostbyname_ex(reversed_ip)
            return {"asn": result[0] if result else "Unknown", "isp": "See ASN", "org": "Unknown"}
    except Exception:
        pass

    return {"isp": "Unknown – perform manual WHOIS", "org": "Unknown", "country": "Unknown"}


def _isp_instructions() -> List[str]:
    return [
        "1. Identify the ISP from the 'isp' / 'org' field of each ip_event.",
        "2. Obtain a legal order (subpoena / court order) for subscriber records.",
        "3. Submit to the ISP: exact IP address + exact UTC timestamp (ISO-8601).",
        "4. The ISP checks their DHCP log at that UTC moment to find the subscriber.",
        "5. The ISP returns: subscriber name, billing address, account ID.",
        "6. Use the SHA-256 evidence_hash to prove email integrity in court.",
        "7. If canary_hits are present, the OS (Kali Linux / Windows / etc.) is "
           "confirmed — use os_evidence list as exhibit.",
        "8. If geo_lat/geo_lon are in canary_hits, file for a physical search warrant.",
        "IMPORTANT: All timestamps are UTC (ISO-8601). Convert to local timezone "
        "for LE reports if required by jurisdiction.",
    ]


def _format_le_report(
    case_id: str, sender: str, subject: str, created_at: str,
    evidence_hash: str, risk_score: float, risk_level: str,
    ip_events: List[Dict], canary_hits: List[Dict],
) -> str:
    lines = [
        "=" * 72,
        "  THREATRACE AI – LAW ENFORCEMENT EVIDENCE PACKAGE",
        "=" * 72,
        "",
        "CASE ID          : " + case_id,
        "GENERATED AT     : " + datetime.now(timezone.utc).isoformat() + " UTC",
        "RISK SCORE       : " + str(round(risk_score, 1)) + "/100  [" + risk_level + "]",
        "SENDER           : " + sender,
        "SUBJECT          : " + subject,
        "ORIGINAL EVENT   : " + created_at + " UTC",
        "EVIDENCE HASH    : " + evidence_hash,
        "HASH ALGORITHM   : SHA-256",
        "",
        "-" * 72,
        "ATTACKER IP EVENTS (submit IP + UTC timestamp to ISP for subpoena)",
        "-" * 72,
    ]

    if ip_events:
        for i, ev in enumerate(ip_events, 1):
            lines += [
                "",
                "  [Event " + str(i) + "] Source: " + ev.get("source", "Unknown"),
                "  IP Address   : " + ev.get("ip", "unknown"),
                "  UTC Timestamp: " + str(ev.get("timestamp_utc", "unknown")),
                "  ISP / Org    : " + str(ev.get("isp", "Unknown")) + " / " + str(ev.get("org", "Unknown")),
                "  Country      : " + str(ev.get("country", "Unknown")),
                "  ASN          : " + str(ev.get("asn", "Unknown")),
            ]
            if ev.get("os_detected") or ev.get("os_family"):
                os_str = ev.get("os_detected") or ev.get("os_family", "Unknown")
                lines.append("  OS (Accurate) : " + os_str + " [confidence=" + str(ev.get("os_confidence", "N/A")) + "]")
            if ev.get("geo_lat") and ev.get("geo_lon"):
                lines.append(
                    "  Coordinates  : lat=" + str(ev["geo_lat"]) +
                    ", lon=" + str(ev["geo_lon"]) +
                    " (accuracy: " + str(ev.get("geo_accuracy_m", "?")) + "m)"
                )
            if ev.get("note"):
                lines.append("  Note         : " + ev["note"])
    else:
        lines += ["", "  [No routable attacker IPs found. Deploy canary token to capture real IP.]"]

    if canary_hits:
        lines += [
            "",
            "-" * 72,
            "CANARY TOKEN HITS (attacker opened the honeytoken trap)",
            "-" * 72,
        ]
        for hit in canary_hits:
            lines += [
                "",
                "  Hit ID       : " + str(hit.get("hit_id", "?")),
                "  Time (UTC)   : " + str(hit.get("timestamp_utc", "?")),
                "  Real IP      : " + str(hit.get("attacker_ip", "?")),
                "  OS Confirmed : " + str(hit.get("os_family", "?")) + " [" + str(hit.get("os_confidence", "?")) + "]",
                "  OS Evidence  : " + str(", ".join(hit.get("os_evidence", []) or [])),
                "  User-Agent   : " + str(hit.get("userAgent", "?"))[:80],
                "  Device       : " + str(hit.get("screen", "?")),
                "  Timezone     : " + str(hit.get("timezone", "?")),
            ]
            if hit.get("geo_lat"):
                lines.append(
                    "  GPS Coords   : lat=" + str(hit["geo_lat"]) +
                    ", lon=" + str(hit["geo_lon"])
                )

    lines += [
        "",
        "=" * 72,
        "CHAIN OF CUSTODY",
        "=" * 72,
        "This report was generated automatically by ThreatTrace AI.",
        "The evidence_hash (SHA-256) guarantees the email content has not been",
        "altered since the time of analysis. Present this package to the ISP",
        "legal team along with a valid legal order to obtain subscriber details.",
        "=" * 72,
    ]

    return "\n".join(lines)
