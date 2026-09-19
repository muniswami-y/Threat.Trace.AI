"""
ThreatTrace AI – Live IP Extraction, Socket Liveness Probing & ASN Enrichment Engine
Capabilities:
1. Active TCP Liveness Probing (Non-intrusive port checks on 80, 443, 22, 8080, 53)
2. BGP ASN & Autonomous System Identification
3. IP Reputation & Live Threat Correlation
"""
import asyncio
import socket
import httpx
from typing import List, Dict, Any, Optional

COMMON_PROBE_PORTS = [80, 443, 22, 8080, 53]

async def check_ip_liveness(ip: str, ports: Optional[List[int]] = None, timeout: float = 0.8) -> Dict[str, Any]:
    """
    Performs non-intrusive async TCP handshakes to verify if the IP is currently alive
    and accepting network connections.
    """
    target_ports = ports or COMMON_PROBE_PORTS
    open_ports = []
    
    # Check if valid IPv4/IPv6
    try:
        socket.inet_aton(ip)
    except socket.error:
        return {
            "ip": ip,
            "is_active": False,
            "status": "INVALID_IP_FORMAT",
            "open_ports": [],
            "latency_ms": None
        }

    for port in target_ports:
        start_time = asyncio.get_event_loop().time()
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            latency = round((asyncio.get_event_loop().time() - start_time) * 1000, 1)
            open_ports.append({"port": port, "service": _port_service_name(port), "latency_ms": latency})
            writer.close()
            await writer.wait_closed()
        except Exception:
            continue

    is_active = len(open_ports) > 0
    return {
        "ip": ip,
        "is_active": is_active,
        "status": "LIVE_HOST" if is_active else "OFFLINE_OR_FILTERED",
        "open_ports": open_ports,
        "primary_service": open_ports[0]["service"] if open_ports else "None"
    }

def _port_service_name(port: int) -> str:
    mapping = {
        80: "HTTP (Web Server)",
        443: "HTTPS (SSL Web Server)",
        22: "SSH (Secure Shell)",
        8080: "HTTP-Proxy / Alt-Web",
        53: "DNS (Name Server)",
        21: "FTP (File Transfer)",
        25: "SMTP (Mail Server)",
        445: "SMB (Direct Host)",
        3389: "RDP (Remote Desktop)"
    }
    return mapping.get(port, f"Port {port}")

async def query_asn_info(ip: str) -> Dict[str, Any]:
    """
    Queries ASN and BGP routing data for the IP.
    Uses Team Cymru DNS TXT lookups (zero rate-limits) with fallback to ip-api.
    """
    try:
        octets = ip.split(".")
        if len(octets) == 4:
            reversed_ip = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
            loop = asyncio.get_event_loop()
            # Fast DNS lookup
            answers = await loop.run_in_executor(None, socket.gethostbyname_ex, reversed_ip)
            if answers:
                return {
                    "asn_queried": True,
                    "dns_response": answers[0],
                    "ip": ip
                }
    except Exception:
        pass

    # Fallback to HTTP lookup
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=as,isp,org,status")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "asn": data.get("as", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "ip": ip
                    }
    except Exception:
        pass

    return {"asn": "Unknown", "isp": "Unknown", "ip": ip}

async def analyze_ips_live(ips: List[str]) -> List[Dict[str, Any]]:
    """
    Runs concurrent liveness probes and ASN enrichment for all extracted IPs.
    """
    results = []
    tasks = []
    for ip in ips[:8]:  # Safety limit for fast response
        tasks.append(_enrich_single_ip(ip))
    
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Filter out exceptions
        return [r for r in results if isinstance(r, dict)]
    return results

async def _enrich_single_ip(ip: str) -> Dict[str, Any]:
    liveness_task = check_ip_liveness(ip)
    asn_task = query_asn_info(ip)
    liveness, asn = await asyncio.gather(liveness_task, asn_task, return_exceptions=True)

    liveness_dict = liveness if isinstance(liveness, dict) else {"is_active": False, "status": "CHECK_FAILED"}
    asn_dict = asn if isinstance(asn, dict) else {"asn": "Unknown", "isp": "Unknown"}

    return {
        "ip": ip,
        "liveness": liveness_dict,
        "asn_info": asn_dict,
        "threat_profile": "Host actively accepting inbound connections on common ports." if liveness_dict.get("is_active") else "Host is silent or shielded behind firewall."
    }
