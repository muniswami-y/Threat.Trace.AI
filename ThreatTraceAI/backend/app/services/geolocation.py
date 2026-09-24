"""
Live approximate GeoIP using free ip-api.com (no key required for low volume).
Optimized with parallel async dispatch and 1.2s timeout.
"""
import asyncio
import httpx
import ipaddress
from typing import List, Dict
from app.config import get_settings

settings = get_settings()

def is_private_or_local(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_reserved or obj.is_link_local
    except Exception:
        return False

async def _geolocate_single_ip(client: httpx.AsyncClient, ip: str) -> Dict:
    entry = {
        "ip": ip,
        "country": None,
        "region": None,
        "city": None,
        "lat": None,
        "lon": None,
        "isp": None,
        "org": None,
        "is_private": False,
        "status": "fail"
    }

    if is_private_or_local(ip):
        # NOTE: OS detection (Linux/Windows/Kali) is NOT reliable from IP range alone.
        # The canary JS probe (navigator.platform, navigator.oscpu) provides accurate OS data.
        # We label this neutrally; the canary beacon will capture real OS fingerprint.
        import ipaddress as _ipa
        try:
            addr = _ipa.ip_address(ip)
            if addr.is_loopback:
                subnet_label = "Loopback (localhost)"
                org_label = "Local Machine (Loopback Interface)"
            elif str(ip).startswith("10."):
                subnet_label = "RFC1918 Class-A Private (10.x.x.x)"
                org_label = "Private LAN / Corporate Intranet"
            elif str(ip).startswith("192.168."):
                subnet_label = "RFC1918 Class-C Private (192.168.x.x)"
                org_label = "Home / Office LAN – Router Subnet"
            elif str(ip).startswith("172."):
                subnet_label = "RFC1918 Class-B Private (172.16–31.x.x)"
                org_label = "Private LAN / Docker / VM Host"
            else:
                subnet_label = "RFC1918 Private Subnet"
                org_label = "Private Network Host"
        except Exception:
            subnet_label = "RFC1918 Private Subnet"
            org_label = "Private Network Host"

        entry.update({
            "country": "Private Network (No GeoIP Available)",
            "region": subnet_label,
            "city": f"Private Host – {ip}",
            "isp": "Private LAN / Local Network",
            "org": org_label,
            "lat": None,
            "lon": None,
            "is_private": True,
            "status": "success",
            # OS will be filled in by canary JS beacon if trap is triggered
            "os_fingerprint": None,
            "os_note": "Deploy canary token to capture real OS/platform via JS probe (navigator.platform, navigator.oscpu)"
        })
        return entry

    try:
        url = f"{settings.IP_API_URL}{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,query"
        r = await client.get(url)
        data = r.json()
        if data.get("status") == "success":
            isp = data.get("isp") or ""
            org = data.get("org") or ""
            
            # ESP Provider Masking (to prevent falsely attributing datacenter to the attacker)
            provider_str = (isp + " " + org).lower()
            esp_keywords = ["google", "microsoft", "yahoo", "amazon", "aws", "cloudflare", "fastly", "akamai", "proofpoint", "mimecast"]
            
            if any(k in provider_str for k in esp_keywords):
                entry.update({
                    "country": "Masked (Provider Infrastructure)",
                    "region": "Masked by Email/Cloud Provider",
                    "city": "Unknown (Sender IP Hidden)",
                    "lat": 0.0,
                    "lon": 0.0,
                    "isp": f"{isp} (ESP Gateway)",
                    "org": f"{org} (Original Sender IP Masked for Privacy)",
                    "is_private": False,
                    "status": "success",
                    "error": None
                })
            else:
                entry.update({
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp": isp,
                    "org": org,
                    "is_private": False,
                    "status": "success",
                    "error": None
                })
        else:
            # Fallback for public IP when ip-api rate-limited or unlisted
            entry.update({
                "country": "Public WAN Host",
                "region": "External Subnet",
                "city": f"Host {ip}",
                "isp": "Public Internet Gateway",
                "org": "Unknown",
                "is_private": False,
                "status": "partial",
                "error": data.get("message", "lookup limited")
            })
    except Exception as e:
        entry.update({
            "country": "Public WAN Host",
            "region": "External Subnet",
            "city": f"Host {ip}",
            "isp": "Public Internet Gateway",
            "org": "Unknown",
            "is_private": False,
            "status": "partial",
            "error": str(e)[:100]
        })

    return entry

async def geolocate_ips(ips: List[str]) -> List[Dict]:
    if not ips:
        return []

    unique_ips = list(dict.fromkeys(ips))[:6]

    async with httpx.AsyncClient(timeout=1.2) as client:
        tasks = [_geolocate_single_ip(client, ip) for ip in unique_ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        cleaned = []
        for i, res in enumerate(results):
            if isinstance(res, dict):
                cleaned.append(res)
            else:
                cleaned.append({"ip": unique_ips[i], "status": "fail", "error": str(res)[:80]})
        return cleaned
