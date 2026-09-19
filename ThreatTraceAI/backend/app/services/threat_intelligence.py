"""
Live checks against free public threat intelligence feeds:
  - OpenPhish      : phishing URL feed
  - URLHaus        : abuse.ch malware URL feed
  - Spamhaus DROP  : BGP-hijacked / bulletproof / botnet IP ranges
                     (covers Tor exits, Kali VPS hosts, C2 infrastructure)
  - PhishTank      : community-verified phishing URLs (CSV feed)
  - Domain-level matching (not just exact URL) for all feeds
"""
import httpx
import ipaddress
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse
from app.config import get_settings

settings = get_settings()

# ---------------------------------------------------------------------------
# Cached feeds (refreshed per-process lifecycle)
# ---------------------------------------------------------------------------
_OPENPHISH_URLS: Set[str] = set()
_OPENPHISH_DOMAINS: Set[str] = set()
_OPENPHISH_LOADED = False

_URLHAUS_URLS: Set[str] = set()
_URLHAUS_DOMAINS: Set[str] = set()
_URLHAUS_LOADED = False

# Spamhaus DROP / EDROP (BGP-hijacked ranges, bulletproof hosting, Tor infrastructure)
# Free text feed — no API key required
_SPAMHAUS_RANGES: List[Tuple] = []   # list of ipaddress.IPv4Network objects
_SPAMHAUS_LOADED = False

# PhishTank (community-verified phishing URLs, public CSV)
_PHISHTANK_URLS: Set[str] = set()
_PHISHTANK_DOMAINS: Set[str] = set()
_PHISHTANK_LOADED = False


def _extract_domain(url: str) -> str:
    """Get the hostname from a URL, lowercase."""
    try:
        if not url.startswith("http"):
            url = "http://" + url
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


async def _load_openphish() -> None:
    global _OPENPHISH_URLS, _OPENPHISH_DOMAINS, _OPENPHISH_LOADED
    if _OPENPHISH_LOADED:
        return
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get("https://openphish.com/feed.txt")
            if r.status_code == 200:
                for line in r.text.splitlines()[:5000]:
                    url = line.strip().lower().rstrip("/")
                    if url:
                        _OPENPHISH_URLS.add(url)
                        dom = _extract_domain(url)
                        if dom:
                            _OPENPHISH_DOMAINS.add(dom)
                _OPENPHISH_LOADED = True
    except Exception:
        pass


async def _load_urlhaus() -> None:
    global _URLHAUS_URLS, _URLHAUS_DOMAINS, _URLHAUS_LOADED
    if _URLHAUS_LOADED:
        return
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers={"Accept": "application/json"},
            )
            if r.status_code == 200:
                data = r.json()
                for entry in (data.get("urls") or [])[:1000]:
                    url = (entry.get("url") or "").lower().rstrip("/")
                    if url:
                        _URLHAUS_URLS.add(url)
                        dom = _extract_domain(url)
                        if dom:
                            _URLHAUS_DOMAINS.add(dom)
                _URLHAUS_LOADED = True
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Spamhaus DROP / EDROP loader
# ──────────────────────────────────────────────────────────────────────────────

async def _load_spamhaus_drop() -> None:
    """Loads Spamhaus DROP + EDROP lists (BGP-hijacked IP ranges)."""
    global _SPAMHAUS_RANGES, _SPAMHAUS_LOADED
    if _SPAMHAUS_LOADED:
        return
    feeds = [
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.spamhaus.org/drop/edrop.txt",
    ]
    loaded_ranges = []
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            for url in feeds:
                try:
                    r = await client.get(url)
                    if r.status_code == 200:
                        for line in r.text.splitlines():
                            line = line.strip()
                            if not line or line.startswith(";"):
                                continue
                            # Format: "1.2.3.0/24 ; SBLxxxxxxxxx"
                            cidr = line.split(";")[0].strip()
                            if "/" in cidr:
                                try:
                                    net = ipaddress.IPv4Network(cidr, strict=False)
                                    loaded_ranges.append(net)
                                except ValueError:
                                    pass
                except Exception:
                    continue
        _SPAMHAUS_RANGES = loaded_ranges
        _SPAMHAUS_LOADED = True
    except Exception:
        pass


def _ip_in_spamhaus(ip: str) -> bool:
    """Returns True if IP falls within any Spamhaus DROP/EDROP range."""
    if not _SPAMHAUS_RANGES:
        return False
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in _SPAMHAUS_RANGES)
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# PhishTank loader (verified phishing URLs)
# ──────────────────────────────────────────────────────────────────────────────

async def _load_phishtank() -> None:
    """Loads PhishTank verified phishing URL feed (JSON, no key required for community)."""
    global _PHISHTANK_URLS, _PHISHTANK_DOMAINS, _PHISHTANK_LOADED
    if _PHISHTANK_LOADED:
        return
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            # PhishTank provides a public JSON dump (updated hourly)
            r = await client.get(
                "http://data.phishtank.com/data/online-valid.json",
                headers={"User-Agent": "ThreatTraceAI/1.0 (threattraceai.com)"}
            )
            if r.status_code == 200:
                entries = r.json()
                for entry in entries[:3000]:  # Cap for performance
                    url = (entry.get("url") or "").lower().rstrip("/")
                    if url:
                        _PHISHTANK_URLS.add(url)
                        dom = _extract_domain(url)
                        if dom:
                            _PHISHTANK_DOMAINS.add(dom)
                _PHISHTANK_LOADED = True
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# IP Reputation check (Spamhaus range + UA string correlation)
# ──────────────────────────────────────────────────────────────────────────────

async def check_ip_reputation(ips: List[str]) -> List[Dict]:
    """
    Checks IPs against Spamhaus DROP/EDROP blocklists.
    Flags Tor exit nodes, bulletproof hosts, and botnet C2 ranges
    commonly used by Linux/Kali attackers.
    """
    import asyncio
    if not _SPAMHAUS_LOADED:
        asyncio.create_task(_load_spamhaus_drop())

    results = []
    for ip in ips[:10]:
        entry = {
            "ip": ip,
            "is_malicious": False,
            "sources": [],
            "details": None,
            "le_note": None,
        }

        if _ip_in_spamhaus(ip):
            entry["is_malicious"] = True
            entry["sources"].append("Spamhaus DROP/EDROP")
            entry["details"] = (
                "IP falls within a Spamhaus DROP/EDROP range. "
                "These ranges are BGP-hijacked or used by bulletproof hosting, "
                "Tor infrastructure, and botnet C2 — commonly used by Kali Linux "
                "attackers and cybercriminal infrastructure."
            )
            entry["le_note"] = (
                "This IP is on the Spamhaus DROP/EDROP blocklist. "
                "It may be a VPN/proxy endpoint — subpoena the VPN provider "
                "or use canary token to capture the attacker's real exit IP."
            )

        results.append(entry)
    return results


async def check_urls(urls: List[str]) -> List[Dict]:
    """
    Check URLs against OpenPhish + URLHaus feeds.
    Uses both exact URL matching AND domain-level matching.
    """
    import asyncio
    results = []

    # Non-blocking feed refresh in background if not yet loaded
    if not _OPENPHISH_LOADED and settings.OPENPHISH_ENABLED:
        asyncio.create_task(_load_openphish())
    if not _URLHAUS_LOADED:
        asyncio.create_task(_load_urlhaus())
    if not _PHISHTANK_LOADED:
        asyncio.create_task(_load_phishtank())
    if not _SPAMHAUS_LOADED:
        asyncio.create_task(_load_spamhaus_drop())

    for u in urls[:20]:
        u_lower = u.lower().rstrip("/")
        u_domain = _extract_domain(u)

        entry = {
            "url": u,
            "is_malicious": False,
            "source": None,
            "details": None,
            "match_type": None,
        }

        # --- OpenPhish exact URL match ---
        if u_lower in _OPENPHISH_URLS:
            entry["is_malicious"] = True
            entry["source"] = "OpenPhish"
            entry["details"] = "Exact URL match in OpenPhish phishing feed"
            entry["match_type"] = "exact_url"
            results.append(entry)
            continue

        # --- OpenPhish domain-level match ---
        if u_domain and u_domain in _OPENPHISH_DOMAINS:
            entry["is_malicious"] = True
            entry["source"] = "OpenPhish"
            entry["details"] = f"Domain '{u_domain}' found in OpenPhish phishing feed"
            entry["match_type"] = "domain"
            results.append(entry)
            continue

        # --- URLHaus exact URL match ---
        if u_lower in _URLHAUS_URLS:
            entry["is_malicious"] = True
            entry["source"] = "URLHaus (abuse.ch)"
            entry["details"] = "Exact URL match in URLHaus malware feed"
            entry["match_type"] = "exact_url"
            results.append(entry)
            continue

        # --- URLHaus domain-level match ---
        if u_domain and u_domain in _URLHAUS_DOMAINS:
            entry["is_malicious"] = True
            entry["source"] = "URLHaus (abuse.ch)"
            entry["details"] = f"Domain '{u_domain}' found in URLHaus malware feed"
            entry["match_type"] = "domain"
            results.append(entry)
            continue

        # --- Partial / prefix matching for OpenPhish ---
        matched = False
        for feed_url in _OPENPHISH_URLS:
            if len(feed_url) > 10 and (
                u_lower.startswith(feed_url) or feed_url.startswith(u_lower)
            ):
                entry["is_malicious"] = True
                entry["source"] = "OpenPhish"
                entry["details"] = "Partial URL match in OpenPhish feed"
                entry["match_type"] = "partial"
                matched = True
                break
        if matched:
            results.append(entry)
            continue

        # --- PhishTank exact URL match ---
        if u_lower in _PHISHTANK_URLS:
            entry["is_malicious"] = True
            entry["source"] = "PhishTank"
            entry["details"] = "Exact URL match in PhishTank verified phishing database"
            entry["match_type"] = "exact_url"
            results.append(entry)
            continue

        # --- PhishTank domain-level match ---
        if u_domain and u_domain in _PHISHTANK_DOMAINS:
            entry["is_malicious"] = True
            entry["source"] = "PhishTank"
            entry["details"] = "Domain '" + u_domain + "' found in PhishTank phishing database"
            entry["match_type"] = "domain"
            results.append(entry)
            continue

        results.append(entry)

    return results


async def check_domains(domains: List[str]) -> List[Dict]:
    """Check domains against all loaded feeds."""
    results = []

    if settings.OPENPHISH_ENABLED:
        await _load_openphish()
    await _load_urlhaus()

    for d in domains[:15]:
        d_lower = d.lower()
        entry = {
            "domain": d,
            "is_malicious": False,
            "source": None,
            "details": None,
        }

        if d_lower in _OPENPHISH_DOMAINS:
            entry["is_malicious"] = True
            entry["source"] = "OpenPhish"
            entry["details"] = f"Domain listed in OpenPhish phishing feed"
        elif d_lower in _URLHAUS_DOMAINS:
            entry["is_malicious"] = True
            entry["source"] = "URLHaus (abuse.ch)"
            entry["details"] = f"Domain listed in URLHaus malware feed"
        else:
            entry["details"] = "Not found in threat feeds"

        results.append(entry)

    return results
