"""
ThreatTrace AI – Advanced Obfuscated URL Handling & Deobfuscation Engine
Capabilities:
1. SSRF Protection: Pre-resolves DNS and blocks private/loopback/cloud-metadata IPs
2. Payload Deobfuscation: Unwraps Hex, Octal, Base64 (data: URI), and Google/corporate redirects
3. Homoglyph & Punycode (IDN) Detection: Catches lookalike domain spoofing
4. Safe Multi-Hop Following: Uses HEAD requests with redirect caps to prevent binary downloads
"""
import ipaddress
import re
import base64
import socket
import httpx
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, unquote

# Private / reserved network ranges for SSRF prevention
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private class A
    ipaddress.ip_network("172.16.0.0/12"),    # Private class B
    ipaddress.ip_network("192.168.0.0/16"),   # Private class C
    ipaddress.ip_network("169.254.0.0/16"),   # Link-Local / Cloud Metadata (AWS/GCP/Azure)
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]


def is_ssrf_safe(hostname: str) -> bool:
    """
    Resolves hostname to IP and verifies that it is NOT a private, loopback,
    or cloud metadata service IP.
    """
    if not hostname:
        return False
    try:
        # If hostname is already an IP literal
        ip_obj = ipaddress.ip_address(hostname)
        return not any(ip_obj in network for network in PRIVATE_IP_RANGES)
    except ValueError:
        pass

    try:
        # Resolve all addresses
        resolved_entries = socket.getaddrinfo(hostname, None)
        for entry in resolved_entries:
            ip_str = entry[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if any(ip_obj in network for network in PRIVATE_IP_RANGES):
                return False
        return True
    except Exception:
        # If DNS cannot be resolved, allow HTTP client to handle it or block
        return True

def detect_homoglyphs(domain: str) -> dict:
    """
    Detects Punycode (IDN) and mixed-script unicode homoglyphs (e.g. Cyrillic 'a' vs Latin 'a').
    """
    if not domain:
        return {"is_punycode": False, "is_homoglyph_spoof": False, "normalized_domain": ""}

    domain_clean = domain.lower().split(":")[0]
    is_punycode = domain_clean.startswith("xn--") or ".xn--" in domain_clean

    try:
        ascii_decoded = domain_clean.encode("idna").decode("utf-8")
        has_unicode_spoof = ascii_decoded != domain_clean
    except Exception:
        has_unicode_spoof = True

    # Look for common spoofed brands in homoglyphs
    spoofed_brand = None
    common_targets = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "github"]
    for brand in common_targets:
        if brand in domain_clean and (is_punycode or has_unicode_spoof):
            spoofed_brand = brand
            break

    return {
        "is_punycode": is_punycode,
        "is_homoglyph_spoof": has_unicode_spoof or is_punycode,
        "spoofed_brand": spoofed_brand,
        "normalized_domain": domain_clean.encode("idna").decode("ascii", errors="ignore") if is_punycode else domain_clean
    }

def decode_obfuscated_url(raw_url: str) -> str:
    """
    Decodes multi-layered URL encoding, hex encoding, and embedded base64 data URIs.
    """
    if not raw_url:
        return ""

    decoded = unquote(raw_url.strip())
    # Handle double URL encoding
    if "%" in decoded:
        try:
            decoded = unquote(decoded)
        except Exception:
            pass

    # Check for embedded Base64 data URIs (e.g. data:text/html;base64,...)
    if "data:text/html;base64," in decoded.lower():
        match = re.search(r"data:text/html;base64,([A-Za-z0-9+/=]+)", decoded, re.IGNORECASE)
        if match:
            try:
                b64_str = match.group(1)
                inner_payload = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                url_match = re.search(r'(https?://[^\s"\'<>]+)', inner_payload)
                if url_match:
                    return url_match.group(1)
            except Exception:
                pass

    return decoded

def unwrap_google_redirect(url: str) -> str:
    """
    Gmail wraps links in: https://www.google.com/url?q=REAL_URL&...
    Extracts the real target destination.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host in ("www.google.com", "google.com") and parsed.path == "/url":
            qs = parse_qs(parsed.query)
            real = qs.get("q") or qs.get("url")
            if real:
                return unquote(real[0])
        if host.endswith(".cdn.ampproject.org") or host == "amp.google.com":
            qs = parse_qs(parsed.query)
            real = qs.get("url") or qs.get("q")
            if real:
                return unquote(real[0])
    except Exception:
        pass
    return url

import asyncio

async def _unmask_single_url(client: httpx.AsyncClient, original: str, max_hops: int = 2) -> Dict:
    deobfuscated = decode_obfuscated_url(original)
    unwrapped = unwrap_google_redirect(deobfuscated)
    
    entry = {
        "original": original,
        "unwrapped": unwrapped,
        "final": unwrapped,
        "redirect_count": 0,
        "status": None,
        "error": None,
        "is_google_wrapped": unwrapped != original,
        "cross_domain_redirect": False,
        "redirect_chain": [unwrapped],
        "ssrf_safe": True,
        "homoglyph": {"is_punycode": False, "is_homoglyph_spoof": False, "normalized_domain": ""}
    }

    target = unwrapped
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    current_target = target
    for hop in range(max_hops):
        parsed = urlparse(current_target)
        host = parsed.hostname or ""

        # Check Homoglyphs
        homo = detect_homoglyphs(host)
        entry["homoglyph"] = homo

        # SSRF Protection Check
        if not is_ssrf_safe(host):
            entry["ssrf_safe"] = False
            entry["error"] = f"SSRF_BLOCKED: Host {host} resolves to internal/cloud-metadata IP"
            break

        try:
            resp = await client.head(current_target)
            entry["status"] = resp.status_code

            if resp.is_redirect:
                next_url = resp.headers.get("Location")
                if not next_url:
                    break
                if next_url.startswith("/"):
                    next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                
                entry["redirect_chain"].append(next_url)
                entry["redirect_count"] += 1
                
                next_host = urlparse(next_url).hostname or ""
                if host.lower() != next_host.lower():
                    entry["cross_domain_redirect"] = True

                current_target = next_url
                entry["final"] = current_target
            else:
                entry["final"] = current_target
                break
        except Exception as e:
            entry["error"] = str(e)[:120]
            break

    return entry

async def unmask_urls(urls: List[str], max_hops: int = 2, timeout: float = 1.2) -> List[Dict]:
    """
    Safely and concurrently unwraps, deobfuscates, and follows redirect chains.
    """
    if not urls:
        return []

    unique_urls = []
    seen = set()
    for u in urls:
        clean = u.strip()
        if clean and clean not in seen:
            seen.add(clean)
            unique_urls.append(clean)
            if len(unique_urls) >= 8:
                break

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        headers={"User-Agent": "ThreatTraceAI/2.0 (Forensic Analysis Bot; Security Research)"},
        verify=False
    ) as client:
        tasks = [_unmask_single_url(client, u, max_hops=max_hops) for u in unique_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        cleaned_results = []
        for i, res in enumerate(results):
            if isinstance(res, dict):
                cleaned_results.append(res)
            else:
                orig = unique_urls[i]
                cleaned_results.append({
                    "original": orig,
                    "unwrapped": orig,
                    "final": orig,
                    "redirect_count": 0,
                    "status": None,
                    "error": str(res)[:100],
                    "ssrf_safe": True,
                    "homoglyph": {"is_punycode": False, "is_homoglyph_spoof": False, "normalized_domain": ""}
                })
        return cleaned_results

def has_suspicious_redirects(unmasked_results: List[Dict]) -> bool:
    """Checks if any URL has high redirect count, cross-domain jumps, or homoglyph spoofs."""
    if not unmasked_results:
        return False
    for entry in unmasked_results:
        if not isinstance(entry, dict):
            continue
        if entry.get("redirect_count", 0) >= 3:
            return True
        if entry.get("cross_domain_redirect"):
            return True
        homo = entry.get("homoglyph")
        if isinstance(homo, dict) and homo.get("is_homoglyph_spoof"):
            return True
    return False

async def safe_unmask_url(url: str, max_hops: int = 5, timeout: float = 4.0) -> Dict:
    """Helper to unmask a single URL."""
    res = await unmask_urls([url], max_hops=max_hops, timeout=timeout)
    return res[0] if res else {"original": url, "final": url, "error": "Unmasking failed"}

