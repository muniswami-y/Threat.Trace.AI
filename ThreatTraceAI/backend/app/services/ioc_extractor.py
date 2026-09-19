"""
Extract URLs, domains, and IPs from email body + headers.
Accurately separates Origin IP (sender infrastructure/Kali Linux) from
Payload IP (destination link hosting web server).
"""
import re
import socket
from urllib.parse import urlparse
from typing import List, Optional, Dict, Tuple
import tldextract
from app.utils.validators import extract_urls, extract_ips, extract_emails
from app.services.url_unmasker import unwrap_google_redirect

IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Common origin header keys
ORIGIN_HEADER_KEYS = (
    "x-originating-ip",
    "x-sender-ip",
    "x-client-ip",
    "client-ip",
    "x-remote-ip",
    "x-real-ip",
    "x-forwarded-for",
)

def resolve_domain_ip(domain: str) -> Optional[str]:
    """Resolve a domain to its hosting IP address via DNS."""
    try:
        skip_domains = {
            "google.com", "www.google.com", "mail.google.com",
            "googleapis.com", "gstatic.com", "localhost",
        }
        if domain.lower() in skip_domains:
            return None
        # If domain is already an IP, return as-is
        if IPV4_RE.fullmatch(domain):
            return domain
        ip = socket.gethostbyname(domain)
        return ip
    except (socket.gaierror, socket.timeout, OSError):
        pass
    return None


def extract_origin_ip_from_headers(headers: dict) -> Tuple[Optional[str], List[str]]:
    """
    Extract the most accurate sender origin IP and all header hops.
    Preserves private / RFC1918 / Kali Linux IPs.
    """
    if not headers:
        return None, []

    all_header_ips: List[str] = []
    direct_origin_ip: Optional[str] = None

    # Priority 1: Explicit client origin headers (e.g. X-Originating-IP)
    for k, v in headers.items():
        k_lower = k.lower()
        if any(ok == k_lower or ok in k_lower for ok in ORIGIN_HEADER_KEYS):
            values = v if isinstance(v, list) else [v]
            for val in values:
                matches = IPV4_RE.findall(str(val))
                for ip in matches:
                    if not direct_origin_ip:
                        direct_origin_ip = ip
                    if ip not in all_header_ips:
                        all_header_ips.append(ip)

    # Priority 2: Authentication & SPF headers (client-ip=...)
    for k, v in headers.items():
        k_lower = k.lower()
        if any(ak in k_lower for ak in ("authentication-results", "received-spf", "arc-authentication-results")):
            values = v if isinstance(v, list) else [v]
            for val in values:
                spf_ips = re.findall(r'client-ip=([0-9\.]+)', str(val), re.IGNORECASE)
                for ip in spf_ips:
                    if IPV4_RE.fullmatch(ip):
                        if not direct_origin_ip:
                            direct_origin_ip = ip
                        if ip not in all_header_ips:
                            all_header_ips.append(ip)

    # Priority 3: Received headers (tracking delivery hops)
    received_hops: List[str] = []
    for k, v in headers.items():
        if "received" in k.lower():
            values = v if isinstance(v, list) else [v]
            for val in values:
                val_str = str(val)
                # First check for parenthesized or bracketed sender IPs: from ... [ip] or from ... (ip)
                client_matches = re.findall(r'from\s+[^\s\[\(]+\s*[\[\(]([0-9\.]+)[\]\)]', val_str, re.IGNORECASE)
                for ip in client_matches:
                    if IPV4_RE.fullmatch(ip) and ip not in received_hops:
                        received_hops.append(ip)

                # Also capture bracketed from [ip] directly
                direct_from = re.findall(r'from\s+\[([0-9\.]+)\]', val_str, re.IGNORECASE)
                for ip in direct_from:
                    if IPV4_RE.fullmatch(ip) and ip not in received_hops:
                        received_hops.append(ip)

                # Any other IPv4 in Received header
                for ip in IPV4_RE.findall(val_str):
                    if ip not in received_hops:
                        received_hops.append(ip)

    # In SMTP, Received headers are prepended at the top by each hop.
    # The earliest hop (closest to sender / Kali) is at the bottom of the list.
    for ip in received_hops:
        if ip not in all_header_ips:
            all_header_ips.append(ip)

    if not direct_origin_ip and received_hops:
        # Pick the hop closest to the origin client
        direct_origin_ip = received_hops[-1]

    return direct_origin_ip, all_header_ips


def extract_origin_ip_from_text(text: str) -> Optional[str]:
    """
    Fallback: Extract origin IP if explicitly stated in text/body.
    E.g. "IP: 192.168.1.105", "X-Originating-IP: [192.168.1.105]", "Sender IP: 10.0.2.15"
    """
    patterns = [
        r'(?:Origin(?:ating)?|Sender|Client|Source|Kali|Host)\s*IP\s*[:=]\s*([0-9\.]+)',
        r'X-Originating-IP:\s*[\[\(]?([0-9\.]+)[\]\)]?',
        r'Received:\s*from.*?\[([0-9\.]+)\]',
        r'Received:\s*from.*?\(([0-9\.]+)\)',
        r'\bclient-ip=([0-9\.]+)',
        r'\bIP\s*[:=]\s*([0-9\.]+)',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            candidate = m.group(1)
            if IPV4_RE.fullmatch(candidate):
                return candidate
    return None


def extract_iocs(body: str, headers: dict = None, extension_links: list = None) -> dict:
    text = body or ""
    headers = headers or {}

    urls = extract_urls(text)
    emails = extract_emails(text)
    body_ips = extract_ips(text)

    # -------------------------------------------------------------------
    # Merge links sent directly from the browser extension
    # -------------------------------------------------------------------
    if extension_links:
        for link_obj in extension_links:
            href = ""
            if isinstance(link_obj, str):
                href = link_obj
            elif isinstance(link_obj, dict):
                href = link_obj.get("href") or link_obj.get("url") or ""
            href_clean = href.strip()
            if not href_clean or href_clean.lower().startswith(("tel:", "mailto:", "sms:", "callto:", "javascript:", "#")):
                continue
            if href_clean and href_clean not in urls:
                unwrapped = unwrap_google_redirect(href_clean)
                if unwrapped not in urls:
                    urls.append(unwrapped)

    # Unwrap Google redirect wrappers & clean URLs
    unwrapped_urls = []
    for u in urls:
        u_clean = u.strip()
        if u_clean.lower().startswith(("tel:", "mailto:", "sms:", "callto:", "javascript:")):
            continue
        unwrapped = unwrap_google_redirect(u_clean)
        if unwrapped not in unwrapped_urls:
            unwrapped_urls.append(unwrapped)
    urls = unwrapped_urls

    # -------------------------------------------------------------------
    # Extract domains & direct URL payload IPs
    # -------------------------------------------------------------------
    domains = set()
    url_host_ips = []
    for u in urls:
        try:
            if not u.startswith("http"):
                u = "http://" + u
            parsed = urlparse(u)
            host = (parsed.hostname or "").lower()
            if host:
                if IPV4_RE.fullmatch(host):
                    if host not in url_host_ips:
                        url_host_ips.append(host)
                else:
                    ext = tldextract.extract(host)
                    if ext.registered_domain:
                        domains.add(ext.registered_domain.lower())
                    elif host:
                        domains.add(host.lower())
        except Exception:
            continue

    # Also extract direct domain mentions from text
    DOMAIN_RE = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|io|ai|co|xyz|info|biz|me|online|top|site|app|dev|in|us|uk|de|cc|live)\b",
        re.IGNORECASE
    )
    for d in DOMAIN_RE.findall(text):
        d_clean = d.lower().strip(".")
        if d_clean and not d_clean.startswith("www."):
            domains.add(d_clean)
        elif d_clean.startswith("www."):
            domains.add(d_clean[4:])

    for e in emails:
        try:
            dom = e.split("@")[-1].lower().strip("<> ")
            if dom:
                domains.add(dom)
        except Exception:
            pass

    # -------------------------------------------------------------------
    # Extract Origin IP (Sender infrastructure)
    # -------------------------------------------------------------------
    origin_ip, header_ips = extract_origin_ip_from_headers(headers)

    # Fallback to text patterns if headers didn't have explicit origin
    if not origin_ip:
        origin_ip = extract_origin_ip_from_text(text)

    # Fallback to any header IP
    if not origin_ip and header_ips:
        origin_ip = header_ips[0]

    # Fallback: if no header IPs and body has an IP that isn't a URL link
    if not origin_ip and body_ips:
        non_url_body_ips = [ip for ip in body_ips if ip not in url_host_ips]
        if non_url_body_ips:
            origin_ip = non_url_body_ips[0]

    # -------------------------------------------------------------------
    # Resolve Payload IPs via DNS (Destination Web Server IPs)
    # -------------------------------------------------------------------
    resolved_ips: Dict[str, str] = {}
    for d in list(domains)[:8]:
        ip = resolve_domain_ip(d)
        if ip:
            resolved_ips[d] = ip

    # Primary payload IP: from direct URL IP or first resolved domain
    payload_ip: Optional[str] = None
    if url_host_ips:
        payload_ip = url_host_ips[0]
    elif resolved_ips:
        payload_ip = next(iter(resolved_ips.values()), None)

    # -------------------------------------------------------------------
    # Construct ordered all_ips list:
    # 1. origin_ip (ALWAYS index 0 if exists)
    # 2. other header_ips
    # 3. payload_ip & other resolved domain IPs
    # 4. other body IPs
    # -------------------------------------------------------------------
    all_ips: List[str] = []
    if origin_ip:
        all_ips.append(origin_ip)
    for hip in header_ips:
        if hip not in all_ips:
            all_ips.append(hip)
    if payload_ip and payload_ip not in all_ips:
        all_ips.append(payload_ip)
    for rip in resolved_ips.values():
        if rip not in all_ips:
            all_ips.append(rip)
    for bip in body_ips:
        if bip not in all_ips:
            all_ips.append(bip)

    return {
        "urls": sorted(list(set(urls))),
        "domains": sorted(list(domains)),
        "origin_ip": origin_ip,
        "payload_ip": payload_ip,
        "header_ips": header_ips,
        "resolved_ips": resolved_ips,
        "ips": all_ips,
        "emails": sorted(list(set(emails))),
    }

