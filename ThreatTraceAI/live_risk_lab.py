"""
Live risk-factor lab — independent of the SIH app UI.

Pulls real public threat-intel URLs, scores them with a transparent rubric,
and prints every factor + point so you can see analysis on running data.
Does not visit phishing pages (feed URLs are treated as IOCs only).
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.request
from urllib.parse import urlparse

OPENPHISH = "https://openphish.com/feed.txt"
IP_API = "http://ip-api.com/json/{ip}?fields=status,country,city,isp,query,lat,lon"

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".buzz", ".gq", ".ml", ".tk", ".cf",
    ".ga", ".work", ".icu", ".cfd", ".sbs", ".rest", ".monster",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy"}
URGENCY = ["urgent", "immediately", "account locked", "verify immediately", "suspended"]
CREDENTIAL = ["password", "login", "verify your account", "otp", "reset your password"]
FINANCIAL = ["wire transfer", "invoice", "overdue", "bank details", "gift card"]

DEMO_PHISH = """From: payroll-reminder@urgent-verify-now.net
Subject: Urgent: Account Lockout Warning - Immediate Verification Required

Your payroll account has been suspended. Verify immediately or it will be locked.
Reset your password here: {live_url}
"""

DEMO_SAFE = """From: noreply@github.com
Subject: [GitHub] Please reset your password

We received a password reset request for your GitHub account.
If this was you, continue on github.com. If not, ignore this email.
"""


def fetch_text(url: str, timeout: int = 20) -> str:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "RiskFactorLab/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_json(url: str, timeout: int = 15) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "RiskFactorLab/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>\"']+", text)


def score_content(text: str) -> tuple[list[str], int]:
    t = text.lower()
    factors, pts = [], 0
    for kw in URGENCY:
        if kw in t:
            factors.append(f"[NLP keywords] Urgency: '{kw}'")
            pts += 12
            break
    for kw in CREDENTIAL:
        if kw in t:
            factors.append(f"[NLP keywords] Credential harvest: '{kw}'")
            pts += 18
            break
    for kw in FINANCIAL:
        if kw in t:
            factors.append(f"[Financial language] '{kw}'")
            pts += 15
            break
    return factors, min(pts, 55)


def score_url(url: str, live_bad: set[str], live_domains: set[str]) -> tuple[list[str], int]:
    factors, pts = [], 0
    raw = url.strip().lower().rstrip("/")
    try:
        host = (urlparse(url if url.startswith("http") else "http://" + url).hostname or "").lower()
    except Exception:
        return [f"[Parse] Could not parse URL: {url[:80]}"], 5

    if raw in live_bad or host in live_domains:
        factors.append(f"[Live intel OpenPhish] URL/domain listed NOW: {host or raw[:60]}")
        pts += 45

    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            factors.append(f"[URL heuristic] Suspicious TLD {tld} on {host}")
            pts += 12
            break

    if host in URL_SHORTENERS:
        factors.append(f"[URL heuristic] Shortener hides destination: {host}")
        pts += 10

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host or ""):
        factors.append(f"[URL heuristic] Raw IP in URL: {host}")
        pts += 20

    if host.count(".") >= 3:
        factors.append(f"[URL heuristic] Deep subdomain chain: {host}")
        pts += 10

    path = urlparse(url).path.lower()
    for kw in ("login", "verify", "secure", "account", "signin"):
        if kw in path:
            factors.append(f"[URL heuristic] Phish-like path keyword '/{kw}'")
            pts += 5
            break

    return factors, min(pts, 70)


def score_headers(text: str) -> tuple[list[str], int]:
    factors, pts = [], 0
    low = text.lower()
    if "spf=fail" in low or "spf=softfail" in low:
        factors.append("[Email auth] SPF failed")
        pts += 25
    if "dkim=fail" in low:
        factors.append("[Email auth] DKIM failed")
        pts += 20
    if "dmarc=fail" in low:
        factors.append("[Email auth] DMARC failed")
        pts += 25
    if "authentication-results:" not in low and "received:" not in low:
        factors.append("[Email auth] No SPF/DKIM/DMARC headers in this sample (webmail-style)")
        pts += 8
    m = re.search(r"from:\s*.+?@([^\s>]+)", text, re.I)
    if m and m.group(1).lower() in {"gmail.com", "yahoo.com", "outlook.com"} and "paypal" in low:
        factors.append("[Sender heuristic] Brand language + free mailbox")
        pts += 20
    return factors, min(pts, 60)


def verdict(total: float) -> tuple[str, str]:
    if total >= 70:
        return "HIGH", "QUARANTINE"
    if total >= 40:
        return "MEDIUM", "REVIEW"
    return "LOW", "ALLOW"


def analyze(email_text: str, live_bad: set[str], live_domains: set[str]) -> dict:
    factors: list[str] = []
    h_f, h_p = score_headers(email_text)
    c_f, c_p = score_content(email_text)
    factors.extend(h_f)
    factors.extend(c_f)
    url_pts = 0
    urls = extract_urls(email_text)
    for u in urls[:10]:
        uf, up = score_url(u, live_bad, live_domains)
        factors.extend(uf)
        url_pts += up
    total = min(100.0, float(h_p + c_p + min(url_pts, 70)))
    level, rec = verdict(total)
    return {
        "risk_score": total,
        "risk_level": level,
        "recommendation": rec,
        "urls": urls,
        "points": {"headers": h_p, "content": c_p, "urls": min(url_pts, 70)},
        "risk_factors": factors,
    }


def main() -> None:
    print("=" * 72)
    print("LIVE RISK-FACTOR LAB  (public intel + transparent rubric)")
    print("Technologies: HTTP threat feed, regex IOC extract, keyword NLP,")
    print("              URL heuristics, additive 0-100 scoring")
    print("=" * 72)

    print("\n[1] Fetching LIVE OpenPhish feed: https://openphish.com/feed.txt")
    feed = fetch_text(OPENPHISH)
    live_urls = [ln.strip() for ln in feed.splitlines() if ln.strip().startswith("http")]
    live_bad = {u.lower().rstrip("/") for u in live_urls}
    live_domains = set()
    for u in live_urls:
        host = urlparse(u).hostname
        if host:
            live_domains.add(host.lower())

    print(f"    Loaded {len(live_urls)} live phishing URLs, {len(live_domains)} domains")
    print("    Sample of REAL listed URLs (do not visit):")
    for u in live_urls[:5]:
        print(f"      - {u}")

    live_url = live_urls[0]
    print("\n[2] Scoring a phishing-style email that contains a LIVE feed URL")
    phish = analyze(DEMO_PHISH.format(live_url=live_url), live_bad, live_domains)
    print(f"    SCORE {phish['risk_score']:.0f}/100  {phish['risk_level']} -> {phish['recommendation']}")
    print(f"    points breakdown: {phish['points']}")
    for f in phish["risk_factors"]:
        print(f"      - {f}")

    print("\n[3] Scoring a legitimate-looking GitHub mail (no live IOC)")
    safe = analyze(DEMO_SAFE, live_bad, live_domains)
    print(f"    SCORE {safe['risk_score']:.0f}/100  {safe['risk_level']} -> {safe['recommendation']}")
    print(f"    points breakdown: {safe['points']}")
    for f in safe["risk_factors"]:
        print(f"      - {f}")

    print("\n[4] Live GeoIP on a public resolver (1.1.1.1) via ip-api.com")
    try:
        geo = fetch_json(IP_API.format(ip="1.1.1.1"))
        print(f"    {geo}")
    except Exception as exc:
        print(f"    GeoIP skipped: {exc}")

    print("\n[5] Score the first 8 LIVE feed URLs as IOCs (string analysis only)")
    for u in live_urls[:8]:
        uf, up = score_url(u, live_bad, live_domains)
        print(f"    +{up:2d}  {u[:90]}")
        for line in uf[:2]:
            print(f"         {line}")

    print("\nDone. You just ran: live feed pull -> IOC match -> keyword NLP -> URL heuristics -> verdict.")


if __name__ == "__main__":
    main()
