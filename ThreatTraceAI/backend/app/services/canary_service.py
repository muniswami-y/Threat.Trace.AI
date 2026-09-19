"""
ThreatTrace AI – Canary / Honeytoken Trap Engine
=================================================
Accurate OS/Platform detection via JavaScript probe (NOT IP-range guessing).

When the attacker opens the canary page:
  1. navigator.platform  -> "Linux x86_64", "Win32", "MacIntel" (accurate)
  2. navigator.oscpu     -> "Linux x86_64" (Firefox exposes this)
  3. navigator.userAgent -> full UA string (Kali/Debian/Ubuntu hints)
  4. Screen + CPU cores  -> device fingerprint
  5. Intl timezone       -> geographic correlation
  6. HTML5 Geolocation   -> physical coords (if browser grants permission)
  All POSTed silently to /api/canary/ping/{token}

Industry-standard approach (same as CanaryTokens.org, Canarytrap, Blue Teams).
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

# ---------------------------------------------------------------------------
# In-memory registry (survives hot-reload; cleared on server restart)
# ---------------------------------------------------------------------------
_CANARY_REGISTRY: Dict[str, Dict] = {}    # token -> metadata
_CANARY_HITS: Dict[str, List[Dict]] = {}  # token -> list of hit records


# ---------------------------------------------------------------------------
# JS bait snippet (embedded inside the HTML bait page)
# Uses string concatenation to avoid f-string / curly-brace escaping issues
# ---------------------------------------------------------------------------
def _build_js_probe(token: str, ping_url: str) -> str:
    return (
        "(function(){"
        "var token='" + token + "';"
        "var pingUrl='" + ping_url + "';"
        "var fp={"
        "platform:navigator.platform||'unknown',"
        "oscpu:navigator.oscpu||null,"
        "userAgent:navigator.userAgent||'unknown',"
        "language:navigator.language||'unknown',"
        "screenWidth:screen.width,screenHeight:screen.height,"
        "colorDepth:screen.colorDepth,pixelRatio:window.devicePixelRatio||1,"
        "timezone:(typeof Intl!=='undefined')?Intl.DateTimeFormat().resolvedOptions().timeZone:'unknown',"
        "accessedAt:new Date().toISOString(),"
        "connectionType:(navigator.connection&&navigator.connection.effectiveType)||null,"
        "cpuCores:navigator.hardwareConcurrency||null,"
        "touchSupport:('ontouchstart' in window),"
        "webdriver:navigator.webdriver||false,"
        "referrer:document.referrer||null,"
        "canvasSupported:!!document.createElement('canvas').getContext"
        "};"
        # ── OS inference from platform + oscpu + UA ──
        "function inferOS(f){"
        "var p=(f.platform||'').toLowerCase();"
        "var ua=(f.userAgent||'').toLowerCase();"
        "var osc=(f.oscpu||'').toLowerCase();"
        "if(p.indexOf('linux')!==-1||osc.indexOf('linux')!==-1){"
        "if(ua.indexOf('kali')!==-1)return 'Kali Linux (Confirmed via UA)';"
        "if(ua.indexOf('debian')!==-1)return 'Debian Linux';"
        "if(ua.indexOf('ubuntu')!==-1)return 'Ubuntu Linux';"
        "if(ua.indexOf('fedora')!==-1)return 'Fedora Linux';"
        "if(ua.indexOf('android')!==-1)return 'Android (Linux Kernel)';"
        "return 'Linux x86_64 (Distro unknown)';"
        "}"
        "if(p.indexOf('win')!==-1){"
        "if(ua.indexOf('windows nt 10')!==-1)return 'Windows 10/11';"
        "if(ua.indexOf('windows nt 6.1')!==-1)return 'Windows 7';"
        "return 'Windows (version unknown)';"
        "}"
        "if(p.indexOf('mac')!==-1||p.indexOf('iphone')!==-1||p.indexOf('ipad')!==-1)"
        "return 'macOS / iOS (Apple)';"
        "return 'Unknown OS (platform='+f.platform+')';"
        "}"
        "fp.os_family=inferOS(fp);"
        # ── Multi-method beacon fire ──
        "function fire(data){"
        "var body=JSON.stringify(data);"
        "if(typeof fetch==='function'){"
        "fetch(pingUrl,{method:'POST',headers:{'Content-Type':'application/json'},body:body,keepalive:true})"
        ".catch(function(){});"
        "}"
        "try{var x=new XMLHttpRequest();x.open('POST',pingUrl,true);"
        "x.setRequestHeader('Content-Type','application/json');x.send(body);}catch(e){}"
        "if(navigator.sendBeacon){navigator.sendBeacon(pingUrl+'?t=beacon',body);}"
        "}"
        # ── Geolocation (HTML5 – best-effort) ──
        "if(navigator.geolocation){"
        "navigator.geolocation.getCurrentPosition("
        "function(pos){"
        "fp.geo_lat=pos.coords.latitude;fp.geo_lon=pos.coords.longitude;"
        "fp.geo_accuracy_m=pos.coords.accuracy;fp.geo_source='HTML5_Geolocation_API';"
        "fire(fp);"
        "},"
        "function(err){fp.geo_source='denied';fp.geo_error=err.message;fire(fp);},"
        "{timeout:8000,enableHighAccuracy:true}"
        ");"
        "}else{fp.geo_source='not_supported';fire(fp);}"
        "})();"
    )


def _build_html_bait(token: str, ping_url: str, case_id: str) -> str:
    js_probe = _build_js_probe(token, ping_url)
    short_id = case_id[:8]
    img_src = ping_url + "?t=img"
    return (
        "<!DOCTYPE html>"
        "<html lang='en'>"
        "<head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
        "<title>Shared Document - Invoice_" + short_id + ".pdf</title>"
        "<style>"
        "body{font-family:Arial,sans-serif;margin:60px auto;max-width:600px;color:#333}"
        ".spin{border:4px solid #f3f3f3;border-top:4px solid #3498db;border-radius:50%;"
        "width:40px;height:40px;animation:spin 1s linear infinite;margin:0 auto 20px}"
        "@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}"
        "</style>"
        "</head>"
        "<body>"
        "<div style='text-align:center;padding:40px'>"
        "<div class='spin'></div>"
        "<p>Loading document... Please wait.</p>"
        "</div>"
        "<img src='" + img_src + "' width='1' height='1' "
        "style='position:absolute;opacity:0' alt=''>"
        "<script>" + js_probe + "</script>"
        "</body>"
        "</html>"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_canary_token(case_id: str, analyst_email: str) -> Dict[str, Any]:
    """
    Creates a unique canary token for a case.
    Returns the token, HTML bait page, and instructions.
    """
    token = uuid.uuid4().hex + uuid.uuid4().hex[:8]  # 40-char unique token
    created_at = datetime.now(timezone.utc).isoformat()

    _CANARY_REGISTRY[token] = {
        "token": token,
        "case_id": case_id,
        "analyst_email": analyst_email,
        "created_at": created_at,
        "hit_count": 0,
    }
    _CANARY_HITS[token] = []

    ping_url = "/api/canary/ping/" + token
    html_payload = _build_html_bait(token, ping_url, case_id)
    email_lure = (
        "Please review the attached invoice:\n"
        "http://localhost:8000" + ping_url + "?view=email\n\n"
        "The document will open automatically in your browser."
    )

    return {
        "token": token,
        "case_id": case_id,
        "created_at": created_at,
        "ping_url": ping_url,
        "html_payload": html_payload,
        "email_lure": email_lure,
        "instructions": (
            "Send the html_payload as a linked page OR host it and send the URL. "
            "When opened WITHOUT a proxy/VPN the beacon captures: "
            "real IP, accurate OS (navigator.platform/oscpu), geolocation, "
            "device fingerprint, and exact UTC access timestamp."
        ),
    }


def record_canary_hit(token: str, hit_data: Dict[str, Any]) -> Optional[Dict]:
    """
    Records a beacon ping hit from the attacker's device.
    Returns the enriched hit record with OS confidence level.
    """
    if token not in _CANARY_REGISTRY:
        return None  # Unknown / expired token

    hit_id = uuid.uuid4().hex[:12]
    hit_ts = datetime.now(timezone.utc).isoformat()

    platform = str(hit_data.get("platform") or "unknown")
    oscpu    = str(hit_data.get("oscpu") or "")
    ua       = str(hit_data.get("userAgent") or "")
    os_family = str(hit_data.get("os_family") or "Unknown")

    # ── OS detection confidence ──────────────────────────────────────────
    confidence = "LOW"
    os_evidence: List[str] = []

    if "Linux" in platform or "linux" in ua.lower():
        confidence = "HIGH"
        os_evidence.append("navigator.platform contains 'Linux'")
    if oscpu and "linux" in oscpu.lower():
        confidence = "CONFIRMED"
        os_evidence.append("navigator.oscpu='" + oscpu + "'")
    if "kali" in ua.lower():
        confidence = "CONFIRMED"
        os_evidence.append("Kali Linux string detected in User-Agent")
    if "Win" in platform:
        confidence = "HIGH"
        os_evidence.append("navigator.platform='" + platform + "'")
    if any(x in platform for x in ["Mac", "iPhone", "iPad"]):
        confidence = "HIGH"
        os_evidence.append("navigator.platform='" + platform + "'")

    attacker_ip = str(hit_data.get("_server_ip") or "unknown")

    enriched_hit = {
        "hit_id":           hit_id,
        "token":            token,
        "case_id":          _CANARY_REGISTRY[token]["case_id"],
        "timestamp_utc":    hit_ts,
        # OS (accurate from JS)
        "os_family":        os_family,
        "os_confidence":    confidence,
        "os_evidence":      os_evidence,
        "platform":         platform,
        "oscpu":            oscpu,
        "userAgent":        ua,
        # Device fingerprint
        "screen":           str(hit_data.get("screenWidth")) + "x" + str(hit_data.get("screenHeight")),
        "pixel_ratio":      hit_data.get("pixelRatio"),
        "cpu_cores":        hit_data.get("cpuCores"),
        "touch_support":    hit_data.get("touchSupport"),
        "timezone":         hit_data.get("timezone"),
        "language":         hit_data.get("language"),
        "connection_type":  hit_data.get("connectionType"),
        # Geolocation
        "geo_lat":          hit_data.get("geo_lat"),
        "geo_lon":          hit_data.get("geo_lon"),
        "geo_accuracy_m":   hit_data.get("geo_accuracy_m"),
        "geo_source":       hit_data.get("geo_source", "not_attempted"),
        # Network (server-captured real IP)
        "attacker_ip":      attacker_ip,
        "attacker_ip_utc":  hit_ts,   # Exact UTC for ISP subpoena
        "is_webdriver":     hit_data.get("webdriver", False),
        "referrer":         hit_data.get("referrer"),
        # Law-enforcement summary line
        "le_note": (
            "Attacker accessed canary at " + hit_ts + " UTC "
            "from IP " + attacker_ip + ". "
            "OS confirmed: " + os_family + " (confidence=" + confidence + "). "
            "Submit IP + UTC timestamp to ISP for DHCP subscriber lookup."
        ),
    }

    _CANARY_HITS[token].append(enriched_hit)
    _CANARY_REGISTRY[token]["hit_count"] += 1
    _CANARY_REGISTRY[token]["last_hit_at"] = hit_ts
    return enriched_hit


def get_canary_hits(token: str) -> List[Dict]:
    """Returns all recorded hits for a token."""
    return _CANARY_HITS.get(token, [])


def get_hits_by_case(case_id: str) -> List[Dict]:
    """Returns all canary hits across all tokens for a given case_id."""
    hits: List[Dict] = []
    for token, meta in _CANARY_REGISTRY.items():
        if meta.get("case_id") == case_id:
            hits.extend(_CANARY_HITS.get(token, []))
    return hits


def get_all_tokens_for_case(case_id: str) -> List[Dict]:
    """Returns metadata for every canary token created for a case."""
    return [m for m in _CANARY_REGISTRY.values() if m.get("case_id") == case_id]
