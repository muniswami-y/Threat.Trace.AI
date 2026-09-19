"""
SPF / DKIM / DMARC style checks + basic header forensics.
When real headers are unavailable (Gmail content script), falls back to
heuristic analysis of the sender email and display name.
"""
from typing import Dict, List, Tuple
import re

# Free / consumer email providers
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "mail.com", "protonmail.com", "zoho.com",
    "yandex.com", "gmx.com", "live.com", "tutanota.com", "fastmail.com",
    "rediffmail.com", "msn.com", "me.com", "ymail.com", "rocketmail.com",
    "inbox.com",
}

# Common brand names often spoofed in display names
IMPERSONATION_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "chase", "wells fargo", "bank of america", "citibank", "hsbc",
    "dropbox", "adobe", "dhl", "fedex", "ups", "usps",
    "irs", "government", "tax", "police",
]


def analyze_headers(headers: Dict[str, str], sender_email: str) -> Tuple[List[str], int]:
    """
    Returns (list of risk factor strings, additive risk points).
    Performs real header analysis when headers are present,
    falls back to sender heuristics when they're not.
    """
    factors = []
    points = 0
    headers_lower = {k.lower(): v for k, v in (headers or {}).items()}

    has_real_headers = bool(headers_lower.get("authentication-results")
                           or headers_lower.get("arc-authentication-results")
                           or headers_lower.get("received")
                           or headers_lower.get("message-id"))

    if has_real_headers:
        # ===== REAL HEADER ANALYSIS =====
        auth = headers_lower.get("authentication-results", "") or headers_lower.get("arc-authentication-results", "")
        auth_l = auth.lower()

        if "spf=fail" in auth_l or "spf=softfail" in auth_l:
            factors.append("SPF failed or soft-failed")
            points += 25
        elif "spf=pass" in auth_l:
            factors.append("SPF passed ✓")
        elif "spf=none" in auth_l:
            factors.append("No SPF record for sender domain")
            points += 12
        else:
            factors.append("No clear SPF result in headers")
            points += 8

        if "dkim=fail" in auth_l:
            factors.append("DKIM signature failed")
            points += 20
        elif "dkim=pass" in auth_l:
            factors.append("DKIM passed ✓")
        else:
            factors.append("No clear DKIM result")
            points += 5

        if "dmarc=fail" in auth_l:
            factors.append("DMARC failed")
            points += 25
        elif "dmarc=pass" in auth_l:
            factors.append("DMARC passed ✓")

        # From vs Return-Path mismatch
        return_path = headers_lower.get("return-path", "")
        if return_path and sender_email and sender_email not in return_path.lower():
            factors.append("From address does not match Return-Path")
            points += 15

        # Missing Message-ID
        if not headers_lower.get("message-id"):
            factors.append("Missing Message-ID header")
            points += 5

        # Suspicious X-Mailer or User-Agent
        xmailer = (headers_lower.get("x-mailer") or headers_lower.get("user-agent") or "").lower()
        if any(x in xmailer for x in ["php", "python", "script", "bulk"]):
            factors.append(f"Suspicious mailer string: {xmailer[:40]}")
            points += 10

        # Multiple Received headers — deep hop chain can indicate relay abuse
        received_count = sum(1 for k in (headers or {}) if k.lower() == "received")
        if received_count > 6:
            factors.append(f"Unusually long relay chain ({received_count} hops)")
            points += 5

    else:
        # ===== HEURISTIC ANALYSIS (no real headers available) =====
        # This is the typical case when analyzing via Gmail content script
        factors.append("Email headers not available (web client analysis)")

        sender_email_lower = (sender_email or "").lower().strip()

        if sender_email_lower and "@" in sender_email_lower:
            local_part, domain = sender_email_lower.rsplit("@", 1)

            # Check if sender uses a free email provider
            if domain in FREE_EMAIL_PROVIDERS:
                factors.append(f"Sender uses free email provider ({domain})")
                # Not inherently suspicious, but adds minor points
                points += 3
            else:
                factors.append(f"Sender domain: {domain}")

            # Check for suspicious sender patterns
            # Very long local part with random characters
            if len(local_part) > 20:
                factors.append(f"Unusually long sender address ({len(local_part)} chars)")
                points += 5

            # Local part looks auto-generated (mostly numbers/random chars)
            if len(local_part) > 4:
                digit_ratio = sum(1 for c in local_part if c.isdigit()) / len(local_part)
                if digit_ratio > 0.6:
                    factors.append("Sender address appears auto-generated (high digit ratio)")
                    points += 8

            # Check for noreply/notification patterns (less suspicious)
            safe_prefixes = ["noreply", "no-reply", "notifications", "info", "support", "admin", "contact"]
            is_service_sender = any(local_part.startswith(p) for p in safe_prefixes)
            if is_service_sender:
                factors.append("Sender appears to be a service/notification address")
                # Slightly reduces suspicion — no points added

        else:
            factors.append("Sender email not identified")
            points += 10

    return factors, min(points, 60)


def analyze_display_name_spoofing(
    display_name: str,
    sender_email: str,
) -> Tuple[List[str], int]:
    """
    Separate function to detect display-name spoofing.
    E.g., display name says "PayPal Security" but email is random123@gmail.com
    """
    factors = []
    points = 0

    display = (display_name or "").lower().strip()
    email_lower = (sender_email or "").lower().strip()

    if not display or not email_lower or "@" not in email_lower:
        return factors, points

    _, domain = email_lower.rsplit("@", 1)

    for brand in IMPERSONATION_BRANDS:
        if brand in display:
            # Check if the actual email domain matches the brand
            brand_clean = brand.replace(" ", "")
            if brand_clean not in domain and domain in FREE_EMAIL_PROVIDERS:
                factors.append(
                    f"⚠ Display name impersonates '{brand}' but uses free email "
                    f"provider ({domain}) — likely spoofing"
                )
                points += 22
                break
            elif brand_clean not in domain:
                factors.append(
                    f"Display name mentions '{brand}' but email domain is '{domain}'"
                )
                points += 8
                break

    # Display name contains an email address (common phishing trick)
    # Only flag if display name is genuinely different from the sender's own email
    display_clean = display.strip().strip("<>").lower()
    email_clean = email_lower.strip().strip("<>").lower()
    if display_clean != email_clean and not display_clean.endswith(f"<{email_clean}>"):
        if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', display):
            factors.append("Display name contains an email address — common spoofing trick")
            points += 12

    return factors, min(points, 25)
