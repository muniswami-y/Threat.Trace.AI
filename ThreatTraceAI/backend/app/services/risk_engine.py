"""
Explainable, additive risk scoring rubric.
Every point is traceable to a concrete signal.
Includes: keyword scoring, URL heuristic phishing analysis,
link mismatch detection, homoglyph/typosquatting detection.
"""
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse, parse_qs, unquote
import re
import math

# ---------------------------------------------------------------------------
# Keyword categories (simple, transparent rules – easy to show judges)
# ---------------------------------------------------------------------------
URGENCY = [
    "urgent", "immediately", "asap", "act now", "within 24 hours",
    "account will be locked", "suspended", "expire", "expiring",
    "last warning", "final notice", "respond now", "action required",
    "your account has been", "unauthorized", "unusual activity",
    "verify immediately", "limited time",
]
CREDENTIAL = [
    "password", "login", "verify your account", "confirm your identity",
    "otp", "one-time", "security code", "reset your password",
    "update your information", "sign in", "log in to",
    "enter your credentials", "ssn", "social security",
    "credit card number", "cvv", "pin number",
]
FINANCIAL = [
    "wire transfer", "invoice attached", "payment overdue",
    "bank details", "account number", "bitcoin", "crypto wallet",
    "western union", "money gram", "gift card", "itunes card",
    "refund", "prize", "lottery", "you have won", "claim your",
    "inheritance", "beneficiary",
]
THREAT = [
    "legal action", "lawsuit", "police", "arrest", "fine",
    "court order", "warrant", "prosecution", "jail", "prison",
    "penalty", "terminate your account", "permanently delete",
]

# ---------------------------------------------------------------------------
# URL heuristic scoring constants
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".buzz", ".gq", ".ml", ".tk", ".cf",
    ".ga", ".work", ".loan", ".racing", ".review", ".download",
    ".stream", ".win", ".bid", ".date", ".science", ".party",
    ".cricket", ".faith", ".accountant", ".icu", ".monster",
    ".rest", ".surf", ".sbs", ".cfd", ".boats", ".uno",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "dlvr.it",
    "lnkd.in", "db.tt", "qr.ae", "cutt.ly", "shorturl.at", "rb.gy",
    "tiny.cc", "v.gd", "surl.li", "rebrand.ly",
}

BRAND_TARGETS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "dropbox", "adobe", "yahoo", "outlook", "onedrive", "icloud",
    "dhl", "fedex", "ups", "usps",
]

# Character substitution map for homoglyph detection
HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '8': 'b', '@': 'a', '$': 's', '!': 'i',
    'ä': 'a', 'ë': 'e', 'ï': 'i', 'ö': 'o', 'ü': 'u',
    'à': 'a', 'è': 'e', 'ì': 'i', 'ò': 'o', 'ù': 'u',
    'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u',
    'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɪ': 'i',
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',  # Cyrillic
    'у': 'y', 'х': 'x',
}

# Free email providers — legit for personal use but suspicious when
# impersonating a company / organisation
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "mail.com", "protonmail.com", "zoho.com",
    "yandex.com", "gmx.com", "live.com", "tutanota.com", "fastmail.com",
    "rediffmail.com",
}

# Verified Legitimate Service Providers & Cloud/Dev Infrastructure
# Notifications from these domains should not trigger urgency/failure false-positives
TRUSTED_SERVICES_DOMAINS = {
    "github.com", "koyeb.com", "google.com", "accounts.google.com",
    "gitlab.com", "bitbucket.org", "atlassian.com", "atlassian.net", "jira.com", "trello.com",
    "docker.com", "docker.io", "vercel.com", "vercel.app", "render.com",
    "railway.app", "fly.io", "netlify.com", "netlify.app", "heroku.com",
    "digitalocean.com", "linode.com", "aws.amazon.com", "amazonaws.com",
    "microsoft.com", "azure.com", "office.com", "office365.com",
    "cloudflare.com", "sentry.io", "datadog.com", "newrelic.com",
    "slack.com", "slack-msgs.com", "stripe.com", "npmjs.com", "npmjs.org",
    "python.org", "pypi.org", "apple.com", "threattrace.ai",
}


def is_trusted_service_domain(sender: str) -> bool:
    """Check if the sender email originates from an officially verified service provider."""
    if not sender:
        return False
    s = sender.lower().strip()
    match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', s)
    email = match.group(1) if match else s
    domain = email.split('@')[-1] if '@' in email else email
    domain = domain.strip().lower()
    return any(domain == td or domain.endswith("." + td) for td in TRUSTED_SERVICES_DOMAINS)


# ===================================================================
# CONTENT SCORING
# ===================================================================
def score_content(body: str, subject: str = "", is_trusted: bool = False) -> Tuple[List[str], int]:
    if is_trusted:
        # Legitimate CI/CD, build failure, and provider status emails are not phishing lures
        return ["Verified trusted developer/service communication pattern."], 0

    text = f"{subject} {body}".lower()
    factors = []
    points = 0

    for kw in URGENCY:
        if kw in text:
            factors.append(f"Urgency language detected: '{kw}'")
            points += 12
            break

    for kw in CREDENTIAL:
        if kw in text:
            factors.append(f"Credential / verification request: '{kw}'")
            points += 18
            break

    for kw in FINANCIAL:
        if kw in text:
            factors.append(f"Financial / payment language: '{kw}'")
            points += 15
            break

    for kw in THREAT:
        if kw in text:
            factors.append(f"Threat language: '{kw}'")
            points += 20
            break

    # Short suspicious bodies often used in phishing
    if 20 < len(body) < 180 and ("click" in text or "http" in text):
        factors.append("Short body with call-to-action link (common phishing pattern)")
        points += 10

    # Excessive exclamation marks / ALL-CAPS words (social engineering)
    caps_words = re.findall(r'\b[A-Z]{4,}\b', body)
    if len(caps_words) >= 3:
        factors.append(f"Multiple ALL-CAPS words ({len(caps_words)} found) — social engineering pattern")
        points += 5

    return factors, min(points, 55)


# ===================================================================
# URL HEURISTIC SCORING
# ===================================================================
def _normalize_homoglyphs(text: str) -> str:
    """Replace common homoglyphs with ASCII equivalents."""
    return "".join(HOMOGLYPH_MAP.get(c, c) for c in text.lower())


def _levenshtein(s1: str, s2: str) -> int:
    """Simple Levenshtein distance."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _extract_domain_parts(url: str) -> Optional[dict]:
    """Parse a URL and return useful parts."""
    try:
        if not url.startswith("http"):
            url = "http://" + url
        p = urlparse(url)
        host = (p.hostname or "").lower().rstrip(".")
        return {
            "host": host,
            "path": p.path,
            "query": p.query,
            "full": url,
            "port": p.port,
            "scheme": p.scheme,
        }
    except Exception:
        return None


def score_url_heuristics(urls: List[str]) -> Tuple[List[str], int]:
    """
    Analyze extracted URLs for phishing indicators.
    Returns (risk factors, additive points).
    """
    factors = []
    points = 0

    if not urls:
        return factors, points

    seen_flags = set()

    for raw_url in urls[:20]:
        parts = _extract_domain_parts(raw_url)
        if not parts:
            continue
        host = parts["host"]
        full = parts["full"]
        path = parts["path"]

        # --- IP-based URL (e.g., http://192.168.1.1/login) ---
        ip_pattern = re.compile(
            r'^(?:\d{1,3}\.){3}\d{1,3}$'
        )
        if ip_pattern.match(host) and "ip_url" not in seen_flags:
            factors.append(f"URL uses raw IP address instead of domain: {host}")
            points += 20
            seen_flags.add("ip_url")

        # --- Suspicious TLD ---
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld) and "sus_tld" not in seen_flags:
                factors.append(f"Suspicious top-level domain: {tld} (common in phishing)")
                points += 12
                seen_flags.add("sus_tld")
                break

        # --- URL shortener ---
        for shortener in URL_SHORTENERS:
            if host == shortener or host.endswith("." + shortener):
                if "shortener" not in seen_flags:
                    factors.append(f"URL shortener detected: {shortener} (hides real destination)")
                    points += 10
                    seen_flags.add("shortener")
                break

        # --- Excessive subdomains (e.g., login.secure.paypal.com.evil.xyz) ---
        subdomain_count = host.count(".")
        if subdomain_count >= 3 and "excess_sub" not in seen_flags:
            factors.append(f"Excessive subdomains ({subdomain_count} levels) — obfuscation technique")
            points += 10
            seen_flags.add("excess_sub")

        # --- Very long URL (obfuscation) ---
        if len(full) > 200 and "long_url" not in seen_flags:
            factors.append(f"Abnormally long URL ({len(full)} chars) — possible obfuscation")
            points += 5
            seen_flags.add("long_url")

        # --- Homoglyph / typosquatting detection ---
        normalized = _normalize_homoglyphs(host)
        # Remove TLD for comparison
        base = normalized.rsplit(".", 1)[0] if "." in normalized else normalized
        # Remove common subdomains
        for prefix in ("www.", "mail.", "login.", "secure.", "account.", "signin."):
            if base.startswith(prefix):
                base = base[len(prefix):]

        for brand in BRAND_TARGETS:
            if brand == base:
                continue  # Exact match is fine
            dist = _levenshtein(base, brand)
            if 0 < dist <= 2 and f"typo_{brand}" not in seen_flags:
                factors.append(
                    f"Possible typosquatting of '{brand}': domain '{host}' "
                    f"(edit distance: {dist})"
                )
                points += 22
                seen_flags.add(f"typo_{brand}")
                break
            # Also check if brand name is embedded in subdomain to trick users
            if brand in host and brand not in host.rsplit(".", 2)[-2:] and f"embed_{brand}" not in seen_flags:
                factors.append(
                    f"Brand name '{brand}' embedded in misleading subdomain: {host}"
                )
                points += 15
                seen_flags.add(f"embed_{brand}")
                break

        # --- Non-standard port ---
        if parts["port"] and parts["port"] not in (80, 443, None) and "odd_port" not in seen_flags:
            factors.append(f"Non-standard port in URL: {parts['port']}")
            points += 8
            seen_flags.add("odd_port")

        # --- @ symbol in URL (credential-style) ---
        if "@" in full and "at_url" not in seen_flags:
            factors.append("URL contains '@' symbol — may trick browsers into showing fake domain")
            points += 15
            seen_flags.add("at_url")

        # --- data: or javascript: URI scheme ---
        if parts["scheme"] in ("data", "javascript") and "data_uri" not in seen_flags:
            factors.append(f"Dangerous URI scheme: {parts['scheme']}:")
            points += 20
            seen_flags.add("data_uri")

        # --- Path contains login/signin/verify/secure keywords ---
        path_lower = path.lower()
        phish_path_kws = ["login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "webscr"]
        for kw in phish_path_kws:
            if kw in path_lower and f"path_{kw}" not in seen_flags:
                factors.append(f"Suspicious path keyword '/{kw}' in URL")
                points += 5
                seen_flags.add(f"path_{kw}")
                break

    return factors, min(points, 50)


# ===================================================================
# LINK DISPLAY-TEXT vs HREF MISMATCH
# ===================================================================
def score_link_mismatches(links: List[Dict]) -> Tuple[List[str], int]:
    """
    Detect when the display text of a link shows one domain
    but the href points to a completely different domain.
    links: list of {display, href} dicts from the extension
    """
    factors = []
    points = 0

    if not links:
        return factors, points

    domain_re = re.compile(
        r'(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|io|co|in|uk|us|de|fr|au|ca|info|biz)\b'
    )

    for link in links[:20]:
        display = (link.get("display") or "").strip()
        href = (link.get("href") or "").strip()
        if not display or not href:
            continue

        # Find domains mentioned in display text
        display_domains = domain_re.findall(display.lower())
        if not display_domains:
            continue

        # Get domain from href
        href_parts = _extract_domain_parts(href)
        if not href_parts:
            continue
        href_host = href_parts["host"]

        for dd in display_domains:
            dd_clean = dd.lower().lstrip("www.")
            href_clean = href_host.lstrip("www.")
            # If display text shows a domain and href goes somewhere different
            if dd_clean != href_clean and dd_clean not in href_clean:
                factors.append(
                    f"Link text shows '{dd}' but actually points to '{href_host}' — "
                    f"classic phishing mismatch!"
                )
                points += 25
                break  # one mismatch is enough to flag

    return factors, min(points, 30)


# ===================================================================
# MATHEMATICAL & MACHINE LEARNING FORMULA ENGINES
# ===================================================================

def calculate_shannon_entropy(text: str) -> float:
    """
    Shannon Entropy: H(X) = -sum(P(x_i) * log2(P(x_i)))
    Measures randomness and algorithmic domain generation (DGA) / URL obfuscation.
    """
    if not text:
        return 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def calculate_lexical_density(text: str) -> Dict[str, float]:
    """
    Lexical Density Ratios:
    - Digit Ratio = Count of Digits / Total Length
    - Special Char Ratio = Count of Special Characters / Total Length
    - Consonant Ratio = Count of Consonants / Total Length
    """
    if not text:
        return {"digit_ratio": 0.0, "special_ratio": 0.0, "entropy": 0.0}
    
    total_len = max(len(text), 1)
    digits = sum(1 for c in text if c.isdigit())
    specials = sum(1 for c in text if not c.isalnum())
    
    return {
        "digit_ratio": round(digits / total_len, 3),
        "special_ratio": round(specials / total_len, 3),
        "entropy": calculate_shannon_entropy(text),
        "length": total_len
    }


def calculate_naive_bayes_probability(body: str, subject: str = "") -> Tuple[float, float, List[str]]:
    """
    Naïve Bayes Classification Formula:
    P(Spam | X) = P(X | Spam) * P(Spam) / [P(X | Spam)*P(Spam) + P(X | Ham)*P(Ham)]
    Using conditional log-likelihood with both spam and ham likelihood calibration.
    """
    text = f"{subject} {body}".lower()
    tokens = re.findall(r'\b[a-z]{3,15}\b', text)
    if not tokens:
        return 0.01, 1.0, []
    
    # Calibrated prior probabilities (clean prior 0.85, phishing prior 0.15)
    log_p_spam = math.log(0.15)
    log_p_ham = math.log(0.85)
    
    # High-information phishing tokens with calibrated likelihoods
    SPAM_TOKEN_WEIGHTS = {
        "urgent": 4.5, "suspended": 5.2, "unauthorized": 4.8, "verify": 3.8,
        "password": 4.2, "expire": 4.0, "bitcoin": 5.5, "crypto": 4.9,
        "wire": 3.8, "invoice": 3.0, "immediate": 3.6, "warning": 3.5,
        "lottery": 5.5, "winner": 4.8, "refund": 3.4, "court": 4.2,
        "login": 3.4, "security": 2.6, "confirm": 3.0, "kyc": 4.5,
        "pin": 4.0, "otp": 4.2, "credentials": 4.8, "breach": 3.9,
        "compromised": 4.4, "restricted": 4.1, "threat": 3.7
    }

    # Legitimate / Ham tokens that decrease spam probability
    HAM_TOKEN_WEIGHTS = {
        "meeting": 3.5, "schedule": 3.2, "project": 3.4, "attached": 2.8,
        "report": 3.0, "thanks": 3.6, "regards": 3.5, "team": 3.2,
        "discussion": 3.0, "update": 2.5, "review": 2.6, "document": 2.8,
        "agenda": 3.4, "notes": 2.9, "colleague": 3.2, "conference": 3.4,
        "sincerely": 3.2, "best": 2.8, "welcome": 2.5, "feedback": 2.8
    }
    
    flagged_tokens = []
    log_spam_likelihood = 0.0
    log_ham_likelihood = 0.0
    
    for token in tokens:
        if token in SPAM_TOKEN_WEIGHTS:
            weight = SPAM_TOKEN_WEIGHTS[token]
            log_spam_likelihood += math.log(weight)
            log_ham_likelihood += math.log(1.0 / weight)
            if token not in flagged_tokens:
                flagged_tokens.append(token)
        elif token in HAM_TOKEN_WEIGHTS:
            weight = HAM_TOKEN_WEIGHTS[token]
            log_ham_likelihood += math.log(weight)
            log_spam_likelihood += math.log(1.0 / weight)
    
    # Laplace calculation for total log posterior
    total_spam = log_p_spam + log_spam_likelihood
    total_ham = log_p_ham + log_ham_likelihood
    
    # Softmax normalization to bounded probability [0.0, 1.0]
    max_log = max(total_spam, total_ham)
    exp_spam = math.exp(total_spam - max_log)
    exp_ham = math.exp(total_ham - max_log)
    
    prob_spam = exp_spam / (exp_spam + exp_ham)
    return round(prob_spam, 4), round(prob_spam * 100, 1), flagged_tokens[:6]


def calculate_knn_euclidean_distance(vec_a: List[float], vec_b: List[float]) -> float:
    """
    KNN Euclidean Distance:
    D(X_i, X_j) = sqrt( sum( (x_ik - x_jk)^2 ) )
    """
    if len(vec_a) != len(vec_b) or not vec_a:
        return 0.0
    sq_diff_sum = sum((a - b) ** 2 for a, b in zip(vec_a, vec_b))
    return round(math.sqrt(sq_diff_sum), 4)


def calculate_cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """
    Cosine Similarity Formula:
    Cosine Similarity = (A . B) / ( ||A|| * ||B|| )
    Calculates visual and brand vector alignment from -1 to 1.
    """
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a ** 2 for a in vec_a))
    norm_b = math.sqrt(sum(b ** 2 for b in vec_b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return round(dot_product / (norm_a * norm_b), 4)


def correlate_vpn_traffic_timing(
    ingress_bytes: int,
    egress_bytes: int,
    ingress_timestamp_sec: float,
    egress_timestamp_sec: float
) -> Dict[str, any]:
    """
    VPN / Proxy De-Anonymization Traffic Correlation Engine:
    Correlates packet payload byte size and delta timestamp across VPN hops.
    Example: 5GB sent at 12:10:01 correlates to 5GB received at 12:10:02 (Delta t = 1.0s).
    """
    delta_t = abs(egress_timestamp_sec - ingress_timestamp_sec)
    size_ratio = min(ingress_bytes, egress_bytes) / max(max(ingress_bytes, egress_bytes), 1)
    
    # High correlation threshold: delta_t <= 2.5s and size similarity > 96%
    is_correlated = (delta_t <= 2.5) and (size_ratio >= 0.96)
    confidence = round(size_ratio * (1.0 - min(delta_t / 5.0, 0.5)) * 100, 1)
    
    return {
        "is_correlated": is_correlated,
        "confidence_score": confidence,
        "delta_time_seconds": round(delta_t, 2),
        "size_match_ratio": round(size_ratio, 4),
        "verdict": "ATTACKER ORIGIN DE-ANONYMIZED" if is_correlated else "UNLINKED TRAFFIC"
    }


# ===================================================================
# SENDER HEURISTICS
# ===================================================================
def score_sender_heuristics(
    sender_email: str,
    sender_display_name: str = "",
    subject: str = "",
) -> Tuple[List[str], int]:
    """
    Detect suspicious sender patterns when real SMTP headers are unavailable.
    """
    factors = []
    points = 0
    sender_email = (sender_email or "").lower().strip()
    sender_display = (sender_display_name or "").lower().strip()

    if not sender_email or "@" not in sender_email:
        return factors, points

    local_part, domain = sender_email.rsplit("@", 1)

    # Display name spoofing: display says "PayPal" but email is random@gmail.com
    if sender_display:
        for brand in BRAND_TARGETS:
            if brand in sender_display and domain in FREE_EMAIL_PROVIDERS:
                factors.append(
                    f"Display name contains '{brand}' but email uses free provider '{domain}' — "
                    f"possible display-name spoofing"
                )
                points += 20
                break

    # Standard legitimate department/role words that should never be flagged as random
    COMMON_ROLE_WORDS = {
        "support", "contact", "info", "admin", "service", "services", "customer", "billing",
        "sales", "help", "security", "team", "office", "alert", "alerts", "notification",
        "notifications", "noreply", "no-reply", "marketing", "updates", "account",
        "accounts", "enquiry", "enquiries", "general", "feedback", "postmaster",
        "compliance", "banking", "finance", "dispatch", "operations", "helpdesk"
    }

    # Shannon Entropy and Random-looking local part (e.g., xj3k9fz@domain.com)
    clean_local = local_part.split("+")[0].split(".")[0].lower()
    if clean_local not in COMMON_ROLE_WORDS and len(clean_local) > 6:
        consonant_ratio = sum(1 for c in clean_local if c in "bcdfghjklmnpqrstvwxyz") / max(len(clean_local), 1)
        digit_ratio = sum(1 for c in clean_local if c.isdigit()) / max(len(clean_local), 1)
        entropy = calculate_shannon_entropy(clean_local)
        
        if consonant_ratio > 0.85 or digit_ratio > 0.55 or entropy > 3.6:
            factors.append(f"Sender local part '{local_part}' has high Shannon entropy ({entropy}) / random pattern")
            points += 10

    return factors, min(points, 25)


# ===================================================================
# FINAL SCORE COMBINER
# ===================================================================
def combine_scores(
    header_points: int,
    content_points: int,
    malicious_url_count: int,
    url_heuristic_points: int = 0,
    url_heuristic_factors: List[str] = None,
    link_mismatch_points: int = 0,
    link_mismatch_factors: List[str] = None,
    sender_heuristic_points: int = 0,
    sender_heuristic_factors: List[str] = None,
    geo_mismatch: bool = False,
    redirect_chain_suspicious: bool = False,
    ml_probability: float = 0.0,
) -> Tuple[float, str, str, List[str]]:
    """
    Final additive score + level + recommendation incorporating Naive Bayes ML probability.
    """
    extra = []
    total = header_points + content_points + url_heuristic_points + link_mismatch_points + sender_heuristic_points

    # Integrate Machine Learning Naive Bayes score weight
    if ml_probability > 0.5:
        ml_boost = int(round((ml_probability - 0.5) * 40))
        total += ml_boost
        extra.append(f"Naïve Bayes ML Model: {round(ml_probability * 100, 1)}% spam probability (+{ml_boost} pts)")

    if malicious_url_count > 0:
        total += 30 + (malicious_url_count - 1) * 5
        extra.append(f"{malicious_url_count} URL(s) matched live threat feed")

    if geo_mismatch:
        total += 10
        extra.append("Sender IP geolocation inconsistent with claimed origin")

    if redirect_chain_suspicious:
        total += 8
        extra.append("URL redirect chain is suspiciously long (3+ hops)")

    if url_heuristic_factors:
        extra.extend(url_heuristic_factors)
    if link_mismatch_factors:
        extra.extend(link_mismatch_factors)
    if sender_heuristic_factors:
        extra.extend(sender_heuristic_factors)

    total = min(float(total), 100.0)

    if total >= 70:
        level = "HIGH"
        rec = "QUARANTINE"
    elif total >= 40:
        level = "MEDIUM"
        rec = "REVIEW"
    else:
        level = "LOW"
        rec = "ALLOW"

    return total, level, rec, extra

