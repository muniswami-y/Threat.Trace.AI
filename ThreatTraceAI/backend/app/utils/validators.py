import re
from typing import Optional

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
URL_RE = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.IGNORECASE
)

def is_valid_email(value: str) -> bool:
    return bool(EMAIL_RE.fullmatch(value.strip()))

def extract_emails(text: str) -> list[str]:
    return list(set(EMAIL_RE.findall(text or "")))

def extract_ips(text: str) -> list[str]:
    return list(set(IP_RE.findall(text or "")))

def extract_urls(text: str) -> list[str]:
    return list(set(URL_RE.findall(text or "")))
