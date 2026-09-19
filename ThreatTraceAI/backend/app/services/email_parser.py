"""
Basic email / raw text parser.
Accepts full .eml content, MIME, or plain text with headers.
"""
from email import message_from_string, policy
from email.utils import parseaddr
from typing import Optional, Dict, Any, List
import re

HEADER_LINE_RE = re.compile(r"^([A-Za-z0-9\-]+):\s*(.*)$")

def parse_email_content(raw: str) -> dict:
    """
    Accepts either full .eml content or plain body text.
    Returns structured dict ready for the rest of the pipeline.
    Preserves multi-value headers (like multiple Received hops).
    """
    raw = raw or ""
    headers: Dict[str, Any] = {}
    subject = ""
    from_header = ""
    to_header = ""
    body = ""

    # 1. Try standard MIME parsing first
    try:
        msg = message_from_string(raw, policy=policy.default)
        subject = msg.get("Subject", "") or ""
        from_header = msg.get("From", "") or ""
        to_header = msg.get("To", "") or ""

        # Collect all headers preserving multi-values (e.g. Received hops)
        for k, v in msg.items():
            k_lower = k.lower()
            if k_lower in headers:
                if isinstance(headers[k_lower], list):
                    headers[k_lower].append(v)
                else:
                    headers[k_lower] = [headers[k_lower], v]
            else:
                headers[k_lower] = v

        # Explicitly collect all Received headers as a list
        rec_all = msg.get_all("Received", [])
        if rec_all:
            headers["received"] = rec_all

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    body += part.get_content() or ""
                elif ctype == "text/html" and not body:
                    body += part.get_content() or ""
        else:
            body = msg.get_content() or ""
    except Exception:
        body = raw

    # 2. If MIME parsing didn't find headers, check if plain text has header lines at the top
    if not headers or not from_header or not subject:
        lines = raw.splitlines()
        found_any_header = False
        header_lines_count = 0
        for line in lines[:35]:
            m = HEADER_LINE_RE.match(line.strip())
            if m:
                k, v = m.group(1).lower(), m.group(2).strip()
                if k == "from" and not from_header:
                    from_header = v
                elif k == "subject" and not subject:
                    subject = v
                elif k == "to" and not to_header:
                    to_header = v

                if k in headers:
                    if isinstance(headers[k], list):
                        headers[k].append(v)
                    else:
                        headers[k] = [headers[k], v]
                else:
                    headers[k] = v
                found_any_header = True
                header_lines_count += 1
            elif line.strip() == "" and found_any_header:
                # Blank line separates headers from body
                break

    if not body:
        body = raw

    sender_name, sender_email = parseaddr(from_header)

    return {
        "subject": subject.strip(),
        "from_header": from_header.strip(),
        "sender_name": sender_name,
        "sender_email": sender_email.lower() if sender_email else "",
        "to_header": to_header.strip(),
        "headers": headers,
        "body_text": body.strip(),
        "raw": raw
    }

