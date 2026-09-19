import hashlib
import json
from typing import Any

def sha256_of_dict(data: dict) -> str:
    """Deterministic SHA-256 of a case record for blockchain chain-of-custody."""
    # Sort keys for stability
    canonical = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
