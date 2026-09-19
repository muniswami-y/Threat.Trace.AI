"""
salting.py — Cryptographic salt & pepper utility for ThreatTraceAI case/report IDs.

Terminology:
    Salt   : Random alphanumeric prefix added to an ID (stored in DB, non-secret).
    Pepper : Random alphanumeric suffix added to an ID (stored in DB, adds extra entropy).

Resulting public ID format:
    [SALT]_[BASE_ID]_[PEPPER]
    e.g.  Xk9f_TT-2026-3F7A912B_9p2Q

Goals:
    - Prevent sequential enumeration of case/report IDs via the REST API.
    - Make IDs non-guessable even when the internal format is known.
    - Allow full recovery of the original base_id from stored salt + pepper.
"""

import secrets
import string

_ALPHABET = string.ascii_letters + string.digits   # a-z A-Z 0-9


def generate_salt(length: int = 4) -> str:
    """Return a cryptographically secure random alphanumeric salt string."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def generate_pepper(length: int = 4) -> str:
    """Return a cryptographically secure random alphanumeric pepper string.

    Semantically distinct from salt — placed on the opposite end of the ID.
    """
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def apply_salt_pepper(base_id: str, salt_length: int = 4, pepper_length: int = 4) -> tuple[str, str, str]:
    """Wrap *base_id* with a random salt prefix and pepper suffix.

    Returns:
        (salted_id, salt, pepper)

    Example:
        >>> salted, salt, pepper = apply_salt_pepper("TT-2026-3F7A912B")
        >>> salted
        'Xk9f_TT-2026-3F7A912B_9p2Q'
    """
    salt = generate_salt(salt_length)
    pepper = generate_pepper(pepper_length)
    salted_id = f"{salt}_{base_id}_{pepper}"
    return salted_id, salt, pepper


def strip_salt_pepper(salted_id: str, salt: str, pepper: str) -> str:
    """Recover the original *base_id* from a salted ID given the stored salt and pepper.

    Raises:
        ValueError: If the salted_id does not match the expected pattern.
    """
    prefix = f"{salt}_"
    suffix = f"_{pepper}"

    if not salted_id.startswith(prefix):
        raise ValueError(f"salted_id does not start with expected salt prefix '{prefix}'")
    if not salted_id.endswith(suffix):
        raise ValueError(f"salted_id does not end with expected pepper suffix '{suffix}'")

    # Strip prefix and suffix
    base_id = salted_id[len(prefix): len(salted_id) - len(suffix)]
    return base_id
