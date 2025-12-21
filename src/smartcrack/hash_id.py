"""Hash auto-identification module."""

from __future__ import annotations

from smartcrack.models import HashType

# Hex character set for validation
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")

# Length -> (HashType, confidence) for unambiguous hex hashes
_HEX_LENGTH_MAP: dict[int, list[tuple[HashType, float]]] = {
    32: [(HashType.MD5, 0.95), (HashType.NTLM, 0.5)],
    40: [(HashType.SHA1, 0.95)],
    56: [(HashType.SHA224, 0.95)],
    64: [(HashType.SHA256, 0.95)],
    96: [(HashType.SHA384, 0.95)],
    128: [(HashType.SHA512, 0.95)],
}

# Prefix -> (HashType, confidence) for structured hash formats
_PREFIX_MAP: list[tuple[str, HashType, float]] = [
    ("$argon2id$", HashType.ARGON2, 0.99),
    ("$argon2i$", HashType.ARGON2, 0.99),
    ("$2b$", HashType.BCRYPT, 0.99),
    ("$2a$", HashType.BCRYPT, 0.99),
    ("$2y$", HashType.BCRYPT, 0.99),
]


def _is_hex(value: str) -> bool:
    """Return True if every character in value is a valid hex digit."""
    return bool(value) and all(c in _HEX_CHARS for c in value)


def _match_prefix(hash_value: str) -> list[tuple[HashType, float]] | None:
    """Return matches if hash_value starts with a known structured prefix."""
    for prefix, hash_type, confidence in _PREFIX_MAP:
        if hash_value.startswith(prefix):
            return [(hash_type, confidence)]
    return None


def _match_hex_length(hash_value: str) -> list[tuple[HashType, float]] | None:
    """Return matches if hash_value is a known-length hex string."""
    if not _is_hex(hash_value):
        return None
    return _HEX_LENGTH_MAP.get(len(hash_value))


def identify_hash(hash_value: str) -> list[tuple[HashType, float]]:
    """Identify the type(s) of a hash, returning ranked (HashType, confidence) pairs.

    Structured formats (bcrypt, argon2) are checked first by prefix, then
    plain hex hashes are matched by length. Unrecognised input returns
    [(HashType.UNKNOWN, 0.0)].
    """
    if not hash_value:
        return [(HashType.UNKNOWN, 0.0)]

    prefix_matches = _match_prefix(hash_value)
    if prefix_matches is not None:
        return prefix_matches

    hex_matches = _match_hex_length(hash_value)
    if hex_matches is not None:
        return hex_matches

    return [(HashType.UNKNOWN, 0.0)]
