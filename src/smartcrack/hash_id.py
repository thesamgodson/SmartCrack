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
    # Unix crypt formats
    ("$6$", HashType.SHA512CRYPT, 0.99),
    ("$5$", HashType.SHA256CRYPT, 0.99),
    ("$1$", HashType.MD5CRYPT, 0.99),
    ("$y$", HashType.YESCRYPT, 0.99),
    # Argon2
    ("$argon2id$", HashType.ARGON2, 0.99),
    ("$argon2i$", HashType.ARGON2, 0.99),
    ("$argon2d$", HashType.ARGON2, 0.99),
    # bcrypt variants
    ("$2b$", HashType.BCRYPT, 0.99),
    ("$2a$", HashType.BCRYPT, 0.99),
    ("$2y$", HashType.BCRYPT, 0.99),
    # Web CMS
    ("$P$", HashType.PHPASS, 0.99),
    ("$H$", HashType.PHPASS, 0.99),
    ("$S$", HashType.DRUPAL7, 0.99),
    # Windows AD
    ("$krb5tgs$23$", HashType.KERBEROS_TGS, 0.99),
    ("$krb5tgs$17$", HashType.KERBEROS_TGS, 0.99),
    ("$krb5tgs$18$", HashType.KERBEROS_TGS, 0.99),
    ("$krb5asrep$23$", HashType.KERBEROS_ASREP, 0.99),
    ("$DCC2$", HashType.DCC2, 0.99),
    # Django
    ("pbkdf2_sha256$", HashType.DJANGO_PBKDF2, 0.99),
    # LDAP
    ("{SSHA}", HashType.LDAP_SSHA, 0.99),
    ("{SHA}", HashType.SHA1, 0.95),
    # scrypt
    ("SCRYPT:", HashType.SCRYPT, 0.99),
    ("$7$", HashType.SCRYPT, 0.95),
    # Phase 3
    ("$LM$", HashType.LM, 0.95),
    ("$DCC$", HashType.DCC1, 0.95),
    ("SCRAM-SHA-256$", HashType.POSTGRES_SCRAM, 0.99),
    # Phase 4
    ("$keepass$", HashType.KEEPASS, 0.99),
    ("WPA*", HashType.WPA2_PMKID, 0.99),
    ("$office$", HashType.MS_OFFICE, 0.99),
    ("$pdf$", HashType.PDF, 0.99),
    ("$RAR5$", HashType.RAR5, 0.99),
    ("$7z$", HashType.SEVENZIP, 0.99),
    ("$bitcoin$", HashType.BITCOIN, 0.99),
    ("$ethereum$", HashType.ETHEREUM, 0.99),
    ("$8$", HashType.CISCO_TYPE8, 0.99),
    ("$9$", HashType.CISCO_TYPE9, 0.99),
    ("$ml$", HashType.MACOS_PBKDF2, 0.95),
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

    # MySQL 4.1/5: * prefix followed by 40 hex chars
    if hash_value.startswith("*") and len(hash_value) == 41 and _is_hex(hash_value[1:]):
        return [(HashType.MYSQL41, 0.99)]

    # MSSQL: 0x0100 or 0x0200 prefix
    if hash_value.lower().startswith("0x0100") or hash_value.lower().startswith("0x0200"):
        return [(HashType.MSSQL2012, 0.95)]

    # Oracle 11g: S: prefix followed by 60 hex chars
    if hash_value.startswith("S:") and len(hash_value) >= 40:
        return [(HashType.ORACLE11G, 0.95)]

    # Oracle 12c: T: prefix
    if hash_value.startswith("T:") and len(hash_value) >= 40:
        return [(HashType.ORACLE12C, 0.95)]

    # PostgreSQL md5: "md5" + 32 hex chars
    if hash_value.startswith("md5") and len(hash_value) == 35 and _is_hex(hash_value[3:]):
        return [(HashType.POSTGRES_MD5, 0.97)]

    # NetNTLM: contains :: separator pattern
    if "::" in hash_value:
        colon_count = hash_value.count(":")
        if colon_count >= 5:
            return [(HashType.NETNTLMV2, 0.95)]
        elif colon_count >= 3:
            return [(HashType.NETNTLMV1, 0.90)]

    hex_matches = _match_hex_length(hash_value)
    if hex_matches is not None:
        return hex_matches

    # LM hash: exactly 16 hex chars
    if len(hash_value) == 16 and _is_hex(hash_value):
        return [(HashType.LM, 0.7), (HashType.UNKNOWN, 0.3)]

    return [(HashType.UNKNOWN, 0.0)]
