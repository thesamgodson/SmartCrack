"""Hash computation and verification."""

from __future__ import annotations

import hashlib
from typing import Callable

import argon2
import bcrypt as bcrypt_lib

from smartcrack.models import HashTarget, HashType

HASH_FUNCTIONS: dict[HashType, Callable[[bytes], hashlib._Hash]] = {
    HashType.MD5: hashlib.md5,
    HashType.SHA1: hashlib.sha1,
    HashType.SHA224: hashlib.sha224,
    HashType.SHA256: hashlib.sha256,
    HashType.SHA384: hashlib.sha384,
    HashType.SHA512: hashlib.sha512,
}

_SPECIAL_TYPES = frozenset({HashType.BCRYPT, HashType.ARGON2, HashType.NTLM})


def _compute_bcrypt(plaintext: str) -> str:
    """Compute a bcrypt hash of plaintext."""
    return bcrypt_lib.hashpw(plaintext.encode("utf-8"), bcrypt_lib.gensalt()).decode("utf-8")


def _verify_bcrypt(plaintext: str, hash_value: str) -> bool:
    """Verify plaintext against a bcrypt hash."""
    try:
        return bcrypt_lib.checkpw(plaintext.encode("utf-8"), hash_value.encode("utf-8"))
    except Exception:
        return False


def _compute_argon2(plaintext: str) -> str:
    """Compute an argon2 hash of plaintext."""
    ph = argon2.PasswordHasher()
    return ph.hash(plaintext)


def _verify_argon2(plaintext: str, hash_value: str) -> bool:
    """Verify plaintext against an argon2 hash."""
    ph = argon2.PasswordHasher()
    try:
        return ph.verify(hash_value, plaintext)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except Exception:
        return False


def _md4(data: bytes) -> str:
    """Pure-Python MD4 digest per RFC 1320, returned as lowercase hex string.

    MD4 is no longer available in OpenSSL 3+ (Python 3.14's hashlib),
    so we implement it directly.
    """
    import struct

    def _rol(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    # Padding
    msg = bytearray(data)
    orig_bit_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack("<Q", orig_bit_len)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off : off + 64]))
        aa, bb, cc, dd = a, b, c, d

        # Round 1 — F(b,c,d) = (b & c) | (~b & d)
        def R1(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
            return _rol((a + ((b & c) | (~b & d)) + X[k]) & 0xFFFFFFFF, s)

        for k, s in [(0, 3), (1, 7), (2, 11), (3, 19),
                     (4, 3), (5, 7), (6, 11), (7, 19),
                     (8, 3), (9, 7), (10, 11), (11, 19),
                     (12, 3), (13, 7), (14, 11), (15, 19)]:
            a = R1(a, b, c, d, k, s)
            a, b, c, d = d, a, b, c

        # Round 2 — G(b,c,d) = (b & c) | (b & d) | (c & d)
        def R2(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
            return _rol((a + ((b & c) | (b & d) | (c & d)) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)

        for k, s in [(0, 3), (4, 5), (8, 9), (12, 13),
                     (1, 3), (5, 5), (9, 9), (13, 13),
                     (2, 3), (6, 5), (10, 9), (14, 13),
                     (3, 3), (7, 5), (11, 9), (15, 13)]:
            a = R2(a, b, c, d, k, s)
            a, b, c, d = d, a, b, c

        # Round 3 — H(b,c,d) = b ^ c ^ d
        def R3(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
            return _rol((a + (b ^ c ^ d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        for k, s in [(0, 3), (8, 9), (4, 11), (12, 15),
                     (2, 3), (10, 9), (6, 11), (14, 15),
                     (1, 3), (9, 9), (5, 11), (13, 15),
                     (3, 3), (11, 9), (7, 11), (15, 15)]:
            a = R3(a, b, c, d, k, s)
            a, b, c, d = d, a, b, c

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d).hex()


def _compute_ntlm(plaintext: str) -> str:
    """Compute NTLM hash (MD4 of UTF-16LE encoded plaintext)."""
    return _md4(plaintext.encode("utf-16-le"))


def _verify_ntlm(plaintext: str, hash_value: str) -> bool:
    """Verify plaintext against an NTLM hash."""
    return _compute_ntlm(plaintext) == hash_value.lower()


def compute_hash(plaintext: str, hash_type: HashType, salt: str = "") -> str:
    """Compute hash of plaintext+salt for the given algorithm."""
    if hash_type == HashType.BCRYPT:
        return _compute_bcrypt(plaintext + salt)
    if hash_type == HashType.ARGON2:
        return _compute_argon2(plaintext + salt)
    if hash_type == HashType.NTLM:
        return _compute_ntlm(plaintext + salt)
    hash_fn = HASH_FUNCTIONS.get(hash_type)
    if hash_fn is None:
        raise ValueError(f"Unsupported hash type for computation: {hash_type}")
    return hash_fn((plaintext + salt).encode("utf-8")).hexdigest()


def verify(plaintext: str, target: HashTarget) -> bool:
    """Check if plaintext matches the target hash."""
    if target.hash_type == HashType.UNKNOWN:
        return False
    if target.hash_type == HashType.BCRYPT:
        return _verify_bcrypt(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.ARGON2:
        return _verify_argon2(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.NTLM:
        return _verify_ntlm(plaintext + target.salt, target.hash_value)
    return compute_hash(plaintext, target.hash_type, target.salt) == target.hash_value.lower()


def verify_any(plaintext: str, target: HashTarget) -> HashType | None:
    """Try all supported hash types, return the matching one or None."""
    types_to_try = target.possible_types if target.possible_types else tuple(HASH_FUNCTIONS) + tuple(_SPECIAL_TYPES)
    salted = plaintext + target.salt
    encoded = salted.encode("utf-8")
    target_lower = target.hash_value.lower()

    for hash_type in types_to_try:
        if hash_type in _SPECIAL_TYPES:
            # Special types use their own verify logic
            temp_target = HashTarget(hash_value=target.hash_value, hash_type=hash_type, salt=target.salt)
            if verify(plaintext, temp_target):
                return hash_type
            continue
        hash_fn = HASH_FUNCTIONS.get(hash_type)
        if hash_fn is None:
            continue
        if hash_fn(encoded).hexdigest() == target_lower:
            return hash_type
    return None
