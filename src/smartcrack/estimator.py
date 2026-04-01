"""Crack time estimator — pre-attack probability and duration estimates."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

import httpx

from smartcrack.models import HashTarget, HashType

logger = logging.getLogger(__name__)

HASH_SPEEDS: dict[HashType, int] = {
    # Fast (CPU H/s estimates)
    HashType.MD5: 5_000_000,
    HashType.SHA1: 3_000_000,
    HashType.SHA224: 2_500_000,
    HashType.SHA256: 2_000_000,
    HashType.SHA384: 1_500_000,
    HashType.SHA512: 1_000_000,
    HashType.NTLM: 8_000_000,
    # Iterated
    HashType.MD5CRYPT: 50_000,
    HashType.SHA256CRYPT: 10_000,
    HashType.SHA512CRYPT: 5_000,
    HashType.PHPASS: 30_000,
    HashType.DRUPAL7: 3_000,
    HashType.DJANGO_PBKDF2: 2_000,
    HashType.MYSQL41: 4_000_000,
    HashType.MSSQL2012: 500_000,
    # Slow
    HashType.BCRYPT: 100,
    HashType.SCRYPT: 50,
    HashType.ARGON2: 10,
    HashType.YESCRYPT: 20,
    # AD/Kerberos
    HashType.NETNTLMV2: 1_000_000,
    HashType.KERBEROS_TGS: 500_000,
    HashType.KERBEROS_ASREP: 500_000,
    HashType.DCC2: 5_000,
    # LDAP
    HashType.LDAP_SSHA: 3_000_000,
    # Phase 3
    HashType.LM: 10_000_000,
    HashType.NETNTLMV1: 2_000_000,
    HashType.DCC1: 5_000_000,
    HashType.ORACLE11G: 1_000_000,
    HashType.ORACLE12C: 2_000,
    HashType.POSTGRES_MD5: 4_000_000,
    HashType.POSTGRES_SCRAM: 2_000,
    # Phase 4
    HashType.KEEPASS: 500,
    HashType.WPA2_PMKID: 200_000,
    HashType.MS_OFFICE: 500,
    HashType.PDF: 5_000,
    HashType.RAR5: 1_000,
    HashType.SEVENZIP: 500,
    HashType.BITCOIN: 500,
    HashType.ETHEREUM: 1_000,
    HashType.CISCO_TYPE8: 2_000,
    HashType.CISCO_TYPE9: 50,
    HashType.MACOS_PBKDF2: 1_000,
    # Unknown
    HashType.UNKNOWN: 1_000_000,
}

_RULES_MULTIPLIER: dict[str, int] = {
    "none": 1,
    "quick": 11,
    "thorough": 23,
}

_COMMON_PASSWORD_SPACE = 10_000_000


@dataclass(frozen=True)
class CrackEstimate:
    """Immutable pre-attack estimate for a hash cracking attempt."""

    hash_type: HashType
    wordlist_size: int
    dictionary_probability: float
    dictionary_eta: float
    rules_probability: float
    rules_eta: float
    mask_eta: float | None
    hibp_seen_count: int | None
    recommendation: str


def _count_wordlist_lines(wordlist_path: Path) -> int:
    """Count non-empty lines in a wordlist file."""
    count = 0
    with open(wordlist_path, "r", encoding="iso-8859-1") as f:
        for line in f:
            if line.rstrip("\n\r"):
                count += 1
    return count


def _eta_seconds(candidate_count: int, hash_type: HashType) -> float:
    """Estimate seconds to exhaust candidate_count candidates for hash_type."""
    speed = HASH_SPEEDS.get(hash_type, 1_000_000)
    if speed <= 0:
        return float("inf")
    return candidate_count / speed


def _estimate_probability(wordlist_size: int, multiplier: int) -> float:
    """Estimate probability of cracking based on coverage of common password space."""
    effective_size = wordlist_size * multiplier
    probability = min(effective_size / _COMMON_PASSWORD_SPACE, 0.95)
    return round(probability, 4)


def _build_recommendation(
    hash_type: HashType,
    dictionary_prob: float,
    rules_prob: float,
    hibp_count: int | None,
) -> str:
    """Generate a recommendation string based on the estimate."""
    parts: list[str] = []

    if dictionary_prob >= 0.5:
        parts.append(
            "High probability of dictionary crack — the wordlist covers a large "
            "portion of common passwords."
        )
    elif dictionary_prob >= 0.1:
        parts.append(
            "Moderate dictionary probability. Rules will significantly improve coverage."
        )
    else:
        parts.append(
            "Low dictionary probability. Consider a larger wordlist or profile-based attack."
        )

    if hash_type in (HashType.MD5, HashType.SHA1, HashType.NTLM):
        parts.append(
            f"{hash_type.name} is a fast hash — attacks will complete quickly. "
            "The target should migrate to bcrypt or argon2."
        )
    elif hash_type in (HashType.BCRYPT, HashType.ARGON2):
        parts.append(
            f"{hash_type.name} is a slow hash — expect long runtimes. "
            "Focus on targeted attacks (profile, AI masks) over brute force."
        )

    if hibp_count is not None and hibp_count > 0:
        parts.append(
            f"This hash has been seen {hibp_count:,} times in breaches (HIBP). "
            "Very likely to be a common password."
        )

    return " ".join(parts)


def estimate_crack(
    target: HashTarget,
    wordlist_path: Path,
    rules_preset: str = "quick",
) -> CrackEstimate:
    """Estimate probability and time to crack a hash before running any attack."""
    wordlist_size = _count_wordlist_lines(wordlist_path)
    hash_type = target.hash_type if target.hash_type != HashType.UNKNOWN else HashType.MD5

    rules_mult = _RULES_MULTIPLIER.get(rules_preset, 11)

    dictionary_prob = _estimate_probability(wordlist_size, 1)
    rules_prob = _estimate_probability(wordlist_size, rules_mult)

    dictionary_eta = _eta_seconds(wordlist_size, hash_type)
    rules_eta = _eta_seconds(wordlist_size * rules_mult, hash_type)

    hibp_count = check_hibp(target.hash_value) if len(target.hash_value) == 40 else None

    recommendation = _build_recommendation(hash_type, dictionary_prob, rules_prob, hibp_count)

    return CrackEstimate(
        hash_type=hash_type,
        wordlist_size=wordlist_size,
        dictionary_probability=dictionary_prob,
        dictionary_eta=dictionary_eta,
        rules_probability=rules_prob,
        rules_eta=rules_eta,
        mask_eta=None,
        hibp_seen_count=hibp_count,
        recommendation=recommendation,
    )


_HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def check_hibp(hash_value: str) -> int | None:
    """Check a SHA1 hash against the Have I Been Pwned Passwords API."""
    sha1_hex = hash_value.upper()
    if len(sha1_hex) != 40:
        sha1_hex = hashlib.sha1(hash_value.encode()).hexdigest().upper()

    prefix = sha1_hex[:5]
    suffix = sha1_hex[5:]

    try:
        response = httpx.get(
            f"{_HIBP_API_URL}{prefix}",
            timeout=5.0,
            headers={"User-Agent": "SmartCrack-PasswordAuditor"},
        )
        response.raise_for_status()
    except (httpx.TimeoutException, httpx.HTTPStatusError, Exception) as exc:
        logger.warning("HIBP check failed (%s) — skipping", type(exc).__name__)
        return None

    for line in response.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            try:
                return int(parts[1])
            except ValueError:
                return None

    return 0
