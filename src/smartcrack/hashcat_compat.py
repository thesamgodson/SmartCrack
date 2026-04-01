"""Hashcat compatibility layer — mode mapping, potfile parsing, mask files."""

from __future__ import annotations

from pathlib import Path

from smartcrack.models import HashType

HASHCAT_MODES: dict[int, HashType] = {
    # Fast
    0: HashType.MD5,
    100: HashType.SHA1,
    1300: HashType.SHA224,
    1400: HashType.SHA256,
    10800: HashType.SHA384,
    1700: HashType.SHA512,
    1000: HashType.NTLM,
    # Unix crypt
    500: HashType.MD5CRYPT,
    7400: HashType.SHA256CRYPT,
    1800: HashType.SHA512CRYPT,
    # Web CMS
    400: HashType.PHPASS,
    7900: HashType.DRUPAL7,
    # bcrypt
    3200: HashType.BCRYPT,
    # Database
    300: HashType.MYSQL41,
    1731: HashType.MSSQL2012,
    # Windows AD
    5600: HashType.NETNTLMV2,
    13100: HashType.KERBEROS_TGS,
    18200: HashType.KERBEROS_ASREP,
    2100: HashType.DCC2,
    # Django
    10000: HashType.DJANGO_PBKDF2,
    # Phase 3
    3000: HashType.LM,
    5500: HashType.NETNTLMV1,
    1100: HashType.DCC1,
    112: HashType.ORACLE11G,
    12300: HashType.ORACLE12C,
    12: HashType.POSTGRES_MD5,
    28600: HashType.POSTGRES_SCRAM,
    # Phase 4
    13400: HashType.KEEPASS,
    22000: HashType.WPA2_PMKID,
    9600: HashType.MS_OFFICE,
    10500: HashType.PDF,
    13000: HashType.RAR5,
    11600: HashType.SEVENZIP,
    11300: HashType.BITCOIN,
    15600: HashType.ETHEREUM,
    9200: HashType.CISCO_TYPE8,
    9300: HashType.CISCO_TYPE9,
    7100: HashType.MACOS_PBKDF2,
}


def resolve_hashcat_mode(mode: int) -> HashType:
    return HASHCAT_MODES[mode]


def parse_potfile(path: Path) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        hash_val, plaintext = stripped.split(":", 1)
        results.append((hash_val, plaintext))
    return results


def parse_hcmask_file(path: Path) -> list[str]:
    masks: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        masks.append(stripped)
    return masks
