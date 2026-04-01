"""Core data models — frozen dataclasses and enums."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


class HashType(Enum):
    MD5 = auto()
    SHA1 = auto()
    SHA224 = auto()
    SHA256 = auto()
    SHA384 = auto()
    SHA512 = auto()
    BCRYPT = auto()
    ARGON2 = auto()
    NTLM = auto()
    # Unix crypt formats
    MD5CRYPT = auto()       # $1$ — old Linux, Cisco
    SHA256CRYPT = auto()    # $5$ — RHEL/CentOS
    SHA512CRYPT = auto()    # $6$ — most common Linux
    YESCRYPT = auto()       # $y$ — Debian 11+, Ubuntu 22+
    # Web CMS
    PHPASS = auto()         # $P$/$H$ — WordPress, phpBB
    DRUPAL7 = auto()        # $S$ — Drupal 7
    # Windows AD
    NETNTLMV2 = auto()     # NetNTLMv2 challenge/response
    KERBEROS_TGS = auto()  # $krb5tgs$23$ — Kerberoasting
    KERBEROS_ASREP = auto() # $krb5asrep$23$ — AS-REP Roasting
    DCC2 = auto()           # $DCC2$ — cached domain creds
    # Database
    MYSQL41 = auto()        # *hex — MySQL 4.1/5
    MSSQL2012 = auto()      # 0x0200 — SQL Server 2012+
    # Web framework
    DJANGO_PBKDF2 = auto()  # pbkdf2_sha256$ — Django
    SCRYPT = auto()         # scrypt format
    # LDAP
    LDAP_SSHA = auto()      # {SSHA} — LDAP salted SHA1
    # Phase 3 — Medium priority
    LM = auto()             # LAN Manager (16 hex)
    NETNTLMV1 = auto()      # NetNTLMv1 challenge/response
    DCC1 = auto()            # Domain Cached Credentials v1
    ORACLE11G = auto()       # Oracle 11g S: type
    ORACLE12C = auto()       # Oracle 12c+ T: type
    POSTGRES_MD5 = auto()    # md5 + md5(pass+user)
    POSTGRES_SCRAM = auto()  # SCRAM-SHA-256
    # Phase 4 — Specialized
    KEEPASS = auto()         # $keepass$ — KeePass 1/2
    WPA2_PMKID = auto()     # WPA*01* — WiFi PMKID
    MS_OFFICE = auto()       # Office 2007-2019
    PDF = auto()             # PDF 1.4-1.7
    RAR5 = auto()            # RAR5 archive
    SEVENZIP = auto()        # 7-Zip archive
    BITCOIN = auto()         # Bitcoin wallet.dat
    ETHEREUM = auto()        # Ethereum wallet
    CISCO_TYPE8 = auto()     # $8$ — Cisco PBKDF2
    CISCO_TYPE9 = auto()     # $9$ — Cisco scrypt
    MACOS_PBKDF2 = auto()   # macOS 10.8+ user password
    UNKNOWN = auto()


class AttackPhase(Enum):
    DICTIONARY = "dictionary"
    RULES = "rules"
    PROFILE = "profile"
    HYBRID = "hybrid"
    MASK = "mask"
    RAINBOW = "rainbow"
    COMBO = "combo"
    EXPANDED_PROFILE = "expanded_profile"


@dataclass(frozen=True)
class HashTarget:
    """Immutable representation of a hash to crack."""

    hash_value: str
    hash_type: HashType = HashType.UNKNOWN
    salt: str = ""
    possible_types: tuple[HashType, ...] = ()


@dataclass(frozen=True)
class CrackResult:
    """Immutable result from a cracking attempt."""

    found: bool
    plaintext: str | None = None
    hash_type: HashType | None = None
    attack_phase: AttackPhase | None = None
    attempts: int = 0
    duration_seconds: float = 0.0


@dataclass(frozen=True)
class AttackConfig:
    """Configuration for an attack run."""

    wordlist_path: Path = Path("100K.txt")
    rules_enabled: bool = False
    rules_preset: str = "quick"
    max_workers: int | None = None
    batch_size: int = 10_000


@dataclass(frozen=True)
class TargetProfile:
    """Target profile for personalized password generation."""

    first_name: str = ""
    last_name: str = ""
    nickname: str = ""
    birthdate: str = ""
    partner_name: str = ""
    partner_birthdate: str = ""
    child_name: str = ""
    pet_name: str = ""
    keywords: tuple[str, ...] = ()
    special_numbers: tuple[str, ...] = ()


@dataclass(frozen=True)
class LLMConfig:
    """Configuration for the LLM-powered profiler."""

    base_url: str = ""
    api_key: str = ""
    model: str = ""
    timeout_seconds: int = 90


@dataclass(frozen=True)
class MutationProfile:
    """LLM-inferred password mutation preferences for a target persona."""

    leet_likelihood: str = "low"  # none|low|medium|high
    special_char_preference: tuple[str, ...] = ("!", "1")
    separator_preference: tuple[str, ...] = ("", "_", ".")
    capitalization_style: str = "capitalize"  # lower|capitalize|camel|upper
    typical_length_range: tuple[int, int] = (8, 16)
    suffix_patterns: tuple[str, ...] = ("123", "!", "1")


@dataclass(frozen=True)
class ExpandedProfile:
    """Culturally-expanded target profile from LLM knowledge extraction."""

    names: tuple[str, ...] = ()
    nicknames: tuple[str, ...] = ()
    dates: tuple[str, ...] = ()
    keywords_direct: tuple[str, ...] = ()
    keywords_cultural: tuple[str, ...] = ()
    keywords_generational: tuple[str, ...] = ()
    locale_slang: tuple[str, ...] = ()
    phonetic_variants: tuple[str, ...] = ()
    related_numbers: tuple[str, ...] = ()
    mutation_profile: MutationProfile = field(default_factory=MutationProfile)
    high_confidence_seeds: tuple[str, ...] = ()


@dataclass
class CrackSession:
    """Mutable session state for save/resume."""

    session_id: str = ""
    target: HashTarget = field(default_factory=lambda: HashTarget(hash_value=""))
    profile: TargetProfile | None = None
    current_phase: AttackPhase = AttackPhase.DICTIONARY
    candidates_tried: int = 0
    wordlist_offset: int = 0
    phases_completed: tuple[str, ...] = ()  # Stores AttackPhase.value strings (e.g. "dictionary")
    completed: bool = False
    result: CrackResult | None = None
