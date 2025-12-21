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
    UNKNOWN = auto()


class AttackPhase(Enum):
    DICTIONARY = "dictionary"
    RULES = "rules"
    PROFILE = "profile"
    HYBRID = "hybrid"
    ADAPTIVE = "adaptive"


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
    timeout_seconds: int = 0
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


@dataclass
class CrackSession:
    """Mutable session state for save/resume."""

    session_id: str = ""
    target: HashTarget = field(default_factory=lambda: HashTarget(hash_value=""))
    profile: TargetProfile | None = None
    current_phase: AttackPhase = AttackPhase.DICTIONARY
    candidates_tried: int = 0
    wordlist_offset: int = 0
    phases_completed: tuple[str, ...] = ()
    completed: bool = False
    result: CrackResult | None = None
