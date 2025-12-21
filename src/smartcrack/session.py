"""Session save/resume functionality for SmartCrack."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from smartcrack.models import (
    AttackPhase,
    CrackResult,
    CrackSession,
    HashTarget,
    HashType,
    TargetProfile,
)


def generate_session_id() -> str:
    """Return the first 8 characters of a UUID4 hex string."""
    return uuid.uuid4().hex[:8]


def _hash_target_to_dict(target: HashTarget) -> dict[str, Any]:
    return {
        "hash_value": target.hash_value,
        "hash_type": target.hash_type.name,
        "salt": target.salt,
        "possible_types": [ht.name for ht in target.possible_types],
    }


def _safe_hash_type(name: str) -> HashType:
    """Resolve a hash type name, falling back to UNKNOWN for unrecognized values."""
    try:
        return HashType[name]
    except KeyError:
        return HashType.UNKNOWN


def _safe_attack_phase(name: str) -> AttackPhase:
    """Resolve an attack phase name, falling back to DICTIONARY for unrecognized values."""
    try:
        return AttackPhase[name]
    except KeyError:
        return AttackPhase.DICTIONARY


def _hash_target_from_dict(data: dict[str, Any]) -> HashTarget:
    return HashTarget(
        hash_value=data.get("hash_value", ""),
        hash_type=_safe_hash_type(data.get("hash_type", "UNKNOWN")),
        salt=data.get("salt", ""),
        possible_types=tuple(
            _safe_hash_type(name) for name in data.get("possible_types", [])
        ),
    )


def _crack_result_to_dict(result: CrackResult) -> dict[str, Any]:
    return {
        "found": result.found,
        "plaintext": result.plaintext,
        "hash_type": result.hash_type.name if result.hash_type is not None else None,
        "attack_phase": result.attack_phase.name if result.attack_phase is not None else None,
        "attempts": result.attempts,
        "duration_seconds": result.duration_seconds,
    }


def _crack_result_from_dict(data: dict[str, Any]) -> CrackResult:
    raw_hash_type = data.get("hash_type")
    raw_phase = data.get("attack_phase")
    return CrackResult(
        found=data.get("found", False),
        plaintext=data.get("plaintext"),
        hash_type=_safe_hash_type(raw_hash_type) if raw_hash_type is not None else None,
        attack_phase=_safe_attack_phase(raw_phase) if raw_phase is not None else None,
        attempts=data.get("attempts", 0),
        duration_seconds=data.get("duration_seconds", 0.0),
    )


def _target_profile_to_dict(profile: TargetProfile) -> dict[str, Any]:
    return {
        "first_name": profile.first_name,
        "last_name": profile.last_name,
        "nickname": profile.nickname,
        "birthdate": profile.birthdate,
        "partner_name": profile.partner_name,
        "partner_birthdate": profile.partner_birthdate,
        "child_name": profile.child_name,
        "pet_name": profile.pet_name,
        "keywords": list(profile.keywords),
        "special_numbers": list(profile.special_numbers),
    }


def _target_profile_from_dict(data: dict[str, Any]) -> TargetProfile:
    return TargetProfile(
        first_name=data.get("first_name", ""),
        last_name=data.get("last_name", ""),
        nickname=data.get("nickname", ""),
        birthdate=data.get("birthdate", ""),
        partner_name=data.get("partner_name", ""),
        partner_birthdate=data.get("partner_birthdate", ""),
        child_name=data.get("child_name", ""),
        pet_name=data.get("pet_name", ""),
        keywords=tuple(data.get("keywords", [])),
        special_numbers=tuple(data.get("special_numbers", [])),
    )


def _session_to_dict(session: CrackSession) -> dict[str, Any]:
    return {
        "session_id": session.session_id,
        "target": _hash_target_to_dict(session.target),
        "profile": _target_profile_to_dict(session.profile) if session.profile is not None else None,
        "current_phase": session.current_phase.name,
        "candidates_tried": session.candidates_tried,
        "wordlist_offset": session.wordlist_offset,
        "phases_completed": list(session.phases_completed),
        "completed": session.completed,
        "result": _crack_result_to_dict(session.result) if session.result is not None else None,
    }


def _session_from_dict(data: dict[str, Any]) -> CrackSession:
    raw_phase = data.get("current_phase", "DICTIONARY")
    # AttackPhase uses string values, not auto() — look up by name
    current_phase = _safe_attack_phase(raw_phase)

    raw_result = data.get("result")
    raw_profile = data.get("profile")

    return CrackSession(
        session_id=data.get("session_id", ""),
        target=_hash_target_from_dict(data.get("target", {"hash_value": ""})),
        profile=_target_profile_from_dict(raw_profile) if raw_profile is not None else None,
        current_phase=current_phase,
        candidates_tried=data.get("candidates_tried", 0),
        wordlist_offset=data.get("wordlist_offset", 0),
        phases_completed=tuple(data.get("phases_completed", [])),
        completed=data.get("completed", False),
        result=_crack_result_from_dict(raw_result) if raw_result is not None else None,
    )


def save_session(session: CrackSession, path: Path) -> None:
    """Serialize a CrackSession to a JSON file at the given path."""
    data = _session_to_dict(session)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_session(path: Path) -> CrackSession:
    """Deserialize a CrackSession from a JSON file, handling missing fields gracefully."""
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return _session_from_dict(data)
