"""Tests for session save/resume functionality."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hashcrack.models import (
    AttackPhase,
    CrackResult,
    CrackSession,
    HashTarget,
    HashType,
    TargetProfile,
)
from hashcrack.session import generate_session_id, load_session, save_session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(**kwargs) -> CrackSession:
    defaults: dict = {
        "session_id": "abc12345",
        "target": HashTarget(
            hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
            hash_type=HashType.MD5,
            salt="",
            possible_types=(HashType.MD5,),
        ),
        "profile": None,
        "current_phase": AttackPhase.DICTIONARY,
        "candidates_tried": 100,
        "wordlist_offset": 50,
        "phases_completed": ("DICTIONARY",),
        "completed": False,
        "result": None,
    }
    defaults.update(kwargs)
    return CrackSession(**defaults)


# ---------------------------------------------------------------------------
# generate_session_id
# ---------------------------------------------------------------------------


def test_generate_session_id_length() -> None:
    sid = generate_session_id()
    assert len(sid) == 8


def test_generate_session_id_is_hex() -> None:
    sid = generate_session_id()
    int(sid, 16)  # raises ValueError if not valid hex


def test_generate_session_id_unique() -> None:
    ids = {generate_session_id() for _ in range(100)}
    assert len(ids) == 100


# ---------------------------------------------------------------------------
# Roundtrip: basic session (no result, no profile)
# ---------------------------------------------------------------------------


def test_roundtrip_minimal(tmp_path: Path) -> None:
    session = _make_session()
    path = tmp_path / "session.json"
    save_session(session, path)
    loaded = load_session(path)

    assert loaded.session_id == session.session_id
    assert loaded.target.hash_value == session.target.hash_value
    assert loaded.target.hash_type == session.target.hash_type
    assert loaded.target.salt == session.target.salt
    assert loaded.target.possible_types == session.target.possible_types
    assert loaded.current_phase == session.current_phase
    assert loaded.candidates_tried == session.candidates_tried
    assert loaded.wordlist_offset == session.wordlist_offset
    assert loaded.phases_completed == session.phases_completed
    assert loaded.completed == session.completed
    assert loaded.result is None
    assert loaded.profile is None


# ---------------------------------------------------------------------------
# Roundtrip: session with found result
# ---------------------------------------------------------------------------


def test_roundtrip_with_found_result(tmp_path: Path) -> None:
    result = CrackResult(
        found=True,
        plaintext="password",
        hash_type=HashType.MD5,
        attack_phase=AttackPhase.DICTIONARY,
        attempts=42,
        duration_seconds=1.23,
    )
    session = _make_session(result=result, completed=True)
    path = tmp_path / "session_found.json"
    save_session(session, path)
    loaded = load_session(path)

    assert loaded.completed is True
    assert loaded.result is not None
    assert loaded.result.found is True
    assert loaded.result.plaintext == "password"
    assert loaded.result.hash_type == HashType.MD5
    assert loaded.result.attack_phase == AttackPhase.DICTIONARY
    assert loaded.result.attempts == 42
    assert loaded.result.duration_seconds == pytest.approx(1.23)


# ---------------------------------------------------------------------------
# Roundtrip: session with not-found result
# ---------------------------------------------------------------------------


def test_roundtrip_with_not_found_result(tmp_path: Path) -> None:
    result = CrackResult(found=False, attempts=9999, duration_seconds=60.0)
    session = _make_session(result=result, completed=True)
    path = tmp_path / "session_notfound.json"
    save_session(session, path)
    loaded = load_session(path)

    assert loaded.result is not None
    assert loaded.result.found is False
    assert loaded.result.plaintext is None
    assert loaded.result.hash_type is None
    assert loaded.result.attack_phase is None
    assert loaded.result.attempts == 9999


# ---------------------------------------------------------------------------
# Roundtrip: session with TargetProfile
# ---------------------------------------------------------------------------


def test_roundtrip_with_profile(tmp_path: Path) -> None:
    profile = TargetProfile(
        first_name="Alice",
        last_name="Smith",
        nickname="ali",
        birthdate="1990-01-01",
        partner_name="Bob",
        partner_birthdate="1988-05-15",
        child_name="Charlie",
        pet_name="Fluffy",
        keywords=("cats", "coffee"),
        special_numbers=("1234", "42"),
    )
    session = _make_session(profile=profile)
    path = tmp_path / "session_profile.json"
    save_session(session, path)
    loaded = load_session(path)

    assert loaded.profile is not None
    assert loaded.profile.first_name == "Alice"
    assert loaded.profile.last_name == "Smith"
    assert loaded.profile.nickname == "ali"
    assert loaded.profile.birthdate == "1990-01-01"
    assert loaded.profile.partner_name == "Bob"
    assert loaded.profile.partner_birthdate == "1988-05-15"
    assert loaded.profile.child_name == "Charlie"
    assert loaded.profile.pet_name == "Fluffy"
    assert loaded.profile.keywords == ("cats", "coffee")
    assert loaded.profile.special_numbers == ("1234", "42")


# ---------------------------------------------------------------------------
# Roundtrip: session without TargetProfile
# ---------------------------------------------------------------------------


def test_roundtrip_without_profile(tmp_path: Path) -> None:
    session = _make_session(profile=None)
    path = tmp_path / "session_noprofile.json"
    save_session(session, path)
    loaded = load_session(path)
    assert loaded.profile is None


# ---------------------------------------------------------------------------
# Forward compatibility: missing optional fields
# ---------------------------------------------------------------------------


def test_load_handles_missing_optional_fields(tmp_path: Path) -> None:
    """A JSON file with only required fields should load without error."""
    minimal = {
        "session_id": "deadbeef",
        "target": {"hash_value": "abc123"},
    }
    path = tmp_path / "minimal.json"
    path.write_text(json.dumps(minimal), encoding="utf-8")
    loaded = load_session(path)

    assert loaded.session_id == "deadbeef"
    assert loaded.target.hash_value == "abc123"
    assert loaded.target.hash_type == HashType.UNKNOWN
    assert loaded.profile is None
    assert loaded.result is None
    assert loaded.candidates_tried == 0
    assert loaded.wordlist_offset == 0
    assert loaded.phases_completed == ()
    assert loaded.completed is False


def test_load_handles_missing_result_fields(tmp_path: Path) -> None:
    """A result dict with missing fields should default gracefully."""
    data = {
        "session_id": "aabbccdd",
        "target": {"hash_value": "xyz"},
        "result": {"found": True},
    }
    path = tmp_path / "partial_result.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = load_session(path)

    assert loaded.result is not None
    assert loaded.result.found is True
    assert loaded.result.plaintext is None
    assert loaded.result.attempts == 0
