"""Tests for session save/resume functionality."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from smartcrack.models import (
    AttackPhase,
    CrackResult,
    CrackSession,
    HashTarget,
    HashType,
    TargetProfile,
)
from smartcrack.session import generate_session_id, load_session, save_session


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


# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------


def test_save_session_file_permissions(tmp_path: Path) -> None:
    """Session files must be owner-read/write only (0o600) to protect PII."""
    import stat

    session = _make_session()
    path = tmp_path / "session_perms.json"
    save_session(session, path)

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"Expected 0o600, got 0o{mode:o}"

    # Content must still be valid and round-trip correctly.
    loaded = load_session(path)
    assert loaded.session_id == session.session_id
    assert loaded.target.hash_value == session.target.hash_value


# ---------------------------------------------------------------------------
# Input validation: integer field clamping
# ---------------------------------------------------------------------------


def test_wordlist_offset_clamped_when_too_large(tmp_path: Path) -> None:
    """wordlist_offset above 10_000_000 should be clamped to the cap."""
    data = {
        "session_id": "clamped1",
        "target": {"hash_value": "abc"},
        "wordlist_offset": 99_999_999,
    }
    path = tmp_path / "offset_large.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = load_session(path)
    assert loaded.wordlist_offset == 10_000_000


def test_wordlist_offset_clamped_when_negative(tmp_path: Path) -> None:
    """wordlist_offset below 0 should be clamped to 0."""
    data = {
        "session_id": "clamped2",
        "target": {"hash_value": "abc"},
        "wordlist_offset": -500,
    }
    path = tmp_path / "offset_neg.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = load_session(path)
    assert loaded.wordlist_offset == 0


def test_candidates_tried_clamped_when_too_large(tmp_path: Path) -> None:
    """candidates_tried above 10_000_000_000 should be clamped to the cap."""
    data = {
        "session_id": "clamped3",
        "target": {"hash_value": "abc"},
        "candidates_tried": 99_999_999_999,
    }
    path = tmp_path / "candidates_large.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = load_session(path)
    assert loaded.candidates_tried == 10_000_000_000


# ---------------------------------------------------------------------------
# Input validation: invalid phase names filtered
# ---------------------------------------------------------------------------


def test_invalid_phases_filtered_out(tmp_path: Path) -> None:
    """Phase names not in AttackPhase should be silently dropped."""
    data = {
        "session_id": "phases1",
        "target": {"hash_value": "abc"},
        "phases_completed": ["dictionary", "BOGUS_PHASE", "rules", "__evil__"],
    }
    path = tmp_path / "bad_phases.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = load_session(path)
    assert set(loaded.phases_completed) == {"dictionary", "rules"}


def test_all_invalid_phases_yields_empty_tuple(tmp_path: Path) -> None:
    """If all phase names are invalid the result should be an empty tuple."""
    data = {
        "session_id": "phases2",
        "target": {"hash_value": "abc"},
        "phases_completed": ["NOT_A_PHASE", "ALSO_NOT"],
    }
    path = tmp_path / "all_bad_phases.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = load_session(path)
    assert loaded.phases_completed == ()


# ---------------------------------------------------------------------------
# Error handling: malformed JSON raises ValueError
# ---------------------------------------------------------------------------


def test_malformed_json_raises_value_error(tmp_path: Path) -> None:
    """A file with invalid JSON should raise ValueError, not JSONDecodeError."""
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="Corrupt session file"):
        load_session(path)


# ---------------------------------------------------------------------------
# Regression: valid sessions still load correctly after hardening
# ---------------------------------------------------------------------------


def test_valid_session_roundtrip_after_hardening(tmp_path: Path) -> None:
    """Ensure normal in-range values are preserved exactly after hardening."""
    session = _make_session(
        candidates_tried=42_000,
        wordlist_offset=1_500,
        phases_completed=("dictionary", "rules"),
    )
    path = tmp_path / "valid.json"
    save_session(session, path)
    loaded = load_session(path)

    assert loaded.candidates_tried == 42_000
    assert loaded.wordlist_offset == 1_500
    assert set(loaded.phases_completed) == {"dictionary", "rules"}
