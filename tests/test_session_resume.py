"""Tests for session resume wiring in the orchestrator."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from smartcrack.models import (
    AttackPhase,
    CrackSession,
    HashTarget,
    HashType,
)
from smartcrack.orchestrator import plan_attacks, run_orchestrated
from smartcrack.session import load_session, save_session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_wordlist(tmp_path: Path) -> Path:
    words = ["apple", "banana", "password", "hello", "world", "admin", "root", "letmein"]
    wl = tmp_path / "words.txt"
    wl.write_text("\n".join(words) + "\n")
    return wl


@pytest.fixture()
def md5_password_target() -> HashTarget:
    return HashTarget(
        hash_value=hashlib.md5(b"password").hexdigest(),
        hash_type=HashType.MD5,
    )


@pytest.fixture()
def md5_unfindable_target() -> HashTarget:
    return HashTarget(
        hash_value=hashlib.md5(b"zzz_never_found_zzz").hexdigest(),
        hash_type=HashType.MD5,
    )


# ---------------------------------------------------------------------------
# Phase skipping
# ---------------------------------------------------------------------------


class TestPhaseSkipping:
    def test_completed_phases_are_skipped(
        self, tmp_wordlist: Path, md5_password_target: HashTarget
    ) -> None:
        """When DICTIONARY is in phases_completed, it should be skipped."""
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        session = CrackSession(
            phases_completed=("dictionary",),
        )

        phase_names: list[str] = []
        run_orchestrated(
            md5_password_target,
            plans,
            max_workers=1,
            on_phase_change=lambda name, idx, total: phase_names.append(name),
            session=session,
        )

        # Dictionary phase should NOT appear in the phase change callbacks
        assert "Dictionary" not in phase_names

    def test_multiple_completed_phases_skipped(
        self, tmp_wordlist: Path, md5_unfindable_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        session = CrackSession(
            phases_completed=("dictionary", "rules"),
        )

        phase_names: list[str] = []
        run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
            on_phase_change=lambda name, idx, total: phase_names.append(name),
            session=session,
        )

        # Both phases skipped, no callbacks fired
        assert len(phase_names) == 0

    def test_empty_phases_completed_skips_nothing(
        self, tmp_wordlist: Path, md5_password_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none")
        session = CrackSession(phases_completed=())

        result = run_orchestrated(
            md5_password_target,
            plans,
            max_workers=1,
            session=session,
        )

        assert result.found is True
        assert result.plaintext == "password"


# ---------------------------------------------------------------------------
# Session state accumulation
# ---------------------------------------------------------------------------


class TestSessionStateUpdates:
    def test_candidates_tried_accumulates(
        self, tmp_wordlist: Path, md5_unfindable_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        session = CrackSession(candidates_tried=0)

        run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
            session=session,
        )

        # Should have tried candidates from both dictionary and rules phases
        assert session.candidates_tried > 0

    def test_candidates_tried_accumulates_with_prior_count(
        self, tmp_wordlist: Path, md5_unfindable_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none")
        session = CrackSession(candidates_tried=100)

        run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
            session=session,
        )

        # Must be more than the initial 100
        assert session.candidates_tried > 100

    def test_phases_completed_updated_after_each_phase(
        self, tmp_wordlist: Path, md5_unfindable_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        session = CrackSession()

        run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
            session=session,
        )

        assert "dictionary" in session.phases_completed
        assert "rules" in session.phases_completed

    def test_phases_completed_appends_to_existing(
        self, tmp_wordlist: Path, md5_unfindable_target: HashTarget
    ) -> None:
        """Resuming with some phases already done should append new completions."""
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        session = CrackSession(
            phases_completed=("dictionary",),
        )

        run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
            session=session,
        )

        assert session.phases_completed == ("dictionary", "rules")

    def test_current_phase_tracks_last_executed(
        self, tmp_wordlist: Path, md5_unfindable_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        session = CrackSession()

        run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
            session=session,
        )

        assert session.current_phase == AttackPhase.RULES

    def test_session_marked_completed_on_success(
        self, tmp_wordlist: Path, md5_password_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none")
        session = CrackSession()

        result = run_orchestrated(
            md5_password_target,
            plans,
            max_workers=1,
            session=session,
        )

        assert session.completed is True
        assert session.result is not None
        assert session.result.found is True
        assert result.found is True

    def test_session_marked_completed_on_exhaustion(
        self, tmp_wordlist: Path, md5_unfindable_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none")
        session = CrackSession()

        run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
            session=session,
        )

        assert session.completed is True
        assert session.result is not None
        assert session.result.found is False

    def test_wordlist_offset_updated_for_dictionary_phase(
        self, tmp_wordlist: Path, md5_unfindable_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none")
        session = CrackSession(wordlist_offset=0)

        run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
            session=session,
        )

        # Offset should reflect the number of dictionary candidates tried
        assert session.wordlist_offset > 0


# ---------------------------------------------------------------------------
# Backwards compatibility — session=None
# ---------------------------------------------------------------------------


class TestNoSessionBackwardsCompat:
    def test_no_session_returns_crack_result(
        self, tmp_wordlist: Path, md5_password_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none")

        result = run_orchestrated(
            md5_password_target,
            plans,
            max_workers=1,
        )

        assert result.found is True
        assert result.plaintext == "password"

    def test_no_session_not_found(
        self, tmp_wordlist: Path, md5_unfindable_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none")

        result = run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
        )

        assert result.found is False
        assert result.attempts > 0


# ---------------------------------------------------------------------------
# Wordlist offset in plan_attacks
# ---------------------------------------------------------------------------


class TestWordlistOffset:
    def test_plan_attacks_with_offset_skips_lines(self, tmp_wordlist: Path) -> None:
        """With offset=3, dictionary phase should skip first 3 words."""
        plans = plan_attacks(tmp_wordlist, rules_preset="none", wordlist_offset=3)
        candidates = list(plans[0].candidates_fn())
        # Original: apple, banana, password, hello, world, admin, root, letmein
        # After skipping 3: hello, world, admin, root, letmein
        assert candidates == ["hello", "world", "admin", "root", "letmein"]

    def test_plan_attacks_zero_offset_reads_all(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none", wordlist_offset=0)
        candidates = list(plans[0].candidates_fn())
        assert len(candidates) == 8
        assert candidates[0] == "apple"


# ---------------------------------------------------------------------------
# Save / load / resume round trip
# ---------------------------------------------------------------------------


class TestSaveLoadResumeRoundTrip:
    def test_round_trip_skips_completed_phases(
        self,
        tmp_path: Path,
        tmp_wordlist: Path,
        md5_unfindable_target: HashTarget,
    ) -> None:
        """Save a session with phases_completed, reload it, and verify skipping works."""
        session_path = tmp_path / "session.json"

        # Build a session that already finished the dictionary phase
        original = CrackSession(
            session_id="abc12345",
            target=md5_unfindable_target,
            phases_completed=("dictionary",),
            candidates_tried=50,
            wordlist_offset=8,
        )

        # Persist and reload
        save_session(original, session_path)
        loaded = load_session(session_path)

        # Round-trip preserves key fields
        assert loaded.session_id == "abc12345"
        assert loaded.phases_completed == ("dictionary",)
        assert loaded.candidates_tried == 50
        assert loaded.wordlist_offset == 8

        # Run orchestrator with the reloaded session (rules_preset="quick" adds RULES phase)
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        phase_names: list[str] = []
        run_orchestrated(
            md5_unfindable_target,
            plans,
            max_workers=1,
            on_phase_change=lambda name, idx, total: phase_names.append(name),
            session=loaded,
        )

        # Dictionary was in phases_completed — it must have been skipped
        assert "Dictionary" not in phase_names
        # Rules phase ran (not pre-completed)
        assert "Dictionary + Quick Rules" in phase_names
        # Session now reflects both phases as completed
        assert "dictionary" in loaded.phases_completed
        assert "rules" in loaded.phases_completed
        assert loaded.completed is True
