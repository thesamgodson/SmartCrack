"""Tests for timeout_seconds enforcement in run_orchestrated."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from smartcrack.models import AttackPhase, HashTarget, HashType
from smartcrack.orchestrator import plan_attacks, run_orchestrated


@pytest.fixture()
def tmp_wordlist(tmp_path: Path) -> Path:
    words = ["apple", "banana", "password", "hello", "world"]
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
def unfindable_target() -> HashTarget:
    return HashTarget(
        hash_value=hashlib.md5(b"zzz_never_found_zzz").hexdigest(),
        hash_type=HashType.MD5,
    )


class TestTimeoutZeroMeansNoTimeout:
    def test_all_phases_run_with_zero_timeout(
        self, tmp_wordlist: Path, unfindable_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        phase_events: list[str] = []

        run_orchestrated(
            target=unfindable_target,
            plans=plans,
            max_workers=1,
            on_phase_change=lambda name, idx, total: phase_events.append(name),
            timeout_seconds=0,
        )

        assert len(phase_events) == len(plans)

    def test_default_timeout_is_zero(
        self, tmp_wordlist: Path, md5_password_target: HashTarget
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none")
        result = run_orchestrated(
            target=md5_password_target,
            plans=plans,
            max_workers=1,
        )
        assert result.found is True


class TestTimeoutStopsBeforeNextPhase:
    def test_timeout_prevents_second_phase(
        self, tmp_wordlist: Path, unfindable_target: HashTarget
    ) -> None:
        """When timeout expires after phase 1, phase 2 should not start."""
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        assert len(plans) >= 2, "Need at least 2 phases for this test"

        phase_events: list[str] = []

        # Patch time.monotonic so it reports past-deadline after the first phase.
        # call_count <= 2: call 1 computes the deadline (time.monotonic() + timeout),
        # call 2 is the pre-phase-1 check — both return 100.0 (within deadline).
        # call_count > 2: pre-phase-2 check returns 200.0 (past deadline 110).
        call_count = 0

        def fake_monotonic() -> float:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return 100.0  # start time and first check — within deadline
            return 200.0  # second check onwards — past deadline (100 + 10 = 110 < 200)

        with patch("smartcrack.orchestrator.time.monotonic", side_effect=fake_monotonic):
            result = run_orchestrated(
                target=unfindable_target,
                plans=plans,
                max_workers=1,
                on_phase_change=lambda name, idx, total: phase_events.append(name),
                timeout_seconds=10,
            )

        assert result.found is False
        assert len(phase_events) == 1
        assert result.attempts > 0

    def test_timeout_returns_accumulated_attempts(
        self, tmp_wordlist: Path, unfindable_target: HashTarget
    ) -> None:
        """Result from a timed-out run should have attempts from completed phases."""
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")

        # call_count <= 2: call 1 computes the deadline, call 2 is the pre-phase-1
        # check — both within deadline. call_count > 2: past deadline.
        call_count = 0

        def fake_monotonic() -> float:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return 100.0
            return 200.0

        with patch("smartcrack.orchestrator.time.monotonic", side_effect=fake_monotonic):
            result = run_orchestrated(
                target=unfindable_target,
                plans=plans,
                max_workers=1,
                timeout_seconds=10,
            )

        assert result.found is False
        assert result.attempts > 0
        assert result.duration_seconds > 0.0


class TestTimeoutWithImmediateFind:
    def test_found_before_timeout_returns_result(
        self, tmp_wordlist: Path, md5_password_target: HashTarget
    ) -> None:
        """If hash is found in phase 1 before timeout, result is returned normally."""
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")

        result = run_orchestrated(
            target=md5_password_target,
            plans=plans,
            max_workers=1,
            timeout_seconds=9999,
        )

        assert result.found is True
        assert result.plaintext == "password"
        assert result.attack_phase == AttackPhase.DICTIONARY


class TestNegativeTimeoutRaises:
    def test_negative_timeout_raises(self) -> None:
        target = HashTarget(hash_value="abc", hash_type=HashType.MD5)
        plans: list = []
        with pytest.raises(ValueError, match="timeout_seconds must be >= 0"):
            run_orchestrated(target, plans, timeout_seconds=-1)
