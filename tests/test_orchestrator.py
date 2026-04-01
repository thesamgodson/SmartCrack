"""Tests for the smart attack orchestrator."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from smartcrack.models import AttackPhase, HashTarget, HashType, TargetProfile
from smartcrack.orchestrator import AttackPlan, plan_attacks, run_orchestrated


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_wordlist(tmp_path: Path) -> Path:
    """Small temp wordlist with known plaintexts."""
    words = ["apple", "banana", "password", "hello", "world", "admin", "root", "letmein"]
    wl = tmp_path / "words.txt"
    wl.write_text("\n".join(words) + "\n")
    return wl


@pytest.fixture()
def simple_profile() -> TargetProfile:
    return TargetProfile(first_name="Alice", birthdate="1990-01-15", pet_name="Fluffy")


@pytest.fixture()
def md5_password_hash() -> tuple[str, str]:
    """(plaintext, md5_hex) for 'password'."""
    return "password", hashlib.md5(b"password").hexdigest()


@pytest.fixture()
def md5_hello_hash() -> tuple[str, str]:
    """(plaintext, md5_hex) for 'hello'."""
    return "hello", hashlib.md5(b"hello").hexdigest()


# ---------------------------------------------------------------------------
# plan_attacks — plan count and phase ordering
# ---------------------------------------------------------------------------


class TestPlanAttacks:
    def test_wordlist_only_gives_one_plan(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none")
        assert len(plans) == 1
        assert plans[0].phase == AttackPhase.DICTIONARY

    def test_with_rules_gives_two_plans(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        assert len(plans) == 2
        assert plans[0].phase == AttackPhase.DICTIONARY
        assert plans[1].phase == AttackPhase.RULES

    def test_with_thorough_rules_gives_two_plans(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="thorough")
        assert len(plans) == 2
        assert plans[1].phase == AttackPhase.RULES

    def test_with_profile_no_rules_gives_two_plans(
        self, tmp_wordlist: Path, simple_profile: TargetProfile
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="none", profile=simple_profile)
        assert len(plans) == 2
        assert plans[0].phase == AttackPhase.DICTIONARY
        assert plans[1].phase == AttackPhase.PROFILE

    def test_with_rules_and_profile_gives_four_plans(
        self, tmp_wordlist: Path, simple_profile: TargetProfile
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick", profile=simple_profile)
        assert len(plans) == 4

    def test_phase_order_with_all_options(
        self, tmp_wordlist: Path, simple_profile: TargetProfile
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick", profile=simple_profile)
        phases = [p.phase for p in plans]
        assert phases == [
            AttackPhase.DICTIONARY,
            AttackPhase.RULES,
            AttackPhase.PROFILE,
            AttackPhase.HYBRID,
        ]

    def test_dictionary_always_first(
        self, tmp_wordlist: Path, simple_profile: TargetProfile
    ) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="thorough", profile=simple_profile)
        assert plans[0].phase == AttackPhase.DICTIONARY

    def test_plans_are_frozen_dataclasses(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(tmp_wordlist)
        for plan in plans:
            assert isinstance(plan, AttackPlan)
            with pytest.raises((AttributeError, TypeError)):
                plan.name = "mutated"  # type: ignore[misc]

    def test_candidates_fn_is_lazy(self, tmp_wordlist: Path) -> None:
        """candidates_fn must return an iterator, not materialise on plan creation."""
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        # Simply calling candidates_fn should produce an iterator without error
        for plan in plans:
            it = plan.candidates_fn()
            assert hasattr(it, "__iter__") and hasattr(it, "__next__")


# ---------------------------------------------------------------------------
# run_orchestrated — cracking behaviour
# ---------------------------------------------------------------------------


class TestRunOrchestrated:
    def test_finds_hash_in_first_phase_dictionary(
        self,
        tmp_wordlist: Path,
        md5_password_hash: tuple[str, str],
    ) -> None:
        plaintext, hash_value = md5_password_hash
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        plans = plan_attacks(tmp_wordlist, rules_preset="none")

        result = run_orchestrated(target, plans, max_workers=1)

        assert result.found is True
        assert result.plaintext == plaintext
        assert result.attack_phase == AttackPhase.DICTIONARY
        assert result.attempts > 0

    def test_finds_hash_in_rules_phase(self, tmp_path: Path) -> None:
        """'Password1' is not in the plain wordlist but is produced by capitalize+append_1."""
        # "password" → capitalize → "Password" → append_1 → "Password1"
        plaintext = "Password1"
        hash_value = hashlib.md5(plaintext.encode()).hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)

        # wordlist contains base word but NOT the mutated form
        wl = tmp_path / "short.txt"
        wl.write_text("password\n")

        plans = plan_attacks(wl, rules_preset="quick")
        result = run_orchestrated(target, plans, max_workers=1)

        assert result.found is True
        assert result.plaintext == plaintext
        assert result.attack_phase == AttackPhase.RULES

    def test_returns_not_found_when_all_phases_exhausted(
        self, tmp_wordlist: Path
    ) -> None:
        hash_value = hashlib.md5(b"zzz_not_in_any_list_zzz").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        plans = plan_attacks(tmp_wordlist, rules_preset="none")

        result = run_orchestrated(target, plans, max_workers=1)

        assert result.found is False
        assert result.plaintext is None
        assert result.attempts > 0

    def test_accumulates_attempts_across_phases(self, tmp_path: Path) -> None:
        """Total attempts must span all phases attempted before the match."""
        plaintext = "Password1"
        hash_value = hashlib.md5(plaintext.encode()).hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)

        wl = tmp_path / "short.txt"
        wl.write_text("apple\nbanana\npassword\n")

        plans = plan_attacks(wl, rules_preset="quick")
        result = run_orchestrated(target, plans, max_workers=1)

        # Phase 1 (dictionary) exhausts 3 words; phase 2 (rules) finds the match
        # Total must be > 3
        assert result.found is True
        assert result.attempts > 3

    def test_on_phase_change_callback_is_called(
        self, tmp_wordlist: Path, md5_password_hash: tuple[str, str]
    ) -> None:
        _, hash_value = md5_password_hash
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")

        phase_events: list[tuple[str, int, int]] = []
        run_orchestrated(
            target,
            plans,
            max_workers=1,
            on_phase_change=lambda name, idx, total: phase_events.append((name, idx, total)),
        )

        # At least the first phase must have fired
        assert len(phase_events) >= 1
        # First event: phase_index=0, total=len(plans)
        assert phase_events[0][1] == 0
        assert phase_events[0][2] == len(plans)

    def test_on_progress_callback_is_called(
        self, tmp_wordlist: Path, md5_hello_hash: tuple[str, str]
    ) -> None:
        _, hash_value = md5_hello_hash
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        plans = plan_attacks(tmp_wordlist, rules_preset="none")

        progress_calls: list[int] = []
        run_orchestrated(
            target,
            plans,
            max_workers=1,
            on_progress=progress_calls.append,
        )

        assert len(progress_calls) > 0
        assert all(c >= 1 for c in progress_calls)

    def test_stops_after_first_success_no_extra_phases(
        self, tmp_wordlist: Path, md5_password_hash: tuple[str, str]
    ) -> None:
        """phase_change must not fire for phases after the winning phase."""
        _, hash_value = md5_password_hash
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        # 4-phase plan: dict, rules, profile, hybrid
        profile = TargetProfile(first_name="Bob")
        plans = plan_attacks(tmp_wordlist, rules_preset="quick", profile=profile)

        phase_events: list[tuple[str, int, int]] = []
        result = run_orchestrated(
            target,
            plans,
            max_workers=1,
            on_phase_change=lambda name, idx, total: phase_events.append((name, idx, total)),
        )

        assert result.found is True
        # "password" is in the wordlist so it must be found in phase 0 (dictionary)
        assert result.attack_phase == AttackPhase.DICTIONARY
        # Only one phase_change event fired (for phase 0)
        assert len(phase_events) == 1

    def test_no_plans_returns_not_found(self) -> None:
        hash_value = hashlib.md5(b"x").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)

        result = run_orchestrated(target, plans=[])

        assert result.found is False
        assert result.attempts == 0

    def test_duration_is_positive(
        self, tmp_wordlist: Path, md5_password_hash: tuple[str, str]
    ) -> None:
        _, hash_value = md5_password_hash
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        plans = plan_attacks(tmp_wordlist, rules_preset="none")

        result = run_orchestrated(target, plans, max_workers=1)

        assert result.duration_seconds >= 0.0




class TestMaskPhasePlanning:
    def test_manual_mask_adds_mask_phase(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(
            wordlist_path=tmp_wordlist,
            rules_preset="none",
            mask_pattern="?d?d?d?d",
        )
        mask_plans = [p for p in plans if p.phase == AttackPhase.MASK]
        assert len(mask_plans) == 1
        assert "?d?d?d?d" in mask_plans[0].name

    def test_manual_mask_candidates_are_generated(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(
            wordlist_path=tmp_wordlist,
            rules_preset="none",
            mask_pattern="?d?d",
        )
        mask_plan = [p for p in plans if p.phase == AttackPhase.MASK][0]
        candidates = list(mask_plan.candidates_fn())
        assert len(candidates) == 100  # 10 * 10

    def test_no_mask_when_not_requested(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(
            wordlist_path=tmp_wordlist,
            rules_preset="quick",
        )
        mask_plans = [p for p in plans if p.phase == AttackPhase.MASK]
        assert len(mask_plans) == 0

    def test_ai_masks_requires_profile_and_llm(self, tmp_wordlist: Path) -> None:
        """ai_masks=True without profile/llm should not add a mask phase."""
        plans = plan_attacks(
            wordlist_path=tmp_wordlist,
            rules_preset="none",
            ai_masks=True,
        )
        mask_plans = [p for p in plans if p.phase == AttackPhase.MASK]
        assert len(mask_plans) == 0


# ---------------------------------------------------------------------------
# Rainbow phase integration
# ---------------------------------------------------------------------------


class TestRainbowPhaseIntegration:
    @pytest.fixture()
    def rainbow_table(self, tmp_path: Path) -> Path:
        from smartcrack.rainbow import build_rainbow_table

        wordlist = tmp_path / "rainbow_words.txt"
        wordlist.write_text("password\nhello\nworld\nadmin\n")
        table = tmp_path / "test.rainbow"
        build_rainbow_table(wordlist, HashType.MD5, table)
        return table

    def test_rainbow_phase_inserted_first_when_table_provided(
        self, tmp_wordlist: Path, rainbow_table: Path
    ) -> None:
        plans = plan_attacks(
            tmp_wordlist, rules_preset="none", rainbow_table_path=rainbow_table
        )
        assert plans[0].phase == AttackPhase.RAINBOW

    def test_rainbow_phase_before_dictionary(
        self, tmp_wordlist: Path, rainbow_table: Path
    ) -> None:
        plans = plan_attacks(
            tmp_wordlist, rules_preset="quick", rainbow_table_path=rainbow_table
        )
        phases = [p.phase for p in plans]
        assert phases[0] == AttackPhase.RAINBOW
        assert phases[1] == AttackPhase.DICTIONARY

    def test_no_rainbow_phase_when_path_is_none(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        phases = [p.phase for p in plans]
        assert AttackPhase.RAINBOW not in phases

    def test_rainbow_phase_finds_hash_instantly(
        self, tmp_wordlist: Path, rainbow_table: Path
    ) -> None:
        hash_value = hashlib.md5(b"password").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        plans = plan_attacks(
            tmp_wordlist, rules_preset="none", rainbow_table_path=rainbow_table
        )
        result = run_orchestrated(target, plans, max_workers=1)
        assert result.found is True
        assert result.plaintext == "password"
        assert result.attack_phase == AttackPhase.RAINBOW

    def test_rainbow_miss_falls_through_to_dictionary(
        self, tmp_wordlist: Path, rainbow_table: Path
    ) -> None:
        hash_value = hashlib.md5(b"letmein").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        plans = plan_attacks(
            tmp_wordlist, rules_preset="none", rainbow_table_path=rainbow_table
        )
        result = run_orchestrated(target, plans, max_workers=1)
        assert result.found is True
        assert result.plaintext == "letmein"
        assert result.attack_phase == AttackPhase.DICTIONARY


# ---------------------------------------------------------------------------
# Combo phase integration
# ---------------------------------------------------------------------------


class TestComboPhaseIntegration:
    @pytest.fixture()
    def combo_wordlist(self, tmp_path: Path) -> Path:
        wl = tmp_path / "combo.txt"
        wl.write_text("123\n456\n789\n")
        return wl

    def test_combo_phase_added_after_rules(
        self, tmp_wordlist: Path, combo_wordlist: Path
    ) -> None:
        plans = plan_attacks(
            tmp_wordlist,
            rules_preset="quick",
            combo_wordlist_path=combo_wordlist,
        )
        phases = [p.phase for p in plans]
        rules_idx = phases.index(AttackPhase.RULES)
        combo_idx = phases.index(AttackPhase.COMBO)
        assert combo_idx == rules_idx + 1

    def test_combo_phase_added_after_dictionary_when_no_rules(
        self, tmp_wordlist: Path, combo_wordlist: Path
    ) -> None:
        plans = plan_attacks(
            tmp_wordlist,
            rules_preset="none",
            combo_wordlist_path=combo_wordlist,
        )
        phases = [p.phase for p in plans]
        dict_idx = phases.index(AttackPhase.DICTIONARY)
        combo_idx = phases.index(AttackPhase.COMBO)
        assert combo_idx == dict_idx + 1

    def test_no_combo_phase_when_path_is_none(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        phases = [p.phase for p in plans]
        assert AttackPhase.COMBO not in phases

    def test_combo_phase_finds_combined_password(
        self, tmp_path: Path, combo_wordlist: Path
    ) -> None:
        wl = tmp_path / "base.txt"
        wl.write_text("apple\nbanana\nadmin\n")

        target_hash = hashlib.md5(b"admin123").hexdigest()
        target = HashTarget(hash_value=target_hash, hash_type=HashType.MD5)

        plans = plan_attacks(
            wl,
            rules_preset="none",
            combo_wordlist_path=combo_wordlist,
        )
        result = run_orchestrated(target, plans, max_workers=1)
        assert result.found is True
        assert result.plaintext == "admin123"
        assert result.attack_phase == AttackPhase.COMBO
