"""Tests for LocalProfiler."""

from __future__ import annotations

import pytest

from smartcrack.models import TargetProfile
from smartcrack.profiler import LocalProfiler


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def full_profile() -> TargetProfile:
    return TargetProfile(
        first_name="John",
        last_name="Smith",
        nickname="johnny",
        birthdate="1990-05-14",
        partner_name="Jane",
        partner_birthdate="1992-08-22",
        child_name="Max",
        pet_name="Buddy",
        keywords=("football", "guitar"),
        special_numbers=("42", "7"),
    )


@pytest.fixture
def minimal_profile() -> TargetProfile:
    return TargetProfile(first_name="Alice")


# ---------------------------------------------------------------------------
# LocalProfiler
# ---------------------------------------------------------------------------

class TestLocalProfiler:
    def test_requires_api_is_false(self) -> None:
        assert LocalProfiler().requires_api is False

    def test_generate_returns_iterator(self, full_profile: TargetProfile) -> None:
        result = LocalProfiler().generate(full_profile)
        assert hasattr(result, "__iter__") and hasattr(result, "__next__")

    def test_generator_is_lazy(self, full_profile: TargetProfile) -> None:
        profiler = LocalProfiler()
        gen = profiler.generate(full_profile)
        first = next(gen)
        assert isinstance(first, str)
        second = next(gen)
        assert isinstance(second, str)

    def test_full_profile_produces_candidates(self, full_profile: TargetProfile) -> None:
        candidates = list(LocalProfiler().generate(full_profile))
        assert len(candidates) > 0

    def test_all_candidates_meet_min_length(self, full_profile: TargetProfile) -> None:
        for candidate in LocalProfiler().generate(full_profile):
            assert len(candidate) >= 6, f"Candidate too short: {candidate!r}"

    def test_no_duplicate_candidates(self, full_profile: TargetProfile) -> None:
        candidates = list(LocalProfiler().generate(full_profile))
        assert len(candidates) == len(set(candidates))

    def test_contains_name_variations(self, full_profile: TargetProfile) -> None:
        candidates = set(LocalProfiler().generate(full_profile))
        assert "johnny" in candidates
        assert "JOHNNY" in candidates
        assert "Johnny" in candidates

    def test_contains_name_date_combination(self, full_profile: TargetProfile) -> None:
        candidates = set(LocalProfiler().generate(full_profile))
        assert "john1990" in candidates

    def test_contains_name_suffix_combination(self, full_profile: TargetProfile) -> None:
        candidates = set(LocalProfiler().generate(full_profile))
        assert "John123" in candidates

    def test_minimal_profile_still_produces_candidates(self, minimal_profile: TargetProfile) -> None:
        candidates = list(LocalProfiler().generate(minimal_profile))
        assert len(candidates) > 0
        assert all(len(c) >= 6 for c in candidates)

    def test_minimal_profile_includes_name_with_suffixes(self, minimal_profile: TargetProfile) -> None:
        candidates = set(LocalProfiler().generate(minimal_profile))
        assert "Alice123" in candidates or "alice123" in candidates

    def test_keywords_included(self, full_profile: TargetProfile) -> None:
        candidates = set(LocalProfiler().generate(full_profile))
        assert "football123" in candidates

    def test_profile_with_no_names_produces_no_errors(self) -> None:
        empty = TargetProfile(keywords=("summer", "2024"), special_numbers=("99",))
        candidates = list(LocalProfiler().generate(empty))
        assert isinstance(candidates, list)
