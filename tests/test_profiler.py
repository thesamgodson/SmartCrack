"""Tests for LocalProfiler, AIProfiler, and create_profiler factory."""

from __future__ import annotations

from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest

from hashcrack.models import LLMConfig, TargetProfile
from hashcrack.profiler import AIProfiler, LocalProfiler, create_profiler


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


@pytest.fixture
def no_key_config() -> LLMConfig:
    return LLMConfig(api_key="")


@pytest.fixture
def keyed_config() -> LLMConfig:
    return LLMConfig(base_url="https://test.example.com/v1", api_key="sk-test-key", model="gpt-4o", timeout_seconds=10)


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
        """Calling generate() should not materialise all candidates immediately."""
        profiler = LocalProfiler()
        gen = profiler.generate(full_profile)
        # Consuming only the first item must not exhaust the generator
        first = next(gen)
        assert isinstance(first, str)
        # Generator should still have more items
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
        # "john" is 4 chars and filtered by _MIN_LENGTH=6; use "johnny" (6 chars) instead
        candidates = set(LocalProfiler().generate(full_profile))
        assert "johnny" in candidates
        assert "JOHNNY" in candidates
        assert "Johnny" in candidates

    def test_contains_name_date_combination(self, full_profile: TargetProfile) -> None:
        """e.g. john + 1990 → john1990."""
        candidates = set(LocalProfiler().generate(full_profile))
        assert "john1990" in candidates

    def test_contains_name_suffix_combination(self, full_profile: TargetProfile) -> None:
        """e.g. John + 123 → John123."""
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
        # keyword + suffix
        assert "football123" in candidates

    def test_profile_with_no_names_produces_no_errors(self) -> None:
        empty = TargetProfile(keywords=("summer", "2024"), special_numbers=("99",))
        candidates = list(LocalProfiler().generate(empty))
        # keywords should still produce something
        assert isinstance(candidates, list)


# ---------------------------------------------------------------------------
# AIProfiler
# ---------------------------------------------------------------------------

def _make_mock_response(content: str, status_code: int = 200) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


class TestAIProfiler:
    def test_requires_api_is_true(self, keyed_config: LLMConfig) -> None:
        assert AIProfiler(keyed_config).requires_api is True

    def test_generate_returns_iterator(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        mock_resp = _make_mock_response("pass1\npass2\npass3")
        with patch("httpx.post", return_value=mock_resp):
            result = AIProfiler(keyed_config).generate(full_profile)
            assert hasattr(result, "__iter__") and hasattr(result, "__next__")

    def test_parses_llm_response_lines(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        mock_resp = _make_mock_response("hunter2\nsecret99\njohn1990!")
        with patch("httpx.post", return_value=mock_resp):
            candidates = list(AIProfiler(keyed_config).generate(full_profile))
        assert candidates == ["hunter2", "secret99", "john1990!"]

    def test_skips_blank_lines(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        mock_resp = _make_mock_response("hunter2\n\nsecret99\n\n")
        with patch("httpx.post", return_value=mock_resp):
            candidates = list(AIProfiler(keyed_config).generate(full_profile))
        assert "" not in candidates
        assert len(candidates) == 2

    def test_uses_correct_endpoint(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        mock_resp = _make_mock_response("pw1")
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            list(AIProfiler(keyed_config).generate(full_profile))
        call_url = mock_post.call_args[0][0]
        assert call_url.endswith("/chat/completions")

    def test_bearer_token_in_headers(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        mock_resp = _make_mock_response("pw1")
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            list(AIProfiler(keyed_config).generate(full_profile))
        headers = mock_post.call_args[1]["headers"]
        assert headers.get("Authorization") == "Bearer sk-test-key"

    def test_timeout_error_returns_empty_iterator(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        import httpx as _httpx
        with patch("httpx.post", side_effect=_httpx.TimeoutException("timed out")):
            candidates = list(AIProfiler(keyed_config).generate(full_profile))
        assert candidates == []

    def test_http_status_error_returns_empty_iterator(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        import httpx as _httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        error = _httpx.HTTPStatusError("server error", request=MagicMock(), response=mock_resp)
        with patch("httpx.post", side_effect=error):
            candidates = list(AIProfiler(keyed_config).generate(full_profile))
        assert candidates == []

    def test_generic_exception_returns_empty_iterator(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        with patch("httpx.post", side_effect=RuntimeError("connection refused")):
            candidates = list(AIProfiler(keyed_config).generate(full_profile))
        assert candidates == []

    def test_api_down_logs_warning(self, keyed_config: LLMConfig, full_profile: TargetProfile, caplog: pytest.LogCaptureFixture) -> None:
        import httpx as _httpx
        import logging
        with caplog.at_level(logging.WARNING, logger="hashcrack.profiler"):
            with patch("httpx.post", side_effect=_httpx.TimeoutException("timed out")):
                list(AIProfiler(keyed_config).generate(full_profile))
        assert any("timed out" in record.message or "AIProfiler" in record.message for record in caplog.records)

    def test_ai_generate_strips_code_fences(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        """Markdown code fences should be stripped from LLM response."""
        mock_resp = _make_mock_response("```\npassword1\npassword2\n```")
        with patch("httpx.post", return_value=mock_resp):
            results = list(AIProfiler(keyed_config).generate(full_profile))
        assert "```" not in results
        assert "password1" in results
        assert "password2" in results

    def test_ai_generate_strips_preamble(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        """Preamble text with spaces should be filtered out."""
        mock_resp = _make_mock_response("Here are the passwords:\npassword1\npassword2")
        with patch("httpx.post", return_value=mock_resp):
            results = list(AIProfiler(keyed_config).generate(full_profile))
        assert all(" " not in r for r in results)
        assert "password1" in results

    def test_ai_generate_strips_numbering(self, keyed_config: LLMConfig, full_profile: TargetProfile) -> None:
        """Leading numbering should be stripped from candidates."""
        mock_resp = _make_mock_response("1. password1\n2) password2\n- password3")
        with patch("httpx.post", return_value=mock_resp):
            results = list(AIProfiler(keyed_config).generate(full_profile))
        assert "password1" in results
        assert "password2" in results
        assert "password3" in results

    def test_default_timeout_is_90_seconds(self) -> None:
        """LLMConfig default timeout_seconds should be 90."""
        config = LLMConfig()
        assert config.timeout_seconds == 90


# ---------------------------------------------------------------------------
# create_profiler factory
# ---------------------------------------------------------------------------

class TestCreateProfiler:
    def test_returns_local_profiler_when_no_key(self, no_key_config: LLMConfig) -> None:
        profiler = create_profiler(no_key_config)
        assert isinstance(profiler, LocalProfiler)

    def test_returns_ai_profiler_when_key_set(self, keyed_config: LLMConfig) -> None:
        profiler = create_profiler(keyed_config)
        assert isinstance(profiler, AIProfiler)

    def test_local_profiler_satisfies_protocol(self, no_key_config: LLMConfig) -> None:
        from hashcrack.protocols import ProfilerProtocol
        profiler = create_profiler(no_key_config)
        assert isinstance(profiler, ProfilerProtocol)

    def test_ai_profiler_satisfies_protocol(self, keyed_config: LLMConfig) -> None:
        from hashcrack.protocols import ProfilerProtocol
        profiler = create_profiler(keyed_config)
        assert isinstance(profiler, ProfilerProtocol)
