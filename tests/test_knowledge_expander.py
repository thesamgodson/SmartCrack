"""Tests for knowledge expander — LLM cultural keyword extraction."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from smartcrack.models import ExpandedProfile, LLMConfig, TargetProfile


SAMPLE_LLM_RESPONSE = {
    "base_tokens": {
        "names": ["johnny", "john", "jon"],
        "nicknames": ["jboy", "j-man"],
        "dates": ["1990", "90", "0101", "0115"],
        "keywords_direct": ["arsenal", "football"],
        "keywords_cultural": ["gunners", "highbury", "emirates", "henry", "wenger", "coyg", "49unbeaten"],
        "keywords_generational": ["pokemon", "freshprince", "n64"],
        "locale_slang": ["lad", "mate", "bloke"],
        "phonetic_variants": ["arsnl", "arse", "jnny"],
        "related_numbers": ["14", "49", "1886"],
    },
    "mutation_profile": {
        "leet_likelihood": "medium",
        "special_char_preference": ["!", "@", "#"],
        "separator_preference": ["", "_", "."],
        "capitalization_style": "capitalize",
        "typical_length_range": [8, 14],
        "suffix_patterns": ["!", "90", "1990", "123"],
    },
    "high_confidence_seeds": [
        "Johnny1990", "Arsenal90", "JohnnyArsenal", "Fluffy90",
        "Gunners1990", "Johnny!", "Arsenal!",
    ],
}

SAMPLE_PROFILE = TargetProfile(
    first_name="TestUser",
    partner_name="TestPartner",
    birthdate="1985-06-20",
    pet_name="TestPet",
    keywords=("testing", "unittest"),
    special_numbers=("99", "77"),
)

SAMPLE_LLM_CONFIG = LLMConfig(
    base_url="https://test.example.com/v1",
    api_key="sk-test",
    model="test-model",
)


def _mock_response(content: str) -> MagicMock:
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    mock.raise_for_status = MagicMock()
    return mock


class TestExpandProfile:
    def test_returns_expanded_profile_from_valid_response(self, tmp_path: Path) -> None:
        from smartcrack.knowledge_expander import expand_profile

        with patch("httpx.post", return_value=_mock_response(json.dumps(SAMPLE_LLM_RESPONSE))):
            result = expand_profile(SAMPLE_PROFILE, SAMPLE_LLM_CONFIG, cache_dir=tmp_path)

        assert isinstance(result, ExpandedProfile)
        assert "gunners" in result.keywords_cultural
        assert "johnny" in result.names  # from SAMPLE_LLM_RESPONSE
        assert result.mutation_profile.leet_likelihood == "medium"

    def test_high_confidence_seeds_populated(self, tmp_path: Path) -> None:
        from smartcrack.knowledge_expander import expand_profile

        with patch("httpx.post", return_value=_mock_response(json.dumps(SAMPLE_LLM_RESPONSE))):
            result = expand_profile(SAMPLE_PROFILE, SAMPLE_LLM_CONFIG, cache_dir=tmp_path)

        assert len(result.high_confidence_seeds) > 0
        assert "JohnnyArsenal" in result.high_confidence_seeds

    def test_mutation_profile_parsed(self, tmp_path: Path) -> None:
        from smartcrack.knowledge_expander import expand_profile

        with patch("httpx.post", return_value=_mock_response(json.dumps(SAMPLE_LLM_RESPONSE))):
            result = expand_profile(SAMPLE_PROFILE, SAMPLE_LLM_CONFIG, cache_dir=tmp_path)

        mp = result.mutation_profile
        assert mp.capitalization_style == "capitalize"
        assert "!" in mp.special_char_preference
        assert mp.typical_length_range == (8, 14)


class TestFallback:
    def test_timeout_returns_fallback(self, tmp_path: Path) -> None:
        from smartcrack.knowledge_expander import expand_profile

        with patch("httpx.post", side_effect=httpx.TimeoutException("timeout")):
            result = expand_profile(SAMPLE_PROFILE, SAMPLE_LLM_CONFIG, cache_dir=tmp_path)

        assert isinstance(result, ExpandedProfile)
        assert "testuser" in result.names

    def test_http_error_returns_fallback(self, tmp_path: Path) -> None:
        from smartcrack.knowledge_expander import expand_profile

        mock = MagicMock()
        mock.status_code = 500
        error = httpx.HTTPStatusError("error", request=MagicMock(), response=mock)

        with patch("httpx.post", side_effect=error):
            result = expand_profile(SAMPLE_PROFILE, SAMPLE_LLM_CONFIG, cache_dir=tmp_path)

        assert isinstance(result, ExpandedProfile)
        assert "testuser" in result.names

    def test_malformed_json_returns_fallback(self, tmp_path: Path) -> None:
        from smartcrack.knowledge_expander import expand_profile

        with patch("httpx.post", return_value=_mock_response("not json at all {{{}")):
            result = expand_profile(SAMPLE_PROFILE, SAMPLE_LLM_CONFIG, cache_dir=tmp_path)

        assert isinstance(result, ExpandedProfile)

    def test_fallback_extracts_dates_from_birthdate(self) -> None:
        from smartcrack.knowledge_expander import _fallback_expand

        result = _fallback_expand(SAMPLE_PROFILE)
        assert "1985" in result.dates
        assert "85" in result.dates
        assert "0620" in result.dates


class TestExtractJson:
    def test_raw_json(self) -> None:
        from smartcrack.knowledge_expander import _extract_json

        data = _extract_json('{"key": "value"}')
        assert data == {"key": "value"}

    def test_code_fenced_json(self) -> None:
        from smartcrack.knowledge_expander import _extract_json

        data = _extract_json('Here is the result:\n```json\n{"key": "value"}\n```\n')
        assert data == {"key": "value"}

    def test_embedded_json(self) -> None:
        from smartcrack.knowledge_expander import _extract_json

        data = _extract_json('The analysis shows {"key": "value"} as the result.')
        assert data == {"key": "value"}

    def test_garbage_raises(self) -> None:
        from smartcrack.knowledge_expander import _extract_json
        import pytest

        with pytest.raises(ValueError):
            _extract_json("no json here at all")


class TestCache:
    def test_cache_round_trip(self, tmp_path: Path) -> None:
        from smartcrack.knowledge_expander import expand_profile

        with patch("httpx.post", return_value=_mock_response(json.dumps(SAMPLE_LLM_RESPONSE))):
            result1 = expand_profile(SAMPLE_PROFILE, SAMPLE_LLM_CONFIG, cache_dir=tmp_path)

        # Second call should NOT hit LLM (cache hit)
        with patch("httpx.post", side_effect=AssertionError("should not be called")):
            result2 = expand_profile(SAMPLE_PROFILE, SAMPLE_LLM_CONFIG, cache_dir=tmp_path)

        assert result1.keywords_cultural == result2.keywords_cultural
        assert result1.high_confidence_seeds == result2.high_confidence_seeds

    def test_cache_creates_directory(self, tmp_path: Path) -> None:
        from smartcrack.knowledge_expander import expand_profile

        cache_dir = tmp_path / "sub" / "cache"
        with patch("httpx.post", return_value=_mock_response(json.dumps(SAMPLE_LLM_RESPONSE))):
            expand_profile(SAMPLE_PROFILE, SAMPLE_LLM_CONFIG, cache_dir=cache_dir)

        assert cache_dir.exists()
