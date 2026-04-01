"""Tests for the mask attack engine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from smartcrack.mask import (
    CHARSETS,
    generate_ai_masks,
    mask_candidates,
    parse_mask,
)
from smartcrack.models import LLMConfig, TargetProfile


@pytest.mark.unit
class TestCharsets:
    def test_lowercase_charset(self) -> None:
        assert CHARSETS["?l"] == "abcdefghijklmnopqrstuvwxyz"

    def test_uppercase_charset(self) -> None:
        assert CHARSETS["?u"] == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def test_digit_charset(self) -> None:
        assert CHARSETS["?d"] == "0123456789"

    def test_special_charset(self) -> None:
        assert "!" in CHARSETS["?s"]
        assert "@" in CHARSETS["?s"]
        assert "#" in CHARSETS["?s"]
        assert "$" in CHARSETS["?s"]
        assert "%" in CHARSETS["?s"]
        assert "^" in CHARSETS["?s"]
        assert "&" in CHARSETS["?s"]
        assert "*" in CHARSETS["?s"]

    def test_all_printable_charset(self) -> None:
        charset_a = CHARSETS["?a"]
        for char in CHARSETS["?l"]:
            assert char in charset_a
        for char in CHARSETS["?u"]:
            assert char in charset_a
        for char in CHARSETS["?d"]:
            assert char in charset_a
        for char in CHARSETS["?s"]:
            assert char in charset_a


@pytest.mark.unit
class TestParseMask:
    def test_single_lowercase_token(self) -> None:
        result = parse_mask("?l")
        assert result == [CHARSETS["?l"]]

    def test_multiple_tokens(self) -> None:
        result = parse_mask("?l?d")
        assert len(result) == 2
        assert result[0] == CHARSETS["?l"]
        assert result[1] == CHARSETS["?d"]

    def test_all_builtin_tokens(self) -> None:
        result = parse_mask("?l?u?d?s?a")
        assert len(result) == 5
        assert result[0] == CHARSETS["?l"]
        assert result[1] == CHARSETS["?u"]
        assert result[2] == CHARSETS["?d"]
        assert result[3] == CHARSETS["?s"]
        assert result[4] == CHARSETS["?a"]

    def test_literal_characters(self) -> None:
        result = parse_mask("abc")
        assert result == ["a", "b", "c"]

    def test_mixed_tokens_and_literals(self) -> None:
        result = parse_mask("P?d?d?d")
        assert len(result) == 4
        assert result[0] == "P"
        assert result[1] == CHARSETS["?d"]
        assert result[2] == CHARSETS["?d"]
        assert result[3] == CHARSETS["?d"]

    def test_custom_charset_override(self) -> None:
        custom = {"?1": "ABC"}
        result = parse_mask("?1?d", custom_charsets=custom)
        assert result[0] == "ABC"
        assert result[1] == CHARSETS["?d"]

    def test_custom_charset_does_not_override_builtins(self) -> None:
        custom = {"?1": "XYZ"}
        result = parse_mask("?l?1", custom_charsets=custom)
        assert result[0] == CHARSETS["?l"]
        assert result[1] == "XYZ"

    def test_empty_mask_returns_empty_list(self) -> None:
        result = parse_mask("")
        assert result == []

    def test_escaped_question_mark(self) -> None:
        result = parse_mask("?z")
        assert len(result) == 2
        assert result[0] == "?"
        assert result[1] == "z"


@pytest.mark.unit
class TestMaskCandidates:
    def test_returns_iterator(self) -> None:
        gen = mask_candidates("?d")
        assert hasattr(gen, "__iter__") and hasattr(gen, "__next__")

    def test_single_digit_yields_10(self) -> None:
        results = list(mask_candidates("?d"))
        assert len(results) == 10
        assert "0" in results
        assert "9" in results

    def test_two_digits_yields_100(self) -> None:
        results = list(mask_candidates("?d?d"))
        assert len(results) == 100
        assert "00" in results
        assert "99" in results
        assert "42" in results

    def test_candidate_count_is_product_of_charset_sizes(self) -> None:
        results = list(mask_candidates("?l?d"))
        assert len(results) == 26 * 10

    def test_literal_prefix_with_digit(self) -> None:
        results = list(mask_candidates("A?d"))
        assert len(results) == 10
        assert all(r.startswith("A") for r in results)

    def test_all_candidates_match_mask_pattern(self) -> None:
        results = list(mask_candidates("?u?l?d"))
        for candidate in results:
            assert len(candidate) == 3
            assert candidate[0].isupper()
            assert candidate[1].islower()
            assert candidate[2].isdigit()

    def test_custom_charset_candidates(self) -> None:
        custom = {"?1": "AB"}
        results = list(mask_candidates("?1?d", custom_charsets=custom))
        assert len(results) == 2 * 10
        assert "A0" in results
        assert "B9" in results

    def test_empty_mask_yields_single_empty_string(self) -> None:
        results = list(mask_candidates(""))
        assert results == [""]

    def test_generator_is_lazy(self) -> None:
        gen = mask_candidates("?l?l?l?l?l")
        first = next(gen)
        assert isinstance(first, str)
        assert len(first) == 5


def _make_mock_response(content: str, status_code: int = 200) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


@pytest.mark.unit
class TestGenerateAIMasks:
    @pytest.fixture
    def llm_config(self) -> LLMConfig:
        return LLMConfig(
            base_url="https://test.example.com/v1",
            api_key="sk-test-key",
            model="gpt-4o",
            timeout_seconds=10,
        )

    @pytest.fixture
    def profile(self) -> TargetProfile:
        return TargetProfile(
            first_name="John",
            last_name="Smith",
            birthdate="1990-05-14",
        )

    def test_returns_list_of_strings(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        mock_resp = _make_mock_response("?l?l?l?l?d?d\n?u?l?l?l?l?d?d?d?d\n?l?l?l?l?l?l?d?d?s")
        with patch("smartcrack.mask.httpx.post", return_value=mock_resp):
            masks = generate_ai_masks(profile, llm_config)
        assert isinstance(masks, list)
        assert all(isinstance(m, str) for m in masks)

    def test_filters_invalid_mask_syntax(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        mock_resp = _make_mock_response(
            "?l?l?l?d?d\nThis is not a mask\n?u?d?d?d?d\nAnother sentence here"
        )
        with patch("smartcrack.mask.httpx.post", return_value=mock_resp):
            masks = generate_ai_masks(profile, llm_config)
        for mask in masks:
            assert "?" in mask

    def test_caps_at_10_masks(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        lines = "\n".join(f"?l?l?l?d?d{i}" for i in range(20))
        mock_resp = _make_mock_response(lines)
        with patch("smartcrack.mask.httpx.post", return_value=mock_resp):
            masks = generate_ai_masks(profile, llm_config)
        assert len(masks) <= 10

    def test_sends_correct_endpoint(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        mock_resp = _make_mock_response("?l?l?l?d?d")
        with patch("smartcrack.mask.httpx.post", return_value=mock_resp) as mock_post:
            generate_ai_masks(profile, llm_config)
        call_url = mock_post.call_args[0][0]
        assert call_url.endswith("/chat/completions")

    def test_timeout_returns_empty_list(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        import httpx as _httpx
        with patch(
            "smartcrack.mask.httpx.post",
            side_effect=_httpx.TimeoutException("timed out"),
        ):
            masks = generate_ai_masks(profile, llm_config)
        assert masks == []

    def test_http_error_returns_empty_list(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        import httpx as _httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        error = _httpx.HTTPStatusError(
            "server error", request=MagicMock(), response=mock_resp
        )
        with patch("smartcrack.mask.httpx.post", side_effect=error):
            masks = generate_ai_masks(profile, llm_config)
        assert masks == []

    def test_no_base_url_returns_empty_list(
        self, profile: TargetProfile
    ) -> None:
        config = LLMConfig(api_key="sk-test", model="gpt-4o")
        masks = generate_ai_masks(profile, config)
        assert masks == []
