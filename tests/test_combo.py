"""Tests for combo attack engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from smartcrack.models import LLMConfig, TargetProfile


class TestComboCandidates:
    def test_basic_combination(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates
        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("hello\nworld\n")
        w2.write_text("123\n456\n")
        results = list(combo_candidates(w1, w2))
        assert "hello123" in results
        assert "hello456" in results
        assert "world123" in results
        assert "world456" in results

    def test_with_separators(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates
        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("foo\n")
        w2.write_text("bar\n")
        results = list(combo_candidates(w1, w2, separators=("", "_", ".")))
        assert "foobar" in results
        assert "foo_bar" in results
        assert "foo.bar" in results

    def test_default_separator_is_empty(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates
        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("aa\n")
        w2.write_text("bb\n")
        results = list(combo_candidates(w1, w2))
        assert results == ["aabb"]

    def test_max_length_filtering(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates
        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("longword\n")
        w2.write_text("anotherlongword\n")
        results = list(combo_candidates(w1, w2, max_length=10))
        assert len(results) == 0

    def test_max_length_keeps_short_combos(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates
        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("ab\nlong_word_here\n")
        w2.write_text("cd\n")
        results = list(combo_candidates(w1, w2, max_length=10))
        assert "abcd" in results
        assert all(len(r) <= 10 for r in results)

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates
        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("alpha\n\nbeta\n")
        w2.write_text("\ngamma\n")
        results = list(combo_candidates(w1, w2))
        assert "alphagamma" in results
        assert "betagamma" in results
        assert len(results) == 2

    def test_returns_iterator(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates
        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("x\n")
        w2.write_text("y\n")
        result = combo_candidates(w1, w2)
        assert hasattr(result, "__iter__") and hasattr(result, "__next__")


class TestProfileComboCandidates:
    def test_generates_from_profile_fields(self) -> None:
        from smartcrack.combo import profile_combo_candidates
        profile = TargetProfile(first_name="John", last_name="Smith", pet_name="Buddy")
        results = list(profile_combo_candidates(profile))
        assert len(results) > 0

    def test_includes_name_combinations(self) -> None:
        from smartcrack.combo import profile_combo_candidates
        profile = TargetProfile(first_name="John", last_name="Smith")
        results = set(profile_combo_candidates(profile))
        assert "JohnSmith" in results or "johnsmith" in results

    def test_uses_separators(self) -> None:
        from smartcrack.combo import profile_combo_candidates
        profile = TargetProfile(first_name="John", last_name="Smith")
        results = set(profile_combo_candidates(profile, separators=("_",)))
        assert "John_Smith" in results or "john_smith" in results

    def test_includes_keywords(self) -> None:
        from smartcrack.combo import profile_combo_candidates
        profile = TargetProfile(first_name="Alice", keywords=("football",))
        results = set(profile_combo_candidates(profile))
        assert any("football" in r.lower() for r in results)

    def test_includes_numbers(self) -> None:
        from smartcrack.combo import profile_combo_candidates
        profile = TargetProfile(first_name="Alice", special_numbers=("42",))
        results = set(profile_combo_candidates(profile))
        assert any("42" in r for r in results)

    def test_empty_profile_returns_empty(self) -> None:
        from smartcrack.combo import profile_combo_candidates
        profile = TargetProfile()
        results = list(profile_combo_candidates(profile))
        assert results == []


class TestAiRankedCombos:
    def test_returns_list_of_strings(self) -> None:
        from smartcrack.combo import ai_ranked_combos
        config = LLMConfig(base_url="https://test.example.com/v1", api_key="sk-test", model="test-model")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "john_smith\nsmithbuddy\njohn123\n"}}]}
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.post", return_value=mock_resp):
            results = ai_ranked_combos(["john", "smith"], ["buddy", "123"], config, top_n=10)
        assert isinstance(results, list)
        assert all(isinstance(r, str) for r in results)

    def test_respects_top_n_limit(self) -> None:
        from smartcrack.combo import ai_ranked_combos
        config = LLMConfig(base_url="https://test.example.com/v1", api_key="sk-test", model="test-model")
        lines = "\n".join(f"combo{i}" for i in range(50))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": lines}}]}
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.post", return_value=mock_resp):
            results = ai_ranked_combos(["a", "b"], ["c", "d"], config, top_n=10)
        assert len(results) <= 10

    def test_sends_words_in_prompt(self) -> None:
        from smartcrack.combo import ai_ranked_combos
        config = LLMConfig(base_url="https://test.example.com/v1", api_key="sk-test", model="test-model")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "result1\n"}}]}
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            ai_ranked_combos(["alpha", "beta"], ["gamma"], config)
        payload = mock_post.call_args[1]["json"]
        user_msg = payload["messages"][-1]["content"]
        assert "alpha" in user_msg
        assert "beta" in user_msg
        assert "gamma" in user_msg

    def test_returns_empty_on_api_error(self) -> None:
        from smartcrack.combo import ai_ranked_combos
        import httpx as _httpx
        config = LLMConfig(base_url="https://test.example.com/v1", api_key="sk-test", model="test-model")
        with patch("httpx.post", side_effect=_httpx.TimeoutException("timeout")):
            results = ai_ranked_combos(["a"], ["b"], config)
        assert results == []

    def test_filters_blank_lines_and_spaces(self) -> None:
        from smartcrack.combo import ai_ranked_combos
        config = LLMConfig(base_url="https://test.example.com/v1", api_key="sk-test", model="test-model")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "good_combo\n\nHere is another:\nbad space\nclean123\n"}}]}
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.post", return_value=mock_resp):
            results = ai_ranked_combos(["x"], ["y"], config)
        assert "good_combo" in results
        assert "clean123" in results
        assert "bad space" not in results
