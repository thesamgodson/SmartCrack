"""Tests for wordlist loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from smartcrack.wordlist import file_candidates, file_candidates_from_offset, resolve_wordlist


class TestFileCandidates:
    def test_yields_all_lines(self, tmp_wordlist: Path) -> None:
        words = list(file_candidates(tmp_wordlist))
        assert "password" in words
        assert "test123" in words
        assert len(words) == 8

    def test_strips_newlines(self, tmp_path: Path) -> None:
        f = tmp_path / "w.txt"
        f.write_text("hello\nworld\n")
        words = list(file_candidates(f))
        assert words == ["hello", "world"]

    def test_skips_empty_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "w.txt"
        f.write_text("a\n\nb\n\n")
        words = list(file_candidates(f))
        assert words == ["a", "b"]

    def test_generator_lazy(self, tmp_wordlist: Path) -> None:
        gen = file_candidates(tmp_wordlist)
        first = next(gen)
        assert isinstance(first, str)


class TestFileCandidatesFromOffset:
    def test_skips_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "w.txt"
        f.write_text("a\nb\nc\nd\n")
        words = list(file_candidates_from_offset(f, offset=2))
        assert words == ["c", "d"]

    def test_offset_zero(self, tmp_wordlist: Path) -> None:
        all_words = list(file_candidates(tmp_wordlist))
        from_zero = list(file_candidates_from_offset(tmp_wordlist, offset=0))
        assert all_words == from_zero


class TestResolveWordlist:
    def test_existing_file(self, tmp_wordlist: Path) -> None:
        assert resolve_wordlist(tmp_wordlist) == tmp_wordlist

    def test_fallback_to_bundled(self) -> None:
        result = resolve_wordlist(Path("nonexistent_file.txt"))
        assert result.name == "100K.txt"
        assert result.exists()

    def test_raises_if_nothing_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Point bundled path to a nonexistent location
        import smartcrack.wordlist as wl
        original = Path(__file__).parent / "definitely_not_a_real_path"
        monkeypatch.setattr(wl, "__file__", str(original))
        with pytest.raises(FileNotFoundError):
            resolve_wordlist(Path("also_nonexistent.txt"))
