"""Tests for rainbow table build and lookup."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from smartcrack.models import HashType


class TestBuildRainbowTable:
    def test_build_creates_file(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("apple\nbanana\ncherry\n")
        output = tmp_path / "table.rainbow"
        count = build_rainbow_table(wordlist, HashType.MD5, output)
        assert output.exists()
        assert count == 3

    def test_build_returns_entry_count(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("one\ntwo\nthree\nfour\nfive\n")
        output = tmp_path / "table.rainbow"
        count = build_rainbow_table(wordlist, HashType.SHA1, output)
        assert count == 5

    def test_build_skips_blank_lines(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("alpha\n\nbeta\n\n\ngamma\n")
        output = tmp_path / "table.rainbow"
        count = build_rainbow_table(wordlist, HashType.MD5, output)
        assert count == 3

    def test_build_raises_on_missing_wordlist(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table
        missing = tmp_path / "nope.txt"
        output = tmp_path / "table.rainbow"
        with pytest.raises(FileNotFoundError):
            build_rainbow_table(missing, HashType.MD5, output)

    def test_build_raises_on_unsupported_hash_type(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("test\n")
        output = tmp_path / "table.rainbow"
        with pytest.raises(ValueError, match="Unsupported"):
            build_rainbow_table(wordlist, HashType.BCRYPT, output)


class TestLookupRainbowTable:
    @pytest.fixture()
    def md5_table(self, tmp_path: Path) -> Path:
        from smartcrack.rainbow import build_rainbow_table
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("apple\nbanana\ncherry\ndate\nelderberry\n")
        output = tmp_path / "table.rainbow"
        build_rainbow_table(wordlist, HashType.MD5, output)
        return output

    def test_lookup_finds_known_entry(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table
        target_hash = hashlib.md5(b"banana").hexdigest()
        result = lookup_rainbow_table(target_hash, md5_table)
        assert result == "banana"

    def test_lookup_finds_first_entry(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table
        target_hash = hashlib.md5(b"apple").hexdigest()
        result = lookup_rainbow_table(target_hash, md5_table)
        assert result == "apple"

    def test_lookup_finds_last_entry(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table
        for word in ("apple", "banana", "cherry", "date", "elderberry"):
            h = hashlib.md5(word.encode()).hexdigest()
            assert lookup_rainbow_table(h, md5_table) == word

    def test_lookup_returns_none_for_unknown(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table
        unknown_hash = hashlib.md5(b"not_in_table").hexdigest()
        result = lookup_rainbow_table(unknown_hash, md5_table)
        assert result is None

    def test_lookup_is_case_insensitive(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table
        target_hash = hashlib.md5(b"cherry").hexdigest().upper()
        result = lookup_rainbow_table(target_hash, md5_table)
        assert result == "cherry"

    def test_lookup_on_large_table(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table, lookup_rainbow_table
        words = [f"word{i:04d}" for i in range(1500)]
        wordlist = tmp_path / "big.txt"
        wordlist.write_text("\n".join(words) + "\n")
        output = tmp_path / "big.rainbow"
        count = build_rainbow_table(wordlist, HashType.SHA256, output)
        assert count == 1500
        for i in range(0, 1500, 75):
            word = f"word{i:04d}"
            h = hashlib.sha256(word.encode()).hexdigest()
            assert lookup_rainbow_table(h, output) == word
        miss_hash = hashlib.sha256(b"not_a_word").hexdigest()
        assert lookup_rainbow_table(miss_hash, output) is None

    def test_lookup_raises_on_missing_file(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table
        missing = tmp_path / "nope.rainbow"
        with pytest.raises(FileNotFoundError):
            lookup_rainbow_table("abc123", missing)
