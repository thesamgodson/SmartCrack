"""Tests for hashcat compatibility layer."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from smartcrack.cli import app
from smartcrack.models import HashType


class TestHashcatModeMapping:
    def test_mode_0_is_md5(self) -> None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode
        assert resolve_hashcat_mode(0) == HashType.MD5

    def test_mode_100_is_sha1(self) -> None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode
        assert resolve_hashcat_mode(100) == HashType.SHA1

    def test_mode_1400_is_sha256(self) -> None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode
        assert resolve_hashcat_mode(1400) == HashType.SHA256

    def test_mode_1700_is_sha512(self) -> None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode
        assert resolve_hashcat_mode(1700) == HashType.SHA512

    def test_mode_3200_is_bcrypt(self) -> None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode
        assert resolve_hashcat_mode(3200) == HashType.BCRYPT

    def test_mode_1000_is_ntlm(self) -> None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode
        assert resolve_hashcat_mode(1000) == HashType.NTLM

    def test_unknown_mode_raises_key_error(self) -> None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode
        with pytest.raises(KeyError):
            resolve_hashcat_mode(99999)


class TestPotfileParsing:
    def test_parse_basic_potfile(self, tmp_path: Path) -> None:
        from smartcrack.hashcat_compat import parse_potfile
        pot = tmp_path / "test.pot"
        pot.write_text("5f4dcc3b5aa765d61d8327deb882cf99:password\ne10adc3949ba59abbe56e057f20f883e:123456\n")
        results = parse_potfile(pot)
        assert len(results) == 2
        assert results[0] == ("5f4dcc3b5aa765d61d8327deb882cf99", "password")
        assert results[1] == ("e10adc3949ba59abbe56e057f20f883e", "123456")

    def test_parse_potfile_skips_empty_lines(self, tmp_path: Path) -> None:
        from smartcrack.hashcat_compat import parse_potfile
        pot = tmp_path / "test.pot"
        pot.write_text("5f4dcc3b5aa765d61d8327deb882cf99:password\n\ne10adc3949ba59abbe56e057f20f883e:123456\n")
        results = parse_potfile(pot)
        assert len(results) == 2

    def test_parse_potfile_handles_plaintext_with_colon(self, tmp_path: Path) -> None:
        from smartcrack.hashcat_compat import parse_potfile
        pot = tmp_path / "test.pot"
        pot.write_text("abc123def:pass:word\n")
        results = parse_potfile(pot)
        assert results[0] == ("abc123def", "pass:word")

    def test_parse_empty_potfile(self, tmp_path: Path) -> None:
        from smartcrack.hashcat_compat import parse_potfile
        pot = tmp_path / "test.pot"
        pot.write_text("")
        results = parse_potfile(pot)
        assert results == []


class TestHCMaskParsing:
    def test_parse_basic_hcmask(self, tmp_path: Path) -> None:
        from smartcrack.hashcat_compat import parse_hcmask_file
        mask_file = tmp_path / "test.hcmask"
        mask_file.write_text("?l?l?l?l?l?l\n?u?l?l?l?l?d?d\n?d?d?d?d?d?d\n")
        masks = parse_hcmask_file(mask_file)
        assert len(masks) == 3
        assert masks[0] == "?l?l?l?l?l?l"

    def test_parse_hcmask_skips_comments(self, tmp_path: Path) -> None:
        from smartcrack.hashcat_compat import parse_hcmask_file
        mask_file = tmp_path / "test.hcmask"
        mask_file.write_text("# This is a comment\n?l?l?l?l?l?l\n# Another comment\n?d?d?d?d\n")
        masks = parse_hcmask_file(mask_file)
        assert len(masks) == 2

    def test_parse_hcmask_skips_blank_lines(self, tmp_path: Path) -> None:
        from smartcrack.hashcat_compat import parse_hcmask_file
        mask_file = tmp_path / "test.hcmask"
        mask_file.write_text("?l?l?l?l\n\n?d?d?d?d\n")
        masks = parse_hcmask_file(mask_file)
        assert len(masks) == 2

    def test_parse_empty_hcmask(self, tmp_path: Path) -> None:
        from smartcrack.hashcat_compat import parse_hcmask_file
        mask_file = tmp_path / "test.hcmask"
        mask_file.write_text("")
        masks = parse_hcmask_file(mask_file)
        assert masks == []


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------

runner = CliRunner()


class TestHashcatCLI:
    def test_smart_accepts_hashcat_mode_flag(self) -> None:
        """Verify -m flag is recognized (even if hash is not found)."""
        result = runner.invoke(app, [
            "smart",
            "-H", "5f4dcc3b5aa765d61d8327deb882cf99",
            "-m", "0",
            "--rules", "none",
        ])
        # Should not error on unknown flag
        assert result.exit_code == 0 or "Cracked" in result.output or "Not found" in result.output

    def test_smart_hashcat_mode_sets_correct_type(self) -> None:
        """Verify -m 0 resolves to MD5 in output."""
        result = runner.invoke(app, [
            "smart",
            "-H", "5f4dcc3b5aa765d61d8327deb882cf99",
            "-m", "0",
            "--rules", "none",
        ])
        assert "MD5" in result.output

    def test_analyze_potfile_command(self, tmp_path: Path) -> None:
        """Verify analyze command reads potfile and produces output."""
        pot = tmp_path / "test.pot"
        pot.write_text(
            "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
            "e10adc3949ba59abbe56e057f20f883e:123456\n"
        )
        result = runner.invoke(app, [
            "analyze",
            "--potfile", str(pot),
        ])
        assert result.exit_code == 0
        assert "password" in result.output.lower() or "entropy" in result.output.lower() or "analyzed" in result.output.lower()
