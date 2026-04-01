"""Tests for the doctor and quickstart commands."""

from __future__ import annotations

from typer.testing import CliRunner

from smartcrack.cli import app

runner = CliRunner()


class TestDoctorCommand:
    def test_doctor_exits_successfully(self) -> None:
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0

    def test_doctor_shows_python_version(self) -> None:
        result = runner.invoke(app, ["doctor"])
        assert "Python" in result.output

    def test_doctor_shows_bundled_wordlist(self) -> None:
        result = runner.invoke(app, ["doctor"])
        assert "100K.txt" in result.output or "Bundled" in result.output or "wordlist" in result.output.lower()

    def test_doctor_shows_cpu_cores(self) -> None:
        result = runner.invoke(app, ["doctor"])
        assert "CPU" in result.output or "core" in result.output.lower()

    def test_doctor_checks_optional_deps(self) -> None:
        result = runner.invoke(app, ["doctor"])
        assert "bcrypt" in result.output or "argon2" in result.output


class TestQuickstartCommand:
    def test_quickstart_command_exists(self) -> None:
        result = runner.invoke(app, ["quickstart", "--help"])
        assert result.exit_code == 0
        assert "quickstart" in result.output.lower() or "demo" in result.output.lower() or "wizard" in result.output.lower()
