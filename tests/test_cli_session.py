"""Tests for --session-file option on the smart CLI command."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from smartcrack.cli import app
from smartcrack.models import CrackResult, CrackSession, HashTarget, HashType
from smartcrack.session import save_session

runner = CliRunner()

# A simple MD5 hash of "password"
_MD5_HASH = hashlib.md5(b"password").hexdigest()  # noqa: S324


def _make_wordlist(tmp_path: Path) -> Path:
    wl = tmp_path / "words.txt"
    wl.write_text("hello\nworld\npassword\ntest\n")
    return wl


@patch("smartcrack.cli.run_orchestrated")
@patch("smartcrack.cli.resolve_wordlist")
def test_session_file_new_creates_file(
    mock_resolve: object,
    mock_run: object,
    tmp_path: Path,
) -> None:
    """When --session-file points to a non-existent path, a session file is created after run."""
    wl = _make_wordlist(tmp_path)
    mock_resolve.return_value = wl  # type: ignore[attr-defined]
    mock_run.return_value = CrackResult(found=False, attempts=4, duration_seconds=0.1)  # type: ignore[attr-defined]

    sf = tmp_path / "session.json"
    result = runner.invoke(app, [
        "smart", "--hash", _MD5_HASH, "--wordlist", str(wl),
        "--session-file", str(sf), "--rules", "none",
    ])

    assert result.exit_code == 0, result.output
    assert sf.exists(), "Session file should be created"
    assert "Session saved to" in result.output

    data = json.loads(sf.read_text())
    assert "session_id" in data
    assert data["target"]["hash_value"] == _MD5_HASH


@patch("smartcrack.cli.run_orchestrated")
@patch("smartcrack.cli.resolve_wordlist")
def test_session_file_resume_existing(
    mock_resolve: object,
    mock_run: object,
    tmp_path: Path,
) -> None:
    """When --session-file points to an existing session, it resumes."""
    wl = _make_wordlist(tmp_path)
    mock_resolve.return_value = wl  # type: ignore[attr-defined]
    mock_run.return_value = CrackResult(found=False, attempts=2, duration_seconds=0.05)  # type: ignore[attr-defined]

    sf = tmp_path / "session.json"
    existing_session = CrackSession(
        session_id="resume01",
        target=HashTarget(hash_value=_MD5_HASH, hash_type=HashType.MD5),
        phases_completed=("dictionary",),
        wordlist_offset=100,
    )
    save_session(existing_session, sf)

    result = runner.invoke(app, [
        "smart", "--hash", _MD5_HASH, "--wordlist", str(wl),
        "--session-file", str(sf), "--rules", "none",
    ])

    assert result.exit_code == 0, result.output
    assert "Resuming session" in result.output
    assert "resume01" in result.output
    assert "1 phases completed" in result.output

    # Verify session was passed to run_orchestrated
    call_kwargs = mock_run.call_args.kwargs  # type: ignore[attr-defined]
    assert call_kwargs["session"] is not None
    assert call_kwargs["session"].session_id == "resume01"


@patch("smartcrack.cli.run_orchestrated")
@patch("smartcrack.cli.resolve_wordlist")
def test_session_file_corrupt_prints_error(
    mock_resolve: object,
    mock_run: object,
    tmp_path: Path,
) -> None:
    """Corrupt session file prints a friendly error and exits."""
    wl = _make_wordlist(tmp_path)
    mock_resolve.return_value = wl  # type: ignore[attr-defined]

    sf = tmp_path / "session.json"
    sf.write_text("NOT VALID JSON {{{")

    result = runner.invoke(app, [
        "smart", "--hash", _MD5_HASH, "--wordlist", str(wl),
        "--session-file", str(sf), "--rules", "none",
    ])

    assert result.exit_code == 1
    assert "Corrupt session file" in result.output
    mock_run.assert_not_called()  # type: ignore[attr-defined]
