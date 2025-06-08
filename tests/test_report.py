"""Tests for report generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hashcrack.models import (
    AttackPhase,
    CrackResult,
    CrackSession,
    HashTarget,
    HashType,
)
from hashcrack.report import generate_report, save_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(
    *,
    found: bool = False,
    plaintext: str | None = None,
    attempts: int = 500,
    duration: float = 3.5,
    phases: tuple[str, ...] = ("DICTIONARY", "RULES"),
    candidates: int = 500,
    salt: str = "",
) -> CrackSession:
    target = HashTarget(
        hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
        hash_type=HashType.MD5,
        salt=salt,
    )
    result = CrackResult(
        found=found,
        plaintext=plaintext,
        hash_type=HashType.MD5 if found else None,
        attack_phase=AttackPhase.DICTIONARY if found else None,
        attempts=attempts,
        duration_seconds=duration,
    )
    return CrackSession(
        session_id="testid01",
        target=target,
        profile=None,
        current_phase=AttackPhase.RULES,
        candidates_tried=candidates,
        wordlist_offset=0,
        phases_completed=phases,
        completed=found,
        result=result,
    )


# ---------------------------------------------------------------------------
# Markdown: structure
# ---------------------------------------------------------------------------


def test_markdown_contains_title() -> None:
    session = _make_session()
    report = generate_report(session, format="markdown")
    assert "# HashCrack Report" in report


def test_markdown_contains_target_section() -> None:
    session = _make_session()
    report = generate_report(session, format="markdown")
    assert "## Target" in report
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in report
    assert "MD5" in report


def test_markdown_contains_result_section() -> None:
    session = _make_session()
    report = generate_report(session, format="markdown")
    assert "## Result" in report
    assert "## Attack Summary" in report


def test_markdown_salt_shown_when_present() -> None:
    session = _make_session(salt="mysalt")
    report = generate_report(session, format="markdown")
    assert "mysalt" in report


def test_markdown_salt_shows_none_when_absent() -> None:
    session = _make_session(salt="")
    report = generate_report(session, format="markdown")
    assert "Salt: none" in report


# ---------------------------------------------------------------------------
# Markdown: found result
# ---------------------------------------------------------------------------


def test_markdown_found_result() -> None:
    session = _make_session(found=True, plaintext="password", attempts=42, duration=1.5)
    report = generate_report(session, format="markdown")
    assert "Status: Cracked" in report
    assert "Plaintext: password" in report
    assert "Attempts: 42" in report
    assert "Duration: 1.5s" in report


def test_markdown_found_shows_algorithm() -> None:
    session = _make_session(found=True, plaintext="hello")
    report = generate_report(session, format="markdown")
    assert "Algorithm: MD5" in report


# ---------------------------------------------------------------------------
# Markdown: not-found result
# ---------------------------------------------------------------------------


def test_markdown_not_found_result() -> None:
    session = _make_session(found=False, attempts=9999, duration=60.0)
    report = generate_report(session, format="markdown")
    assert "Status: Not Found" in report
    assert "Attempts: 9999" in report


def test_markdown_attack_summary_phases() -> None:
    session = _make_session(phases=("DICTIONARY", "RULES"), candidates=750)
    report = generate_report(session, format="markdown")
    assert "DICTIONARY" in report
    assert "RULES" in report
    assert "750" in report


# ---------------------------------------------------------------------------
# JSON format
# ---------------------------------------------------------------------------


def test_json_report_is_valid_json() -> None:
    session = _make_session()
    report = generate_report(session, format="json")
    data = json.loads(report)  # must not raise
    assert isinstance(data, dict)


def test_json_report_has_expected_top_level_keys() -> None:
    session = _make_session()
    data = json.loads(generate_report(session, format="json"))
    assert "target" in data
    assert "result" in data
    assert "attack_summary" in data


def test_json_report_target_fields() -> None:
    session = _make_session()
    data = json.loads(generate_report(session, format="json"))
    assert data["target"]["hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert data["target"]["type"] == "MD5"


def test_json_report_found_result() -> None:
    session = _make_session(found=True, plaintext="secret", attempts=7, duration=0.5)
    data = json.loads(generate_report(session, format="json"))
    assert data["result"]["status"] == "Cracked"
    assert data["result"]["plaintext"] == "secret"
    assert data["result"]["attempts"] == 7
    assert data["result"]["duration_seconds"] == pytest.approx(0.5)


def test_json_report_not_found_result() -> None:
    session = _make_session(found=False, attempts=1000)
    data = json.loads(generate_report(session, format="json"))
    assert data["result"]["status"] == "Not Found"
    assert data["result"]["plaintext"] is None


def test_json_report_attack_summary() -> None:
    session = _make_session(phases=("DICTIONARY",), candidates=200)
    data = json.loads(generate_report(session, format="json"))
    assert data["attack_summary"]["total_candidates"] == 200
    assert "DICTIONARY" in data["attack_summary"]["phases_completed"]


# ---------------------------------------------------------------------------
# Invalid format
# ---------------------------------------------------------------------------


def test_invalid_format_raises() -> None:
    session = _make_session()
    with pytest.raises(ValueError, match="Unsupported report format"):
        generate_report(session, format="csv")


# ---------------------------------------------------------------------------
# save_report
# ---------------------------------------------------------------------------


def test_save_report_writes_file(tmp_path: Path) -> None:
    session = _make_session(found=True, plaintext="test")
    content = generate_report(session, format="markdown")
    out = tmp_path / "report.md"
    save_report(content, out)
    assert out.exists()
    assert out.read_text(encoding="utf-8") == content


def test_save_report_json(tmp_path: Path) -> None:
    session = _make_session()
    content = generate_report(session, format="json")
    out = tmp_path / "report.json"
    save_report(content, out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "target" in data


# ---- Audit report tests ----

class TestAuditReport:
    def _make_summary(self):
        from hashcrack.analysis import generate_audit_summary
        return generate_audit_summary(["password", "123456", "john1990", "X#9kL!mP2@vQ"])

    def test_audit_markdown(self):
        from hashcrack.report import generate_audit_report
        summary = self._make_summary()
        md = generate_audit_report(summary, format="markdown")
        assert "# Security Audit Report" in md
        assert "Executive Summary" in md
        assert "Strength Distribution" in md
        assert "Pattern Analysis" in md

    def test_audit_html(self):
        from hashcrack.report import generate_audit_report
        summary = self._make_summary()
        html = generate_audit_report(summary, format="html")
        assert "<!DOCTYPE html>" in html
        assert "Security Audit Report" in html
        assert "Passwords Analyzed" in html

    def test_audit_invalid_format(self):
        from hashcrack.report import generate_audit_report
        summary = self._make_summary()
        with pytest.raises(ValueError, match="Unsupported format"):
            generate_audit_report(summary, format="pdf")
