"""Tests for export report generation (CSV, HTML dashboard)."""

from __future__ import annotations

import csv
import io

from smartcrack.analysis import AuditSummary, generate_audit_summary
from smartcrack.models import AttackPhase, CrackResult, HashType


def _make_results() -> list[tuple[str, CrackResult]]:
    return [
        (
            "5f4dcc3b5aa765d61d8327deb882cf99",
            CrackResult(
                found=True, plaintext="password", hash_type=HashType.MD5,
                attack_phase=AttackPhase.DICTIONARY, attempts=42, duration_seconds=1.5,
            ),
        ),
        (
            "e10adc3949ba59abbe56e057f20f883e",
            CrackResult(
                found=True, plaintext="123456", hash_type=HashType.MD5,
                attack_phase=AttackPhase.RULES, attempts=100, duration_seconds=3.2,
            ),
        ),
        (
            "d8578edf8458ce06fbc5bb76a58c5ca4",
            CrackResult(
                found=False, plaintext=None, hash_type=None,
                attack_phase=None, attempts=50000, duration_seconds=120.0,
            ),
        ),
    ]


def _make_summary() -> AuditSummary:
    passwords = [r.plaintext for _, r in _make_results() if r.found and r.plaintext]
    return generate_audit_summary(passwords)


class TestCSVReport:
    def test_csv_has_correct_header_columns(self) -> None:
        from smartcrack.report import generate_csv_report
        output = generate_csv_report(_make_results())
        reader = csv.reader(io.StringIO(output))
        header = next(reader)
        assert header == ["hash", "plaintext", "algorithm", "attempts", "duration", "entropy", "strength", "patterns"]

    def test_csv_has_row_per_result(self) -> None:
        from smartcrack.report import generate_csv_report
        output = generate_csv_report(_make_results())
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 4

    def test_csv_cracked_row_has_plaintext(self) -> None:
        from smartcrack.report import generate_csv_report
        output = generate_csv_report(_make_results())
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        assert row[0] == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert row[1] == "password"
        assert row[2] == "MD5"

    def test_csv_not_found_row_has_empty_plaintext(self) -> None:
        from smartcrack.report import generate_csv_report
        output = generate_csv_report(_make_results())
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        last_row = rows[-1]
        assert last_row[1] == ""
        assert last_row[2] == ""

    def test_csv_entropy_and_strength_populated_for_cracked(self) -> None:
        from smartcrack.report import generate_csv_report
        output = generate_csv_report(_make_results())
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        entropy = float(row[5])
        assert entropy > 0
        assert row[6] in ("weak", "moderate", "strong", "very_strong")

    def test_csv_empty_results_returns_header_only(self) -> None:
        from smartcrack.report import generate_csv_report
        output = generate_csv_report([])
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0][0] == "hash"


class TestHTMLDashboard:
    def test_html_contains_doctype(self) -> None:
        from smartcrack.report import generate_html_dashboard
        html = generate_html_dashboard(_make_results(), _make_summary())
        assert "<!DOCTYPE html>" in html

    def test_html_contains_chartjs_script(self) -> None:
        from smartcrack.report import generate_html_dashboard
        html = generate_html_dashboard(_make_results(), _make_summary())
        assert "chart.js" in html.lower() or "Chart.js" in html

    def test_html_contains_strength_pie_chart_data(self) -> None:
        from smartcrack.report import generate_html_dashboard
        summary = _make_summary()
        html = generate_html_dashboard(_make_results(), summary)
        assert "strengthChart" in html
        for strength in summary.strength_distribution:
            assert strength in html

    def test_html_contains_entropy_bar_chart(self) -> None:
        from smartcrack.report import generate_html_dashboard
        html = generate_html_dashboard(_make_results(), _make_summary())
        assert "entropyChart" in html

    def test_html_contains_all_cracked_hashes_in_table(self) -> None:
        from smartcrack.report import generate_html_dashboard
        html = generate_html_dashboard(_make_results(), _make_summary())
        for hash_value, result in _make_results():
            assert hash_value in html

    def test_html_contains_executive_summary(self) -> None:
        from smartcrack.report import generate_html_dashboard
        summary = _make_summary()
        html = generate_html_dashboard(_make_results(), summary)
        assert "Executive Summary" in html
        assert str(summary.total) in html
        assert f"{summary.avg_entropy:.1f}" in html

    def test_html_contains_sortable_table_script(self) -> None:
        from smartcrack.report import generate_html_dashboard
        html = generate_html_dashboard(_make_results(), _make_summary())
        assert "sortTable" in html

    def test_html_contains_recommendations_when_present(self) -> None:
        from smartcrack.report import generate_html_dashboard
        summary = _make_summary()
        html = generate_html_dashboard(_make_results(), summary)
        if summary.recommendations:
            assert "Recommendations" in html

    def test_html_empty_results_still_renders(self) -> None:
        from smartcrack.report import generate_html_dashboard
        from smartcrack.analysis import generate_audit_summary
        empty_summary = generate_audit_summary([])
        html = generate_html_dashboard([], empty_summary)
        assert "<!DOCTYPE html>" in html
        assert "Executive Summary" in html
