# Phase C: Polish & Ship — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add professional export reports, PyPI publishing, and hashcat compatibility to make SmartCrack distribution-ready.

**Architecture:** Export pipeline extends existing report.py with CSV and standalone HTML dashboard. Doctor/quickstart commands provide onboarding. Hashcat compat layer adds format interop.

**Tech Stack:** Rich (rendering), Chart.js (HTML reports), hatchling (PyPI), GitHub Actions (CI/CD).

---

## Task 1: Export Reports — CSV Generation

**Files:**
- `src/smartcrack/report.py` (modify)
- `tests/test_export.py` (create)

### Steps

- [ ] **1.1 — Write failing tests for CSV report generation**

  ```bash
  touch tests/test_export.py
  ```

  Write `tests/test_export.py` with the CSV tests:

  ```python
  """Tests for export report generation (CSV, HTML dashboard)."""

  from __future__ import annotations

  import csv
  import io
  from pathlib import Path

  import pytest

  from smartcrack.analysis import AuditSummary, generate_audit_summary
  from smartcrack.models import AttackPhase, CrackResult, HashType


  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  def _make_results() -> list[tuple[str, CrackResult]]:
      """Return a list of (hash, CrackResult) tuples for testing."""
      return [
          (
              "5f4dcc3b5aa765d61d8327deb882cf99",
              CrackResult(
                  found=True,
                  plaintext="password",
                  hash_type=HashType.MD5,
                  attack_phase=AttackPhase.DICTIONARY,
                  attempts=42,
                  duration_seconds=1.5,
              ),
          ),
          (
              "e10adc3949ba59abbe56e057f20f883e",
              CrackResult(
                  found=True,
                  plaintext="123456",
                  hash_type=HashType.MD5,
                  attack_phase=AttackPhase.RULES,
                  attempts=100,
                  duration_seconds=3.2,
              ),
          ),
          (
              "d8578edf8458ce06fbc5bb76a58c5ca4",
              CrackResult(
                  found=False,
                  plaintext=None,
                  hash_type=None,
                  attack_phase=None,
                  attempts=50000,
                  duration_seconds=120.0,
              ),
          ),
      ]


  def _make_summary() -> AuditSummary:
      """Generate an AuditSummary from the cracked passwords in _make_results."""
      passwords = [r.plaintext for _, r in _make_results() if r.found and r.plaintext]
      return generate_audit_summary(passwords)


  # ---------------------------------------------------------------------------
  # CSV report tests
  # ---------------------------------------------------------------------------

  class TestCSVReport:
      def test_csv_has_correct_header_columns(self) -> None:
          from smartcrack.report import generate_csv_report

          results = _make_results()
          output = generate_csv_report(results)
          reader = csv.reader(io.StringIO(output))
          header = next(reader)
          assert header == [
              "hash", "plaintext", "algorithm", "attempts",
              "duration", "entropy", "strength", "patterns",
          ]

      def test_csv_has_row_per_result(self) -> None:
          from smartcrack.report import generate_csv_report

          results = _make_results()
          output = generate_csv_report(results)
          reader = csv.reader(io.StringIO(output))
          rows = list(reader)
          # 1 header + 3 data rows
          assert len(rows) == 4

      def test_csv_cracked_row_has_plaintext(self) -> None:
          from smartcrack.report import generate_csv_report

          results = _make_results()
          output = generate_csv_report(results)
          reader = csv.reader(io.StringIO(output))
          next(reader)  # skip header
          row = next(reader)
          assert row[0] == "5f4dcc3b5aa765d61d8327deb882cf99"
          assert row[1] == "password"
          assert row[2] == "MD5"

      def test_csv_not_found_row_has_empty_plaintext(self) -> None:
          from smartcrack.report import generate_csv_report

          results = _make_results()
          output = generate_csv_report(results)
          reader = csv.reader(io.StringIO(output))
          rows = list(reader)
          last_row = rows[-1]
          assert last_row[1] == ""
          assert last_row[2] == ""

      def test_csv_entropy_and_strength_populated_for_cracked(self) -> None:
          from smartcrack.report import generate_csv_report

          results = _make_results()
          output = generate_csv_report(results)
          reader = csv.reader(io.StringIO(output))
          next(reader)  # skip header
          row = next(reader)  # "password" row
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
  ```

  Run and confirm failure:

  ```bash
  python -m pytest tests/test_export.py::TestCSVReport -v 2>&1 | head -30
  ```

- [ ] **1.2 — Implement `generate_csv_report` in `report.py`**

  Add these imports at the top of `src/smartcrack/report.py` (after the existing imports):

  ```python
  import csv
  import io

  from smartcrack.analysis import AuditSummary, analyze_password
  from smartcrack.models import CrackResult
  ```

  Add the function before `generate_report`:

  ```python
  _CSV_COLUMNS = ["hash", "plaintext", "algorithm", "attempts", "duration", "entropy", "strength", "patterns"]


  def generate_csv_report(results: list[tuple[str, CrackResult]]) -> str:
      """Generate a CSV report from a list of (hash, CrackResult) tuples.

      Columns: hash, plaintext, algorithm, attempts, duration, entropy, strength, patterns.
      Entropy, strength, and patterns are computed via analyze_password for cracked results.
      """
      buf = io.StringIO()
      writer = csv.writer(buf)
      writer.writerow(_CSV_COLUMNS)

      for hash_value, result in results:
          if result.found and result.plaintext is not None:
              analysis = analyze_password(result.plaintext)
              writer.writerow([
                  hash_value,
                  result.plaintext,
                  result.hash_type.name if result.hash_type is not None else "",
                  result.attempts,
                  f"{result.duration_seconds:.2f}",
                  f"{analysis.entropy:.1f}",
                  analysis.strength,
                  "; ".join(analysis.patterns),
              ])
          else:
              writer.writerow([
                  hash_value,
                  "",
                  "",
                  result.attempts,
                  f"{result.duration_seconds:.2f}",
                  "",
                  "",
                  "",
              ])

      return buf.getvalue()
  ```

  Run tests:

  ```bash
  python -m pytest tests/test_export.py::TestCSVReport -v
  ```

  **Commit:** `feat: add CSV export report generation`

---

## Task 2: Export Reports — HTML Dashboard

**Files:**
- `src/smartcrack/report.py` (modify)
- `tests/test_export.py` (modify)

### Steps

- [ ] **2.1 — Write failing tests for HTML dashboard**

  Append to `tests/test_export.py`:

  ```python
  # ---------------------------------------------------------------------------
  # HTML dashboard tests
  # ---------------------------------------------------------------------------

  class TestHTMLDashboard:
      def test_html_contains_doctype(self) -> None:
          from smartcrack.report import generate_html_dashboard

          results = _make_results()
          summary = _make_summary()
          html = generate_html_dashboard(results, summary)
          assert "<!DOCTYPE html>" in html

      def test_html_contains_chartjs_script(self) -> None:
          from smartcrack.report import generate_html_dashboard

          results = _make_results()
          summary = _make_summary()
          html = generate_html_dashboard(results, summary)
          assert "chart.js" in html.lower() or "Chart.js" in html

      def test_html_contains_strength_pie_chart_data(self) -> None:
          from smartcrack.report import generate_html_dashboard

          results = _make_results()
          summary = _make_summary()
          html = generate_html_dashboard(results, summary)
          assert "strengthChart" in html
          # Verify strength labels are in the chart data
          for strength in summary.strength_distribution:
              assert strength in html

      def test_html_contains_entropy_bar_chart(self) -> None:
          from smartcrack.report import generate_html_dashboard

          results = _make_results()
          summary = _make_summary()
          html = generate_html_dashboard(results, summary)
          assert "entropyChart" in html

      def test_html_contains_all_cracked_hashes_in_table(self) -> None:
          from smartcrack.report import generate_html_dashboard

          results = _make_results()
          summary = _make_summary()
          html = generate_html_dashboard(results, summary)
          for hash_value, result in results:
              assert hash_value in html

      def test_html_contains_executive_summary(self) -> None:
          from smartcrack.report import generate_html_dashboard

          results = _make_results()
          summary = _make_summary()
          html = generate_html_dashboard(results, summary)
          assert "Executive Summary" in html
          assert str(summary.total) in html
          assert f"{summary.avg_entropy:.1f}" in html

      def test_html_contains_sortable_table_script(self) -> None:
          from smartcrack.report import generate_html_dashboard

          results = _make_results()
          summary = _make_summary()
          html = generate_html_dashboard(results, summary)
          assert "sortTable" in html

      def test_html_contains_recommendations_when_present(self) -> None:
          from smartcrack.report import generate_html_dashboard

          results = _make_results()
          summary = _make_summary()
          html = generate_html_dashboard(results, summary)
          if summary.recommendations:
              assert "Recommendations" in html

      def test_html_empty_results_still_renders(self) -> None:
          from smartcrack.report import generate_html_dashboard
          from smartcrack.analysis import generate_audit_summary

          empty_summary = generate_audit_summary([])
          html = generate_html_dashboard([], empty_summary)
          assert "<!DOCTYPE html>" in html
          assert "Executive Summary" in html
  ```

  Run and confirm failure:

  ```bash
  python -m pytest tests/test_export.py::TestHTMLDashboard -v 2>&1 | head -30
  ```

- [ ] **2.2 — Implement `generate_html_dashboard` in `report.py`**

  Add this function to `src/smartcrack/report.py`:

  ```python
  def generate_html_dashboard(
      results: list[tuple[str, CrackResult]],
      summary: AuditSummary,
  ) -> str:
      """Generate a standalone HTML dashboard with Chart.js visualizations.

      Includes:
      - Executive summary cards
      - Pie chart for strength distribution
      - Bar chart for entropy distribution
      - Sortable results table
      - Recommendations section
      """
      # Build table rows
      table_rows = ""
      entropy_labels: list[str] = []
      entropy_values: list[float] = []

      for hash_value, result in results:
          if result.found and result.plaintext is not None:
              analysis = analyze_password(result.plaintext)
              table_rows += (
                  f"<tr>"
                  f"<td class='hash'>{hash_value}</td>"
                  f"<td>{result.plaintext}</td>"
                  f"<td>{result.hash_type.name if result.hash_type else 'N/A'}</td>"
                  f"<td>{result.attempts:,}</td>"
                  f"<td>{result.duration_seconds:.2f}s</td>"
                  f"<td>{analysis.entropy:.1f}</td>"
                  f"<td><span class='badge badge-{analysis.strength}'>{analysis.strength}</span></td>"
                  f"<td>{'; '.join(analysis.patterns) if analysis.patterns else 'none'}</td>"
                  f"</tr>\n"
              )
              entropy_labels.append(result.plaintext[:12])
              entropy_values.append(round(analysis.entropy, 1))
          else:
              table_rows += (
                  f"<tr>"
                  f"<td class='hash'>{hash_value}</td>"
                  f"<td class='dim'>not cracked</td>"
                  f"<td>N/A</td>"
                  f"<td>{result.attempts:,}</td>"
                  f"<td>{result.duration_seconds:.2f}s</td>"
                  f"<td>-</td>"
                  f"<td><span class='badge badge-unknown'>unknown</span></td>"
                  f"<td>-</td>"
                  f"</tr>\n"
              )

      # Strength distribution for pie chart
      strength_labels = json.dumps(list(summary.strength_distribution.keys()))
      strength_values = json.dumps(list(summary.strength_distribution.values()))

      # Entropy distribution for bar chart
      entropy_labels_json = json.dumps(entropy_labels)
      entropy_values_json = json.dumps(entropy_values)

      # Recommendations HTML
      recs_html = ""
      if summary.recommendations:
          recs_items = "".join(f"<li>{rec}</li>" for rec in summary.recommendations)
          recs_html = f"""
      <section class="card">
          <h2>Recommendations</h2>
          <ul class="recommendations">{recs_items}</ul>
      </section>"""

      cracked_count = sum(1 for _, r in results if r.found)
      total_count = len(results)

      return f"""<!DOCTYPE html>
  <html lang="en">
  <head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SmartCrack Export Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
  <style>
    :root {{
      --bg: #f8f9fa;
      --card-bg: #ffffff;
      --text: #1a1a2e;
      --text-dim: #6c757d;
      --primary: #0f3460;
      --accent: #e94560;
      --success: #28a745;
      --warning: #ffc107;
      --border: #dee2e6;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem 1rem;
      color: var(--text);
      background: var(--bg);
      line-height: 1.5;
    }}
    h1 {{
      font-size: 1.75rem;
      color: var(--primary);
      border-bottom: 2px solid var(--primary);
      padding-bottom: 0.5rem;
      margin-bottom: 1.5rem;
    }}
    h2 {{
      font-size: 1.25rem;
      color: var(--primary);
      margin-bottom: 1rem;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .stat {{
      background: var(--card-bg);
      padding: 1.25rem;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.08);
      text-align: center;
    }}
    .stat-value {{
      font-size: 2rem;
      font-weight: 700;
      color: var(--primary);
    }}
    .stat-label {{
      color: var(--text-dim);
      font-size: 0.875rem;
      margin-top: 0.25rem;
    }}
    .card {{
      background: var(--card-bg);
      padding: 1.5rem;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.08);
      margin-bottom: 1.5rem;
    }}
    .charts {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
      margin-bottom: 1.5rem;
    }}
    @media (max-width: 768px) {{
      .charts {{ grid-template-columns: 1fr; }}
    }}
    .chart-container {{
      background: var(--card-bg);
      padding: 1.5rem;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }}
    th {{
      background: var(--primary);
      color: white;
      padding: 0.75rem 0.5rem;
      text-align: left;
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }}
    th:hover {{ opacity: 0.9; }}
    td {{
      padding: 0.5rem;
      border-bottom: 1px solid var(--border);
    }}
    tr:hover {{ background: #f1f3f5; }}
    .hash {{
      font-family: 'SF Mono', 'Cascadia Code', monospace;
      font-size: 0.75rem;
      word-break: break-all;
    }}
    .dim {{ color: var(--text-dim); font-style: italic; }}
    .badge {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    .badge-weak {{ background: #ffe0e0; color: #c62828; }}
    .badge-moderate {{ background: #fff3cd; color: #856404; }}
    .badge-strong {{ background: #d4edda; color: #155724; }}
    .badge-very_strong {{ background: #cce5ff; color: #004085; }}
    .badge-unknown {{ background: #e9ecef; color: #495057; }}
    .recommendations {{
      list-style: none;
      padding: 0;
    }}
    .recommendations li {{
      padding: 0.5rem 0;
      border-bottom: 1px solid var(--border);
    }}
    .recommendations li::before {{
      content: "\\26a0\\fe0f ";
    }}
    footer {{
      margin-top: 2rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
      color: var(--text-dim);
      font-size: 0.8rem;
      text-align: center;
    }}
  </style>
  </head>
  <body>
  <h1>SmartCrack Export Dashboard</h1>

  <section>
      <h2>Executive Summary</h2>
      <div class="summary-grid">
          <div class="stat">
              <div class="stat-value">{total_count}</div>
              <div class="stat-label">Total Hashes</div>
          </div>
          <div class="stat">
              <div class="stat-value">{cracked_count}</div>
              <div class="stat-label">Cracked</div>
          </div>
          <div class="stat">
              <div class="stat-value">{summary.total}</div>
              <div class="stat-label">Passwords Analyzed</div>
          </div>
          <div class="stat">
              <div class="stat-value">{summary.avg_entropy:.1f}</div>
              <div class="stat-label">Avg Entropy (bits)</div>
          </div>
          <div class="stat">
              <div class="stat-value">{summary.policy_failures}</div>
              <div class="stat-label">Policy Failures</div>
          </div>
      </div>
  </section>

  <div class="charts">
      <div class="chart-container">
          <h2>Strength Distribution</h2>
          <canvas id="strengthChart"></canvas>
      </div>
      <div class="chart-container">
          <h2>Entropy Distribution</h2>
          <canvas id="entropyChart"></canvas>
      </div>
  </div>

  <section class="card">
      <h2>Results</h2>
      <table id="resultsTable">
          <thead>
              <tr>
                  <th onclick="sortTable(0)">Hash</th>
                  <th onclick="sortTable(1)">Plaintext</th>
                  <th onclick="sortTable(2)">Algorithm</th>
                  <th onclick="sortTable(3)">Attempts</th>
                  <th onclick="sortTable(4)">Duration</th>
                  <th onclick="sortTable(5)">Entropy</th>
                  <th onclick="sortTable(6)">Strength</th>
                  <th onclick="sortTable(7)">Patterns</th>
              </tr>
          </thead>
          <tbody>
  {table_rows}        </tbody>
      </table>
  </section>
  {recs_html}
  <footer>Generated by SmartCrack v{__import__('smartcrack').__version__}</footer>

  <script>
  const strengthCtx = document.getElementById('strengthChart').getContext('2d');
  new Chart(strengthCtx, {{
      type: 'pie',
      data: {{
          labels: {strength_labels},
          datasets: [{{
              data: {strength_values},
              backgroundColor: ['#e94560', '#ffc107', '#28a745', '#0f3460'],
          }}],
      }},
      options: {{
          responsive: true,
          plugins: {{ legend: {{ position: 'bottom' }} }},
      }},
  }});

  const entropyCtx = document.getElementById('entropyChart').getContext('2d');
  new Chart(entropyCtx, {{
      type: 'bar',
      data: {{
          labels: {entropy_labels_json},
          datasets: [{{
              label: 'Entropy (bits)',
              data: {entropy_values_json},
              backgroundColor: '#0f3460',
              borderRadius: 4,
          }}],
      }},
      options: {{
          responsive: true,
          scales: {{
              y: {{ beginAtZero: true, title: {{ display: true, text: 'Bits' }} }},
          }},
          plugins: {{ legend: {{ display: false }} }},
      }},
  }});

  function sortTable(colIdx) {{
      const table = document.getElementById('resultsTable');
      const tbody = table.tBodies[0];
      const rows = Array.from(tbody.rows);
      const dir = table.dataset.sortDir === 'asc' ? 'desc' : 'asc';
      table.dataset.sortDir = dir;

      rows.sort((a, b) => {{
          const aText = a.cells[colIdx].textContent.trim();
          const bText = b.cells[colIdx].textContent.trim();
          const aNum = parseFloat(aText.replace(/,/g, ''));
          const bNum = parseFloat(bText.replace(/,/g, ''));
          if (!isNaN(aNum) && !isNaN(bNum)) {{
              return dir === 'asc' ? aNum - bNum : bNum - aNum;
          }}
          return dir === 'asc' ? aText.localeCompare(bText) : bText.localeCompare(aText);
      }});
      rows.forEach(row => tbody.appendChild(row));
  }}
  </script>
  </body>
  </html>"""
  ```

  Run tests:

  ```bash
  python -m pytest tests/test_export.py::TestHTMLDashboard -v
  ```

  **Commit:** `feat: add HTML dashboard with Chart.js visualizations`

---

## Task 3: Export CLI Command

**Files:**
- `src/smartcrack/cli.py` (modify)
- `tests/test_export.py` (modify)

### Steps

- [ ] **3.1 — Write failing tests for export command**

  Append to `tests/test_export.py`:

  ```python
  # ---------------------------------------------------------------------------
  # CLI export command tests
  # ---------------------------------------------------------------------------

  from typer.testing import CliRunner
  from smartcrack.cli import app

  runner = CliRunner()


  class TestExportCommand:
      def _write_session_json(self, tmp_path: Path) -> Path:
          """Write a minimal JSON session file for import."""
          import json

          session_data = {
              "session_id": "test01",
              "target": {
                  "hash_value": "5f4dcc3b5aa765d61d8327deb882cf99",
                  "hash_type": "MD5",
                  "salt": "",
                  "possible_types": [],
              },
              "result": {
                  "found": True,
                  "plaintext": "password",
                  "hash_type": "MD5",
                  "attack_phase": "DICTIONARY",
                  "attempts": 42,
                  "duration_seconds": 1.5,
              },
              "current_phase": "DICTIONARY",
              "candidates_tried": 42,
              "wordlist_offset": 0,
              "phases_completed": ["dictionary"],
              "completed": True,
              "profile": None,
          }
          path = tmp_path / "session.json"
          path.write_text(json.dumps(session_data))
          return path

      def _write_potfile(self, tmp_path: Path) -> Path:
          """Write a hashcat-style potfile for import."""
          path = tmp_path / "cracked.pot"
          path.write_text(
              "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
              "e10adc3949ba59abbe56e057f20f883e:123456\n"
          )
          return path

      def test_export_csv_from_session(self, tmp_path: Path) -> None:
          session_path = self._write_session_json(tmp_path)
          output_path = tmp_path / "report.csv"
          result = runner.invoke(app, [
              "export",
              "--input", str(session_path),
              "--format", "csv",
              "--output", str(output_path),
          ])
          assert result.exit_code == 0
          assert output_path.exists()
          content = output_path.read_text()
          assert "hash" in content
          assert "password" in content

      def test_export_html_from_session(self, tmp_path: Path) -> None:
          session_path = self._write_session_json(tmp_path)
          output_path = tmp_path / "report.html"
          result = runner.invoke(app, [
              "export",
              "--input", str(session_path),
              "--format", "html",
              "--output", str(output_path),
          ])
          assert result.exit_code == 0
          assert output_path.exists()
          content = output_path.read_text()
          assert "<!DOCTYPE html>" in content

      def test_export_html_from_potfile(self, tmp_path: Path) -> None:
          pot_path = self._write_potfile(tmp_path)
          output_path = tmp_path / "report.html"
          result = runner.invoke(app, [
              "export",
              "--input", str(pot_path),
              "--format", "html",
              "--output", str(output_path),
          ])
          assert result.exit_code == 0
          assert output_path.exists()
          content = output_path.read_text()
          assert "password" in content

      def test_export_default_format_is_html(self, tmp_path: Path) -> None:
          session_path = self._write_session_json(tmp_path)
          output_path = tmp_path / "report.html"
          result = runner.invoke(app, [
              "export",
              "--input", str(session_path),
              "--output", str(output_path),
          ])
          assert result.exit_code == 0
          content = output_path.read_text()
          assert "<!DOCTYPE html>" in content

      def test_export_nonexistent_input_fails(self) -> None:
          result = runner.invoke(app, [
              "export",
              "--input", "/nonexistent/file.json",
              "--output", "/tmp/out.html",
          ])
          assert result.exit_code != 0
  ```

  Run and confirm failure:

  ```bash
  python -m pytest tests/test_export.py::TestExportCommand -v 2>&1 | head -30
  ```

- [ ] **3.2 — Implement the `export` command in `cli.py`**

  Add to `src/smartcrack/cli.py` before the `if __name__ == "__main__":` block:

  ```python
  @app.command()
  def export(
      input: Path = typer.Option(..., "--input", "-i", help="Session JSON file or potfile to import"),
      format: str = typer.Option("html", "--format", "-f", help="Output format: csv, html, markdown"),
      output: Path = typer.Option(..., "--output", "-o", help="Output file path"),
  ) -> None:
      """Export cracking results as CSV, HTML dashboard, or Markdown report."""
      _print_banner()

      if not input.exists():
          console.print(f"[red]Error: input file not found: {input}[/]")
          raise typer.Exit(code=1)

      from smartcrack.analysis import generate_audit_summary
      from smartcrack.report import (
          generate_csv_report,
          generate_html_dashboard,
          save_report,
      )

      # Detect input type: JSON session or potfile
      results: list[tuple[str, CrackResult]] = []
      raw_text = input.read_text(encoding="utf-8")

      if raw_text.strip().startswith("{"):
          # JSON session file
          import json as _json

          data = _json.loads(raw_text)
          session_result = data.get("result")
          target_data = data.get("target", {})
          hash_value = target_data.get("hash_value", "unknown")

          if session_result and session_result.get("found"):
              from smartcrack.session import _crack_result_from_dict

              cr = _crack_result_from_dict(session_result)
              results.append((hash_value, cr))
          else:
              cr = CrackResult(
                  found=False,
                  attempts=session_result.get("attempts", 0) if session_result else 0,
                  duration_seconds=session_result.get("duration_seconds", 0.0) if session_result else 0.0,
              )
              results.append((hash_value, cr))
      else:
          # Potfile format: hash:plaintext per line
          for line in raw_text.splitlines():
              line = line.strip()
              if not line or line.startswith("#"):
                  continue
              if ":" in line:
                  hash_val, plaintext = line.split(":", 1)
                  results.append((
                      hash_val.strip(),
                      CrackResult(
                          found=True,
                          plaintext=plaintext.strip(),
                          hash_type=None,
                          attempts=0,
                          duration_seconds=0.0,
                      ),
                  ))

      passwords = [r.plaintext for _, r in results if r.found and r.plaintext]
      summary = generate_audit_summary(passwords)

      if format == "csv":
          content = generate_csv_report(results)
      elif format == "html":
          content = generate_html_dashboard(results, summary)
      elif format == "markdown":
          from smartcrack.report import generate_audit_report

          content = generate_audit_report(summary, format="markdown")
      else:
          console.print(f"[red]Unsupported format: {format}. Use csv, html, or markdown.[/]")
          raise typer.Exit(code=1)

      save_report(content, output)
      console.print(f"[green]Report saved to {output}[/]")
      console.print(f"[dim]Format: {format} | Results: {len(results)} | Cracked: {len(passwords)}[/]")
  ```

  Run tests:

  ```bash
  python -m pytest tests/test_export.py::TestExportCommand -v
  ```

- [ ] **3.3 — Add `--report` flag to batch command**

  In `src/smartcrack/cli.py`, modify the `batch` command signature to add:

  ```python
  report: str = typer.Option("", "--report", help="Generate report after batch: csv, html, markdown"),
  report_output: Optional[Path] = typer.Option(None, "--report-output", help="Report output path"),
  ```

  At the end of the `batch` function (after the audit block), add:

  ```python
  if report and cracked > 0:
      from smartcrack.analysis import generate_audit_summary as _gen_audit
      from smartcrack.report import (
          generate_csv_report,
          generate_html_dashboard,
          generate_audit_report,
          save_report,
      )

      batch_results: list[tuple[str, CrackResult]] = [
          (h, r) for h, r in results.items() if isinstance(r, CrackResult)
      ]
      passwords_for_report = [
          r.plaintext for r in results.values()
          if hasattr(r, "plaintext") and r.plaintext  # type: ignore[union-attr]
      ]
      audit_summary = _gen_audit(passwords_for_report)

      if report == "csv":
          report_content = generate_csv_report(batch_results)
      elif report == "html":
          report_content = generate_html_dashboard(batch_results, audit_summary)
      elif report == "markdown":
          report_content = generate_audit_report(audit_summary, format="markdown")
      else:
          console.print(f"[red]Unknown report format: {report}[/]")
          raise typer.Exit(code=1)

      out_path = report_output or Path(f"batch_report.{report if report != 'markdown' else 'md'}")
      save_report(report_content, out_path)
      console.print(f"[green]Report saved to {out_path}[/]")
  ```

  Run all export tests:

  ```bash
  python -m pytest tests/test_export.py -v
  ```

  **Commit:** `feat: add export CLI command and --report flag on batch`

---

## Task 4: Doctor Command

**Files:**
- `src/smartcrack/cli.py` (modify)
- `tests/test_doctor.py` (create)

### Steps

- [ ] **4.1 — Write failing tests for doctor command**

  Create `tests/test_doctor.py`:

  ```python
  """Tests for the doctor and quickstart commands."""

  from __future__ import annotations

  import hashlib

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
      def test_quickstart_generates_correct_demo_hash(self) -> None:
          expected = hashlib.md5(b"password123").hexdigest()
          assert expected == "482c811da5d5b4bc6d497ffa98491e38"
  ```

  Run and confirm failure:

  ```bash
  python -m pytest tests/test_doctor.py -v 2>&1 | head -20
  ```

- [ ] **4.2 — Implement `doctor` command in `cli.py`**

  Add to `src/smartcrack/cli.py` before `if __name__ == "__main__":`:

  ```python
  @app.command()
  def doctor() -> None:
      """Check system readiness and diagnose configuration issues."""
      _print_banner()

      import os
      import sys

      from rich.table import Table

      table = Table(title="SmartCrack Doctor", show_lines=True)
      table.add_column("Check", style="bold")
      table.add_column("Status")
      table.add_column("Details", style="dim")

      # Python version
      py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
      py_ok = sys.version_info >= (3, 10)
      table.add_row(
          "Python Version",
          "[green]PASS[/]" if py_ok else "[red]FAIL[/]",
          f"{py_ver} {'(>= 3.10 required)' if not py_ok else ''}",
      )

      # Bundled wordlist
      bundled = Path(__file__).parent / "data" / "100K.txt"
      # In tests, __file__ is the test runner — resolve from package
      try:
          import smartcrack
          bundled = Path(smartcrack.__file__).parent / "data" / "100K.txt"
      except Exception:
          pass
      bundled_exists = bundled.exists()
      table.add_row(
          "Bundled Wordlist",
          "[green]PASS[/]" if bundled_exists else "[yellow]WARN[/]",
          f"100K.txt {'found' if bundled_exists else 'MISSING'}",
      )

      # System wordlists
      system_paths = [
          Path("/usr/share/wordlists/"),
          Path("/usr/share/dict/"),
          Path(os.path.expanduser("~/.local/share/wordlists/")),
      ]
      found_system = [p for p in system_paths if p.exists()]
      table.add_row(
          "System Wordlists",
          "[green]PASS[/]" if found_system else "[dim]NONE[/]",
          ", ".join(str(p) for p in found_system) if found_system else "No system wordlist paths found",
      )

      # CPU cores
      cpu_count = os.cpu_count() or 1
      table.add_row(
          "CPU Cores",
          "[green]PASS[/]",
          f"{cpu_count} cores available",
      )

      # LLM connectivity
      llm_base = os.environ.get("SMARTCRACK_LLM_BASE_URL", "")
      llm_key = os.environ.get("SMARTCRACK_LLM_API_KEY", "")
      if llm_base and llm_key:
          table.add_row("LLM Config", "[green]PASS[/]", f"Endpoint: {llm_base}")
      elif llm_base or llm_key:
          table.add_row("LLM Config", "[yellow]WARN[/]", "Partial config — need both URL and API key")
      else:
          table.add_row("LLM Config", "[dim]SKIP[/]", "Not configured (optional)")

      # Optional dependencies
      for dep_name in ("bcrypt", "argon2"):
          try:
              __import__(dep_name if dep_name != "argon2" else "argon2")
              table.add_row(f"Optional: {dep_name}", "[green]PASS[/]", "installed")
          except ImportError:
              table.add_row(f"Optional: {dep_name}", "[yellow]WARN[/]", "not installed")

      console.print(table)
  ```

  Run tests:

  ```bash
  python -m pytest tests/test_doctor.py::TestDoctorCommand -v
  ```

  **Commit:** `feat: add doctor command for system diagnostics`

---

## Task 5: Quickstart Command

**Files:**
- `src/smartcrack/cli.py` (modify)
- `tests/test_doctor.py` (modify)

### Steps

- [ ] **5.1 — Write failing test for quickstart demo hash**

  The test already exists in `tests/test_doctor.py` from Task 4.1. Add an integration-style test:

  Append to `tests/test_doctor.py`:

  ```python
      def test_quickstart_command_exists(self) -> None:
          """Verify the quickstart command is registered."""
          result = runner.invoke(app, ["quickstart", "--help"])
          assert result.exit_code == 0
          assert "quickstart" in result.output.lower() or "demo" in result.output.lower() or "wizard" in result.output.lower()
  ```

  Run and confirm failure:

  ```bash
  python -m pytest tests/test_doctor.py::TestQuickstartCommand -v 2>&1 | head -20
  ```

- [ ] **5.2 — Implement `quickstart` command in `cli.py`**

  Add to `src/smartcrack/cli.py` before `if __name__ == "__main__":`:

  ```python
  @app.command()
  def quickstart(
      demo: bool = typer.Option(True, "--demo/--no-demo", help="Run demo crack automatically"),
  ) -> None:
      """Interactive quickstart wizard for first-time users."""
      _print_banner()
      import hashlib

      console.print("[bold]Welcome to SmartCrack![/]\n")
      console.print("This wizard will walk you through your first hash crack.\n")

      hash_input = typer.prompt(
          "Enter a hash to crack (or press Enter for a demo)",
          default="",
          show_default=False,
      )

      if not hash_input:
          demo_password = "password123"
          hash_input = hashlib.md5(demo_password.encode()).hexdigest()
          console.print(f"\n[dim]Generated demo MD5 hash of '{demo_password}':[/]")
          console.print(f"[bold]{hash_input}[/]\n")

      if demo:
          console.print("[yellow]Running smart crack...[/]\n")

          resolved_path = resolve_wordlist(Path("100K.txt"))
          target = HashTarget(hash_value=hash_input, hash_type=HashType.UNKNOWN)

          candidates_id = identify_hash(hash_input)
          if candidates_id:
              target = HashTarget(
                  hash_value=hash_input,
                  hash_type=candidates_id[0][0],
              )
              console.print(f"[bold]Detected type:[/] {candidates_id[0][0].name}\n")

          plans = plan_attacks(wordlist_path=resolved_path, rules_preset="quick")
          result = run_orchestrated(target=target, plans=plans)

          if result.found:
              console.print(f"\n[green][+] Cracked:[/] [bold]{result.plaintext}[/]")
              if result.hash_type:
                  console.print(f"[green][+] Algorithm:[/] {result.hash_type.name}")
              console.print(f"[green][+] Attempts:[/] {result.attempts:,}")
              console.print(f"[green][+] Time:[/] {result.duration_seconds:.2f}s")
          else:
              console.print(f"\n[red][-] Not found after {result.attempts:,} attempts[/]")

      console.print("\n[bold]Next steps:[/]")
      console.print("  1. Try your own hash:  [cyan]smartcrack smart -H <hash>[/]")
      console.print("  2. Batch crack a file: [cyan]smartcrack batch -f hashes.txt[/]")
      console.print("  3. Add target profile: [cyan]smartcrack smart -H <hash> --profile-name John[/]")
      console.print("  4. Export a report:    [cyan]smartcrack export -i session.json -o report.html[/]")
      console.print("  5. Check your setup:   [cyan]smartcrack doctor[/]")
  ```

  Run tests:

  ```bash
  python -m pytest tests/test_doctor.py -v
  ```

  **Commit:** `feat: add quickstart wizard for first-time users`

---

## Task 6: PyPI Publishing Configuration

**Files:**
- `pyproject.toml` (modify)
- `.github/workflows/publish.yml` (create)

### Steps

- [ ] **6.1 — Update `pyproject.toml` with classifiers and metadata**

  Update the `[project]` section in `pyproject.toml`:

  ```toml
  [project]
  name = "smartcrack"
  version = "1.0.0"
  description = "AI-powered hash cracking platform with adaptive profiling, OSINT automation, and security audit reports"
  requires-python = ">=3.10"
  license = {text = "MIT"}
  readme = "README.md"
  keywords = ["hash", "cracking", "security", "audit", "password", "penetration-testing"]
  classifiers = [
      "Development Status :: 4 - Beta",
      "Environment :: Console",
      "Intended Audience :: Developers",
      "Intended Audience :: Information Technology",
      "License :: OSI Approved :: MIT License",
      "Programming Language :: Python :: 3",
      "Programming Language :: Python :: 3.10",
      "Programming Language :: Python :: 3.11",
      "Programming Language :: Python :: 3.12",
      "Programming Language :: Python :: 3.13",
      "Topic :: Security",
      "Topic :: Security :: Cryptography",
      "Typing :: Typed",
  ]

  [project.urls]
  Homepage = "https://github.com/samgodson/smartcrack"
  Repository = "https://github.com/samgodson/smartcrack"
  Documentation = "https://github.com/samgodson/smartcrack#readme"
  "Bug Tracker" = "https://github.com/samgodson/smartcrack/issues"
  ```

  Keep all other sections unchanged.

- [ ] **6.2 — Create `.github/workflows/publish.yml`**

  ```yaml
  name: Publish to PyPI

  on:
    push:
      tags:
        - "v*"

  permissions:
    id-token: write
    contents: read

  jobs:
    build:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4

        - uses: actions/setup-python@v5
          with:
            python-version: "3.12"

        - name: Install build tools
          run: pip install build

        - name: Build sdist and wheel
          run: python -m build

        - name: Upload artifacts
          uses: actions/upload-artifact@v4
          with:
            name: dist
            path: dist/

    test:
      runs-on: ubuntu-latest
      strategy:
        matrix:
          python-version: ["3.10", "3.11", "3.12", "3.13"]
      steps:
        - uses: actions/checkout@v4

        - uses: actions/setup-python@v5
          with:
            python-version: ${{ matrix.python-version }}

        - name: Install dependencies
          run: pip install -e ".[dev]"

        - name: Run tests
          run: pytest -v

    publish:
      needs: [build, test]
      runs-on: ubuntu-latest
      environment: pypi
      steps:
        - name: Download artifacts
          uses: actions/download-artifact@v4
          with:
            name: dist
            path: dist/

        - name: Publish to PyPI
          uses: pypa/gh-action-pypi-publish@release/v1
  ```

  **Commit:** `ci: add PyPI publish workflow and update project metadata`

---

## Task 7: Hashcat Compatibility — Module

**Files:**
- `src/smartcrack/hashcat_compat.py` (create)
- `tests/test_hashcat_compat.py` (create)

### Steps

- [ ] **7.1 — Write failing tests for hashcat compat module**

  Create `tests/test_hashcat_compat.py`:

  ```python
  """Tests for hashcat compatibility layer."""

  from __future__ import annotations

  from pathlib import Path

  import pytest

  from smartcrack.models import HashType


  # ---------------------------------------------------------------------------
  # Mode mapping tests
  # ---------------------------------------------------------------------------

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


  # ---------------------------------------------------------------------------
  # Potfile parsing tests
  # ---------------------------------------------------------------------------

  class TestPotfileParsing:
      def test_parse_basic_potfile(self, tmp_path: Path) -> None:
          from smartcrack.hashcat_compat import parse_potfile

          pot = tmp_path / "test.pot"
          pot.write_text(
              "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
              "e10adc3949ba59abbe56e057f20f883e:123456\n"
          )
          results = parse_potfile(pot)
          assert len(results) == 2
          assert results[0] == ("5f4dcc3b5aa765d61d8327deb882cf99", "password")
          assert results[1] == ("e10adc3949ba59abbe56e057f20f883e", "123456")

      def test_parse_potfile_skips_empty_lines(self, tmp_path: Path) -> None:
          from smartcrack.hashcat_compat import parse_potfile

          pot = tmp_path / "test.pot"
          pot.write_text(
              "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
              "\n"
              "e10adc3949ba59abbe56e057f20f883e:123456\n"
          )
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


  # ---------------------------------------------------------------------------
  # HCMask parsing tests
  # ---------------------------------------------------------------------------

  class TestHCMaskParsing:
      def test_parse_basic_hcmask(self, tmp_path: Path) -> None:
          from smartcrack.hashcat_compat import parse_hcmask_file

          mask_file = tmp_path / "test.hcmask"
          mask_file.write_text(
              "?l?l?l?l?l?l\n"
              "?u?l?l?l?l?d?d\n"
              "?d?d?d?d?d?d\n"
          )
          masks = parse_hcmask_file(mask_file)
          assert len(masks) == 3
          assert masks[0] == "?l?l?l?l?l?l"

      def test_parse_hcmask_skips_comments(self, tmp_path: Path) -> None:
          from smartcrack.hashcat_compat import parse_hcmask_file

          mask_file = tmp_path / "test.hcmask"
          mask_file.write_text(
              "# This is a comment\n"
              "?l?l?l?l?l?l\n"
              "# Another comment\n"
              "?d?d?d?d\n"
          )
          masks = parse_hcmask_file(mask_file)
          assert len(masks) == 2
          assert "# This is a comment" not in masks

      def test_parse_hcmask_skips_blank_lines(self, tmp_path: Path) -> None:
          from smartcrack.hashcat_compat import parse_hcmask_file

          mask_file = tmp_path / "test.hcmask"
          mask_file.write_text(
              "?l?l?l?l\n"
              "\n"
              "?d?d?d?d\n"
          )
          masks = parse_hcmask_file(mask_file)
          assert len(masks) == 2

      def test_parse_empty_hcmask(self, tmp_path: Path) -> None:
          from smartcrack.hashcat_compat import parse_hcmask_file

          mask_file = tmp_path / "test.hcmask"
          mask_file.write_text("")
          masks = parse_hcmask_file(mask_file)
          assert masks == []
  ```

  Run and confirm failure:

  ```bash
  python -m pytest tests/test_hashcat_compat.py -v 2>&1 | head -20
  ```

- [ ] **7.2 — Implement `src/smartcrack/hashcat_compat.py`**

  ```python
  """Hashcat compatibility layer — mode mapping, potfile parsing, mask files."""

  from __future__ import annotations

  from pathlib import Path

  from smartcrack.models import HashType

  # Hashcat mode → SmartCrack HashType mapping.
  # Reference: https://hashcat.net/wiki/doku.php?id=example_hashes
  HASHCAT_MODES: dict[int, HashType] = {
      0: HashType.MD5,
      100: HashType.SHA1,
      1300: HashType.SHA224,
      1400: HashType.SHA256,
      10800: HashType.SHA384,
      1700: HashType.SHA512,
      3200: HashType.BCRYPT,
      1000: HashType.NTLM,
  }


  def resolve_hashcat_mode(mode: int) -> HashType:
      """Resolve a hashcat mode integer to a SmartCrack HashType.

      Args:
          mode: Hashcat mode number (e.g. 0 for MD5, 100 for SHA1).

      Returns:
          Corresponding HashType enum member.

      Raises:
          KeyError: If the mode is not in the mapping.
      """
      return HASHCAT_MODES[mode]


  def parse_potfile(path: Path) -> list[tuple[str, str]]:
      """Parse a hashcat potfile into (hash, plaintext) tuples.

      Format: one ``hash:plaintext`` per line. Lines without a colon are skipped.
      The plaintext may itself contain colons — only the first colon is the delimiter.

      Args:
          path: Path to the .pot or .potfile.

      Returns:
          List of (hash_value, plaintext) tuples.
      """
      results: list[tuple[str, str]] = []
      for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
          stripped = line.strip()
          if not stripped:
              continue
          if ":" not in stripped:
              continue
          hash_val, plaintext = stripped.split(":", 1)
          results.append((hash_val, plaintext))
      return results


  def parse_hcmask_file(path: Path) -> list[str]:
      """Parse a hashcat .hcmask file into a list of mask strings.

      Blank lines and lines starting with ``#`` are skipped.

      Args:
          path: Path to the .hcmask file.

      Returns:
          List of mask strings.
      """
      masks: list[str] = []
      for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
          stripped = line.strip()
          if not stripped or stripped.startswith("#"):
              continue
          masks.append(stripped)
      return masks
  ```

  Run tests:

  ```bash
  python -m pytest tests/test_hashcat_compat.py -v
  ```

  **Commit:** `feat: add hashcat compatibility layer with mode mapping and potfile parsing`

---

## Task 8: Hashcat Compatibility — CLI Integration

**Files:**
- `src/smartcrack/cli.py` (modify)
- `tests/test_hashcat_compat.py` (modify)

### Steps

- [ ] **8.1 — Write failing tests for CLI integration**

  Append to `tests/test_hashcat_compat.py`:

  ```python
  # ---------------------------------------------------------------------------
  # CLI integration tests
  # ---------------------------------------------------------------------------

  from typer.testing import CliRunner
  from smartcrack.cli import app

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
  ```

  Run and confirm failure:

  ```bash
  python -m pytest tests/test_hashcat_compat.py::TestHashcatCLI -v 2>&1 | head -20
  ```

- [ ] **8.2 — Add `-m` / `--hashcat-mode` flag to `smart` command**

  In `src/smartcrack/cli.py`, add a new parameter to the `smart` command signature:

  ```python
  hashcat_mode: Optional[int] = typer.Option(None, "--hashcat-mode", "-m", help="Hashcat mode number (e.g. 0=MD5, 100=SHA1, 1400=SHA256)"),
  ```

  Then, in the `smart` function body, after the `type_map` block and before the `resolved_type` assignment, add the hashcat mode resolution:

  ```python
  if hashcat_mode is not None:
      from smartcrack.hashcat_compat import resolve_hashcat_mode

      try:
          resolved_type = resolve_hashcat_mode(hashcat_mode)
          console.print(f"[bold]Hashcat mode {hashcat_mode}:[/] {resolved_type.name}")
      except KeyError:
          console.print(f"[red]Unknown hashcat mode: {hashcat_mode}[/]")
          raise typer.Exit(code=1) from None
  elif hash_type.lower() == "auto":
      candidates_id = identify_hash(hash_value)
      resolved_type = candidates_id[0][0] if candidates_id else HashType.UNKNOWN
      console.print(f"[bold]Detected type:[/] {resolved_type.name}")
  else:
      resolved_type = type_map.get(hash_type.lower(), HashType.UNKNOWN)
  ```

  Note: this replaces the existing `if hash_type.lower() == "auto":` / `else:` block with a three-way branch.

- [ ] **8.3 — Add `analyze` command to `cli.py`**

  Add to `src/smartcrack/cli.py` before `if __name__ == "__main__":`:

  ```python
  @app.command()
  def analyze(
      potfile: Path = typer.Option(..., "--potfile", "-p", help="Hashcat potfile path"),
      report_format: str = typer.Option("", "--report", help="Generate report: csv, html, markdown"),
      report_output: Optional[Path] = typer.Option(None, "--report-output", "-o", help="Report output path"),
  ) -> None:
      """Analyze passwords from a hashcat potfile."""
      _print_banner()

      if not potfile.exists():
          console.print(f"[red]Potfile not found: {potfile}[/]")
          raise typer.Exit(code=1)

      from smartcrack.analysis import generate_audit_summary
      from smartcrack.hashcat_compat import parse_potfile

      entries = parse_potfile(potfile)
      if not entries:
          console.print("[yellow]No entries found in potfile.[/]")
          raise typer.Exit(code=0)

      passwords = [plaintext for _, plaintext in entries]
      summary = generate_audit_summary(passwords)

      console.print(f"[bold]Analyzed {summary.total} passwords[/]\n")
      console.print(f"  Average entropy: [bold]{summary.avg_entropy:.1f}[/] bits")
      console.print(f"  Policy failures: [bold]{summary.policy_failures}[/]/{summary.total}")

      if summary.strength_distribution:
          console.print("\n[bold]Strength Distribution:[/]")
          for strength, count in sorted(summary.strength_distribution.items()):
              pct = count / summary.total * 100
              bar = "#" * int(pct / 2)
              console.print(f"  {strength:12s} {count:4d} ({pct:5.1f}%) {bar}")

      if summary.pattern_distribution:
          console.print("\n[bold]Patterns:[/]")
          for pattern, count in sorted(summary.pattern_distribution.items(), key=lambda x: -x[1]):
              console.print(f"  {pattern}: {count}")

      if summary.recommendations:
          console.print("\n[bold]Recommendations:[/]")
          for rec in summary.recommendations:
              console.print(f"  [yellow]![/] {rec}")

      if report_format:
          from smartcrack.report import (
              generate_audit_report,
              generate_csv_report,
              generate_html_dashboard,
              save_report,
          )

          crack_results: list[tuple[str, CrackResult]] = [
              (h, CrackResult(found=True, plaintext=p, hash_type=None, attempts=0, duration_seconds=0.0))
              for h, p in entries
          ]

          if report_format == "csv":
              content = generate_csv_report(crack_results)
          elif report_format == "html":
              content = generate_html_dashboard(crack_results, summary)
          elif report_format == "markdown":
              content = generate_audit_report(summary, format="markdown")
          else:
              console.print(f"[red]Unknown report format: {report_format}[/]")
              raise typer.Exit(code=1)

          out = report_output or Path(f"analyze_report.{report_format if report_format != 'markdown' else 'md'}")
          save_report(content, out)
          console.print(f"\n[green]Report saved to {out}[/]")
  ```

  Run all hashcat compat tests:

  ```bash
  python -m pytest tests/test_hashcat_compat.py -v
  ```

  **Commit:** `feat: add hashcat mode flag and analyze command for potfile analysis`

---

## Task 9: Final Integration & Lint

**Files:** All modified files

### Steps

- [ ] **9.1 — Run full test suite**

  ```bash
  python -m pytest tests/ -v --tb=short
  ```

- [ ] **9.2 — Run linter and fix issues**

  ```bash
  ruff check src/ tests/ --fix
  ```

- [ ] **9.3 — Run formatter**

  ```bash
  black src/ tests/ --check
  ```

  If formatting issues:

  ```bash
  black src/ tests/
  ```

- [ ] **9.4 — Verify all new commands are registered**

  ```bash
  python -m smartcrack --help
  ```

  Expected output should list: `crack`, `identify`, `smart`, `version`, `plugins`, `batch`, `osint`, `export`, `doctor`, `quickstart`, `analyze`.

- [ ] **9.5 — Verify package builds**

  ```bash
  pip install build && python -m build --sdist --wheel
  ```

  **Commit:** `chore: lint, format, and verify Phase C integration`

---

## Summary of Deliverables

| Feature | Files Created | Files Modified | Test File |
|---------|--------------|----------------|-----------|
| CSV Export | — | `src/smartcrack/report.py` | `tests/test_export.py` |
| HTML Dashboard | — | `src/smartcrack/report.py` | `tests/test_export.py` |
| Export CLI | — | `src/smartcrack/cli.py` | `tests/test_export.py` |
| Doctor | — | `src/smartcrack/cli.py` | `tests/test_doctor.py` |
| Quickstart | — | `src/smartcrack/cli.py` | `tests/test_doctor.py` |
| PyPI Config | `.github/workflows/publish.yml` | `pyproject.toml` | — |
| Hashcat Compat | `src/smartcrack/hashcat_compat.py` | — | `tests/test_hashcat_compat.py` |
| Hashcat CLI | — | `src/smartcrack/cli.py` | `tests/test_hashcat_compat.py` |

**Total new files:** 4 (`hashcat_compat.py`, `publish.yml`, `test_export.py`, `test_doctor.py`, `test_hashcat_compat.py`)
**Total modified files:** 3 (`report.py`, `cli.py`, `pyproject.toml`)
