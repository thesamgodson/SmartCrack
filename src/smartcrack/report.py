"""Report generation for SmartCrack sessions."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from smartcrack.analysis import AuditSummary, analyze_password
from smartcrack.models import CrackResult, CrackSession


_CSV_COLUMNS = ["hash", "plaintext", "algorithm", "attempts", "duration", "entropy", "strength", "patterns"]


def generate_csv_report(results: list[tuple[str, CrackResult]]) -> str:
    """Generate a CSV report from a list of (hash, CrackResult) pairs."""
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
                hash_value, "", "", result.attempts,
                f"{result.duration_seconds:.2f}", "", "", "",
            ])
    return buf.getvalue()


def generate_html_dashboard(results: list[tuple[str, CrackResult]], summary: AuditSummary) -> str:
    """Generate a standalone HTML dashboard with charts and sortable table."""
    # Build analysis data for cracked passwords
    analyses = []
    for hash_value, result in results:
        if result.found and result.plaintext is not None:
            analysis = analyze_password(result.plaintext)
            analyses.append((hash_value, result, analysis))
        else:
            analyses.append((hash_value, result, None))

    # Strength pie chart data
    strength_labels = list(summary.strength_distribution.keys())
    strength_values = list(summary.strength_distribution.values())

    # Entropy bar chart data
    entropy_labels = []
    entropy_values = []
    for hash_value, result, analysis in analyses:
        if analysis is not None:
            label = hash_value[:12] + "..."
            entropy_labels.append(label)
            entropy_values.append(round(analysis.entropy, 1))

    # Results table rows
    table_rows = ""
    for hash_value, result, analysis in analyses:
        if analysis is not None:
            table_rows += (
                f"<tr>"
                f"<td>{hash_value}</td>"
                f"<td>{result.plaintext}</td>"
                f"<td>{result.hash_type.name if result.hash_type else ''}</td>"
                f"<td>{result.attempts}</td>"
                f"<td>{result.duration_seconds:.2f}s</td>"
                f"<td>{analysis.entropy:.1f}</td>"
                f"<td>{analysis.strength}</td>"
                f"<td>{'; '.join(analysis.patterns)}</td>"
                f"</tr>\n"
            )
        else:
            table_rows += (
                f"<tr>"
                f"<td>{hash_value}</td>"
                f"<td>-</td><td>-</td>"
                f"<td>{result.attempts}</td>"
                f"<td>{result.duration_seconds:.2f}s</td>"
                f"<td>-</td><td>-</td><td>-</td>"
                f"</tr>\n"
            )

    # Recommendations section
    recs_html = ""
    if summary.recommendations:
        recs_html = "<h2>Recommendations</h2><ul>\n"
        for rec in summary.recommendations:
            recs_html += f"  <li>{rec}</li>\n"
        recs_html += "</ul>"

    version = __import__("smartcrack").__version__

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SmartCrack Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1200px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; background: #fafafa; }}
  h1 {{ color: #16213e; border-bottom: 2px solid #0f3460; padding-bottom: 0.5rem; }}
  h2 {{ color: #0f3460; margin-top: 2rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin: 1rem 0; }}
  .stat {{ background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
  .stat-value {{ font-size: 2rem; font-weight: bold; color: #0f3460; }}
  .stat-label {{ color: #666; font-size: 0.875rem; }}
  .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 2rem 0; }}
  .chart-container {{ background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid #ddd; }}
  th {{ background: #16213e; color: white; cursor: pointer; }}
  th:hover {{ background: #1a2a4e; }}
  ul {{ line-height: 1.8; }}
</style>
</head>
<body>
<h1>SmartCrack Dashboard</h1>

<h2>Executive Summary</h2>
<div class="summary">
  <div class="stat"><div class="stat-value">{summary.total}</div><div class="stat-label">Passwords Analyzed</div></div>
  <div class="stat"><div class="stat-value">{summary.avg_entropy:.1f}</div><div class="stat-label">Avg Entropy (bits)</div></div>
  <div class="stat"><div class="stat-value">{summary.policy_failures}</div><div class="stat-label">Policy Failures</div></div>
</div>

<div class="charts">
  <div class="chart-container"><canvas id="strengthChart"></canvas></div>
  <div class="chart-container"><canvas id="entropyChart"></canvas></div>
</div>

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
{table_rows}</tbody>
</table>

{recs_html}

<script>
new Chart(document.getElementById('strengthChart'), {{
  type: 'pie',
  data: {{
    labels: {strength_labels},
    datasets: [{{ data: {strength_values}, backgroundColor: ['#e74c3c','#f39c12','#2ecc71','#3498db'] }}]
  }},
  options: {{ plugins: {{ title: {{ display: true, text: 'Strength Distribution' }} }} }}
}});

new Chart(document.getElementById('entropyChart'), {{
  type: 'bar',
  data: {{
    labels: {entropy_labels},
    datasets: [{{ label: 'Entropy (bits)', data: {entropy_values}, backgroundColor: '#0f3460' }}]
  }},
  options: {{ plugins: {{ title: {{ display: true, text: 'Password Entropy' }} }} }}
}});

function sortTable(col) {{
  var table = document.getElementById('resultsTable');
  var rows = Array.from(table.tBodies[0].rows);
  var asc = table.dataset.sortCol == col && table.dataset.sortAsc !== 'true';
  rows.sort(function(a, b) {{
    var aText = a.cells[col].textContent;
    var bText = b.cells[col].textContent;
    var aNum = parseFloat(aText);
    var bNum = parseFloat(bText);
    if (!isNaN(aNum) && !isNaN(bNum)) return asc ? aNum - bNum : bNum - aNum;
    return asc ? aText.localeCompare(bText) : bText.localeCompare(aText);
  }});
  rows.forEach(function(row) {{ table.tBodies[0].appendChild(row); }});
  table.dataset.sortCol = col;
  table.dataset.sortAsc = asc;
}}
</script>

<footer style="margin-top:2rem;padding-top:1rem;border-top:1px solid #ddd;color:#999;font-size:0.8rem;">
Generated by SmartCrack v{version}
</footer>
</body>
</html>"""


def _build_report_dict(session: CrackSession) -> dict[str, Any]:
    target = session.target
    result = session.result

    target_section: dict[str, Any] = {
        "hash": target.hash_value,
        "type": target.hash_type.name,
        "salt": target.salt or None,
    }

    result_section: dict[str, Any]
    if result is not None:
        result_section = {
            "status": "Cracked" if result.found else "Not Found",
            "plaintext": result.plaintext,
            "algorithm": result.hash_type.name if result.hash_type is not None else None,
            "attempts": result.attempts,
            "duration_seconds": result.duration_seconds,
        }
    else:
        result_section = {
            "status": "Not Found",
            "plaintext": None,
            "algorithm": None,
            "attempts": 0,
            "duration_seconds": 0.0,
        }

    summary_section: dict[str, Any] = {
        "phases_completed": list(session.phases_completed),
        "total_candidates": session.candidates_tried,
    }

    return {
        "session_id": session.session_id,
        "target": target_section,
        "result": result_section,
        "attack_summary": summary_section,
    }


def _render_markdown(report: dict[str, Any]) -> str:
    target = report["target"]
    result = report["result"]
    summary = report["attack_summary"]

    phases = summary["phases_completed"]
    phases_str = ", ".join(phases) if phases else "none"

    salt_display = target["salt"] if target["salt"] else "none"
    plaintext_display = result["plaintext"] if result["plaintext"] is not None else "N/A"
    algorithm_display = result["algorithm"] if result["algorithm"] is not None else "N/A"

    lines = [
        "# SmartCrack Report",
        "",
        "## Target",
        f"- Hash: {target['hash']}",
        f"- Type: {target['type']}",
        f"- Salt: {salt_display}",
        "",
        "## Result",
        f"- Status: {result['status']}",
        f"- Plaintext: {plaintext_display}",
        f"- Algorithm: {algorithm_display}",
        f"- Attempts: {result['attempts']}",
        f"- Duration: {result['duration_seconds']}s",
        "",
        "## Attack Summary",
        f"- Phases completed: {phases_str}",
        f"- Total candidates: {summary['total_candidates']}",
    ]
    return "\n".join(lines)


def generate_report(session: CrackSession, format: str = "markdown") -> str:
    """Generate a report from a CrackSession in the requested format.

    Args:
        session: The completed or in-progress crack session.
        format: Output format — "markdown" or "json".

    Returns:
        Rendered report as a string.

    Raises:
        ValueError: If an unsupported format is requested.
    """
    report = _build_report_dict(session)

    if format == "markdown":
        return _render_markdown(report)
    if format == "json":
        return json.dumps(report, indent=2)

    raise ValueError(f"Unsupported report format: {format!r}. Use 'markdown' or 'json'.")


def generate_audit_report(summary: Any, format: str = "markdown") -> str:
    """Generate a security audit report from an AuditSummary.

    Args:
        summary: An AuditSummary from the analysis module.
        format: Output format — "markdown" or "html".

    Returns:
        Rendered audit report as a string.
    """
    if format == "markdown":
        return _render_audit_markdown(summary)
    if format == "html":
        return _render_audit_html(summary)
    raise ValueError(f"Unsupported format: {format!r}. Use 'markdown' or 'html'.")


def _render_audit_markdown(summary: Any) -> str:
    """Render audit summary as Markdown."""
    lines = [
        "# Security Audit Report",
        "",
        "## Executive Summary",
        f"- **Total passwords analyzed:** {summary.total}",
        f"- **Average entropy:** {summary.avg_entropy:.1f} bits",
        f"- **Policy failures:** {summary.policy_failures}/{summary.total}",
        "",
        "## Strength Distribution",
    ]
    for strength, count in sorted(summary.strength_distribution.items()):
        pct = count / summary.total * 100 if summary.total else 0
        bar = "#" * int(pct / 2)
        lines.append(f"- **{strength}:** {count} ({pct:.0f}%) {bar}")

    lines.extend(["", "## Pattern Analysis"])
    for pattern, count in sorted(
        summary.pattern_distribution.items(), key=lambda x: -x[1]
    ):
        lines.append(f"- {pattern}: {count}")

    if summary.weakest_passwords:
        lines.extend(["", "## Weakest Passwords"])
        for pw in summary.weakest_passwords[:5]:
            masked = pw[:2] + "*" * (len(pw) - 2) if len(pw) > 2 else "**"
            lines.append(f"- `{masked}`")

    if summary.recommendations:
        lines.extend(["", "## Recommendations"])
        for rec in summary.recommendations:
            lines.append(f"- {rec}")

    return "\n".join(lines)


def _render_audit_html(summary: Any) -> str:
    """Render audit summary as standalone HTML."""
    strength_rows = ""
    for strength, count in sorted(summary.strength_distribution.items()):
        pct = count / summary.total * 100 if summary.total else 0
        strength_rows += f"<tr><td>{strength}</td><td>{count}</td><td>{pct:.0f}%</td></tr>\n"

    pattern_rows = ""
    for pattern, count in sorted(
        summary.pattern_distribution.items(), key=lambda x: -x[1]
    ):
        pattern_rows += f"<tr><td>{pattern}</td><td>{count}</td></tr>\n"

    recs_html = ""
    if summary.recommendations:
        recs_html = "<h2>Recommendations</h2><ul>"
        for rec in summary.recommendations:
            recs_html += f"<li>{rec}</li>"
        recs_html += "</ul>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; background: #fafafa; }}
  h1 {{ color: #16213e; border-bottom: 2px solid #0f3460; padding-bottom: 0.5rem; }}
  h2 {{ color: #0f3460; margin-top: 2rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid #ddd; }}
  th {{ background: #16213e; color: white; }}
  .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin: 1rem 0; }}
  .stat {{ background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
  .stat-value {{ font-size: 2rem; font-weight: bold; color: #0f3460; }}
  .stat-label {{ color: #666; font-size: 0.875rem; }}
  ul {{ line-height: 1.8; }}
</style>
</head>
<body>
<h1>Security Audit Report</h1>
<div class="summary">
  <div class="stat"><div class="stat-value">{summary.total}</div><div class="stat-label">Passwords Analyzed</div></div>
  <div class="stat"><div class="stat-value">{summary.avg_entropy:.1f}</div><div class="stat-label">Avg Entropy (bits)</div></div>
  <div class="stat"><div class="stat-value">{summary.policy_failures}</div><div class="stat-label">Policy Failures</div></div>
</div>
<h2>Strength Distribution</h2>
<table><tr><th>Strength</th><th>Count</th><th>Percentage</th></tr>
{strength_rows}</table>
<h2>Pattern Analysis</h2>
<table><tr><th>Pattern</th><th>Count</th></tr>
{pattern_rows}</table>
{recs_html}
<footer style="margin-top:2rem;padding-top:1rem;border-top:1px solid #ddd;color:#999;font-size:0.8rem;">
Generated by SmartCrack Security Audit
</footer>
</body>
</html>"""


def save_report(content: str, path: Path) -> None:
    """Write report content to the given path."""
    path.write_text(content, encoding="utf-8")
