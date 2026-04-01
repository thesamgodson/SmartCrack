"""Forensic result card — Rich Panel with autopsy-style cracking report."""

from __future__ import annotations

from typing import Sequence

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from smartcrack.analysis import analyze_password
from smartcrack.models import CrackResult

_ENTROPY_BAR_WIDTH = 20
_ENTROPY_MAX = 80.0

def _strength_style(strength: str) -> str:
    """Map a strength rating to a Rich style string."""
    styles = {
        "weak": "bold red",
        "moderate": "bold yellow",
        "strong": "bold green",
        "very_strong": "bold cyan",
    }
    return styles.get(strength, "bold white")


def _entropy_bar(entropy: float, strength: str) -> str:
    """Build a colored entropy bar string like [████████░░░░░░░░░░░░] 35.2 bits.

    Returns a Rich markup string.
    """
    ratio = min(entropy / _ENTROPY_MAX, 1.0)
    filled = int(ratio * _ENTROPY_BAR_WIDTH)
    empty = _ENTROPY_BAR_WIDTH - filled

    color_map = {
        "weak": "red",
        "moderate": "yellow",
        "strong": "green",
        "very_strong": "cyan",
    }
    color = color_map.get(strength, "white")

    filled_str = "█" * filled
    empty_str = "░" * empty
    return f"[{color}]{filled_str}[/{color}][dim]{empty_str}[/dim] {entropy:.1f} bits"


def render_result_card(
    result: CrackResult,
) -> Panel:
    """Build a Rich Panel 'autopsy card' for a cracking result."""
    sections: list[Table | Text] = []

    result_table = Table(show_header=False, show_edge=False, box=None, padding=(0, 2))
    result_table.add_column("label", style="bold", width=14)
    result_table.add_column("value")

    if result.found and result.plaintext:
        result_table.add_row("Plaintext", f"[bold green]{result.plaintext}[/bold green]")
    else:
        result_table.add_row("Plaintext", "[dim]Not found[/dim]")

    algorithm = result.hash_type.name if result.hash_type else "Unknown"
    result_table.add_row("Algorithm", algorithm)

    phase = result.attack_phase.value if result.attack_phase else "—"
    result_table.add_row("Phase", phase)

    result_table.add_row("Attempts", f"{result.attempts:,}")
    result_table.add_row("Time", f"{result.duration_seconds:.2f}s")

    sections.append(Text("─── RESULT ───", style="bold cyan"))
    sections.append(result_table)

    if result.found and result.plaintext:
        analysis = analyze_password(result.plaintext)

        forensic_table = Table(show_header=False, show_edge=False, box=None, padding=(0, 2))
        forensic_table.add_column("label", style="bold", width=14)
        forensic_table.add_column("value")

        entropy_bar = _entropy_bar(analysis.entropy, analysis.strength)
        forensic_table.add_row("Entropy", entropy_bar)

        strength_display = f"[{_strength_style(analysis.strength)}]{analysis.strength.upper()}[/{_strength_style(analysis.strength)}]"
        forensic_table.add_row("Strength", strength_display)

        forensic_table.add_row("Length", str(analysis.length))
        forensic_table.add_row("Charset Size", str(analysis.charset_size))

        if analysis.patterns:
            patterns_str = ", ".join(analysis.patterns)
            forensic_table.add_row("Patterns", f"[yellow]{patterns_str}[/yellow]")
        else:
            forensic_table.add_row("Patterns", "[dim]None detected[/dim]")

        sections.append(Text(""))
        sections.append(Text("─── FORENSIC ANALYSIS ───", style="bold cyan"))
        sections.append(forensic_table)

    from rich.console import Group

    panel_title = "[bold green]CRACKED[/bold green]" if result.found else "[bold red]NOT FOUND[/bold red]"

    return Panel(
        Group(*sections),
        title=f"🔓 {panel_title}",
        subtitle="[dim]SmartCrack Forensic Report[/dim]",
        border_style="green" if result.found else "red",
        padding=(1, 2),
    )


def render_batch_summary_table(
    hashes: Sequence[str],
    results: Sequence[CrackResult],
) -> Table:
    """Build a Rich Table summarizing batch cracking results with color-coded strength."""
    table = Table(title="Batch Summary", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Hash", max_width=20)
    table.add_column("Status", width=10)
    table.add_column("Plaintext", max_width=20)
    table.add_column("Strength", width=14)
    table.add_column("Attempts", justify="right", width=12)
    table.add_column("Time", justify="right", width=8)

    for i, (hash_val, result) in enumerate(zip(hashes, results), 1):
        hash_display = hash_val[:16] + "…" if len(hash_val) > 16 else hash_val

        if result.found and result.plaintext:
            status = "[green]CRACKED[/green]"
            plaintext = result.plaintext
            analysis = analyze_password(result.plaintext)
            style = _strength_style(analysis.strength)
            strength = f"[{style}]{analysis.strength.upper()}[/{style}]"
        else:
            status = "[red]FAILED[/red]"
            plaintext = "—"
            strength = "—"

        table.add_row(
            str(i),
            hash_display,
            status,
            plaintext,
            strength,
            f"{result.attempts:,}",
            f"{result.duration_seconds:.2f}s",
        )

    return table
