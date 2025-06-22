"""Result widget — shown when cracking completes."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Static

from hashcrack.models import CrackResult


class ResultWidget(Static):
    """Displays the final crack result; hidden until cracking completes."""

    DEFAULT_CSS = """
    ResultWidget {
        border: solid $primary;
        border-title-color: $primary;
        padding: 0 1;
        height: 3;
        display: none;
    }
    ResultWidget.cracked {
        border: solid green;
        border-title-color: green;
    }
    ResultWidget.not-found {
        border: solid red;
        border-title-color: red;
    }
    #result-label {
        height: 1;
        content-align: center middle;
        text-align: center;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.border_title = "Result"

    def on_mount(self) -> None:
        """Hide the widget after mount — inline style survives CSS cascade."""
        self.display = False

    def compose(self) -> ComposeResult:
        yield Static("", id="result-label")

    def show_result(self, result: CrackResult) -> None:
        """Reveal the widget and populate it with the crack result."""
        self.display = True
        label = self.query_one("#result-label", Static)

        if result.found:
            self.add_class("cracked")
            hash_name = result.hash_type.name if result.hash_type else "?"
            duration = f"{result.duration_seconds:.1f}s"
            tries = f"{result.attempts / 1_000_000:.1f}M" if result.attempts >= 1_000_000 else f"{result.attempts:,}"
            label.update(
                f"[bold green]CRACKED:[/bold green] [bold white]{result.plaintext}[/bold white]"
                f"  [dim]({hash_name}, {duration}, {tries} tries)[/dim]"
            )
        else:
            self.add_class("not-found")
            duration = f"{result.duration_seconds:.1f}s"
            label.update(
                f"[bold red]NOT FOUND[/bold red]"
                f"  [dim]({result.attempts:,} tries, {duration})[/dim]"
            )
