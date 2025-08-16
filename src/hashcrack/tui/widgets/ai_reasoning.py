"""Widget that displays AI chain-of-thought reasoning in real-time."""
from textual.widgets import Static, RichLog
from textual.containers import Vertical


class AIReasoningWidget(Vertical):
    """Shows AI reasoning from adaptive profiling rounds."""

    DEFAULT_CSS = """
    AIReasoningWidget {
        height: auto;
        max-height: 12;
        border: solid $accent;
        padding: 1;
    }
    """

    def compose(self):
        yield Static("[bold]AI Reasoning[/bold]", id="ai-title")
        yield RichLog(id="ai-log", max_lines=50, wrap=True)

    def add_round(self, round_num: int, reasoning: str, candidate_count: int) -> None:
        log = self.query_one("#ai-log", RichLog)
        log.write(f"[bold cyan]Round {round_num + 1}:[/bold cyan] {reasoning[:200]}")
        log.write(f"  Generated {candidate_count} candidates")

    def clear_rounds(self) -> None:
        log = self.query_one("#ai-log", RichLog)
        log.clear()
