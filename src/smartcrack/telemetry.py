"""Live telemetry — rolling-window speed, ETA, and attempt tracking."""

from __future__ import annotations

import time


class CrackTelemetry:
    """Tracks cracking speed using a rolling time window of (timestamp, cumulative_count) samples.

    Thread-safe for single-writer / multiple-reader usage (the on_progress callback
    is the only writer; UI reads properties from the main thread).
    """

    def __init__(self, window_seconds: float = 5.0) -> None:
        self._window_seconds = window_seconds
        self._samples: list[tuple[float, int]] = []
        self._total_attempts: int = 0
        self._start_time: float = time.monotonic()

    def update(self, n: int) -> None:
        """Record *n* new hash attempts. Called from the progress callback."""
        self._total_attempts += n
        self._samples.append((time.monotonic(), self._total_attempts))

    @property
    def total_attempts(self) -> int:
        """Total hashes tested since creation."""
        return self._total_attempts

    @property
    def elapsed_seconds(self) -> float:
        """Wall-clock seconds since this tracker was created."""
        return time.monotonic() - self._start_time

    @property
    def hashes_per_second(self) -> float:
        """Rolling average hash rate over the last *window_seconds*."""
        self._prune()
        if len(self._samples) < 2:
            return 0.0
        first_ts, first_count = self._samples[0]
        last_ts, last_count = self._samples[-1]
        dt = last_ts - first_ts
        if dt <= 0:
            return 0.0
        return (last_count - first_count) / dt

    def eta_seconds(self, total_candidates: int | None) -> float | None:
        """Estimated seconds remaining, or None if unknown."""
        if total_candidates is None:
            return None
        speed = self.hashes_per_second
        if speed <= 0:
            return None
        remaining = total_candidates - self._total_attempts
        if remaining <= 0:
            return 0.0
        return remaining / speed

    def _prune(self) -> None:
        """Discard samples older than the rolling window."""
        cutoff = time.monotonic() - self._window_seconds
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.pop(0)
