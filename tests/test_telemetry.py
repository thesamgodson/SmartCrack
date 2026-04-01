"""Tests for CrackTelemetry rolling-window speed tracker."""

from __future__ import annotations

import time


from smartcrack.telemetry import CrackTelemetry


class TestHashesPerSecond:
    """Test hashes_per_second rolling average calculation."""

    def test_no_updates_returns_zero(self) -> None:
        tel = CrackTelemetry()
        assert tel.hashes_per_second == 0.0

    def test_single_update_calculates_speed(self) -> None:
        tel = CrackTelemetry(window_seconds=5.0)
        tel._samples.append((time.monotonic(), 500))
        tel._total_attempts = 500
        assert tel.hashes_per_second >= 0.0

    def test_rolling_average_over_window(self) -> None:
        tel = CrackTelemetry(window_seconds=5.0)
        base = time.monotonic()
        tel._samples = [
            (base + 1.0, 100),
            (base + 2.0, 200),
            (base + 3.0, 300),
            (base + 4.0, 400),
            (base + 5.0, 500),
        ]
        tel._total_attempts = 500
        speed = tel.hashes_per_second
        assert 50.0 <= speed <= 200.0


class TestEtaSeconds:
    """Test ETA calculation."""

    def test_no_speed_returns_none(self) -> None:
        tel = CrackTelemetry()
        assert tel.eta_seconds(total_candidates=1000) is None

    def test_none_total_returns_none(self) -> None:
        tel = CrackTelemetry()
        assert tel.eta_seconds(total_candidates=None) is None

    def test_all_done_returns_zero(self) -> None:
        tel = CrackTelemetry()
        base = time.monotonic()
        tel._samples = [(base, 1000)]
        tel._total_attempts = 1000
        eta = tel.eta_seconds(total_candidates=1000)
        assert eta is None or eta == 0.0

    def test_eta_positive_when_work_remaining(self) -> None:
        tel = CrackTelemetry(window_seconds=5.0)
        base = time.monotonic()
        tel._samples = [
            (base - 2.0, 100),
            (base - 1.0, 200),
            (base, 300),
        ]
        tel._total_attempts = 300
        eta = tel.eta_seconds(total_candidates=1000)
        assert eta is not None
        assert eta > 0.0


class TestRollingWindow:
    """Test that old entries are discarded."""

    def test_old_entries_pruned(self) -> None:
        tel = CrackTelemetry(window_seconds=2.0)
        base = time.monotonic()
        tel._samples = [
            (base - 10.0, 100),
            (base - 9.0, 200),
            (base - 0.5, 300),
            (base, 400),
        ]
        tel._total_attempts = 400
        _ = tel.hashes_per_second
        assert len(tel._samples) == 2


class TestZeroDivisionSafety:
    """Test that zero-division is handled gracefully."""

    def test_single_sample_no_crash(self) -> None:
        tel = CrackTelemetry()
        base = time.monotonic()
        tel._samples = [(base, 0)]
        tel._total_attempts = 0
        assert tel.hashes_per_second == 0.0

    def test_identical_timestamps_no_crash(self) -> None:
        tel = CrackTelemetry()
        ts = time.monotonic()
        tel._samples = [(ts, 100), (ts, 200)]
        tel._total_attempts = 200
        speed = tel.hashes_per_second
        assert speed >= 0.0


class TestElapsedSeconds:
    """Test elapsed time tracking."""

    def test_elapsed_positive(self) -> None:
        tel = CrackTelemetry()
        assert tel.elapsed_seconds >= 0.0


class TestTotalAttempts:
    """Test total attempt counting."""

    def test_initial_zero(self) -> None:
        tel = CrackTelemetry()
        assert tel.total_attempts == 0

    def test_update_increments(self) -> None:
        tel = CrackTelemetry()
        tel.update(50)
        tel.update(75)
        assert tel.total_attempts == 125


class TestUpdate:
    """Test the update method."""

    def test_update_adds_sample(self) -> None:
        tel = CrackTelemetry()
        tel.update(100)
        assert len(tel._samples) == 1
        assert tel._total_attempts == 100

    def test_multiple_updates_accumulate(self) -> None:
        tel = CrackTelemetry()
        tel.update(100)
        tel.update(200)
        assert tel._total_attempts == 300
        assert len(tel._samples) == 2
