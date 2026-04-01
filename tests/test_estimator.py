"""Tests for the crack time estimator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from smartcrack.estimator import (
    HASH_SPEEDS,
    CrackEstimate,
    check_hibp,
    estimate_crack,
)
from smartcrack.models import HashTarget, HashType


@pytest.mark.unit
class TestHashSpeeds:
    def test_md5_speed_is_defined(self) -> None:
        assert HashType.MD5 in HASH_SPEEDS
        assert HASH_SPEEDS[HashType.MD5] > 0

    def test_sha256_speed_is_defined(self) -> None:
        assert HashType.SHA256 in HASH_SPEEDS
        assert HASH_SPEEDS[HashType.SHA256] > 0

    def test_bcrypt_speed_is_slow(self) -> None:
        assert HASH_SPEEDS[HashType.BCRYPT] < 1000

    def test_md5_faster_than_bcrypt(self) -> None:
        assert HASH_SPEEDS[HashType.MD5] > HASH_SPEEDS[HashType.BCRYPT]

    def test_all_known_types_have_speeds(self) -> None:
        for ht in HashType:
            if ht != HashType.UNKNOWN:
                assert ht in HASH_SPEEDS, f"Missing speed for {ht.name}"


@pytest.mark.unit
class TestCrackEstimate:
    def test_is_frozen(self) -> None:
        est = CrackEstimate(
            hash_type=HashType.MD5,
            wordlist_size=100_000,
            dictionary_probability=0.15,
            dictionary_eta=0.02,
            rules_probability=0.35,
            rules_eta=0.44,
            mask_eta=None,
            hibp_seen_count=None,
            recommendation="Use a stronger password.",
        )
        with pytest.raises(AttributeError):
            est.hash_type = HashType.SHA1  # type: ignore[misc]

    def test_fields_accessible(self) -> None:
        est = CrackEstimate(
            hash_type=HashType.SHA256,
            wordlist_size=50_000,
            dictionary_probability=0.10,
            dictionary_eta=0.025,
            rules_probability=0.25,
            rules_eta=0.275,
            mask_eta=120.0,
            hibp_seen_count=42,
            recommendation="Good.",
        )
        assert est.hash_type == HashType.SHA256
        assert est.wordlist_size == 50_000
        assert est.hibp_seen_count == 42
        assert est.mask_eta == 120.0


@pytest.mark.unit
class TestEstimateCrack:
    @pytest.fixture
    def wordlist_50k(self, tmp_path: Path) -> Path:
        wl = tmp_path / "50k.txt"
        wl.write_text("\n".join(f"word{i}" for i in range(50_000)) + "\n")
        return wl

    def test_returns_crack_estimate(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="d8578edf8458ce06fbc5bb76a58c5ca4", hash_type=HashType.MD5)
        est = estimate_crack(target, wordlist_50k)
        assert isinstance(est, CrackEstimate)

    def test_wordlist_size_matches(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc123", hash_type=HashType.MD5)
        est = estimate_crack(target, wordlist_50k)
        assert est.wordlist_size == 50_000

    def test_dictionary_eta_positive(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc123", hash_type=HashType.MD5)
        est = estimate_crack(target, wordlist_50k)
        assert est.dictionary_eta > 0

    def test_rules_eta_greater_than_dictionary(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc123", hash_type=HashType.MD5)
        est = estimate_crack(target, wordlist_50k)
        assert est.rules_eta >= est.dictionary_eta

    def test_bcrypt_takes_longer_than_md5(self, wordlist_50k: Path) -> None:
        target_md5 = HashTarget(hash_value="abc", hash_type=HashType.MD5)
        target_bcrypt = HashTarget(hash_value="$2b$12$abc", hash_type=HashType.BCRYPT)
        est_md5 = estimate_crack(target_md5, wordlist_50k)
        est_bcrypt = estimate_crack(target_bcrypt, wordlist_50k)
        assert est_bcrypt.dictionary_eta > est_md5.dictionary_eta

    def test_recommendation_is_nonempty(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc", hash_type=HashType.SHA256)
        est = estimate_crack(target, wordlist_50k)
        assert len(est.recommendation) > 0

    def test_thorough_preset_increases_rules_eta(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc", hash_type=HashType.MD5)
        est_quick = estimate_crack(target, wordlist_50k, rules_preset="quick")
        est_thorough = estimate_crack(target, wordlist_50k, rules_preset="thorough")
        assert est_thorough.rules_eta >= est_quick.rules_eta


@pytest.mark.unit
class TestCheckHIBP:
    def test_returns_count_on_match(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            "003D68EB55068C33ACE09247EE4C639306B:3\n"
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\n"
            "FD66A3F84D9E9B0CC542BEB41B3CAE34B9:12\n"
        )
        mock_resp.raise_for_status = MagicMock()

        with patch("smartcrack.estimator.httpx.get", return_value=mock_resp):
            count = check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert count == 9545824

    def test_returns_zero_on_no_match(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            "003D68EB55068C33ACE09247EE4C639306B:3\n"
            "FD66A3F84D9E9B0CC542BEB41B3CAE34B9:12\n"
        )
        mock_resp.raise_for_status = MagicMock()

        with patch("smartcrack.estimator.httpx.get", return_value=mock_resp):
            count = check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert count == 0

    def test_returns_none_on_timeout(self) -> None:
        import httpx as _httpx
        with patch(
            "smartcrack.estimator.httpx.get",
            side_effect=_httpx.TimeoutException("timed out"),
        ):
            count = check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert count is None

    def test_returns_none_on_http_error(self) -> None:
        import httpx as _httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        error = _httpx.HTTPStatusError(
            "rate limited", request=MagicMock(), response=mock_resp
        )
        with patch("smartcrack.estimator.httpx.get", side_effect=error):
            count = check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert count is None

    def test_uses_k_anonymity_prefix(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.raise_for_status = MagicMock()

        with patch("smartcrack.estimator.httpx.get", return_value=mock_resp) as mock_get:
            check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        call_url = mock_get.call_args[0][0]
        assert call_url.endswith("/5BAA6")


@pytest.mark.unit
class TestEstimateRendering:
    def test_estimate_has_all_required_fields_for_table(self, tmp_path: Path) -> None:
        wl = tmp_path / "small.txt"
        wl.write_text("\n".join(f"w{i}" for i in range(100)) + "\n")
        target = HashTarget(hash_value="abc", hash_type=HashType.MD5)
        est = estimate_crack(target, wl)
        assert est.hash_type is not None
        assert est.wordlist_size is not None
        assert est.dictionary_probability is not None
        assert est.dictionary_eta is not None
        assert est.rules_probability is not None
        assert est.rules_eta is not None
        assert est.recommendation is not None
