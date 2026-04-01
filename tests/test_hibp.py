"""Tests for HIBP k-anonymity password breach checker."""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch


class TestCheckHibpPassword:
    def test_returns_count_when_hash_found(self) -> None:
        from smartcrack.hibp import check_hibp_password
        sha1_hex = hashlib.sha1(b"password").hexdigest().upper()
        prefix = sha1_hex[:5]
        suffix = sha1_hex[5:]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = f"0000000000000000000000000000000AAAA:2\n{suffix}:37615252\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:5\n"
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.get", return_value=mock_resp) as mock_get:
            result = check_hibp_password("password")
        assert result == 37615252
        call_url = mock_get.call_args[0][0]
        assert call_url.endswith(f"/range/{prefix}")

    def test_returns_none_when_hash_not_in_range(self) -> None:
        from smartcrack.hibp import check_hibp_password
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "0000000000000000000000000000000AAAA:2\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:5\n"
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.get", return_value=mock_resp):
            result = check_hibp_password("super_unique_never_breached_xyzzy_42")
        assert result is None

    def test_returns_none_on_network_error(self) -> None:
        from smartcrack.hibp import check_hibp_password
        import httpx as _httpx
        with patch("httpx.get", side_effect=_httpx.TimeoutException("timeout")):
            result = check_hibp_password("password")
        assert result is None

    def test_returns_none_on_http_error(self) -> None:
        from smartcrack.hibp import check_hibp_password
        import httpx as _httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        error = _httpx.HTTPStatusError("service unavailable", request=MagicMock(), response=mock_resp)
        with patch("httpx.get", side_effect=error):
            result = check_hibp_password("password")
        assert result is None

    def test_sends_user_agent_header(self) -> None:
        from smartcrack.hibp import check_hibp_password
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.get", return_value=mock_resp) as mock_get:
            check_hibp_password("test")
        headers = mock_get.call_args[1].get("headers", {})
        assert "User-Agent" in headers
        assert "SmartCrack" in headers["User-Agent"]

    def test_uses_k_anonymity_prefix(self) -> None:
        from smartcrack.hibp import check_hibp_password
        sha1_hex = hashlib.sha1(b"hello").hexdigest().upper()
        prefix = sha1_hex[:5]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.get", return_value=mock_resp) as mock_get:
            check_hibp_password("hello")
        call_url = mock_get.call_args[0][0]
        assert prefix in call_url
        assert sha1_hex not in call_url


class TestCheckHibpSha1:
    def test_returns_count_for_known_sha1(self) -> None:
        from smartcrack.hibp import check_hibp_sha1
        full_sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        suffix = full_sha1[5:]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = f"{suffix}:9999\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.get", return_value=mock_resp):
            result = check_hibp_sha1(full_sha1)
        assert result == 9999

    def test_returns_none_when_not_found(self) -> None:
        from smartcrack.hibp import check_hibp_sha1
        full_sha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "0000000000000000000000000000000000000:1\n"
        mock_resp.raise_for_status = MagicMock()
        with patch("httpx.get", return_value=mock_resp):
            result = check_hibp_sha1(full_sha1)
        assert result is None

    def test_returns_none_on_network_error(self) -> None:
        from smartcrack.hibp import check_hibp_sha1
        import httpx as _httpx
        with patch("httpx.get", side_effect=_httpx.TimeoutException("timeout")):
            result = check_hibp_sha1("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        assert result is None
