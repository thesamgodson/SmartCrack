"""Have I Been Pwned (HIBP) password breach checker using k-anonymity API."""

from __future__ import annotations

import hashlib
import logging

import httpx

logger = logging.getLogger(__name__)

_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
_USER_AGENT = "SmartCrack-PasswordAudit"
_TIMEOUT = 10


def _query_range(prefix: str) -> str | None:
    try:
        response = httpx.get(
            f"{_HIBP_RANGE_URL}{prefix}",
            headers={"User-Agent": _USER_AGENT},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.text
    except httpx.TimeoutException:
        logger.warning("HIBP range request timed out for prefix %s", prefix)
        return None
    except httpx.HTTPStatusError as exc:
        logger.warning("HIBP HTTP error %s for prefix %s", exc.response.status_code, prefix)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("HIBP unexpected error (%s) for prefix %s", type(exc).__name__, prefix)
        return None


def _search_range_response(response_text: str, suffix: str) -> int | None:
    suffix_upper = suffix.upper()
    for line in response_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) != 2:
            continue
        if parts[0].upper() == suffix_upper:
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


def check_hibp_password(plaintext: str) -> int | None:
    sha1_hex = hashlib.sha1(plaintext.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hex[:5]
    suffix = sha1_hex[5:]
    response_text = _query_range(prefix)
    if response_text is None:
        return None
    return _search_range_response(response_text, suffix)


def check_hibp_sha1(sha1_hash: str) -> int | None:
    sha1_upper = sha1_hash.upper()
    prefix = sha1_upper[:5]
    suffix = sha1_upper[5:]
    response_text = _query_range(prefix)
    if response_text is None:
        return None
    return _search_range_response(response_text, suffix)
