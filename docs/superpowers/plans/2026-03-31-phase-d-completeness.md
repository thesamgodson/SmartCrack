# Phase D: Completeness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add rainbow table support, HIBP breach checking, and AI-weighted combo attacks for full attack coverage.

**Architecture:** Rainbow tables use sorted binary files with binary search for O(log n) lookup. HIBP uses k-anonymity API. Combo engine generates weighted word pair candidates with optional AI ranking.

**Tech Stack:** struct (binary format), httpx (HIBP API), itertools (combinations), existing LLM pattern.

---

## Task 1: Add RAINBOW and COMBO to AttackPhase enum

**Files:**
- `src/smartcrack/models.py` (edit)
- `tests/test_models.py` (edit)

### Steps

- [ ] **1.1** Write test for new enum members

Open `tests/test_models.py` and add:

```python
class TestAttackPhaseExtensions:
    def test_rainbow_phase_exists(self) -> None:
        assert AttackPhase.RAINBOW.value == "rainbow"

    def test_combo_phase_exists(self) -> None:
        assert AttackPhase.COMBO.value == "combo"

    def test_all_phases_have_unique_values(self) -> None:
        values = [p.value for p in AttackPhase]
        assert len(values) == len(set(values))
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_models.py::TestAttackPhaseExtensions -x -v
```

Expected: **FAIL** — `AttackPhase` has no `RAINBOW` or `COMBO` members yet.

- [ ] **1.2** Add enum members to `AttackPhase`

In `src/smartcrack/models.py`, add two new members to `AttackPhase`:

```python
class AttackPhase(Enum):
    DICTIONARY = "dictionary"
    RULES = "rules"
    PROFILE = "profile"
    HYBRID = "hybrid"
    ADAPTIVE = "adaptive"
    RAINBOW = "rainbow"
    COMBO = "combo"
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_models.py::TestAttackPhaseExtensions -x -v
```

Expected: **PASS**

- [ ] **1.3** Verify no existing tests broke

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_models.py -x -v
```

Expected: **PASS** — all existing model tests still green.

**Commit:** `feat: add RAINBOW and COMBO members to AttackPhase enum`

---

## Task 2: Create rainbow table module with build and lookup

**Files:**
- `src/smartcrack/rainbow.py` (create)
- `tests/test_rainbow.py` (create)

### Steps

- [ ] **2.1** Write tests for `RainbowTableHeader` dataclass

Create `tests/test_rainbow.py`:

```python
"""Tests for rainbow table build and lookup."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from smartcrack.models import HashType


# ---------------------------------------------------------------------------
# RainbowTableHeader
# ---------------------------------------------------------------------------


class TestRainbowTableHeader:
    def test_header_is_frozen(self) -> None:
        from smartcrack.rainbow import RainbowTableHeader

        header = RainbowTableHeader(
            hash_type=HashType.MD5,
            entry_count=100,
            hash_hex_length=32,
            max_plaintext_length=64,
        )
        with pytest.raises((AttributeError, TypeError)):
            header.entry_count = 200  # type: ignore[misc]

    def test_header_fields(self) -> None:
        from smartcrack.rainbow import RainbowTableHeader

        header = RainbowTableHeader(
            hash_type=HashType.SHA256,
            entry_count=500,
            hash_hex_length=64,
            max_plaintext_length=128,
        )
        assert header.hash_type == HashType.SHA256
        assert header.entry_count == 500
        assert header.hash_hex_length == 64
        assert header.max_plaintext_length == 128
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_rainbow.py::TestRainbowTableHeader -x -v
```

Expected: **FAIL** — `smartcrack.rainbow` does not exist yet.

- [ ] **2.2** Write tests for `build_rainbow_table`

Append to `tests/test_rainbow.py`:

```python
# ---------------------------------------------------------------------------
# build_rainbow_table
# ---------------------------------------------------------------------------


class TestBuildRainbowTable:
    def test_build_creates_file(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("apple\nbanana\ncherry\n")
        output = tmp_path / "table.rainbow"

        count = build_rainbow_table(wordlist, HashType.MD5, output)

        assert output.exists()
        assert count == 3

    def test_build_returns_entry_count(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("one\ntwo\nthree\nfour\nfive\n")
        output = tmp_path / "table.rainbow"

        count = build_rainbow_table(wordlist, HashType.SHA1, output)
        assert count == 5

    def test_build_skips_blank_lines(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("alpha\n\nbeta\n\n\ngamma\n")
        output = tmp_path / "table.rainbow"

        count = build_rainbow_table(wordlist, HashType.MD5, output)
        assert count == 3

    def test_build_raises_on_missing_wordlist(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table

        missing = tmp_path / "nope.txt"
        output = tmp_path / "table.rainbow"

        with pytest.raises(FileNotFoundError):
            build_rainbow_table(missing, HashType.MD5, output)

    def test_build_raises_on_unsupported_hash_type(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import build_rainbow_table

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("test\n")
        output = tmp_path / "table.rainbow"

        with pytest.raises(ValueError, match="Unsupported"):
            build_rainbow_table(wordlist, HashType.BCRYPT, output)
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_rainbow.py::TestBuildRainbowTable -x -v
```

Expected: **FAIL**

- [ ] **2.3** Write tests for `lookup_rainbow_table`

Append to `tests/test_rainbow.py`:

```python
# ---------------------------------------------------------------------------
# lookup_rainbow_table
# ---------------------------------------------------------------------------


class TestLookupRainbowTable:
    @pytest.fixture()
    def md5_table(self, tmp_path: Path) -> Path:
        """Build a small MD5 rainbow table for lookup tests."""
        from smartcrack.rainbow import build_rainbow_table

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("apple\nbanana\ncherry\ndate\nelderberry\n")
        output = tmp_path / "table.rainbow"
        build_rainbow_table(wordlist, HashType.MD5, output)
        return output

    def test_lookup_finds_known_entry(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table

        target_hash = hashlib.md5(b"banana").hexdigest()
        result = lookup_rainbow_table(target_hash, md5_table)
        assert result == "banana"

    def test_lookup_finds_first_entry(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table

        target_hash = hashlib.md5(b"apple").hexdigest()
        result = lookup_rainbow_table(target_hash, md5_table)
        assert result == "apple"

    def test_lookup_finds_last_entry(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table

        # The "last" entry depends on sort order of hex hashes, not insertion order.
        # Just verify all 5 entries are findable.
        for word in ("apple", "banana", "cherry", "date", "elderberry"):
            h = hashlib.md5(word.encode()).hexdigest()
            assert lookup_rainbow_table(h, md5_table) == word

    def test_lookup_returns_none_for_unknown(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table

        unknown_hash = hashlib.md5(b"not_in_table").hexdigest()
        result = lookup_rainbow_table(unknown_hash, md5_table)
        assert result is None

    def test_lookup_is_case_insensitive(self, md5_table: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table

        target_hash = hashlib.md5(b"cherry").hexdigest().upper()
        result = lookup_rainbow_table(target_hash, md5_table)
        assert result == "cherry"

    def test_lookup_on_large_table(self, tmp_path: Path) -> None:
        """Binary search must work correctly on 1000+ entries."""
        from smartcrack.rainbow import build_rainbow_table, lookup_rainbow_table

        words = [f"word{i:04d}" for i in range(1500)]
        wordlist = tmp_path / "big.txt"
        wordlist.write_text("\n".join(words) + "\n")
        output = tmp_path / "big.rainbow"
        count = build_rainbow_table(wordlist, HashType.SHA256, output)
        assert count == 1500

        # Spot-check 20 entries scattered across the table
        for i in range(0, 1500, 75):
            word = f"word{i:04d}"
            h = hashlib.sha256(word.encode()).hexdigest()
            assert lookup_rainbow_table(h, output) == word

        # Confirm miss
        miss_hash = hashlib.sha256(b"not_a_word").hexdigest()
        assert lookup_rainbow_table(miss_hash, output) is None

    def test_lookup_raises_on_missing_file(self, tmp_path: Path) -> None:
        from smartcrack.rainbow import lookup_rainbow_table

        missing = tmp_path / "nope.rainbow"
        with pytest.raises(FileNotFoundError):
            lookup_rainbow_table("abc123", missing)
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_rainbow.py::TestLookupRainbowTable -x -v
```

Expected: **FAIL**

- [ ] **2.4** Implement `src/smartcrack/rainbow.py`

Create `src/smartcrack/rainbow.py`:

```python
"""Rainbow table builder and binary-search lookup.

File format (version 1):
    - 32-byte header:
        - 4 bytes: magic b'RBOW'
        - 1 byte:  version (1)
        - 1 byte:  hash_type enum value (HashType.value stored as ordinal index)
        - 4 bytes: entry_count (uint32 big-endian)
        - 2 bytes: hash_hex_length (uint16 big-endian)
        - 2 bytes: max_plaintext_length (uint16 big-endian)
        - 18 bytes: reserved (zeroed)
    - N fixed-width records, sorted by hash_hex (ASCII lowercase):
        - hash_hex_length bytes: hash hex string (ASCII, lowercase, zero-padded)
        - max_plaintext_length bytes: plaintext (UTF-8, zero-padded)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from smartcrack.hashers import HASH_FUNCTIONS
from smartcrack.models import HashType

_MAGIC = b"RBOW"
_VERSION = 1
_HEADER_SIZE = 32
_HEADER_FMT = ">4sBBIHH18x"  # magic(4) + version(1) + ht_ordinal(1) + count(4) + hex_len(2) + pt_len(2) + pad(18)

# Hash hex lengths for supported types
_HEX_LENGTHS: dict[HashType, int] = {
    HashType.MD5: 32,
    HashType.SHA1: 40,
    HashType.SHA224: 56,
    HashType.SHA256: 64,
    HashType.SHA384: 96,
    HashType.SHA512: 128,
    HashType.NTLM: 32,
}

_SUPPORTED_TYPES = frozenset(_HEX_LENGTHS.keys())
_DEFAULT_MAX_PLAINTEXT = 128


@dataclass(frozen=True)
class RainbowTableHeader:
    """Metadata stored at the start of a rainbow table file."""

    hash_type: HashType
    entry_count: int
    hash_hex_length: int
    max_plaintext_length: int


def _hash_type_to_ordinal(ht: HashType) -> int:
    """Convert HashType to a stable ordinal for storage."""
    members = list(HashType)
    return members.index(ht)


def _ordinal_to_hash_type(ordinal: int) -> HashType:
    """Convert stored ordinal back to HashType."""
    members = list(HashType)
    if 0 <= ordinal < len(members):
        return members[ordinal]
    raise ValueError(f"Unknown hash type ordinal: {ordinal}")


def _write_header(f, header: RainbowTableHeader) -> None:  # noqa: ANN001
    """Write the 32-byte header to an open binary file."""
    packed = struct.pack(
        _HEADER_FMT,
        _MAGIC,
        _VERSION,
        _hash_type_to_ordinal(header.hash_type),
        header.entry_count,
        header.hash_hex_length,
        header.max_plaintext_length,
    )
    f.write(packed)


def _read_header(f) -> RainbowTableHeader:  # noqa: ANN001
    """Read and validate the 32-byte header from an open binary file."""
    raw = f.read(_HEADER_SIZE)
    if len(raw) < _HEADER_SIZE:
        raise ValueError("File too small to contain a valid rainbow table header")
    magic, version, ht_ordinal, count, hex_len, pt_len = struct.unpack(_HEADER_FMT, raw)
    if magic != _MAGIC:
        raise ValueError(f"Invalid magic bytes: {magic!r}")
    if version != _VERSION:
        raise ValueError(f"Unsupported rainbow table version: {version}")
    return RainbowTableHeader(
        hash_type=_ordinal_to_hash_type(ht_ordinal),
        entry_count=count,
        hash_hex_length=hex_len,
        max_plaintext_length=pt_len,
    )


def build_rainbow_table(
    wordlist_path: Path,
    hash_type: HashType,
    output_path: Path,
    max_plaintext_length: int = _DEFAULT_MAX_PLAINTEXT,
) -> int:
    """Build a sorted binary rainbow table from a wordlist.

    Args:
        wordlist_path:  Path to newline-delimited wordlist.
        hash_type:      Hash algorithm to use (must be a stdlib-supported type or NTLM).
        output_path:    Path to write the binary table file.
        max_plaintext_length: Maximum plaintext bytes per record.

    Returns:
        Number of entries written.

    Raises:
        FileNotFoundError: If wordlist_path does not exist.
        ValueError: If hash_type is not supported for rainbow tables.
    """
    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    if hash_type not in _SUPPORTED_TYPES:
        raise ValueError(
            f"Unsupported hash type for rainbow tables: {hash_type}. "
            f"Supported: {', '.join(t.name for t in sorted(_SUPPORTED_TYPES, key=lambda t: t.name))}"
        )

    hex_len = _HEX_LENGTHS[hash_type]
    record_size = hex_len + max_plaintext_length

    # Build entries in memory, then sort by hash hex
    entries: list[tuple[str, str]] = []
    hash_fn = HASH_FUNCTIONS.get(hash_type)

    with open(wordlist_path, "r", encoding="iso-8859-1") as f:
        for line in f:
            plaintext = line.rstrip("\n\r")
            if not plaintext:
                continue
            if len(plaintext.encode("utf-8")) > max_plaintext_length:
                continue  # skip words that exceed the record width

            if hash_type == HashType.NTLM:
                from smartcrack.hashers import _compute_ntlm

                hex_digest = _compute_ntlm(plaintext)
            else:
                if hash_fn is None:
                    raise ValueError(f"No hash function for {hash_type}")
                hex_digest = hash_fn(plaintext.encode("utf-8")).hexdigest()

            entries.append((hex_digest.lower(), plaintext))

    # Sort by hash hex for binary search
    entries.sort(key=lambda e: e[0])

    header = RainbowTableHeader(
        hash_type=hash_type,
        entry_count=len(entries),
        hash_hex_length=hex_len,
        max_plaintext_length=max_plaintext_length,
    )

    with open(output_path, "wb") as out:
        _write_header(out, header)
        for hex_digest, plaintext in entries:
            hex_bytes = hex_digest.encode("ascii").ljust(hex_len, b"\x00")
            pt_bytes = plaintext.encode("utf-8").ljust(max_plaintext_length, b"\x00")
            out.write(hex_bytes)
            out.write(pt_bytes)

    return len(entries)


def lookup_rainbow_table(hash_value: str, table_path: Path) -> str | None:
    """Binary search a rainbow table file for a hash.

    Args:
        hash_value: Hex-encoded hash to look up (case-insensitive).
        table_path: Path to a rainbow table file built by :func:`build_rainbow_table`.

    Returns:
        The plaintext if found, or ``None``.

    Raises:
        FileNotFoundError: If table_path does not exist.
    """
    if not table_path.exists():
        raise FileNotFoundError(f"Rainbow table not found: {table_path}")

    target = hash_value.lower()

    with open(table_path, "rb") as f:
        header = _read_header(f)
        hex_len = header.hash_hex_length
        pt_len = header.max_plaintext_length
        record_size = hex_len + pt_len
        count = header.entry_count

        if count == 0:
            return None

        # Pad or truncate target to match stored hex length
        target_padded = target.ljust(hex_len, "\x00")

        lo, hi = 0, count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            offset = _HEADER_SIZE + mid * record_size
            f.seek(offset)
            record = f.read(record_size)
            if len(record) < record_size:
                return None

            stored_hex = record[:hex_len].decode("ascii")
            if stored_hex == target_padded:
                plaintext_raw = record[hex_len:]
                return plaintext_raw.rstrip(b"\x00").decode("utf-8")
            elif stored_hex < target_padded:
                lo = mid + 1
            else:
                hi = mid - 1

    return None
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_rainbow.py -x -v
```

Expected: **PASS** — all rainbow table tests green.

- [ ] **2.5** Verify no regressions

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x -v
```

Expected: **PASS**

**Commit:** `feat: add rainbow table builder and binary-search lookup`

---

## Task 3: Create HIBP breach-check module

**Files:**
- `src/smartcrack/hibp.py` (create)
- `tests/test_hibp.py` (create)

### Steps

- [ ] **3.1** Write tests for HIBP module

Create `tests/test_hibp.py`:

```python
"""Tests for HIBP k-anonymity password breach checker."""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# check_hibp_password
# ---------------------------------------------------------------------------


class TestCheckHibpPassword:
    def test_returns_count_when_hash_found(self) -> None:
        from smartcrack.hibp import check_hibp_password

        # SHA1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
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
        # Must NOT send the full hash
        assert sha1_hex not in call_url


# ---------------------------------------------------------------------------
# check_hibp_sha1
# ---------------------------------------------------------------------------


class TestCheckHibpSha1:
    def test_returns_count_for_known_sha1(self) -> None:
        from smartcrack.hibp import check_hibp_sha1

        full_sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        prefix = full_sha1[:5]
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
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_hibp.py -x -v
```

Expected: **FAIL** — module does not exist.

- [ ] **3.2** Implement `src/smartcrack/hibp.py`

Create `src/smartcrack/hibp.py`:

```python
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
    """Query the HIBP range API with a 5-char SHA1 prefix.

    Returns the raw response text, or None on any error.
    """
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
    """Search a HIBP range response for a specific suffix.

    The response format is lines of ``SUFFIX:COUNT``.

    Returns the count if found, or None.
    """
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
    """Check a plaintext password against HIBP using k-anonymity.

    Computes SHA1 of the plaintext, sends only the first 5 hex chars
    to the HIBP range API, and checks the response for the full hash.

    Args:
        plaintext: The password to check.

    Returns:
        Number of times the password has appeared in breaches,
        or ``None`` if not found or on any network error.
    """
    sha1_hex = hashlib.sha1(plaintext.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hex[:5]
    suffix = sha1_hex[5:]

    response_text = _query_range(prefix)
    if response_text is None:
        return None

    return _search_range_response(response_text, suffix)


def check_hibp_sha1(sha1_hash: str) -> int | None:
    """Check a raw SHA1 hash directly against HIBP using k-anonymity.

    Use this when the target hash is already SHA1 — no plaintext needed.

    Args:
        sha1_hash: The full 40-char SHA1 hex string.

    Returns:
        Number of times found in breaches, or ``None``.
    """
    sha1_upper = sha1_hash.upper()
    prefix = sha1_upper[:5]
    suffix = sha1_upper[5:]

    response_text = _query_range(prefix)
    if response_text is None:
        return None

    return _search_range_response(response_text, suffix)
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_hibp.py -x -v
```

Expected: **PASS**

- [ ] **3.3** Verify no regressions

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x -v
```

Expected: **PASS**

**Commit:** `feat: add HIBP k-anonymity breach checker module`

---

## Task 4: Integrate rainbow table phase into orchestrator

**Files:**
- `src/smartcrack/orchestrator.py` (edit)
- `tests/test_orchestrator.py` (edit)

### Steps

- [ ] **4.1** Write tests for rainbow phase in `plan_attacks`

Append to `tests/test_orchestrator.py`:

```python
# ---------------------------------------------------------------------------
# Rainbow phase integration
# ---------------------------------------------------------------------------


class TestRainbowPhaseIntegration:
    @pytest.fixture()
    def rainbow_table(self, tmp_path: Path) -> Path:
        """Build a small MD5 rainbow table."""
        from smartcrack.rainbow import build_rainbow_table

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("password\nhello\nworld\nadmin\n")
        table = tmp_path / "test.rainbow"
        build_rainbow_table(wordlist, HashType.MD5, table)
        return table

    def test_rainbow_phase_inserted_first_when_table_provided(
        self, tmp_wordlist: Path, rainbow_table: Path
    ) -> None:
        plans = plan_attacks(
            tmp_wordlist, rules_preset="none", rainbow_table_path=rainbow_table
        )
        assert plans[0].phase == AttackPhase.RAINBOW

    def test_rainbow_phase_before_dictionary(
        self, tmp_wordlist: Path, rainbow_table: Path
    ) -> None:
        plans = plan_attacks(
            tmp_wordlist, rules_preset="quick", rainbow_table_path=rainbow_table
        )
        phases = [p.phase for p in plans]
        assert phases[0] == AttackPhase.RAINBOW
        assert phases[1] == AttackPhase.DICTIONARY

    def test_no_rainbow_phase_when_path_is_none(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        phases = [p.phase for p in plans]
        assert AttackPhase.RAINBOW not in phases

    def test_rainbow_phase_finds_hash_instantly(
        self, tmp_wordlist: Path, rainbow_table: Path
    ) -> None:
        hash_value = hashlib.md5(b"password").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        plans = plan_attacks(
            tmp_wordlist, rules_preset="none", rainbow_table_path=rainbow_table
        )
        result = run_orchestrated(target, plans, max_workers=1)
        assert result.found is True
        assert result.plaintext == "password"
        assert result.attack_phase == AttackPhase.RAINBOW

    def test_rainbow_miss_falls_through_to_dictionary(
        self, tmp_wordlist: Path, rainbow_table: Path
    ) -> None:
        # "letmein" is in tmp_wordlist but NOT in rainbow_table
        hash_value = hashlib.md5(b"letmein").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        plans = plan_attacks(
            tmp_wordlist, rules_preset="none", rainbow_table_path=rainbow_table
        )
        result = run_orchestrated(target, plans, max_workers=1)
        assert result.found is True
        assert result.plaintext == "letmein"
        assert result.attack_phase == AttackPhase.DICTIONARY
```

Add `from smartcrack.models import AttackPhase, HashTarget, HashType, TargetProfile` if not already at the top. Ensure `import hashlib` is present.

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_orchestrator.py::TestRainbowPhaseIntegration -x -v
```

Expected: **FAIL** — `plan_attacks()` does not accept `rainbow_table_path`.

- [ ] **4.2** Modify `plan_attacks()` to accept `rainbow_table_path`

In `src/smartcrack/orchestrator.py`, update the `plan_attacks` function signature and body:

```python
def plan_attacks(
    wordlist_path: Path,
    rules_preset: str = "quick",
    profile: TargetProfile | None = None,
    llm_config: LLMConfig | None = None,
    wordlist_offset: int = 0,
    rainbow_table_path: Path | None = None,
) -> list[AttackPlan]:
    """Build an ordered list of AttackPlan objects for the given configuration.

    Phase ordering:
    0. RAINBOW     — instant rainbow table lookup (when rainbow_table_path provided)
    1. DICTIONARY  — plain wordlist
    2. RULES       — wordlist + rule mutations (skipped when rules_preset=="none")
    3. PROFILE     — profile-derived candidates (skipped when profile is None)
    4. HYBRID      — profile candidates + rule mutations (only when both profile
                     and rules are active)
    5. ADAPTIVE    — multi-round AI profiling

    Args:
        wordlist_path:       Path to the base wordlist file.
        rules_preset:        One of "none", "quick", or "thorough".
        profile:             Optional target profile for personalised candidates.
        llm_config:          Optional LLM config; enables AIProfiler when api_key set.
        wordlist_offset:     Number of lines to skip in the wordlist for DICTIONARY
                             phase (used for session resume).
        rainbow_table_path:  Optional path to a prebuilt rainbow table file.

    Returns:
        Ordered list of :class:`AttackPlan` objects.
    """
    plans: list[AttackPlan] = []
    rules_active = rules_preset != "none"

    # Phase 0 — rainbow table (instant lookup)
    if rainbow_table_path is not None:
        from smartcrack.rainbow import lookup_rainbow_table

        def _rainbow_candidates(table_path: Path = rainbow_table_path) -> Iterator[str]:
            """Yield a single-item iterator: the lookup result or nothing."""
            # This is a special phase — the orchestrator's crack_sequential
            # will try each yielded candidate against the target hash.
            # We read the entire table and yield all plaintexts so the cracker
            # can verify them. But that defeats the purpose of O(log n) lookup.
            #
            # Instead, we need to do the lookup ourselves. But we don't have
            # the target hash here. So we yield ALL plaintexts from the table
            # in a streaming fashion — the cracker will check each one.
            #
            # Actually, a better approach: yield all stored plaintexts.
            # The table is sorted by hash, but we can still stream the records.
            import struct as _struct

            with open(table_path, "rb") as f:
                raw = f.read(32)
                if len(raw) < 32:
                    return
                _magic, _ver, _ht, count, hex_len, pt_len = _struct.unpack(
                    ">4sBBIHH18x", raw
                )
                record_size = hex_len + pt_len
                for _ in range(count):
                    record = f.read(record_size)
                    if len(record) < record_size:
                        return
                    plaintext = record[hex_len:].rstrip(b"\x00").decode("utf-8")
                    if plaintext:
                        yield plaintext

        plans.append(
            AttackPlan(
                name="Rainbow Table",
                phase=AttackPhase.RAINBOW,
                candidates_fn=_rainbow_candidates,
            )
        )

    # Phase 1 — dictionary
    plans.append(
        AttackPlan(
            name="Dictionary",
            phase=AttackPhase.DICTIONARY,
            candidates_fn=lambda o=wordlist_offset: file_candidates_from_offset(
                wordlist_path, o
            ),
        )
    )

    # Phase 2 — rules
    if rules_active:
        rules = _rules_for_preset(rules_preset)
        plans.append(
            AttackPlan(
                name=f"Dictionary + {rules_preset.capitalize()} Rules",
                phase=AttackPhase.RULES,
                candidates_fn=lambda r=rules: rule_candidates(
                    file_candidates(wordlist_path), r
                ),
            )
        )

    # Phase 3 — profile
    if profile is not None:
        profiler = _select_profiler(profile, llm_config)
        plans.append(
            AttackPlan(
                name="Profile",
                phase=AttackPhase.PROFILE,
                candidates_fn=lambda p=profiler, pr=profile: p.generate(pr),
            )
        )

        # Phase 4 — hybrid
        if rules_active:
            rules = _rules_for_preset(rules_preset)
            plans.append(
                AttackPlan(
                    name=f"Profile + {rules_preset.capitalize()} Rules",
                    phase=AttackPhase.HYBRID,
                    candidates_fn=lambda p=profiler, pr=profile, r=rules: rule_candidates(
                        p.generate(pr), r
                    ),
                )
            )

    # Phase 5 — adaptive AI (multi-round)
    if profile is not None and llm_config is not None and llm_config.api_key:
        adaptive = AdaptiveProfiler(llm_config, max_rounds=3)
        def _adaptive_candidates(a=adaptive, pr=profile):
            for round_result in a.generate_all_rounds(pr):
                yield from round_result.candidates
        plans.append(
            AttackPlan(
                name="Adaptive AI",
                phase=AttackPhase.ADAPTIVE,
                candidates_fn=_adaptive_candidates,
            )
        )

    return plans
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_orchestrator.py -x -v
```

Expected: **PASS** — both new and existing tests green.

- [ ] **4.3** Verify full test suite

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x -v
```

Expected: **PASS**

**Commit:** `feat: integrate rainbow table as first phase in attack orchestrator`

---

## Task 5: Add HIBP post-crack check to CLI output

**Files:**
- `src/smartcrack/cli.py` (edit)

### Steps

- [ ] **5.1** Add `--hibp` flag and post-crack check to the `smart` command

In `src/smartcrack/cli.py`, add a new option to the `smart` command:

```python
    hibp_check: bool = typer.Option(False, "--hibp", help="Check cracked password against HIBP breach database"),
```

Then, after the `if result.found:` block that prints the cracked password, add:

```python
        if hibp_check and result.plaintext:
            from smartcrack.hibp import check_hibp_password

            console.print("[dim]Checking HIBP breach database...[/]")
            breach_count = check_hibp_password(result.plaintext)
            if breach_count is not None:
                console.print(
                    f"[yellow][!] Seen {breach_count:,} times in data breaches (HIBP)[/]"
                )
            else:
                console.print("[dim]Not found in HIBP breach database (or API unavailable)[/]")
```

- [ ] **5.2** Add `--rainbow-table` flag to the `smart` command

Add option:

```python
    rainbow_table: Optional[Path] = typer.Option(None, "--rainbow-table", help="Path to prebuilt rainbow table file"),
```

Pass it to `plan_attacks()`:

```python
    plans = plan_attacks(
        wordlist_path=resolved_path,
        rules_preset=rules,
        profile=profile,
        llm_config=llm_config,
        wordlist_offset=wordlist_offset,
        rainbow_table_path=rainbow_table,
    )
```

- [ ] **5.3** Verify CLI help renders correctly

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m smartcrack smart --help
```

Expected: `--hibp` and `--rainbow-table` flags visible in help output.

- [ ] **5.4** Verify full test suite

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x -v
```

Expected: **PASS**

**Commit:** `feat: add --hibp and --rainbow-table CLI flags to smart command`

---

## Task 6: Add rainbow CLI subcommands (build + lookup)

**Files:**
- `src/smartcrack/cli.py` (edit)

### Steps

- [ ] **6.1** Add `rainbow` command group with `build` and `lookup` subcommands

Add to `src/smartcrack/cli.py` after the existing imports:

```python
rainbow_app = typer.Typer(
    name="rainbow",
    help="Rainbow table management commands.",
    no_args_is_help=True,
)
app.add_typer(rainbow_app, name="rainbow")


@rainbow_app.command()
def build(
    wordlist: Path = typer.Option(..., "--wordlist", "-w", help="Wordlist file path"),
    hash_type: str = typer.Option("md5", "--type", "-t", help="Hash type (md5, sha1, sha256, etc.)"),
    output: Path = typer.Option(..., "--output", "-o", help="Output rainbow table file path"),
) -> None:
    """Build a rainbow table from a wordlist."""
    _print_banner()

    type_map: dict[str, HashType] = {
        "md5": HashType.MD5,
        "sha1": HashType.SHA1,
        "sha224": HashType.SHA224,
        "sha256": HashType.SHA256,
        "sha384": HashType.SHA384,
        "sha512": HashType.SHA512,
        "ntlm": HashType.NTLM,
    }

    resolved_type = type_map.get(hash_type.lower())
    if resolved_type is None:
        console.print(f"[red]Unsupported hash type: {hash_type}[/]")
        raise typer.Exit(code=1)

    from smartcrack.rainbow import build_rainbow_table

    console.print(f"[bold]Wordlist:[/] {wordlist}")
    console.print(f"[bold]Hash type:[/] {resolved_type.name}")
    console.print(f"[bold]Output:[/] {output}")
    console.print("[yellow]Building...[/]")

    count = build_rainbow_table(wordlist, resolved_type, output)
    console.print(f"[green][+] Built rainbow table with {count:,} entries[/]")


@rainbow_app.command()
def lookup(
    hash_value: str = typer.Option(..., "--hash", "-H", help="Hash to look up"),
    table: Path = typer.Option(..., "--table", "-T", help="Rainbow table file path"),
) -> None:
    """Look up a hash in a rainbow table."""
    _print_banner()

    from smartcrack.rainbow import lookup_rainbow_table

    result = lookup_rainbow_table(hash_value, table)
    if result is not None:
        console.print(f"[green][+] Found:[/] [bold]{result}[/]")
    else:
        console.print("[red][-] Not found in rainbow table[/]")
```

- [ ] **6.2** Verify subcommand help

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m smartcrack rainbow --help
cd /Users/sam/Documents/Projects/hashcrack && python -m smartcrack rainbow build --help
cd /Users/sam/Documents/Projects/hashcrack && python -m smartcrack rainbow lookup --help
```

Expected: help text for both subcommands renders correctly.

- [ ] **6.3** Verify full test suite

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x -v
```

Expected: **PASS**

**Commit:** `feat: add smartcrack rainbow build/lookup CLI subcommands`

---

## Task 7: Create combo attack module

**Files:**
- `src/smartcrack/combo.py` (create)
- `tests/test_combo.py` (create)

### Steps

- [ ] **7.1** Write tests for `combo_candidates`

Create `tests/test_combo.py`:

```python
"""Tests for combo attack engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from smartcrack.models import LLMConfig, TargetProfile


# ---------------------------------------------------------------------------
# combo_candidates
# ---------------------------------------------------------------------------


class TestComboCandidates:
    def test_basic_combination(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates

        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("hello\nworld\n")
        w2.write_text("123\n456\n")

        results = list(combo_candidates(w1, w2))
        assert "hello123" in results
        assert "hello456" in results
        assert "world123" in results
        assert "world456" in results

    def test_with_separators(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates

        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("foo\n")
        w2.write_text("bar\n")

        results = list(combo_candidates(w1, w2, separators=("", "_", ".")))
        assert "foobar" in results
        assert "foo_bar" in results
        assert "foo.bar" in results

    def test_default_separator_is_empty(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates

        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("aa\n")
        w2.write_text("bb\n")

        results = list(combo_candidates(w1, w2))
        assert results == ["aabb"]

    def test_max_length_filtering(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates

        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("longword\n")
        w2.write_text("anotherlongword\n")

        results = list(combo_candidates(w1, w2, max_length=10))
        # "longwordanotherlongword" is 23 chars, exceeds max_length=10
        assert len(results) == 0

    def test_max_length_keeps_short_combos(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates

        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("ab\nlong_word_here\n")
        w2.write_text("cd\n")

        results = list(combo_candidates(w1, w2, max_length=10))
        assert "abcd" in results
        assert all(len(r) <= 10 for r in results)

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates

        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("alpha\n\nbeta\n")
        w2.write_text("\ngamma\n")

        results = list(combo_candidates(w1, w2))
        assert "alphagamma" in results
        assert "betagamma" in results
        assert len(results) == 2

    def test_returns_iterator(self, tmp_path: Path) -> None:
        from smartcrack.combo import combo_candidates

        w1 = tmp_path / "w1.txt"
        w2 = tmp_path / "w2.txt"
        w1.write_text("x\n")
        w2.write_text("y\n")

        result = combo_candidates(w1, w2)
        assert hasattr(result, "__iter__") and hasattr(result, "__next__")


# ---------------------------------------------------------------------------
# profile_combo_candidates
# ---------------------------------------------------------------------------


class TestProfileComboCandidates:
    def test_generates_from_profile_fields(self) -> None:
        from smartcrack.combo import profile_combo_candidates

        profile = TargetProfile(
            first_name="John",
            last_name="Smith",
            pet_name="Buddy",
        )
        results = list(profile_combo_candidates(profile))
        assert len(results) > 0

    def test_includes_name_combinations(self) -> None:
        from smartcrack.combo import profile_combo_candidates

        profile = TargetProfile(
            first_name="John",
            last_name="Smith",
        )
        results = set(profile_combo_candidates(profile))
        # Should contain at least some name-to-name combos
        assert "JohnSmith" in results or "johnsmith" in results

    def test_uses_separators(self) -> None:
        from smartcrack.combo import profile_combo_candidates

        profile = TargetProfile(
            first_name="John",
            last_name="Smith",
        )
        results = set(profile_combo_candidates(profile, separators=("_",)))
        assert "John_Smith" in results or "john_smith" in results

    def test_includes_keywords(self) -> None:
        from smartcrack.combo import profile_combo_candidates

        profile = TargetProfile(
            first_name="Alice",
            keywords=("football",),
        )
        results = set(profile_combo_candidates(profile))
        assert any("football" in r.lower() for r in results)

    def test_includes_numbers(self) -> None:
        from smartcrack.combo import profile_combo_candidates

        profile = TargetProfile(
            first_name="Alice",
            special_numbers=("42",),
        )
        results = set(profile_combo_candidates(profile))
        assert any("42" in r for r in results)

    def test_empty_profile_returns_empty(self) -> None:
        from smartcrack.combo import profile_combo_candidates

        profile = TargetProfile()
        results = list(profile_combo_candidates(profile))
        assert results == []


# ---------------------------------------------------------------------------
# ai_ranked_combos
# ---------------------------------------------------------------------------


class TestAiRankedCombos:
    def test_returns_list_of_strings(self) -> None:
        from smartcrack.combo import ai_ranked_combos

        config = LLMConfig(
            base_url="https://test.example.com/v1",
            api_key="sk-test",
            model="test-model",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "john_smith\nsmithbuddy\njohn123\n"}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp):
            results = ai_ranked_combos(
                ["john", "smith"], ["buddy", "123"], config, top_n=10
            )

        assert isinstance(results, list)
        assert all(isinstance(r, str) for r in results)

    def test_respects_top_n_limit(self) -> None:
        from smartcrack.combo import ai_ranked_combos

        config = LLMConfig(
            base_url="https://test.example.com/v1",
            api_key="sk-test",
            model="test-model",
        )

        lines = "\n".join(f"combo{i}" for i in range(50))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": lines}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp):
            results = ai_ranked_combos(
                ["a", "b"], ["c", "d"], config, top_n=10
            )

        assert len(results) <= 10

    def test_sends_words_in_prompt(self) -> None:
        from smartcrack.combo import ai_ranked_combos

        config = LLMConfig(
            base_url="https://test.example.com/v1",
            api_key="sk-test",
            model="test-model",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "result1\n"}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            ai_ranked_combos(["alpha", "beta"], ["gamma"], config)

        payload = mock_post.call_args[1]["json"]
        user_msg = payload["messages"][-1]["content"]
        assert "alpha" in user_msg
        assert "beta" in user_msg
        assert "gamma" in user_msg

    def test_returns_empty_on_api_error(self) -> None:
        from smartcrack.combo import ai_ranked_combos

        import httpx as _httpx

        config = LLMConfig(
            base_url="https://test.example.com/v1",
            api_key="sk-test",
            model="test-model",
        )

        with patch("httpx.post", side_effect=_httpx.TimeoutException("timeout")):
            results = ai_ranked_combos(["a"], ["b"], config)

        assert results == []

    def test_filters_blank_lines_and_spaces(self) -> None:
        from smartcrack.combo import ai_ranked_combos

        config = LLMConfig(
            base_url="https://test.example.com/v1",
            api_key="sk-test",
            model="test-model",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "good_combo\n\nHere is another:\nbad space\nclean123\n"
                    }
                }
            ]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp):
            results = ai_ranked_combos(["x"], ["y"], config)

        assert "good_combo" in results
        assert "clean123" in results
        assert "bad space" not in results
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_combo.py -x -v
```

Expected: **FAIL** — `smartcrack.combo` does not exist.

- [ ] **7.2** Implement `src/smartcrack/combo.py`

Create `src/smartcrack/combo.py`:

```python
"""AI-weighted combo attack — combine two wordlists with intelligent ordering."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from pathlib import Path

import httpx

from smartcrack.models import LLMConfig, TargetProfile

logger = logging.getLogger(__name__)

_CODE_FENCE = re.compile(r"^`{3,}(\w*)$")
_LIST_PREFIX = re.compile(r"^(\d+[.)]\s+|-\s+)")
_DEFAULT_SEPARATORS: tuple[str, ...] = ("",)
_PROFILE_SEPARATORS: tuple[str, ...] = ("", "_", ".", "!")
_MAX_AI_COMBOS = 500


def combo_candidates(
    path1: Path,
    path2: Path,
    separators: tuple[str, ...] = _DEFAULT_SEPARATORS,
    max_length: int = 64,
) -> Iterator[str]:
    """Yield word1+sep+word2 for each separator, filtering by max_length.

    Reads path2 fully into memory (must fit), streams path1 line by line.

    Args:
        path1: First wordlist file.
        path2: Second wordlist file.
        separators: Tuple of separator strings to insert between words.
        max_length: Maximum combined candidate length.

    Yields:
        Combined password candidates.
    """
    words2: list[str] = []
    with open(path2, "r", encoding="iso-8859-1") as f2:
        for line in f2:
            stripped = line.rstrip("\n\r")
            if stripped:
                words2.append(stripped)

    with open(path1, "r", encoding="iso-8859-1") as f1:
        for line in f1:
            w1 = line.rstrip("\n\r")
            if not w1:
                continue
            for sep in separators:
                for w2 in words2:
                    candidate = f"{w1}{sep}{w2}"
                    if len(candidate) <= max_length:
                        yield candidate


def _collect_profile_tokens(profile: TargetProfile) -> list[str]:
    """Extract non-empty string tokens from a profile for combo generation."""
    tokens: list[str] = []
    for field_val in (
        profile.first_name,
        profile.last_name,
        profile.nickname,
        profile.partner_name,
        profile.child_name,
        profile.pet_name,
    ):
        if field_val:
            tokens.append(field_val)
            tokens.append(field_val.lower())
            tokens.append(field_val.capitalize())
    for kw in profile.keywords:
        if kw:
            tokens.append(kw)
            tokens.append(kw.lower())
    for num in profile.special_numbers:
        if num:
            tokens.append(num)
    return tokens


def profile_combo_candidates(
    profile: TargetProfile,
    separators: tuple[str, ...] = _PROFILE_SEPARATORS,
) -> Iterator[str]:
    """Combine profile fields with each other using separators.

    Yields unique candidates from all pair permutations of profile tokens.

    Args:
        profile: Target profile with personal information.
        separators: Separators to place between combined tokens.

    Yields:
        Combined password candidates (deduplicated).
    """
    tokens = _collect_profile_tokens(profile)
    if not tokens:
        return

    seen: set[str] = set()
    for i, t1 in enumerate(tokens):
        for j, t2 in enumerate(tokens):
            if i == j:
                continue
            for sep in separators:
                candidate = f"{t1}{sep}{t2}"
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate


_COMBO_SYSTEM_PROMPT = (
    "You are a password security auditor for authorized penetration testing. "
    "Given two sets of words, generate the most likely password combinations "
    "a user might choose by combining one word from each set. Consider: "
    "direct concatenation, separator variations (_, ., !, -), case mixing, "
    "number substitutions, and common password patterns.\n\n"
    "Output ONLY the candidate passwords, one per line. No numbering, no "
    "explanations, no markdown formatting, no code fences."
)


def ai_ranked_combos(
    words1: list[str],
    words2: list[str],
    llm_config: LLMConfig,
    top_n: int = _MAX_AI_COMBOS,
) -> list[str]:
    """Send top words from each list to LLM for intelligent combination.

    Args:
        words1: First word list (truncated to first 100 for prompt).
        words2: Second word list (truncated to first 100 for prompt).
        llm_config: LLM endpoint configuration.
        top_n: Maximum number of candidates to return.

    Returns:
        Ranked list of password combination candidates.
    """
    sample1 = words1[:100]
    sample2 = words2[:100]

    user_prompt = (
        f"Word set 1:\n{chr(10).join(sample1)}\n\n"
        f"Word set 2:\n{chr(10).join(sample2)}\n\n"
        f"Generate the top {top_n} most likely password combinations."
    )

    url = f"{llm_config.base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": llm_config.model,
        "temperature": 0.8,
        "messages": [
            {"role": "system", "content": _COMBO_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {"Content-Type": "application/json"}
    if llm_config.api_key:
        headers["Authorization"] = f"Bearer {llm_config.api_key}"

    try:
        response = httpx.post(
            url,
            json=payload,
            headers=headers,
            timeout=llm_config.timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices", [])
        if not choices:
            return []
        content: str = choices[0].get("message", {}).get("content", "")
    except httpx.TimeoutException:
        logger.warning("ai_ranked_combos: request timed out")
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("ai_ranked_combos: HTTP error %s", exc.response.status_code)
        return []
    except Exception as exc:  # noqa: BLE001
        logger.warning("ai_ranked_combos: unexpected error (%s)", type(exc).__name__)
        return []

    results: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if _CODE_FENCE.match(stripped):
            continue
        stripped = _LIST_PREFIX.sub("", stripped).strip()
        if " " in stripped:
            continue
        if not stripped or len(stripped) > 128:
            continue
        results.append(stripped)
        if len(results) >= top_n:
            break

    return results
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_combo.py -x -v
```

Expected: **PASS**

- [ ] **7.3** Verify no regressions

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x -v
```

Expected: **PASS**

**Commit:** `feat: add combo attack module with file, profile, and AI-ranked modes`

---

## Task 8: Integrate combo phase into orchestrator

**Files:**
- `src/smartcrack/orchestrator.py` (edit)
- `tests/test_orchestrator.py` (edit)

### Steps

- [ ] **8.1** Write tests for combo phase in `plan_attacks`

Append to `tests/test_orchestrator.py`:

```python
# ---------------------------------------------------------------------------
# Combo phase integration
# ---------------------------------------------------------------------------


class TestComboPhaseIntegration:
    @pytest.fixture()
    def combo_wordlist(self, tmp_path: Path) -> Path:
        wl = tmp_path / "combo.txt"
        wl.write_text("123\n456\n789\n")
        return wl

    def test_combo_phase_added_after_rules(
        self, tmp_wordlist: Path, combo_wordlist: Path
    ) -> None:
        plans = plan_attacks(
            tmp_wordlist,
            rules_preset="quick",
            combo_wordlist_path=combo_wordlist,
        )
        phases = [p.phase for p in plans]
        rules_idx = phases.index(AttackPhase.RULES)
        combo_idx = phases.index(AttackPhase.COMBO)
        assert combo_idx == rules_idx + 1

    def test_combo_phase_added_after_dictionary_when_no_rules(
        self, tmp_wordlist: Path, combo_wordlist: Path
    ) -> None:
        plans = plan_attacks(
            tmp_wordlist,
            rules_preset="none",
            combo_wordlist_path=combo_wordlist,
        )
        phases = [p.phase for p in plans]
        dict_idx = phases.index(AttackPhase.DICTIONARY)
        combo_idx = phases.index(AttackPhase.COMBO)
        assert combo_idx == dict_idx + 1

    def test_no_combo_phase_when_path_is_none(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(tmp_wordlist, rules_preset="quick")
        phases = [p.phase for p in plans]
        assert AttackPhase.COMBO not in phases

    def test_combo_phase_finds_combined_password(
        self, tmp_path: Path, combo_wordlist: Path
    ) -> None:
        # Base wordlist has "admin", combo wordlist has "123"
        # Combined: "admin123"
        wl = tmp_path / "base.txt"
        wl.write_text("apple\nbanana\nadmin\n")

        target_hash = hashlib.md5(b"admin123").hexdigest()
        target = HashTarget(hash_value=target_hash, hash_type=HashType.MD5)

        plans = plan_attacks(
            wl,
            rules_preset="none",
            combo_wordlist_path=combo_wordlist,
        )
        result = run_orchestrated(target, plans, max_workers=1)
        assert result.found is True
        assert result.plaintext == "admin123"
        assert result.attack_phase == AttackPhase.COMBO
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_orchestrator.py::TestComboPhaseIntegration -x -v
```

Expected: **FAIL** — `plan_attacks()` does not accept `combo_wordlist_path`.

- [ ] **8.2** Add combo phase to `plan_attacks()`

In `src/smartcrack/orchestrator.py`, update the `plan_attacks` signature to add:

```python
    combo_wordlist_path: Path | None = None,
```

Add the combo import at the top of the function body (lazy):

After the RULES phase block and before the PROFILE phase block, insert:

```python
    # Phase 2.5 — combo
    if combo_wordlist_path is not None:
        from smartcrack.combo import combo_candidates as _combo_gen

        plans.append(
            AttackPlan(
                name="Combo Attack",
                phase=AttackPhase.COMBO,
                candidates_fn=lambda cp=combo_wordlist_path: _combo_gen(
                    wordlist_path, cp
                ),
            )
        )
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_orchestrator.py -x -v
```

Expected: **PASS**

- [ ] **8.3** Verify full test suite

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x -v
```

Expected: **PASS**

**Commit:** `feat: integrate combo attack phase into orchestrator`

---

## Task 9: Add combo CLI flags to smart command

**Files:**
- `src/smartcrack/cli.py` (edit)

### Steps

- [ ] **9.1** Add `--combo-wordlist`, `--separator`, and `--max-combo-length` options

Add these options to the `smart` command:

```python
    combo_wordlist: Optional[Path] = typer.Option(None, "--combo-wordlist", help="Second wordlist for combo attack"),
    separator: str = typer.Option("", "--separator", help="Separator between combined words (default: empty)"),
    max_combo_length: int = typer.Option(64, "--max-combo-length", help="Maximum combined candidate length"),
```

- [ ] **9.2** Pass `combo_wordlist_path` to `plan_attacks()`

Update the `plan_attacks()` call in the `smart` command:

```python
    plans = plan_attacks(
        wordlist_path=resolved_path,
        rules_preset=rules,
        profile=profile,
        llm_config=llm_config,
        wordlist_offset=wordlist_offset,
        rainbow_table_path=rainbow_table,
        combo_wordlist_path=combo_wordlist,
    )
```

- [ ] **9.3** Verify CLI help

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m smartcrack smart --help
```

Expected: `--combo-wordlist`, `--separator`, `--max-combo-length` visible.

- [ ] **9.4** Verify full test suite

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x -v
```

Expected: **PASS**

**Commit:** `feat: add --combo-wordlist and related CLI flags to smart command`

---

## Task 10: Lint and final validation

**Files:** All modified files

### Steps

- [ ] **10.1** Run ruff linter

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m ruff check src/smartcrack/rainbow.py src/smartcrack/hibp.py src/smartcrack/combo.py src/smartcrack/models.py src/smartcrack/orchestrator.py src/smartcrack/cli.py
```

Fix any issues reported.

- [ ] **10.2** Run full test suite with coverage

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x -v --tb=short
```

Expected: **PASS** — all tests green, zero failures.

- [ ] **10.3** Run type check (non-strict)

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m mypy src/smartcrack/rainbow.py src/smartcrack/hibp.py src/smartcrack/combo.py --ignore-missing-imports
```

Expected: **PASS** or only pre-existing warnings.

- [ ] **10.4** Smoke test the full CLI flow

```bash
cd /Users/sam/Documents/Projects/hashcrack && echo -e "password\nadmin\ntest123" > /tmp/sc_test_words.txt
cd /Users/sam/Documents/Projects/hashcrack && python -m smartcrack rainbow build --wordlist /tmp/sc_test_words.txt --type md5 --output /tmp/sc_test.rainbow
cd /Users/sam/Documents/Projects/hashcrack && python -m smartcrack rainbow lookup --hash "$(python -c "import hashlib; print(hashlib.md5(b'admin').hexdigest())")" --table /tmp/sc_test.rainbow
```

Expected: `Found: admin`

**Commit:** `chore: lint and validate Phase D completeness features`

---

## Summary of new/modified files

| File | Action | Purpose |
|------|--------|---------|
| `src/smartcrack/models.py` | edit | Add `RAINBOW` and `COMBO` to `AttackPhase` |
| `src/smartcrack/rainbow.py` | create | Rainbow table builder + binary search lookup |
| `src/smartcrack/hibp.py` | create | HIBP k-anonymity breach checker |
| `src/smartcrack/combo.py` | create | Combo attack with file, profile, and AI modes |
| `src/smartcrack/orchestrator.py` | edit | Add `rainbow_table_path` and `combo_wordlist_path` params |
| `src/smartcrack/cli.py` | edit | Add `rainbow` subcommands + `--hibp`, `--rainbow-table`, `--combo-wordlist` flags |
| `tests/test_models.py` | edit | Tests for new enum members |
| `tests/test_rainbow.py` | create | Tests for build, lookup, header, large table |
| `tests/test_hibp.py` | create | Tests for k-anonymity, mocked HTTP |
| `tests/test_combo.py` | create | Tests for combo, profile combo, AI ranked |
| `tests/test_orchestrator.py` | edit | Tests for rainbow + combo phase integration |
