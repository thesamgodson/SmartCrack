"""Parallel and sequential hash cracking engines."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ProcessPoolExecutor, as_completed

from smartcrack.hashers import verify_any
from smartcrack.models import CrackResult, HashTarget, HashType

logger = logging.getLogger(__name__)

# Mapping from HashType name string to hashlib algorithm name.
# Only stdlib-supported types are included; BCRYPT/ARGON2/NTLM are excluded.
_STDLIB_HASH_NAMES: dict[str, str] = {
    "MD5": "md5",
    "SHA1": "sha1",
    "SHA224": "sha224",
    "SHA256": "sha256",
    "SHA384": "sha384",
    "SHA512": "sha512",
}

_AUTO_SENTINELS: frozenset[str] = frozenset({"UNKNOWN", "auto"})


_MEMORY_HARD = frozenset({HashType.ARGON2, HashType.SCRYPT, HashType.YESCRYPT, HashType.CISCO_TYPE9})
_SLOW_ITERATED = frozenset({
    HashType.BCRYPT, HashType.DCC2, HashType.DRUPAL7,
    HashType.ORACLE12C, HashType.KEEPASS, HashType.MS_OFFICE, HashType.SEVENZIP,
    HashType.BITCOIN, HashType.ETHEREUM, HashType.MACOS_PBKDF2, HashType.CISCO_TYPE8,
    HashType.POSTGRES_SCRAM,
})
_MEDIUM_ITERATED = frozenset({
    HashType.MD5CRYPT, HashType.SHA256CRYPT, HashType.SHA512CRYPT,
    HashType.PHPASS, HashType.DJANGO_PBKDF2,
    HashType.WPA2_PMKID, HashType.RAR5, HashType.PDF, HashType.DCC1,
})
_FAST = frozenset({
    HashType.MD5, HashType.SHA1, HashType.SHA224, HashType.SHA256,
    HashType.SHA384, HashType.SHA512, HashType.NTLM, HashType.MYSQL41,
    HashType.NETNTLMV2, HashType.KERBEROS_TGS, HashType.KERBEROS_ASREP,
    HashType.MSSQL2012, HashType.LDAP_SSHA,
    HashType.LM, HashType.NETNTLMV1, HashType.ORACLE11G, HashType.POSTGRES_MD5,
})


def recommended_batch_size(hash_type: HashType) -> int:
    """Return optimal batch size based on hash computation cost."""
    if hash_type in _MEMORY_HARD:
        return 50
    if hash_type in _SLOW_ITERATED:
        return 500
    if hash_type in _MEDIUM_ITERATED:
        return 5_000
    if hash_type in _FAST:
        return 50_000
    return 10_000


def recommended_max_workers(hash_type: HashType) -> int | None:
    """Return optimal worker count for a hash type. None = os.cpu_count()."""
    if hash_type in _MEMORY_HARD:
        return 2  # Memory-bound, more workers just thrash
    if hash_type in _SLOW_ITERATED:
        return max(1, (os.cpu_count() or 4) // 2)
    return None  # Use all cores


# ---------------------------------------------------------------------------
# Module-level worker — must live at module scope for pickle compatibility
# ---------------------------------------------------------------------------


def _check_chunk(
    candidates: list[str],
    hash_value: str,
    hash_type_name: str,
    salt: str,
) -> tuple[str, str] | None:
    """Check a batch of candidates against a target hash.

    Runs in a worker process; all imports must be local.

    Returns ``(plaintext, hash_type_name)`` on first match, ``None`` otherwise.
    Hash type name ``"UNKNOWN"`` or ``"auto"`` triggers auto-detection across
    all stdlib algorithms plus NTLM.
    """
    import hashlib  # noqa: PLC0415 — subprocess needs its own import

    target_lower = hash_value.lower()
    salted_suffix = salt

    # --- bcrypt ---
    if hash_type_name == "BCRYPT":
        import bcrypt as _bcrypt  # noqa: PLC0415
        for candidate in candidates:
            try:
                if _bcrypt.checkpw((candidate + salted_suffix).encode("utf-8"), hash_value.encode("utf-8")):
                    return (candidate, "BCRYPT")
            except Exception:
                pass
        return None

    # --- argon2 ---
    if hash_type_name == "ARGON2":
        import argon2 as _argon2  # noqa: PLC0415
        ph = _argon2.PasswordHasher()
        for candidate in candidates:
            try:
                if ph.verify(hash_value, candidate + salted_suffix):
                    return (candidate, "ARGON2")
            except _argon2.exceptions.VerifyMismatchError:
                pass
            except Exception:
                pass
        return None

    # --- NTLM ---
    if hash_type_name == "NTLM":
        import struct  # noqa: PLC0415

        def _md4(data: bytes) -> str:
            def _rol(x: int, n: int) -> int:
                return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

            msg = bytearray(data)
            orig_bit_len = len(data) * 8
            msg.append(0x80)
            while len(msg) % 64 != 56:
                msg.append(0x00)
            msg += struct.pack("<Q", orig_bit_len)
            a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
            for off in range(0, len(msg), 64):
                X = list(struct.unpack("<16I", msg[off : off + 64]))
                aa, bb, cc, dd = a, b, c, d

                def R1(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
                    return _rol((a + ((b & c) | (~b & d)) + X[k]) & 0xFFFFFFFF, s)

                for k, s in [(0, 3), (1, 7), (2, 11), (3, 19),
                             (4, 3), (5, 7), (6, 11), (7, 19),
                             (8, 3), (9, 7), (10, 11), (11, 19),
                             (12, 3), (13, 7), (14, 11), (15, 19)]:
                    a = R1(a, b, c, d, k, s); a, b, c, d = d, a, b, c  # noqa: E702

                def R2(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
                    return _rol((a + ((b & c) | (b & d) | (c & d)) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)

                for k, s in [(0, 3), (4, 5), (8, 9), (12, 13),
                             (1, 3), (5, 5), (9, 9), (13, 13),
                             (2, 3), (6, 5), (10, 9), (14, 13),
                             (3, 3), (7, 5), (11, 9), (15, 13)]:
                    a = R2(a, b, c, d, k, s); a, b, c, d = d, a, b, c  # noqa: E702

                def R3(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
                    return _rol((a + (b ^ c ^ d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

                for k, s in [(0, 3), (8, 9), (4, 11), (12, 15),
                             (2, 3), (10, 9), (6, 11), (14, 15),
                             (1, 3), (9, 9), (5, 11), (13, 15),
                             (3, 3), (11, 9), (7, 11), (15, 15)]:
                    a = R3(a, b, c, d, k, s); a, b, c, d = d, a, b, c  # noqa: E702

                a = (a + aa) & 0xFFFFFFFF
                b = (b + bb) & 0xFFFFFFFF
                c = (c + cc) & 0xFFFFFFFF
                d = (d + dd) & 0xFFFFFFFF
            return struct.pack("<4I", a, b, c, d).hex()

        for candidate in candidates:
            if _md4((candidate + salted_suffix).encode("utf-16-le")) == target_lower:
                return (candidate, "NTLM")
        return None

    # --- auto-detection (stdlib + NTLM) ---
    if hash_type_name in _AUTO_SENTINELS:
        import struct as _struct  # noqa: PLC0415

        def _md4_auto(data: bytes) -> str:
            def _rol(x: int, n: int) -> int:
                return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

            msg = bytearray(data)
            orig_bit_len = len(data) * 8
            msg.append(0x80)
            while len(msg) % 64 != 56:
                msg.append(0x00)
            msg += _struct.pack("<Q", orig_bit_len)
            a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
            for off in range(0, len(msg), 64):
                X = list(_struct.unpack("<16I", msg[off : off + 64]))
                aa, bb, cc, dd = a, b, c, d

                def R1(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
                    return _rol((a + ((b & c) | (~b & d)) + X[k]) & 0xFFFFFFFF, s)

                for k, s in [(0, 3), (1, 7), (2, 11), (3, 19),
                             (4, 3), (5, 7), (6, 11), (7, 19),
                             (8, 3), (9, 7), (10, 11), (11, 19),
                             (12, 3), (13, 7), (14, 11), (15, 19)]:
                    a = R1(a, b, c, d, k, s); a, b, c, d = d, a, b, c  # noqa: E702

                def R2(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
                    return _rol((a + ((b & c) | (b & d) | (c & d)) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)

                for k, s in [(0, 3), (4, 5), (8, 9), (12, 13),
                             (1, 3), (5, 5), (9, 9), (13, 13),
                             (2, 3), (6, 5), (10, 9), (14, 13),
                             (3, 3), (7, 5), (11, 9), (15, 13)]:
                    a = R2(a, b, c, d, k, s); a, b, c, d = d, a, b, c  # noqa: E702

                def R3(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
                    return _rol((a + (b ^ c ^ d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

                for k, s in [(0, 3), (8, 9), (4, 11), (12, 15),
                             (2, 3), (10, 9), (6, 11), (14, 15),
                             (1, 3), (9, 9), (5, 11), (13, 15),
                             (3, 3), (11, 9), (7, 11), (15, 15)]:
                    a = R3(a, b, c, d, k, s); a, b, c, d = d, a, b, c  # noqa: E702

                a = (a + aa) & 0xFFFFFFFF
                b = (b + bb) & 0xFFFFFFFF
                c = (c + cc) & 0xFFFFFFFF
                d = (d + dd) & 0xFFFFFFFF
            return _struct.pack("<4I", a, b, c, d).hex()

        algo_names = list(_STDLIB_HASH_NAMES.items())
        for candidate in candidates:
            salted = candidate + salted_suffix
            encoded = salted.encode("utf-8")
            for ht_name, algo in algo_names:
                if hashlib.new(algo, encoded).hexdigest() == target_lower:
                    return (candidate, ht_name)
            # Also try NTLM in auto mode
            if _md4_auto(salted.encode("utf-16-le")) == target_lower:
                return (candidate, "NTLM")
        return None

    # --- stdlib fast path (MD5, SHA1, SHA256, etc.) ---
    algo = _STDLIB_HASH_NAMES.get(hash_type_name)
    if algo is not None:
        for candidate in candidates:
            encoded = (candidate + salted_suffix).encode("utf-8")
            if hashlib.new(algo, encoded).hexdigest() == target_lower:
                return (candidate, hash_type_name)
        return None

    # --- general fallback: use hashers.verify for all other types ---
    from smartcrack.hashers import verify  # noqa: PLC0415
    from smartcrack.models import HashTarget, HashType  # noqa: PLC0415

    try:
        ht = HashType[hash_type_name]
    except KeyError:
        return None

    target = HashTarget(hash_value=hash_value, hash_type=ht, salt=salt)
    for candidate in candidates:
        if verify(candidate, target):
            return (candidate, hash_type_name)
    return None


# ---------------------------------------------------------------------------
# Chunking utility
# ---------------------------------------------------------------------------


def _chunk_iter(iterable: Iterator[str], size: int) -> Iterator[list[str]]:
    """Yield successive non-overlapping lists of *size* items from *iterable*.

    Does not materialise the full stream; suitable for large wordlists.
    """
    chunk: list[str] = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) == size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


# ---------------------------------------------------------------------------
# Parallel cracker
# ---------------------------------------------------------------------------


def crack_parallel(
    target: HashTarget,
    candidates: Iterator[str],
    max_workers: int | None = None,
    batch_size: int = 10_000,
    on_progress: Callable[[int], None] | None = None,
) -> CrackResult:
    """Crack *target* using a ``ProcessPoolExecutor``.

    Submits chunks of *batch_size* candidates as futures and uses
    ``as_completed`` for early termination on first match.

    Args:
        target:      The hash to crack.
        candidates:  Iterator of plaintext candidates.
        max_workers: Worker count (defaults to ``os.cpu_count()``).
        batch_size:  Candidates per submitted chunk.
        on_progress: Called with the number of candidates in each completed
                     chunk (whether or not it contained a match).

    Returns:
        A :class:`~smartcrack.models.CrackResult` describing the outcome.
    """
    workers = max_workers or os.cpu_count() or 1
    hash_type_name = target.hash_type.name  # e.g. "MD5", "UNKNOWN"
    window_size = workers * 2  # bounded submission window

    start = time.perf_counter()
    total_attempts = 0
    found_plaintext: str | None = None
    found_type_name: str | None = None

    with ProcessPoolExecutor(max_workers=workers) as executor:
        pending: dict[Future[tuple[str, str] | None], int] = {}
        chunk_gen = _chunk_iter(candidates, batch_size)

        def _submit_one() -> bool:
            """Submit the next chunk. Returns False when generator is exhausted."""
            try:
                chunk = next(chunk_gen)
            except StopIteration:
                return False
            future = executor.submit(
                _check_chunk, chunk, target.hash_value, hash_type_name, target.salt
            )
            pending[future] = len(chunk)
            return True

        # Prime the window
        for _ in range(window_size):
            if not _submit_one():
                break

        while pending:
            done = next(iter(as_completed(pending)))
            chunk_size = pending.pop(done)
            total_attempts += chunk_size

            try:
                result = done.result()
            except Exception:
                logger.warning("Worker process error", exc_info=True)
                result = None

            if on_progress is not None:
                on_progress(chunk_size)

            if result is not None:
                found_plaintext, found_type_name = result
                for fut in pending:
                    fut.cancel()
                break

            # Refill the window
            _submit_one()

    duration = time.perf_counter() - start

    if found_plaintext is not None and found_type_name is not None:
        resolved_type = _resolve_hash_type(found_type_name)
        return CrackResult(
            found=True,
            plaintext=found_plaintext,
            hash_type=resolved_type,
            attempts=total_attempts,
            duration_seconds=duration,
        )

    return CrackResult(
        found=False,
        attempts=total_attempts,
        duration_seconds=duration,
    )


# ---------------------------------------------------------------------------
# Sequential cracker
# ---------------------------------------------------------------------------


def crack_sequential(
    target: HashTarget,
    candidates: Iterator[str],
    on_progress: Callable[[int], None] | None = None,
) -> CrackResult:
    """Crack *target* in a single thread — useful for small wordlists and tests.

    Uses :func:`~smartcrack.hashers.verify_any` which handles auto-detection
    when the target hash type is ``UNKNOWN``.

    Args:
        target:      The hash to crack.
        candidates:  Iterator of plaintext candidates.
        on_progress: Called once per candidate with ``1``.

    Returns:
        A :class:`~smartcrack.models.CrackResult` describing the outcome.
    """
    start = time.perf_counter()
    attempts = 0

    for candidate in candidates:
        attempts += 1
        if on_progress is not None:
            on_progress(1)

        matched_type = verify_any(candidate, target)
        if matched_type is not None:
            duration = time.perf_counter() - start
            return CrackResult(
                found=True,
                plaintext=candidate,
                hash_type=matched_type,
                attempts=attempts,
                duration_seconds=duration,
            )

    duration = time.perf_counter() - start
    return CrackResult(found=False, attempts=attempts, duration_seconds=duration)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_hash_type(name: str) -> HashType:
    """Convert a hash type name string back to a :class:`~smartcrack.models.HashType`."""
    try:
        return HashType[name]
    except KeyError:
        return HashType.UNKNOWN
