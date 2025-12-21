"""Tests for the parallel and sequential cracking engines."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator


from smartcrack.cracker import _check_chunk, _chunk_iter, crack_parallel, crack_sequential, recommended_batch_size
from smartcrack.models import HashTarget, HashType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wordlist(target: str, size: int = 50) -> list[str]:
    """Build a small wordlist of `size` filler words with `target` in the middle."""
    filler = [f"word{i}" for i in range(size)]
    mid = size // 2
    filler.insert(mid, target)
    return filler


def _iter(words: list[str]) -> Iterator[str]:
    return iter(words)


# ---------------------------------------------------------------------------
# _chunk_iter
# ---------------------------------------------------------------------------


class TestChunkIter:
    def test_even_split(self) -> None:
        result = list(_chunk_iter(iter(range(10)), 5))  # type: ignore[arg-type]
        assert result == [list(range(5)), list(range(5, 10))]

    def test_uneven_split(self) -> None:
        result = list(_chunk_iter(iter(range(7)), 3))  # type: ignore[arg-type]
        assert result == [[0, 1, 2], [3, 4, 5], [6]]

    def test_empty(self) -> None:
        assert list(_chunk_iter(iter([]), 5)) == []  # type: ignore[arg-type]

    def test_smaller_than_chunk_size(self) -> None:
        result = list(_chunk_iter(iter(["a", "b"]), 10))  # type: ignore[arg-type]
        assert result == [["a", "b"]]

    def test_exact_chunk_size(self) -> None:
        result = list(_chunk_iter(iter(["x", "y", "z"]), 3))  # type: ignore[arg-type]
        assert result == [["x", "y", "z"]]


# ---------------------------------------------------------------------------
# crack_sequential
# ---------------------------------------------------------------------------


class TestCrackSequential:
    def test_finds_known_md5(self) -> None:
        plaintext = "password"
        hash_value = hashlib.md5(b"password").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        words = _wordlist(plaintext)

        result = crack_sequential(target, _iter(words))

        assert result.found is True
        assert result.plaintext == plaintext
        assert result.hash_type == HashType.MD5
        assert result.attempts > 0
        assert result.duration_seconds >= 0.0

    def test_not_found(self) -> None:
        hash_value = hashlib.md5(b"notinlist").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        words = [f"word{i}" for i in range(20)]

        result = crack_sequential(target, _iter(words))

        assert result.found is False
        assert result.plaintext is None
        assert result.attempts == len(words)

    def test_progress_callback_called(self) -> None:
        plaintext = "hello"
        hash_value = hashlib.sha256(b"hello").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.SHA256)
        words = _wordlist(plaintext, size=20)

        calls: list[int] = []
        result = crack_sequential(target, _iter(words), on_progress=calls.append)

        assert result.found is True
        assert len(calls) == result.attempts
        assert all(c == 1 for c in calls)

    def test_with_salt(self) -> None:
        plaintext = "admin"
        salt = "mysalt"
        hash_value = hashlib.md5(f"{plaintext}{salt}".encode()).hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5, salt=salt)
        words = _wordlist(plaintext, size=30)

        result = crack_sequential(target, _iter(words))

        assert result.found is True
        assert result.plaintext == plaintext

    def test_auto_detect_hash_type(self) -> None:
        plaintext = "hello"
        hash_value = hashlib.sha256(b"hello").hexdigest()
        # HashType.UNKNOWN triggers auto-detection in verify_any
        target = HashTarget(hash_value=hash_value, hash_type=HashType.UNKNOWN)
        words = _wordlist(plaintext, size=20)

        result = crack_sequential(target, _iter(words))

        assert result.found is True
        assert result.plaintext == plaintext
        assert result.hash_type == HashType.SHA256

    def test_returns_correct_hash_type_sha1(self) -> None:
        plaintext = "test123"
        hash_value = hashlib.sha1(b"test123").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.SHA1)
        words = _wordlist(plaintext, size=20)

        result = crack_sequential(target, _iter(words))

        assert result.found is True
        assert result.hash_type == HashType.SHA1


# ---------------------------------------------------------------------------
# crack_parallel
# ---------------------------------------------------------------------------


class TestCrackParallel:
    def test_finds_known_md5_two_workers(self) -> None:
        plaintext = "password"
        hash_value = hashlib.md5(b"password").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        words = _wordlist(plaintext, size=80)

        result = crack_parallel(target, _iter(words), max_workers=2, batch_size=20)

        assert result.found is True
        assert result.plaintext == plaintext
        assert result.hash_type == HashType.MD5

    def test_finds_with_one_worker(self) -> None:
        plaintext = "hello"
        hash_value = hashlib.sha256(b"hello").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.SHA256)
        words = _wordlist(plaintext, size=60)

        result = crack_parallel(target, _iter(words), max_workers=1, batch_size=15)

        assert result.found is True
        assert result.plaintext == plaintext

    def test_not_found(self) -> None:
        hash_value = hashlib.md5(b"notinlist").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        words = [f"word{i}" for i in range(50)]

        result = crack_parallel(target, _iter(words), max_workers=2, batch_size=10)

        assert result.found is False
        assert result.attempts == len(words)

    def test_progress_callback_called(self) -> None:
        plaintext = "admin"
        hash_value = hashlib.md5(b"admin").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.MD5)
        words = _wordlist(plaintext, size=40)

        calls: list[int] = []
        result = crack_parallel(
            target, _iter(words), max_workers=2, batch_size=10, on_progress=calls.append
        )

        assert result.found is True
        # At least one progress call must have been made
        assert len(calls) >= 1
        # Each call value should be a positive int (chunk size)
        assert all(c > 0 for c in calls)

    def test_with_salt(self) -> None:
        plaintext = "root"
        salt = "abc"
        hash_value = hashlib.sha256(f"{plaintext}{salt}".encode()).hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.SHA256, salt=salt)
        words = _wordlist(plaintext, size=40)

        result = crack_parallel(target, _iter(words), max_workers=2, batch_size=10)

        assert result.found is True
        assert result.plaintext == plaintext

    def test_auto_detect_hash_type(self) -> None:
        plaintext = "hello"
        hash_value = hashlib.md5(b"hello").hexdigest()
        target = HashTarget(hash_value=hash_value, hash_type=HashType.UNKNOWN)
        words = _wordlist(plaintext, size=30)

        result = crack_parallel(target, _iter(words), max_workers=2, batch_size=10)

        assert result.found is True
        assert result.plaintext == plaintext
        # UNKNOWN triggers auto-detect; resolved type must be MD5
        assert result.hash_type == HashType.MD5

    def test_early_termination_result_correct(self) -> None:
        """Result is correct even when many futures are still pending."""
        plaintext = "target"
        hash_value = hashlib.sha1(b"target").hexdigest()
        # Put the target near the start so many chunks remain after it's found
        words = [plaintext] + [f"filler{i}" for i in range(90)]
        target = HashTarget(hash_value=hash_value, hash_type=HashType.SHA1)

        result = crack_parallel(target, _iter(words), max_workers=2, batch_size=5)

        assert result.found is True
        assert result.plaintext == plaintext


# ---------------------------------------------------------------------------
# _check_chunk (unit tests for the worker function)
# ---------------------------------------------------------------------------


class TestCheckChunk:
    def test_finds_match(self) -> None:
        h = hashlib.md5(b"secret").hexdigest()
        result = _check_chunk(["apple", "secret", "banana"], h, "MD5", "")
        assert result == ("secret", "MD5")

    def test_no_match(self) -> None:
        h = hashlib.md5(b"nothere").hexdigest()
        result = _check_chunk(["apple", "banana"], h, "MD5", "")
        assert result is None

    def test_auto_detect(self) -> None:
        h = hashlib.sha256(b"hello").hexdigest()
        result = _check_chunk(["world", "hello"], h, "UNKNOWN", "")
        assert result == ("hello", "SHA256")

    def test_with_salt(self) -> None:
        plaintext = "pass"
        salt = "xy"
        h = hashlib.md5(f"{plaintext}{salt}".encode()).hexdigest()
        result = _check_chunk(["pass", "other"], h, "MD5", salt)
        assert result == ("pass", "MD5")

    def test_unsupported_type_returns_none(self) -> None:
        h = hashlib.md5(b"x").hexdigest()
        result = _check_chunk(["x"], h, "WHIRLPOOL", "")
        assert result is None

    def test_bcrypt_match(self) -> None:
        import bcrypt as bcrypt_lib
        hashed = bcrypt_lib.hashpw(b"mypassword", bcrypt_lib.gensalt(rounds=4)).decode()
        result = _check_chunk(["wrong1", "mypassword", "wrong2"], hashed, "BCRYPT", "")
        assert result == ("mypassword", "BCRYPT")

    def test_bcrypt_no_match(self) -> None:
        import bcrypt as bcrypt_lib
        hashed = bcrypt_lib.hashpw(b"secret", bcrypt_lib.gensalt(rounds=4)).decode()
        result = _check_chunk(["wrong1", "wrong2"], hashed, "BCRYPT", "")
        assert result is None

    def test_ntlm_match(self) -> None:
        from smartcrack.hashers import compute_hash
        ntlm_hash = compute_hash("test123", HashType.NTLM)
        result = _check_chunk(["wrong", "test123"], ntlm_hash, "NTLM", "")
        assert result == ("test123", "NTLM")

    def test_auto_detect_ntlm(self) -> None:
        from smartcrack.hashers import compute_hash
        ntlm_hash = compute_hash("hello", HashType.NTLM)
        result = _check_chunk(["world", "hello"], ntlm_hash, "UNKNOWN", "")
        assert result == ("hello", "NTLM")


# ---------------------------------------------------------------------------
# Sequential cracking — bcrypt / NTLM
# ---------------------------------------------------------------------------


def test_crack_sequential_bcrypt() -> None:
    import bcrypt as bcrypt_lib
    hashed = bcrypt_lib.hashpw(b"hello", bcrypt_lib.gensalt(rounds=4)).decode()
    target = HashTarget(hash_value=hashed, hash_type=HashType.BCRYPT)
    result = crack_sequential(target, iter(["wrong1", "wrong2", "hello", "wrong3"]))
    assert result.found is True
    assert result.plaintext == "hello"


def test_crack_sequential_ntlm() -> None:
    from smartcrack.hashers import compute_hash
    ntlm_hash = compute_hash("test123", HashType.NTLM)
    target = HashTarget(hash_value=ntlm_hash, hash_type=HashType.NTLM)
    result = crack_sequential(target, iter(["wrong", "test123"]))
    assert result.found is True


# ---------------------------------------------------------------------------
# recommended_batch_size
# ---------------------------------------------------------------------------


class TestRecommendedBatchSize:
    def test_md5_returns_10000(self) -> None:
        assert recommended_batch_size(HashType.MD5) == 10_000

    def test_sha256_returns_10000(self) -> None:
        assert recommended_batch_size(HashType.SHA256) == 10_000

    def test_bcrypt_returns_100(self) -> None:
        assert recommended_batch_size(HashType.BCRYPT) == 100

    def test_argon2_returns_100(self) -> None:
        assert recommended_batch_size(HashType.ARGON2) == 100
