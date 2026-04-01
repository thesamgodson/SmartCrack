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
_HEADER_FMT = ">4sBBIHH18x"

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
    hash_type: HashType
    entry_count: int
    hash_hex_length: int
    max_plaintext_length: int


def _hash_type_to_ordinal(ht: HashType) -> int:
    members = list(HashType)
    return members.index(ht)


def _ordinal_to_hash_type(ordinal: int) -> HashType:
    members = list(HashType)
    if 0 <= ordinal < len(members):
        return members[ordinal]
    raise ValueError(f"Unknown hash type ordinal: {ordinal}")


def _write_header(f, header: RainbowTableHeader) -> None:  # noqa: ANN001
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
    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    if hash_type not in _SUPPORTED_TYPES:
        raise ValueError(
            f"Unsupported hash type for rainbow tables: {hash_type}. "
            f"Supported: {', '.join(t.name for t in sorted(_SUPPORTED_TYPES, key=lambda t: t.name))}"
        )

    hex_len = _HEX_LENGTHS[hash_type]

    entries: list[tuple[str, str]] = []
    hash_fn = HASH_FUNCTIONS.get(hash_type)

    with open(wordlist_path, "r", encoding="iso-8859-1") as f:
        for line in f:
            plaintext = line.rstrip("\n\r")
            if not plaintext:
                continue
            if len(plaintext.encode("utf-8")) > max_plaintext_length:
                continue

            if hash_type == HashType.NTLM:
                from smartcrack.hashers import _compute_ntlm
                hex_digest = _compute_ntlm(plaintext)
            else:
                if hash_fn is None:
                    raise ValueError(f"No hash function for {hash_type}")
                hex_digest = hash_fn(plaintext.encode("utf-8")).hexdigest()

            entries.append((hex_digest.lower(), plaintext))

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
