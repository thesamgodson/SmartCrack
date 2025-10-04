"""Batch hash processing with deduplication and file parsing."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

from hashcrack.models import HashType, CrackResult
from hashcrack.hash_id import identify_hash

@dataclass
class BatchJob:
    hash_value: str
    salt: str = ""
    hash_type: HashType | None = None

@dataclass
class BatchResult:
    total: int
    cracked: int
    failed: int
    results: dict[str, CrackResult]

    @property
    def success_rate(self) -> float:
        return self.cracked / self.total if self.total > 0 else 0.0

def parse_hash_file(path: Path) -> list[BatchJob]:
    """Parse a file of hashes, one per line. Supports hash:salt format."""
    jobs = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" in stripped:
            hash_val, salt = stripped.split(":", 1)
            jobs.append(BatchJob(hash_value=hash_val.strip(), salt=salt.strip()))
        else:
            jobs.append(BatchJob(hash_value=stripped))
    return jobs

def deduplicate_hashes(jobs: list[BatchJob]) -> list[BatchJob]:
    """Remove duplicate hash+salt combinations."""
    seen: set[tuple[str, str]] = set()
    unique = []
    for job in jobs:
        key = (job.hash_value, job.salt)
        if key not in seen:
            seen.add(key)
            unique.append(job)
    return unique

def auto_type_jobs(jobs: list[BatchJob]) -> list[BatchJob]:
    """Auto-detect hash types for jobs that don't have one set."""
    for job in jobs:
        if job.hash_type is None:
            matches = identify_hash(job.hash_value)
            if matches and matches[0][1] > 0:
                job.hash_type = matches[0][0]
    return jobs
