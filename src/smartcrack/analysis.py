"""Password analysis engine — entropy, patterns, and audit reporting."""
from __future__ import annotations
import math
import re
from dataclasses import dataclass
from collections import Counter

_KEYBOARD_WALKS = {"qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "123456", "654321"}
_LEET_MAP = {"@": "a", "0": "o", "1": "i", "3": "e", "$": "s", "!": "i", "7": "t"}
_COMMON_YEARS = set(str(y) for y in range(1950, 2030))
_SEQUENTIAL = {"abc", "bcd", "cde", "def", "123", "234", "345", "456", "567", "678", "789"}

@dataclass(frozen=True)
class PasswordAnalysis:
    password: str
    entropy: float
    patterns: list[str]
    strength: str
    length: int
    charset_size: int

@dataclass
class AuditSummary:
    total: int
    avg_entropy: float
    strength_distribution: dict[str, int]
    pattern_distribution: dict[str, int]
    policy_failures: int
    weakest_passwords: list[str]
    recommendations: list[str]

def calculate_entropy(password: str) -> float:
    """Compute password entropy using Shannon entropy plus a character-class diversity bonus.

    The Shannon component rewards actual character diversity within the password.
    The bonus rewards using multiple character classes (lower, upper, digit, special),
    incentivising mixed-class passwords over single-class ones of the same length.
    """
    if not password:
        return 0.0
    counts = Counter(password)
    length = len(password)
    shannon = 0.0
    for count in counts.values():
        p = count / length
        shannon -= p * math.log2(p)
    shannon_total = shannon * length

    categories = 0
    if re.search(r"[a-z]", password):
        categories += 1
    if re.search(r"[A-Z]", password):
        categories += 1
    if re.search(r"[0-9]", password):
        categories += 1
    if re.search(r"[^a-zA-Z0-9]", password):
        categories += 1
    # Each additional character class beyond the first contributes 0.5 bits per character.
    category_bonus = (categories - 1) * length * 0.5
    return shannon_total + category_bonus

def detect_patterns(password: str) -> list[str]:
    patterns = []
    lower = password.lower()

    for walk in _KEYBOARD_WALKS:
        if walk in lower:
            patterns.append("keyboard_walk")
            break

    deleet = lower
    for leet, plain in _LEET_MAP.items():
        deleet = deleet.replace(leet, plain)
    if deleet != lower:
        patterns.append("leet_speak")

    if re.match(r"^[a-z]+\d{4}$", lower) and lower[-4:] in _COMMON_YEARS:
        patterns.append("name+year")

    for seq in _SEQUENTIAL:
        if seq in lower:
            patterns.append("sequential")
            break

    if re.search(r"(.)\1{2,}", password):
        patterns.append("repeated_chars")

    if password.isdigit():
        patterns.append("digits_only")

    if re.search(r"(123|!|1|2024|2025)$", password):
        patterns.append("common_suffix")

    return patterns

def _charset_size(password: str) -> int:
    """Return the theoretical charset size based on character classes present."""
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset += 32
    return charset


def analyze_password(password: str) -> PasswordAnalysis:
    entropy = calculate_entropy(password)
    patterns = detect_patterns(password)

    if entropy < 28:
        strength = "weak"
    elif entropy < 40:
        strength = "moderate"
    elif entropy < 70:
        strength = "strong"
    else:
        strength = "very_strong"

    return PasswordAnalysis(
        password=password,
        entropy=entropy,
        patterns=patterns,
        strength=strength,
        length=len(password),
        charset_size=_charset_size(password),
    )

def generate_audit_summary(passwords: list[str]) -> AuditSummary:
    if not passwords:
        return AuditSummary(
            total=0, avg_entropy=0, strength_distribution={},
            pattern_distribution={}, policy_failures=0,
            weakest_passwords=[], recommendations=[],
        )

    analyses = [analyze_password(p) for p in passwords]
    strength_dist = Counter(a.strength for a in analyses)
    pattern_dist: Counter[str] = Counter()
    for a in analyses:
        for p in a.patterns:
            pattern_dist[p] += 1

    avg_entropy = sum(a.entropy for a in analyses) / len(analyses)

    failures = 0
    for p in passwords:
        if (len(p) < 8 or not re.search(r"[A-Z]", p) or
                not re.search(r"[0-9]", p) or not re.search(r"[^a-zA-Z0-9]", p)):
            failures += 1

    weakest = sorted(analyses, key=lambda a: a.entropy)[:5]

    recommendations = []
    if strength_dist.get("weak", 0) > len(analyses) * 0.3:
        recommendations.append("Over 30% of passwords are weak. Enforce minimum complexity policy.")
    if pattern_dist.get("name+year", 0) > 3:
        recommendations.append("Multiple passwords follow name+year pattern. Educate users on password diversity.")
    if pattern_dist.get("keyboard_walk", 0) > 2:
        recommendations.append("Keyboard walk patterns detected. Consider blocking common sequences.")
    if failures > len(analyses) * 0.5:
        recommendations.append("Over 50% fail basic policy. Implement password strength meter at creation time.")

    return AuditSummary(
        total=len(passwords),
        avg_entropy=avg_entropy,
        strength_distribution=dict(strength_dist),
        pattern_distribution=dict(pattern_dist),
        policy_failures=failures,
        weakest_passwords=[a.password for a in weakest],
        recommendations=recommendations,
    )
