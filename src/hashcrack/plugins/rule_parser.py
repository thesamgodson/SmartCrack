"""Parse hashcat .rule files and apply rule operations."""
from __future__ import annotations
from pathlib import Path
from typing import Iterator, Callable

_SIMPLE_RULES: dict[str, Callable[[str], str]] = {
    "l": str.lower,
    "u": str.upper,
    "c": str.capitalize,
    "r": lambda w: w[::-1],
    "d": lambda w: w + w,
    ":": lambda w: w,
}

def apply_hashcat_rule(rule_str: str, word: str) -> str:
    """Apply a hashcat rule string to a word."""
    i = 0
    result = word
    while i < len(rule_str):
        char = rule_str[i]
        if char in _SIMPLE_RULES:
            result = _SIMPLE_RULES[char](result)
            i += 1
        elif char == "$" and i + 1 < len(rule_str):
            result = result + rule_str[i + 1]
            i += 2
        elif char == "^" and i + 1 < len(rule_str):
            result = rule_str[i + 1] + result
            i += 2
        elif char == "T" and i + 1 < len(rule_str):
            pos = int(rule_str[i + 1])
            if pos < len(result):
                chars = list(result)
                chars[pos] = chars[pos].swapcase()
                result = "".join(chars)
            i += 2
        else:
            i += 1
    return result

def parse_rule_file(path: Path) -> list[str]:
    """Parse a hashcat .rule file, return list of rule strings."""
    rules = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if " #" in stripped:
            stripped = stripped[:stripped.index(" #")].strip()
        if stripped:
            rules.append(stripped)
    return rules

def rule_file_candidates(words: Iterator[str], rule_path: Path) -> Iterator[str]:
    """Apply rules from a .rule file to each word."""
    rules = parse_rule_file(rule_path)
    for word in words:
        yield word
        for rule_str in rules:
            try:
                yield apply_hashcat_rule(rule_str, word)
            except Exception:
                continue
