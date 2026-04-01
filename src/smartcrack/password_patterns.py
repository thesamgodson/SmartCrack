"""Static password pattern generators — keyboard walks, date formats, PINs, padding."""

from __future__ import annotations

from collections.abc import Iterator

# ---------------------------------------------------------------------------
# Keyboard walks — QWERTY, AZERTY, QWERTZ, numpad
# ---------------------------------------------------------------------------

_QWERTY_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

_QWERTY_ROWS_SHIFTED = [
    "~!@#$%^&*()_+",
    "QWERTYUIOP{}|",
    'ASDFGHJKL:"',
    "ZXCVBNM<>?",
]

_AZERTY_ROWS = [
    "&é\"'(-è_çà)=",
    "azertyuiop^$",
    "qsdfghjklmù",
    "wxcvbn,;:!",
]

_QWERTZ_ROWS = [
    "1234567890ß",
    "qwertzuiopü",
    "asdfghjklöä",
    "yxcvbnm,.-",
]

_NUMPAD = [
    ["7", "8", "9"],
    ["4", "5", "6"],
    ["1", "2", "3"],
    ["0"],
]

# Pre-computed canonical keyboard walks (most common in breach data)
KEYBOARD_WALKS: tuple[str, ...] = (
    # Horizontal row walks (QWERTY)
    "qwerty", "qwertyu", "qwertyui", "qwertyuiop",
    "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm",
    "qwer", "asdf", "zxcv",
    # Reversed horizontal
    "ytrewq", "lkjhgfdsa", "mnbvcxz",
    "rewq", "fdsa", "vcxz",
    # Number row
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "654321", "987654321",
    "1234", "12345",
    # Diagonal column walks (down-right from number row)
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm",
    "1qaz2wsx", "2wsx3edc", "3edc4rfv",
    "1qaz2wsx3edc", "1qaz2wsx3edc4rfv",
    # Diagonal reversed (up-left)
    "zaq1", "xsw2", "cde3", "vfr4", "bgt5", "nhy6", "mju7",
    "zaq1xsw2",
    # Sawtooth (alternating number+letter)
    "q1w2e3r4", "1q2w3e4r", "q1w2e3r4t5",
    "1q2w3e4r5t", "q1w2e3", "1q2w3e",
    # Shifted diagonal
    "!QAZ", "@WSX", "#EDC",
    "!QAZ@WSX", "@WSX#EDC",
    "!QAZ@WSX#EDC",
    # AZERTY
    "azerty", "azertyuiop", "qsdfgh", "wxcvbn",
    "ytreza",
    # QWERTZ
    "qwertz", "qwertzuiop", "yxcvbn",
    "ztrewq",
    # Numpad patterns
    "147258369", "741852963", "789456123", "321654987",
    "159357", "753159",
    "2580", "0852",
    "147", "258", "369", "741", "852", "963",
    "1470", "2580", "3690",
    "789", "456", "123",
    # Common visual patterns on numpad
    "1379", "3179", "7913", "9713",  # corners
    "1593", "3951",  # X pattern
    "24680", "86420",  # cross
)


def keyboard_walk_candidates() -> Iterator[str]:
    """Yield all canonical keyboard walk patterns with case variants."""
    seen: set[str] = set()
    for walk in KEYBOARD_WALKS:
        for variant in (walk, walk.upper(), walk.capitalize()):
            if variant not in seen:
                seen.add(variant)
                yield variant


# ---------------------------------------------------------------------------
# Date format expansion
# ---------------------------------------------------------------------------

_MONTH_NAMES = (
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
)
_MONTH_ABBREVS = (
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",
)


def expand_date_formats(birthdate: str) -> tuple[str, ...]:
    """Extract every plausible date fragment from a YYYY-MM-DD birthdate string.

    Returns: tuple of strings like '1990', '90', '0315', '15031990', 'march1990', etc.
    """
    if not birthdate or len(birthdate) < 10:
        return ()

    parts = birthdate.split("-")
    if len(parts) != 3:
        return ()

    yyyy, mm, dd = parts[0], parts[1], parts[2]
    yy = yyyy[2:]

    results: set[str] = set()

    # Core fragments
    results.update([yyyy, yy, mm, dd])
    results.add(f"0{dd}" if len(dd) == 1 else dd)
    results.add(f"0{mm}" if len(mm) == 1 else mm)

    # Full date formats
    results.add(f"{dd}{mm}{yyyy}")    # DDMMYYYY
    results.add(f"{mm}{dd}{yyyy}")    # MMDDYYYY
    results.add(f"{yyyy}{mm}{dd}")    # YYYYMMDD
    results.add(f"{dd}{mm}{yy}")      # DDMMYY
    results.add(f"{mm}{dd}{yy}")      # MMDDYY
    results.add(f"{yy}{mm}{dd}")      # YYMMDD

    # Partial date combos
    results.add(f"{dd}{mm}")          # DDMM
    results.add(f"{mm}{dd}")          # MMDD
    results.add(f"{mm}{yyyy}")        # MMYYYY
    results.add(f"{mm}{yy}")          # MMYY
    results.add(f"{yyyy}{dd}")        # YYYYDD
    results.add(f"{yyyy}{mm}")        # YYYYMM

    # Month names
    month_idx = int(mm) - 1
    if 0 <= month_idx < 12:
        mname = _MONTH_NAMES[month_idx]
        mabbrev = _MONTH_ABBREVS[month_idx]
        for mn in (mname, mname.capitalize(), mabbrev, mabbrev.capitalize()):
            results.add(mn)
            results.add(f"{mn}{yyyy}")
            results.add(f"{mn}{yy}")
            results.add(f"{dd}{mn}")
            results.add(f"{dd}{mn}{yy}")
            results.add(f"{mn}{dd}")

    # Day ordinals
    day_int = int(dd)
    if day_int == 1 or day_int == 21 or day_int == 31:
        results.add(f"{day_int}st")
    elif day_int == 2 or day_int == 22:
        results.add(f"{day_int}nd")
    elif day_int == 3 or day_int == 23:
        results.add(f"{day_int}rd")
    else:
        results.add(f"{day_int}th")

    return tuple(sorted(results))


# ---------------------------------------------------------------------------
# Year range — all years a person would reference
# ---------------------------------------------------------------------------

def year_range_numbers(birth_year: int | None = None) -> tuple[str, ...]:
    """Generate common year numbers: 1960-2026 + 2-digit variants."""
    results: set[str] = set()
    for y in range(1960, 2027):
        results.add(str(y))
        results.add(str(y)[2:])
    if birth_year:
        # Key life event years
        for offset in (6, 10, 13, 16, 18, 21, 25, 30):
            event_year = birth_year + offset
            if 1960 <= event_year <= 2026:
                results.add(str(event_year))
                results.add(str(event_year)[2:])
    return tuple(sorted(results))


# ---------------------------------------------------------------------------
# Padding patterns
# ---------------------------------------------------------------------------

def padding_candidates(token: str) -> Iterator[str]:
    """Generate padding variants: repeated chars, symbol wraps, trailing sequences."""
    if not token or len(token) < 3:
        return

    # Trailing repeated digits
    for digit in "01":
        for count in range(2, 5):
            yield f"{token}{digit * count}"

    # Trailing ascending sequences
    for seq in ("123", "1234", "12345", "123456"):
        yield f"{token}{seq}"

    # Leading zeros
    for count in range(1, 4):
        yield f"{'0' * count}{token}"

    # Symbol wrapping (same char both sides)
    for char in ("!", "#", "*", "@", "$"):
        yield f"{char}{token}{char}"
        yield f"{char}{char}{token}{char}{char}"

    # Trailing double/triple special
    for char in ("!", "@", "#", "$"):
        yield f"{token}{char}{char}"
        yield f"{token}{char}{char}{char}"

    # Trailing combos
    yield f"{token}123!"
    yield f"{token}!123"


# ---------------------------------------------------------------------------
# Sandwich / wrapping patterns
# ---------------------------------------------------------------------------

def sandwich_candidates(token: str, numbers: tuple[str, ...]) -> Iterator[str]:
    """Generate sandwich patterns: number-word-number, symbol-word-symbol."""
    if not token:
        return

    for num in numbers:
        yield f"{num}{token}{num}"
        yield f"{num}{token.capitalize()}{num}"

    for char in ("!", "#", "*", "1"):
        yield f"{char}{token}{char}"
        yield f"{char}{token.capitalize()}{char}"


# ---------------------------------------------------------------------------
# Word doubling variants
# ---------------------------------------------------------------------------

def doubling_candidates(token: str) -> Iterator[str]:
    """Generate doubled/mirrored variants of a token."""
    if not token or len(token) < 4:
        return

    lower = token.lower()
    cap = token.capitalize()

    yield f"{lower}{lower}"         # johnJohn
    yield f"{lower}{cap}"           # johnJohn
    yield f"{cap}{lower}"           # Johnjohn
    yield f"{cap}{cap}"             # JohnJohn
    yield f"{lower}{lower}1"
    yield f"{cap}{lower}1"
    yield f"{lower}{lower[::-1]}"   # johnnjoh


# ---------------------------------------------------------------------------
# PIN / numeric-only patterns
# ---------------------------------------------------------------------------

PIN_PATTERNS: tuple[str, ...] = (
    # Repeated single digits
    "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
    "000000", "111111",
    # Repeated pairs
    "1212", "1313", "1414", "2323", "3434", "4545", "5656", "6767", "6969", "7878",
    # Ascending/descending
    "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
    "4321", "54321", "654321", "7654321", "87654321", "987654321",
    "0123456789",
    # Numpad cross
    "2580", "0852", "8520", "0258",
    # Mirrored
    "1221", "12321", "123321", "12344321",
    # Common PINs from breach data
    "0000", "1234", "1111", "0852", "2580",
    "1010", "2020", "2024", "2025", "2026",
)


# ---------------------------------------------------------------------------
# Position-targeted leet (first-only, last-only, cap+leet)
# ---------------------------------------------------------------------------

_LEET_MAP = {"a": "@", "e": "3", "o": "0", "s": "$", "i": "1", "t": "7"}
_LEET_MAP_ALT = {"a": "4", "e": "3", "o": "0", "s": "5", "i": "!", "t": "7"}


def position_leet_candidates(token: str) -> Iterator[str]:
    """Generate leet variants targeting specific positions only."""
    lower = token.lower()
    if len(lower) < 4:
        return

    for leet_map in (_LEET_MAP, _LEET_MAP_ALT):
        for char, repl in leet_map.items():
            if char not in lower:
                continue

            # First occurrence only
            first_idx = lower.index(char)
            first_only = lower[:first_idx] + repl + lower[first_idx + 1:]
            if first_only != lower:
                yield first_only

            # Last occurrence only
            last_idx = lower.rindex(char)
            if last_idx != first_idx:
                last_only = lower[:last_idx] + repl + lower[last_idx + 1:]
                if last_only != lower:
                    yield last_only

    # Capitalize first + leet rest
    if len(lower) >= 2:
        rest = lower[1:]
        for leet_map in (_LEET_MAP, _LEET_MAP_ALT):
            leeted_rest = rest
            for char, repl in leet_map.items():
                leeted_rest = leeted_rest.replace(char, repl)
            if leeted_rest != rest:
                yield f"{lower[0].upper()}{leeted_rest}"
