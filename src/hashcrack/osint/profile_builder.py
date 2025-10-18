"""Build a TargetProfile from OSINT findings."""
from __future__ import annotations
from hashcrack.models import TargetProfile

def build_profile_from_findings(findings: dict) -> TargetProfile:
    """Convert raw OSINT findings into a TargetProfile."""
    display_name = findings.get("display_name", "")
    parts = display_name.split() if display_name else []
    first = parts[0] if len(parts) > 0 else ""
    last = parts[-1] if len(parts) > 1 else ""

    keywords = list(findings.get("bio_keywords", []))
    username = findings.get("username", "")
    if username:
        keywords.insert(0, username)

    platforms = findings.get("platforms", [])
    keywords.extend(platforms)

    return TargetProfile(
        first_name=first,
        last_name=last,
        nickname=username,
        keywords=tuple(keywords),
    )
