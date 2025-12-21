"""Username enumeration across platforms."""
from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Iterator

import httpx

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class Platform:
    name: str
    url_template: str
    check_type: str = "status_code"

@dataclass(frozen=True)
class PlatformResult:
    platform: str
    url: str
    found: bool

DEFAULT_PLATFORMS = (
    Platform("github", "https://github.com/{}", "status_code"),
    Platform("twitter", "https://x.com/{}", "status_code"),
    Platform("instagram", "https://www.instagram.com/{}/", "status_code"),
    Platform("reddit", "https://www.reddit.com/user/{}", "status_code"),
    Platform("linkedin", "https://www.linkedin.com/in/{}", "status_code"),
    Platform("medium", "https://medium.com/@{}", "status_code"),
    Platform("dev.to", "https://dev.to/{}", "status_code"),
    Platform("tiktok", "https://www.tiktok.com/@{}", "status_code"),
    Platform("youtube", "https://www.youtube.com/@{}", "status_code"),
    Platform("pinterest", "https://www.pinterest.com/{}/", "status_code"),
    Platform("twitch", "https://www.twitch.tv/{}", "status_code"),
    Platform("steam", "https://steamcommunity.com/id/{}", "status_code"),
)

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; security-research-tool/1.0)",
}

def check_platform(username: str, platform: Platform, timeout: float = 10.0) -> PlatformResult:
    """Check if a username exists on a platform."""
    url = platform.url_template.format(username)
    try:
        resp = httpx.get(url, headers=_HEADERS, timeout=timeout, follow_redirects=True)
        found = resp.status_code == 200
    except Exception:
        found = False
    return PlatformResult(platform=platform.name, url=url, found=found)

def enumerate_username(
    username: str,
    platforms: tuple[Platform, ...] = DEFAULT_PLATFORMS,
) -> Iterator[PlatformResult]:
    """Check username across all platforms, yielding results."""
    for platform in platforms:
        result = check_platform(username, platform)
        yield result
