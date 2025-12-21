from unittest.mock import patch, MagicMock
from smartcrack.osint.username_enum import check_platform, enumerate_username, Platform, PlatformResult
from smartcrack.osint.profile_builder import build_profile_from_findings

def test_platform_dataclass():
    p = Platform(name="github", url_template="https://github.com/{}", check_type="status_code")
    assert p.name == "github"
    assert "github.com" in p.url_template

def test_check_platform_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("httpx.get", return_value=mock_resp):
        result = check_platform("testuser", Platform("github", "https://github.com/{}", "status_code"))
    assert result.found is True
    assert result.platform == "github"

def test_check_platform_not_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("httpx.get", return_value=mock_resp):
        result = check_platform("testuser", Platform("github", "https://github.com/{}", "status_code"))
    assert result.found is False

def test_check_platform_error():
    with patch("httpx.get", side_effect=Exception("timeout")):
        result = check_platform("testuser", Platform("github", "https://github.com/{}", "status_code"))
    assert result.found is False

def test_enumerate_username():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    platforms = (
        Platform("test1", "https://test1.com/{}", "status_code"),
        Platform("test2", "https://test2.com/{}", "status_code"),
    )
    with patch("httpx.get", return_value=mock_resp):
        results = list(enumerate_username("testuser", platforms))
    assert len(results) == 2
    assert all(isinstance(r, PlatformResult) for r in results)

def test_build_profile_from_findings():
    findings = {
        "username": "johndoe",
        "platforms": ["github", "twitter"],
        "display_name": "John Doe",
        "bio_keywords": ["python", "guitar", "london"],
    }
    profile = build_profile_from_findings(findings)
    assert profile.first_name == "John"
    assert profile.last_name == "Doe"
    assert "python" in profile.keywords
    assert "johndoe" in profile.keywords

def test_build_profile_empty_findings():
    profile = build_profile_from_findings({})
    assert profile.first_name == ""
    assert profile.last_name == ""

def test_build_profile_single_name():
    findings = {"display_name": "Madonna", "username": "madonna"}
    profile = build_profile_from_findings(findings)
    assert profile.first_name == "Madonna"
    assert profile.last_name == ""

def test_platform_result_dataclass():
    r = PlatformResult(platform="github", url="https://github.com/test", found=True)
    assert r.found is True
