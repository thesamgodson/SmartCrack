from unittest.mock import patch, MagicMock
from hashcrack.adaptive_profiler import AdaptiveProfiler, ProfileRound
from hashcrack.models import TargetProfile, LLMConfig


def _mock_llm_response(content: str):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    return mock_resp


def test_adaptive_profiler_first_round():
    config = LLMConfig(base_url="http://fake", api_key="key", model="test")
    profile = TargetProfile(first_name="John", last_name="Smith", birthdate="1990-05-15")
    profiler = AdaptiveProfiler(config, max_rounds=3)

    with patch("httpx.post", return_value=_mock_llm_response("john1990\nsmith123\npassword1")):
        round_result = profiler.generate_round(profile, failed_candidates=[], round_num=0)

    assert len(round_result.candidates) > 0


def test_adaptive_profiler_adapts_on_failure():
    config = LLMConfig(base_url="http://fake", api_key="key", model="test")
    profile = TargetProfile(first_name="John")
    profiler = AdaptiveProfiler(config, max_rounds=3)

    with patch("httpx.post", return_value=_mock_llm_response("Trying technical patterns\njohn_dev\nroot2024\nadmin_john")):
        round_result = profiler.generate_round(
            profile,
            failed_candidates=["john1990", "smith123"],
            round_num=1,
        )

    assert len(round_result.candidates) > 0


def test_confidence_scoring():
    config = LLMConfig(base_url="http://fake", api_key="key", model="test")
    profiler = AdaptiveProfiler(config, max_rounds=3)

    with patch("httpx.post", return_value=_mock_llm_response(
        "[0.9] john1990\n[0.7] smith123\n[0.3] random456"
    )):
        profile = TargetProfile(first_name="John")
        result = profiler.generate_round(profile, [], 0)
        assert result.candidates[0] == "john1990"


def test_profile_round_dataclass():
    r = ProfileRound(
        round_num=0,
        candidates=["a", "b"],
        reasoning="Initial attempt based on name patterns",
        confidence_scores={"a": 0.9, "b": 0.7},
    )
    assert r.round_num == 0
    assert len(r.candidates) == 2


def test_generate_all_rounds():
    config = LLMConfig(base_url="http://fake", api_key="key", model="test")
    profiler = AdaptiveProfiler(config, max_rounds=2)
    profile = TargetProfile(first_name="John")

    with patch("httpx.post", return_value=_mock_llm_response("[0.8] test123\n[0.6] john456")):
        rounds = list(profiler.generate_all_rounds(profile))

    assert len(rounds) == 2
    assert all(isinstance(r, ProfileRound) for r in rounds)


def test_history_tracking():
    config = LLMConfig(base_url="http://fake", api_key="key", model="test")
    profiler = AdaptiveProfiler(config, max_rounds=1)
    profile = TargetProfile(first_name="John")

    with patch("httpx.post", return_value=_mock_llm_response("[0.8] test123")):
        list(profiler.generate_all_rounds(profile))

    assert len(profiler.history) == 1


def test_max_candidates_per_round():
    config = LLMConfig(base_url="http://fake", api_key="key", model="test")
    profiler = AdaptiveProfiler(config, max_rounds=1)
    profile = TargetProfile(first_name="John")

    # Generate 600 candidates — should be capped at 500
    lines = "\n".join(f"[0.5] password{i}" for i in range(600))
    with patch("httpx.post", return_value=_mock_llm_response(lines)):
        result = profiler.generate_round(profile, [], 0)

    assert len(result.candidates) <= 500


def test_filters_long_candidates():
    config = LLMConfig(base_url="http://fake", api_key="key", model="test")
    profiler = AdaptiveProfiler(config, max_rounds=1)
    profile = TargetProfile(first_name="John")

    long_pass = "a" * 200
    with patch("httpx.post", return_value=_mock_llm_response(f"[0.5] short\n[0.5] {long_pass}")):
        result = profiler.generate_round(profile, [], 0)

    assert "short" in result.candidates
    assert long_pass not in result.candidates
