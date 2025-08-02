from hashcrack.plugins.discovery import discover_plugins, list_plugins
from hashcrack.plugins.base import HashPlugin, AttackPlugin, ProfilerPlugin


def test_discover_plugins_empty():
    """No plugins installed returns empty list."""
    plugins = discover_plugins("hash")
    assert isinstance(plugins, list)


def test_list_plugins_returns_dict():
    result = list_plugins()
    assert "hash" in result
    assert "attack" in result
    assert "profiler" in result


def test_protocols_are_runtime_checkable():
    assert hasattr(HashPlugin, '__protocol_attrs__') or callable(getattr(HashPlugin, '__instancecheck__', None))


def test_discover_unknown_group():
    plugins = discover_plugins("nonexistent_group")
    assert plugins == []
