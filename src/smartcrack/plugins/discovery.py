"""Plugin discovery via importlib.metadata entry_points."""
from __future__ import annotations
import importlib.metadata

_ENTRY_POINT_GROUPS = {
    "hash": "smartcrack.hash_plugins",
    "attack": "smartcrack.attack_plugins",
    "profiler": "smartcrack.profiler_plugins",
}


def discover_plugins(group: str) -> list[object]:
    """Discover and load plugins from the given entry point group."""
    ep_group = _ENTRY_POINT_GROUPS.get(group, group)
    plugins = []
    for ep in importlib.metadata.entry_points(group=ep_group):
        try:
            plugin_cls = ep.load()
            plugins.append(plugin_cls())
        except Exception:
            continue
    return plugins


def list_plugins() -> dict[str, list[str]]:
    """List all discovered plugin names by group."""
    result = {}
    for group, ep_group in _ENTRY_POINT_GROUPS.items():
        names = []
        for ep in importlib.metadata.entry_points(group=ep_group):
            names.append(ep.name)
        result[group] = names
    return result
