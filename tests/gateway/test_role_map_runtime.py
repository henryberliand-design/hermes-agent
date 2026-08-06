"""
Tests for gateway/role_map.py — RoleMap loader and filter logic.

Covers the 15 required cases from the Phase 2 Agent A brief:
  - from_profile_dir factory (absent/partial/both yamls, parse error)
  - resolve_role (exact, wildcard channel, no match, default)
  - filter_catalog (allow→deny→global_deny order, unknown role, wildcards)
  - persona_overlay (set, absent, unknown role)

Style: pytest, no class wrapper, direct asserts, tmp_path fixtures.
Mirrors gateway/tests/test_session_key_profile_prefix.py conventions.
"""

import logging
import textwrap
from pathlib import Path

import pytest
import yaml

from gateway.role_map import RoleMap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        yaml.dump(data, fh)


def _write_role_map(profile_dir: Path, data: dict) -> None:
    _write_yaml(profile_dir / "config" / "role-map.yaml", data)


def _write_role_tools(profile_dir: Path, data: dict) -> None:
    _write_yaml(profile_dir / "config" / "role-tools.yaml", data)


def _minimal_role_map() -> dict:
    """Minimal role-map.yaml with one exact entry and a default."""
    return {
        "schema_version": 1,
        "entries": [
            {"entry_point": "telegram", "identity": "111", "channel": "*", "role": "operator"},
            {"entry_point": "dashboard", "identity": "alice@example.test", "channel": "/ops", "role": "alice_ops"},
        ],
        "default_role": "guest",
    }


def _minimal_role_tools() -> dict:
    """Minimal role-tools.yaml with operator, alice_ops, and guest roles."""
    return {
        "schema_version": 1,
        "global_deny": ["tool_c"],
        "roles": {
            "operator": {
                "allow": ["tool_a", "tool_b"],
                "deny": [],
                "persona_overlay": "You are the operator. Direct and terse.",
            },
            "alice_ops": {
                "allow": ["tool_a"],
                "deny": [],
            },
            "guest": {
                "allow": ["tool_a"],
                "deny": [],
            },
        },
    }


# ---------------------------------------------------------------------------
# from_profile_dir — absent / partial / both yamls
# ---------------------------------------------------------------------------

def test_from_profile_dir_returns_none_when_yamls_absent(tmp_path):
    result = RoleMap.from_profile_dir(tmp_path)
    assert result is None


def test_from_profile_dir_returns_none_when_only_role_map_yaml_present(tmp_path):
    _write_role_map(tmp_path, _minimal_role_map())
    result = RoleMap.from_profile_dir(tmp_path)
    assert result is None


def test_from_profile_dir_returns_none_when_only_role_tools_yaml_present(tmp_path):
    _write_role_tools(tmp_path, _minimal_role_tools())
    result = RoleMap.from_profile_dir(tmp_path)
    assert result is None


def test_from_profile_dir_loads_when_both_yamls_present(tmp_path):
    _write_role_map(tmp_path, _minimal_role_map())
    _write_role_tools(tmp_path, _minimal_role_tools())
    result = RoleMap.from_profile_dir(tmp_path)
    assert isinstance(result, RoleMap)


def test_from_profile_dir_yaml_parse_error_returns_none(tmp_path, caplog):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    # Write a valid role-map but malformed role-tools
    _write_role_map(tmp_path, _minimal_role_map())
    bad_yaml = config_dir / "role-tools.yaml"
    bad_yaml.write_text("roles: [\x00invalid: yaml: {{{")

    with caplog.at_level(logging.WARNING, logger="gateway.role_map"):
        result = RoleMap.from_profile_dir(tmp_path)

    assert result is None
    assert any("role-map load failed" in r.message or "falling back" in r.message
               for r in caplog.records)


# ---------------------------------------------------------------------------
# resolve_role
# ---------------------------------------------------------------------------

def test_resolve_role_exact_match(tmp_path):
    _write_role_map(tmp_path, _minimal_role_map())
    _write_role_tools(tmp_path, _minimal_role_tools())
    rm = RoleMap.from_profile_dir(tmp_path)
    assert rm.resolve_role("telegram", "111", "DM") == "operator"


def test_resolve_role_channel_wildcard(tmp_path):
    """entry channel='*' must match any channel string."""
    role_map = {
        "schema_version": 1,
        "entries": [
            {"entry_point": "telegram", "identity": "222", "channel": "*", "role": "viewer"},
        ],
        "default_role": "guest",
    }
    role_tools = {
        "schema_version": 1,
        "global_deny": [],
        "roles": {
            "viewer": {"allow": ["tool_a"], "deny": []},
            "guest": {"allow": [], "deny": []},
        },
    }
    _write_role_map(tmp_path, role_map)
    _write_role_tools(tmp_path, role_tools)
    rm = RoleMap.from_profile_dir(tmp_path)

    for ch in ["DM", "group_999", "/ops", "anything"]:
        assert rm.resolve_role("telegram", "222", ch) == "viewer", f"failed for channel={ch!r}"


def test_resolve_role_no_match_returns_default(tmp_path):
    _write_role_map(tmp_path, _minimal_role_map())
    _write_role_tools(tmp_path, _minimal_role_tools())
    rm = RoleMap.from_profile_dir(tmp_path)
    assert rm.resolve_role("telegram", "unknown-id", "DM") == "guest"


def test_resolve_role_default_is_guest_when_unspecified(tmp_path):
    """When default_role is absent from the yaml, resolve_role falls back to 'guest'."""
    role_map = {
        "schema_version": 1,
        "entries": [
            {"entry_point": "telegram", "identity": "111", "channel": "*", "role": "operator"},
        ],
        # no default_role key
    }
    _write_role_map(tmp_path, role_map)
    _write_role_tools(tmp_path, _minimal_role_tools())
    rm = RoleMap.from_profile_dir(tmp_path)
    assert rm.resolve_role("telegram", "nobody", "DM") == "guest"


# ---------------------------------------------------------------------------
# filter_catalog
# ---------------------------------------------------------------------------

UNIVERSE = ["tool_a", "tool_b", "tool_c"]


def test_filter_catalog_allow_then_deny_then_global_deny_order(tmp_path):
    """
    Load-bearing order:
      1. allow  -> only tool_a and tool_b pass (tool_c not in allow)
      2. deny   -> tool_b removed explicitly
      3. global_deny -> tool_c would have been here; confirm it is absent
    Result for 'analyst': only tool_a.
    """
    role_map = {
        "schema_version": 1,
        "entries": [],
        "default_role": "guest",
    }
    role_tools = {
        "schema_version": 1,
        "global_deny": ["tool_c"],
        "roles": {
            "analyst": {
                "allow": ["tool_a", "tool_b"],
                "deny": ["tool_b"],
            },
            "guest": {"allow": [], "deny": []},
        },
    }
    _write_role_map(tmp_path, role_map)
    _write_role_tools(tmp_path, role_tools)
    rm = RoleMap.from_profile_dir(tmp_path)

    result = rm.filter_catalog(UNIVERSE, "analyst")
    assert result == ["tool_a"]
    assert "tool_b" not in result  # removed by role.deny
    assert "tool_c" not in result  # removed by global_deny


def test_filter_catalog_unknown_role_returns_empty_fail_closed(tmp_path, caplog):
    _write_role_map(tmp_path, _minimal_role_map())
    _write_role_tools(tmp_path, _minimal_role_tools())
    rm = RoleMap.from_profile_dir(tmp_path)

    with caplog.at_level(logging.WARNING, logger="gateway.role_map"):
        result = rm.filter_catalog(UNIVERSE, "nonexistent_role")

    assert result == []
    assert any("not found" in r.message or "fail-closed" in r.message
               for r in caplog.records)


def test_filter_catalog_wildcard_allow_pattern(tmp_path):
    """fnmatch wildcards in allow patterns should expand correctly."""
    universe = ["sandbox_echo", "sandbox_read", "sandbox_write", "other_tool"]
    role_map = {"schema_version": 1, "entries": [], "default_role": "guest"}
    role_tools = {
        "schema_version": 1,
        "global_deny": [],
        "roles": {
            "sandboxer": {
                "allow": ["sandbox_*"],
                "deny": [],
            },
            "guest": {"allow": [], "deny": []},
        },
    }
    _write_role_map(tmp_path, role_map)
    _write_role_tools(tmp_path, role_tools)
    rm = RoleMap.from_profile_dir(tmp_path)

    result = rm.filter_catalog(universe, "sandboxer")
    assert sorted(result) == ["sandbox_echo", "sandbox_read", "sandbox_write"]
    assert "other_tool" not in result


# ---------------------------------------------------------------------------
# persona_overlay
# ---------------------------------------------------------------------------

def test_persona_overlay_returns_string_when_set(tmp_path):
    _write_role_map(tmp_path, _minimal_role_map())
    _write_role_tools(tmp_path, _minimal_role_tools())
    rm = RoleMap.from_profile_dir(tmp_path)

    overlay = rm.persona_overlay("operator")
    assert isinstance(overlay, str)
    assert len(overlay) > 0
    # Must be stripped
    assert overlay == overlay.strip()


def test_persona_overlay_returns_none_when_absent(tmp_path):
    """Role exists in role-tools.yaml but has no persona_overlay key."""
    role_map = {"schema_version": 1, "entries": [], "default_role": "guest"}
    role_tools = {
        "schema_version": 1,
        "global_deny": [],
        "roles": {
            "no_overlay_role": {
                "allow": ["tool_a"],
                "deny": [],
                # persona_overlay intentionally absent
            },
        },
    }
    _write_role_map(tmp_path, role_map)
    _write_role_tools(tmp_path, role_tools)
    rm = RoleMap.from_profile_dir(tmp_path)

    assert rm.persona_overlay("no_overlay_role") is None


def test_persona_overlay_returns_none_for_unknown_role(tmp_path):
    _write_role_map(tmp_path, _minimal_role_map())
    _write_role_tools(tmp_path, _minimal_role_tools())
    rm = RoleMap.from_profile_dir(tmp_path)

    assert rm.persona_overlay("role_that_does_not_exist") is None
