"""
gateway/role_map.py — per-profile role-map loader and tool-catalog filter.

Implements Decision C from 2026-05-14-hermes-role-map-spec.md.
Ported from ~/.hermes/profiles/sandbox-role-test/validate_filter.py
(resolve_role + filter_catalog). Sandbox is the ground truth; changes to the
filter logic must be reflected in both files and re-validated with:
  python3 ~/.hermes/profiles/sandbox-role-test/validate_filter.py

Adoption is opt-in per profile: profiles without config/role-map.yaml +
config/role-tools.yaml return None from from_profile_dir() and receive the
full unfiltered catalog (legacy behaviour).

See ~/Obsidian/Henry/AI Infrastructure/decisions/2026-05-14-hermes-role-map-spec.md
and 2026-05-15-hermes-architecture-validation-report.md for the rationale.
"""
from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import List, Optional

import yaml

logger = logging.getLogger(__name__)


class RoleMap:
    """Per-profile role resolution + tool-catalog filter.

    Two yamls drive behaviour:
      * role-map.yaml   identity -> role tag
      * role-tools.yaml role tag -> allowlist + per-role deny + global_deny

    Both are loaded once at profile boot. Hot-reload is not implemented (v1);
    yaml changes require a gateway restart.
    """

    def __init__(self, role_map: dict, role_tools: dict, profile_name: str) -> None:
        self._role_map = role_map
        self._role_tools = role_tools
        self._profile_name = profile_name
        logger.info("role-map active for profile %s", profile_name)

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    @classmethod
    def from_profile_dir(cls, profile_dir: Path) -> Optional["RoleMap"]:
        """Load from <profile_dir>/config/role-map.yaml + role-tools.yaml.

        Returns None when either file is absent — caller falls back to
        legacy full-catalog behaviour. Never raises; parse errors are
        logged and treated as absent.
        """
        role_map_path = profile_dir / "config" / "role-map.yaml"
        role_tools_path = profile_dir / "config" / "role-tools.yaml"

        if not role_map_path.exists() or not role_tools_path.exists():
            return None

        try:
            role_map = cls._load_yaml(role_map_path)
            role_tools = cls._load_yaml(role_tools_path)
        except Exception as exc:
            logger.warning(
                "role-map load failed for %s — falling back to full catalog: %s",
                profile_dir,
                exc,
            )
            return None

        profile_name = profile_dir.name
        return cls(role_map, role_tools, profile_name)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve_role(self, entry_point: str, identity: str, channel: str) -> str:
        """Resolve (entry_point, identity, channel) -> role tag.

        - entry_point and identity match exactly.
        - channel '*' in the yaml matches any channel.
        - No match -> default_role (typically 'guest').

        Identity is server-derived. Never trust a client-supplied role claim.
        """
        for entry in self._role_map.get("entries", []):
            if entry.get("entry_point") != entry_point:
                continue
            if entry.get("identity") != identity:
                continue
            ch = entry.get("channel")
            if ch != "*" and ch != channel:
                continue
            return entry.get("role")
        return self._role_map.get("default_role", "guest")

    def filter_catalog(self, universe: List[str], role: str) -> List[str]:
        """Three-stage filter pipeline (canonical order, load-bearing):

          1. role.allow  -> candidate set (deny-by-default start).
          2. role.deny   -> explicit per-role redactions.
          3. global_deny -> profile-wide ban list (applied last).

        global_deny last prevents a wildcard allow from re-granting a
        globally banned tool.

        Unknown role -> [] (fail-closed). Never trust a missing role entry.
        """
        role_cfg = self._role_tools.get("roles", {}).get(role)
        if role_cfg is None:
            logger.warning(
                "role '%s' not found in role-tools.yaml for profile %s — "
                "returning empty catalog (fail-closed)",
                role,
                self._profile_name,
            )
            return []

        allow_patterns: List[str] = role_cfg.get("allow") or []
        deny_patterns: List[str] = role_cfg.get("deny") or []
        global_deny: List[str] = self._role_tools.get("global_deny") or []

        candidates = [t for t in universe if self._matches_any(t, allow_patterns)]
        candidates = [t for t in candidates if not self._matches_any(t, deny_patterns)]
        candidates = [t for t in candidates if not self._matches_any(t, global_deny)]
        return sorted(candidates)

    def persona_overlay(self, role: str) -> Optional[str]:
        """Return persona_overlay text for the given role, or None."""
        role_cfg = self._role_tools.get("roles", {}).get(role)
        if not role_cfg:
            return None
        overlay = role_cfg.get("persona_overlay")
        return overlay.strip() if overlay else None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _load_yaml(path: Path) -> dict:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    @staticmethod
    def _matches_any(tool: str, patterns: List[str]) -> bool:
        return any(fnmatch.fnmatchcase(tool, pat) for pat in patterns)
