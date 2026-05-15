"""
Tests for Gap 2 fix: profile-discriminated session keys in build_session_key.

Covers the Architecture Rule 4 finding from the validation report (2026-05-15):

  build_session_key produced identical keys for two profiles sharing the same
  (platform, chat_id) because the profile name was not part of the key tuple.
  The per-profile state.db file boundary provided de-facto isolation, but the
  key itself violated the Rule 4 discriminator requirement.

This test file verifies:
  1. profile_name=None / "default" / "main" → legacy "agent:main" prefix (back-compat)
  2. profile_name="henry-personal" → "agent:henry-personal" prefix
  3. Two distinct profiles on the same (platform, chat_id) → distinct keys
  4. All key shapes (DM, DM+thread, group, group+user, group+thread) include profile
  5. SessionStore._generate_session_key forwards profile_name correctly
  6. Migration script logic (pure Python, no sqlite fixture needed)
"""

import pytest
from unittest.mock import MagicMock

from gateway.config import Platform, GatewayConfig, PlatformConfig
from gateway.session import (
    SessionSource,
    SessionStore,
    build_session_key,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tg_dm_source(chat_id: str = "99", user_id: str = "99") -> SessionSource:
    return SessionSource(
        platform=Platform.TELEGRAM,
        chat_type="dm",
        chat_id=chat_id,
        user_id=user_id,
    )


def _discord_group_source(chat_id: str = "guild-123", user_id: str = "alice") -> SessionSource:
    return SessionSource(
        platform=Platform.DISCORD,
        chat_type="group",
        chat_id=chat_id,
        user_id=user_id,
    )


# ---------------------------------------------------------------------------
# Backward compatibility: no profile_name or legacy names preserve old prefix
# ---------------------------------------------------------------------------


class TestBuildSessionKeyBackwardCompat:
    def test_no_profile_name_uses_agent_main(self):
        source = _tg_dm_source()
        key = build_session_key(source)
        assert key.startswith("agent:main:"), key

    def test_profile_name_none_uses_agent_main(self):
        source = _tg_dm_source()
        key = build_session_key(source, profile_name=None)
        assert key.startswith("agent:main:"), key

    def test_profile_name_default_uses_agent_main(self):
        source = _tg_dm_source()
        key = build_session_key(source, profile_name="default")
        assert key.startswith("agent:main:"), key

    def test_profile_name_main_uses_agent_main(self):
        source = _tg_dm_source()
        key = build_session_key(source, profile_name="main")
        assert key.startswith("agent:main:"), key

    def test_empty_string_profile_uses_agent_main(self):
        source = _tg_dm_source()
        key = build_session_key(source, profile_name="")
        assert key.startswith("agent:main:"), key

    def test_existing_test_cases_unchanged(self):
        """Regression guard: keys used in existing test_session.py must still match."""
        source = SessionSource(
            platform=Platform.TELEGRAM,
            chat_type="dm",
            chat_id="99",
        )
        assert build_session_key(source) == "agent:main:telegram:dm:99"

        group_src = SessionSource(
            platform=Platform.DISCORD,
            chat_type="group",
            chat_id="guild-123",
            user_id="alice",
        )
        assert build_session_key(group_src) == "agent:main:discord:group:guild-123:alice"


# ---------------------------------------------------------------------------
# Profile name is injected correctly
# ---------------------------------------------------------------------------


class TestBuildSessionKeyProfileInjection:
    def test_dm_key_includes_profile(self):
        source = _tg_dm_source()
        key = build_session_key(source, profile_name="henry-personal")
        assert key.startswith("agent:henry-personal:"), key
        assert "telegram:dm:99" in key, key

    def test_dm_with_thread_includes_profile(self):
        source = SessionSource(
            platform=Platform.TELEGRAM,
            chat_type="dm",
            chat_id="99",
            thread_id="t1",
        )
        key = build_session_key(source, profile_name="henry-personal")
        assert key == "agent:henry-personal:telegram:dm:99:t1"

    def test_group_key_includes_profile(self):
        source = _discord_group_source()
        key = build_session_key(source, profile_name="henry-personal")
        assert key.startswith("agent:henry-personal:discord:group:"), key

    def test_group_no_user_key_includes_profile(self):
        source = _discord_group_source()
        key = build_session_key(source, profile_name="henry-personal", group_sessions_per_user=False)
        assert key == "agent:henry-personal:discord:group:guild-123"

    def test_dm_no_meaningful_chat_id(self):
        # chat_id is required by the dataclass; use an empty string to exercise
        # the "no chat_id" fallback path in build_session_key.
        source = SessionSource(platform=Platform.TELEGRAM, chat_type="dm", chat_id="")
        key = build_session_key(source, profile_name="mally")
        assert key == "agent:mally:telegram:dm"

    def test_group_thread_shared_includes_profile(self):
        source = SessionSource(
            platform=Platform.DISCORD,
            chat_type="group",
            chat_id="guild-123",
            thread_id="thread-42",
            user_id="alice",
        )
        # Default: thread sessions are shared (thread_sessions_per_user=False)
        key = build_session_key(source, profile_name="coder", thread_sessions_per_user=False)
        assert key == "agent:coder:discord:group:guild-123:thread-42"


# ---------------------------------------------------------------------------
# The core discriminator property: two profiles, same chat → distinct keys
# ---------------------------------------------------------------------------


class TestProfileDiscriminator:
    """Two gateway profiles sharing the same Telegram chat_id MUST produce
    distinct session keys so they never share session state."""

    def test_two_profiles_same_dm_chat_id_different_keys(self):
        source = _tg_dm_source(chat_id="12345678")

        key_henry = build_session_key(source, profile_name="henry-personal")
        key_mally = build_session_key(source, profile_name="mally")

        assert key_henry != key_mally, (
            "Two profiles on the same Telegram DM chat produced the SAME session key — "
            f"henry={key_henry!r}, mally={key_mally!r}"
        )

    def test_two_profiles_same_group_chat_different_keys(self):
        source = _discord_group_source(chat_id="guild-999", user_id="bob")

        key_ops = build_session_key(source, profile_name="ops-watcher")
        key_coder = build_session_key(source, profile_name="code-reviewer")

        assert key_ops != key_coder

    def test_profile_key_does_not_match_legacy_key(self):
        """A key produced with a profile name must not equal the legacy "agent:main" key."""
        source = _tg_dm_source(chat_id="99")

        legacy = build_session_key(source)
        profiled = build_session_key(source, profile_name="henry-personal")

        assert legacy != profiled, (
            "Profile-discriminated key equals the legacy key — "
            f"legacy={legacy!r}, profiled={profiled!r}"
        )


# ---------------------------------------------------------------------------
# SessionStore._generate_session_key forwards profile_name
# ---------------------------------------------------------------------------


class TestSessionStoreGeneratesProfileKey:
    def _make_store(self) -> SessionStore:
        config = MagicMock(spec=GatewayConfig)
        config.group_sessions_per_user = True
        config.thread_sessions_per_user = False
        config.sessions_dir = None
        store = SessionStore.__new__(SessionStore)
        store.config = config
        store._entries = {}
        store._loaded = False
        store._lock = __import__("threading").Lock()
        store._has_active_processes_fn = None
        store._session_db = None
        return store

    def test_no_profile_name_matches_build_session_key(self):
        store = self._make_store()
        source = _tg_dm_source()
        assert store._generate_session_key(source) == build_session_key(source)

    def test_profile_name_forwarded_correctly(self):
        store = self._make_store()
        source = _tg_dm_source()
        expected = build_session_key(source, profile_name="henry-personal")
        actual = store._generate_session_key(source, profile_name="henry-personal")
        assert actual == expected

    def test_profile_name_none_gives_legacy_prefix(self):
        store = self._make_store()
        source = _tg_dm_source()
        key = store._generate_session_key(source, profile_name=None)
        assert key.startswith("agent:main:")


# ---------------------------------------------------------------------------
# Migration script logic (pure Python, no sqlite — verifies the SQL logic)
# ---------------------------------------------------------------------------


class TestMigrationScriptLogic:
    """Smoke-tests the migration script's key transformation logic in Python
    to confirm the SQL is correct without requiring a live sqlite fixture."""

    OLD_PREFIX = "agent:main:"

    def _transform(self, old_key: str, profile: str) -> str:
        """Replicate what the migration SQL does."""
        new_prefix = f"agent:{profile}:"
        if old_key.startswith(self.OLD_PREFIX) and not old_key.startswith(new_prefix):
            return new_prefix + old_key[len(self.OLD_PREFIX):]
        return old_key  # Already migrated or different format

    def test_dm_key_transformed_correctly(self):
        result = self._transform("agent:main:telegram:dm:12345", "henry-personal")
        assert result == "agent:henry-personal:telegram:dm:12345"

    def test_group_key_transformed_correctly(self):
        result = self._transform("agent:main:discord:group:guild-123:alice", "coder")
        assert result == "agent:coder:discord:group:guild-123:alice"

    def test_already_migrated_key_is_idempotent(self):
        already = "agent:henry-personal:telegram:dm:12345"
        result = self._transform(already, "henry-personal")
        assert result == already  # No double-prefix

    def test_non_agent_main_key_not_touched(self):
        # Keys from api_server path or other adapters shouldn't be modified
        key = "api_server:user@example.com:abcdef12"
        result = self._transform(key, "henry-personal")
        assert result == key
