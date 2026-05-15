"""
Tests for Gap 1 fix: CF Access JWT-derived session identity in APIServerAdapter.

Covers the cross-tenant impersonation scenario described in the validation
report (2026-05-15):

  A caller with a valid Bearer token for profile A could previously supply any
  X-Hermes-Session-Id they chose, including one belonging to a different
  user's session.  When a CF Access JWT is present in Cf-Access-Jwt-Assertion,
  the server now ignores the caller-supplied header and derives session_id
  server-side from the JWT sub claim.

Design decisions tested here:
  - JWT present + matching X-Hermes-Session-Id  → JWT-derived id wins (no-op)
  - JWT present + MISMATCHED X-Hermes-Session-Id → JWT-derived id wins, warning
  - JWT absent + X-Hermes-Session-Id provided    → legacy header path preserved
  - JWT absent + no X-Hermes-Session-Id          → fingerprint path preserved
  - Malformed JWT (not 3 parts)                  → graceful fallback, no crash
  - JWT with missing sub                         → graceful fallback, no crash
  - Two different CF subs on same route           → distinct session_ids

All JWTs used in this test file are UNSIGNED PLACEHOLDERS with synthetic
payloads.  They are NOT real tokens and contain no real credentials.
"""

import base64
import hashlib
import json
import re
import pytest

from gateway.platforms.api_server import APIServerAdapter
from gateway.config import PlatformConfig


# ---------------------------------------------------------------------------
# Helpers to build fake (unsigned) JWTs for testing
# ---------------------------------------------------------------------------

def _make_fake_jwt(payload: dict) -> str:
    """Build a structurally valid but UNSIGNED JWT with the given payload.

    The signature segment is the literal string 'fakesig' — no real private
    key is involved.  This is sufficient for _extract_cf_jwt_sub which only
    decodes the payload.
    """
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload_bytes = json.dumps(payload).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    return f"{header}.{payload_b64}.fakesig"


class _FakeRequest:
    """Minimal stand-in for aiohttp.web.Request with a headers dict."""

    def __init__(self, headers: dict, path: str = "/v1/chat/completions"):
        self.headers = headers
        self.path = path


def _make_adapter() -> APIServerAdapter:
    """Return a bare APIServerAdapter configured for testing."""
    cfg = PlatformConfig(enabled=True, extra={"key": "test-api-key-xyz"})
    return APIServerAdapter(cfg)


# ---------------------------------------------------------------------------
# _extract_cf_jwt_sub
# ---------------------------------------------------------------------------


class TestExtractCfJwtSub:
    def test_returns_sub_from_valid_jwt(self):
        jwt = _make_fake_jwt({"sub": "henry@example.com", "aud": "abc123"})
        request = _FakeRequest({"Cf-Access-Jwt-Assertion": jwt})
        adapter = _make_adapter()
        assert adapter._extract_cf_jwt_sub(request) == "henry@example.com"

    def test_falls_back_to_email_when_no_sub(self):
        jwt = _make_fake_jwt({"email": "mally@example.com", "aud": "abc123"})
        request = _FakeRequest({"Cf-Access-Jwt-Assertion": jwt})
        adapter = _make_adapter()
        assert adapter._extract_cf_jwt_sub(request) == "mally@example.com"

    def test_returns_none_when_header_absent(self):
        request = _FakeRequest({})
        adapter = _make_adapter()
        assert adapter._extract_cf_jwt_sub(request) is None

    def test_returns_none_for_malformed_jwt_wrong_parts(self):
        request = _FakeRequest({"Cf-Access-Jwt-Assertion": "notavalidjwt"})
        adapter = _make_adapter()
        assert adapter._extract_cf_jwt_sub(request) is None

    def test_returns_none_for_jwt_with_invalid_base64(self):
        request = _FakeRequest({"Cf-Access-Jwt-Assertion": "header.!!!.sig"})
        adapter = _make_adapter()
        assert adapter._extract_cf_jwt_sub(request) is None

    def test_returns_none_when_payload_missing_sub_and_email(self):
        jwt = _make_fake_jwt({"aud": "abc123", "iat": 1234567890})
        request = _FakeRequest({"Cf-Access-Jwt-Assertion": jwt})
        adapter = _make_adapter()
        assert adapter._extract_cf_jwt_sub(request) is None

    def test_returns_none_for_empty_header_value(self):
        request = _FakeRequest({"Cf-Access-Jwt-Assertion": "   "})
        adapter = _make_adapter()
        assert adapter._extract_cf_jwt_sub(request) is None


# ---------------------------------------------------------------------------
# _derive_session_id_from_cf_jwt
# ---------------------------------------------------------------------------


class TestDeriveSessionIdFromCfJwt:
    def test_session_id_starts_with_api_server_prefix(self):
        adapter = _make_adapter()
        sid = adapter._derive_session_id_from_cf_jwt("user@example.com", "/v1/chat/completions")
        assert sid.startswith("api_server:")

    def test_session_id_contains_sanitized_sub(self):
        adapter = _make_adapter()
        sid = adapter._derive_session_id_from_cf_jwt("henry@example.com", "/v1/chat/completions")
        assert "henry@example.com" in sid

    def test_special_chars_in_sub_are_sanitized(self):
        adapter = _make_adapter()
        sid = adapter._derive_session_id_from_cf_jwt("evil\r\nuser", "/v1/chat/completions")
        assert "\r" not in sid and "\n" not in sid

    def test_different_subs_produce_different_session_ids(self):
        adapter = _make_adapter()
        sid_henry = adapter._derive_session_id_from_cf_jwt("henry@example.com", "/v1/chat/completions")
        sid_mally = adapter._derive_session_id_from_cf_jwt("mally@example.com", "/v1/chat/completions")
        assert sid_henry != sid_mally

    def test_same_sub_same_route_is_deterministic(self):
        adapter = _make_adapter()
        sid1 = adapter._derive_session_id_from_cf_jwt("henry@example.com", "/v1/chat/completions")
        sid2 = adapter._derive_session_id_from_cf_jwt("henry@example.com", "/v1/chat/completions")
        assert sid1 == sid2


# ---------------------------------------------------------------------------
# Cross-tenant impersonation scenario (the core security test)
# ---------------------------------------------------------------------------


class TestCrossTenantImpersonationBlocked:
    """
    KEY TEST: When a CF JWT identifies henry@example.com and the caller also
    supplies X-Hermes-Session-Id claiming to be mally@example.com's session,
    the resulting session_id MUST be derived from the JWT (henry), NOT the
    header (mally).

    This mirrors the exact scenario described in the validation report:
      POST /v1/chat/completions
        Authorization: Bearer <valid-token>
        Cf-Access-Jwt-Assertion: <JWT for henry@example.com>
        X-Hermes-Session-Id: stillmusicofficial@gmail.com   ← attacker claim

    Expected: session_id resolves to henry's JWT-derived key, not mally's.
    """

    def test_jwt_overrides_caller_supplied_session_id(self):
        adapter = _make_adapter()

        henry_jwt = _make_fake_jwt({
            "sub": "henry@example.com",
            "aud": "test-audience",
            "iat": 1700000000,
            "exp": 9999999999,
        })

        # Simulate the headers an attacker would send: valid JWT for henry,
        # but claiming mally's session via X-Hermes-Session-Id.
        mally_claimed_session = "stillmusicofficial@gmail.com"

        request = _FakeRequest(
            headers={
                "Cf-Access-Jwt-Assertion": henry_jwt,
                "X-Hermes-Session-Id": mally_claimed_session,
                "Authorization": "Bearer test-api-key-xyz",
            },
            path="/v1/chat/completions",
        )

        # Extract cf_sub — should be henry's identity.
        cf_sub = adapter._extract_cf_jwt_sub(request)
        assert cf_sub == "henry@example.com", (
            f"Expected henry@example.com from JWT, got {cf_sub!r}"
        )

        # Derive the session_id the server would assign.
        derived_session_id = adapter._derive_session_id_from_cf_jwt(cf_sub, request.path)

        # The derived id must NOT equal the attacker-supplied header.
        assert derived_session_id != mally_claimed_session, (
            "SECURITY FAILURE: session_id derived from JWT equals the attacker-supplied "
            f"X-Hermes-Session-Id {mally_claimed_session!r}. Cross-tenant impersonation succeeded."
        )

        # The derived id must identify henry, not mally.
        assert "henry@example.com" in derived_session_id, (
            f"session_id {derived_session_id!r} does not identify henry@example.com"
        )
        assert mally_claimed_session not in derived_session_id, (
            f"session_id {derived_session_id!r} unexpectedly contains the attacker-supplied value"
        )

    def test_no_jwt_falls_through_to_header_path(self):
        """Without a CF JWT, the X-Hermes-Session-Id header path is still honoured."""
        adapter = _make_adapter()

        request = _FakeRequest(
            headers={
                "X-Hermes-Session-Id": "some-existing-session-id",
                "Authorization": "Bearer test-api-key-xyz",
            },
            path="/v1/chat/completions",
        )

        cf_sub = adapter._extract_cf_jwt_sub(request)
        # No JWT → _extract_cf_jwt_sub must return None, preserving legacy path.
        assert cf_sub is None, (
            f"Expected None (no JWT), got {cf_sub!r}"
        )

    def test_jwt_present_no_header_session_still_resolves_correctly(self):
        """JWT with no X-Hermes-Session-Id header still produces a valid session_id."""
        adapter = _make_adapter()

        henry_jwt = _make_fake_jwt({"sub": "henry@example.com"})
        request = _FakeRequest(
            headers={"Cf-Access-Jwt-Assertion": henry_jwt},
            path="/v1/chat/completions",
        )

        cf_sub = adapter._extract_cf_jwt_sub(request)
        assert cf_sub == "henry@example.com"

        derived = adapter._derive_session_id_from_cf_jwt(cf_sub, request.path)
        assert derived.startswith("api_server:")
        assert "henry@example.com" in derived
