"""hermes_findings_emit — S2 §2 plugin (v3 — Two-row pattern + reverse-PATCH-back).

Two-row pattern (B.3.b):
  Pre-hook INSERTs a 'started' row.
  Post-hook INSERTs a SEPARATE 'ok'|'failed' row with the SAME span_id but
  a different DB id.  S3 viz JOINs them by span_id at render time.

  This eliminates the _INFLIGHT in-memory map and is crash-safe: even if a
  dispatcher-spawned worker exits before the post-hook fires, the 'started'
  row persists (no orphan UPDATE needed) and the terminal row is written when
  the post-hook fires in the same subprocess that ran the pre-hook.

  A lightweight _SPAN_TIMES dict (keyed by span_id, process-local) carries
  started_at_ms for duration computation within a single subprocess. It is
  intentionally not shared across process boundaries — duration is best-effort.

Reverse-PATCH-back hook (B-bis):
  Fires on kanban_complete / kanban_block / kanban_fail tool calls.
  Reads kanban_task_id from tool args and PATCHes the VectOS kanban endpoint
  to flip the card status.

  Auth: bearer token from env VECTOS_BRIDGE_TOKEN. If unset, logs a warning
  and no-ops. Idempotent — VectOS PATCH with same status is a no-op.

Plan reference: ~/Obsidian/Henry/Handoffs/2026-05-17-atc-execution-plan-karpathy-revised.md
  Phase B Step 3 (B.3.b) + Phase B-bis.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

HERMES_FINDINGS_DB = os.environ.get(
    "HERMES_FINDINGS_DB",
    "/home/ubuntu/data/sqlite/shared/hermes.db",
)
SOURCE_APP = os.environ.get(
    "HERMES_FINDINGS_SOURCE_APP",
    os.environ.get("HERMES_PROFILE", "hermes-chief-of-staff"),
)

# VectOS reverse-PATCH-back config (B-bis)
VECTOS_BRIDGE_TOKEN = os.environ.get("VECTOS_BRIDGE_TOKEN", "")
VECTOS_KANBAN_BASE = os.environ.get(
    "VECTOS_KANBAN_BASE",
    "http://127.0.0.1:3002/api/plugins/kanban/tasks",
)
# Try prod first, fall back to dev. Comma-separated env override supported.
VECTOS_KANBAN_BASES = [u.strip() for u in os.environ.get(
    "VECTOS_KANBAN_BASES",
    "http://127.0.0.1:3002/api/plugins/kanban/tasks,http://127.0.0.1:3005/api/plugins/kanban/tasks",
).split(",") if u.strip()]

# ── Two-row pattern: process-local span start-time store ────────────────────
# Keyed by span_id string. Survives within one subprocess — that is enough
# because pre and post hooks for the same call always run in the same process.
_SPAN_TIMES: Dict[str, int] = {}
_SPAN_LOCK = threading.Lock()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _resolve_intent_id(task_id: str = "", session_id: str = "") -> str:
    return (task_id or session_id or "anon").strip()


def _new_span_id() -> str:
    return uuid.uuid4().hex[:16]


def _connect() -> Optional[sqlite3.Connection]:
    try:
        return sqlite3.connect(HERMES_FINDINGS_DB, timeout=2.0)
    except Exception as e:
        logger.warning("hermes_findings_emit: connect failed: %s", e)
        return None


def _insert_row(
    *,
    intent_id: str,
    span_id: str,
    kind: str,
    label: str,
    status: str,
    duration_ms: Optional[int] = None,
    error_message: Optional[str] = None,
    tool_name: Optional[str] = None,
    mcp_server: Optional[str] = None,
) -> None:
    """Insert a single hermes_findings row (two-row pattern — each call is its own INSERT)."""
    sev = (
        "error" if status in ("failed", "timeout")
        else "warning" if status == "blocked"
        else "info"
    )
    conn = _connect()
    if conn is None:
        return
    try:
        conn.execute(
            "INSERT INTO hermes_findings "
            "(source, severity, title, body, status, intent_id, span_id, "
            "source_app, kind, label, mcp_server, tool_name, duration_ms, error_message) "
            "VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                SOURCE_APP,
                sev,
                f"{kind}:{label}"[:200],
                status,
                intent_id,
                span_id,
                SOURCE_APP,
                kind,
                (label or "")[:200],
                mcp_server,
                tool_name,
                duration_ms,
                error_message,
            ),
        )
        conn.commit()
    except Exception as e:
        logger.warning(
            "hermes_findings_emit: insert failed (%s/%s status=%s): %s",
            kind, label, status, e,
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ── Reverse-PATCH-back helpers (B-bis) ─────────────────────────────────────

_HERMES_TO_VECTOS_STATUS: Dict[str, str] = {
    "done": "done",
    "failed": "quarantine",
    "blocked": "review",
}
_QUARANTINE_OUTCOMES = frozenset({"gave_up", "crashed", "timed_out", "spawn_failed"})


def _vectos_patch(card_id: str, status: str, description: Optional[str] = None) -> None:
    """PATCH VectOS kanban task status. Idempotent."""
    if not VECTOS_BRIDGE_TOKEN:
        logger.warning(
            "hermes_findings_emit: VECTOS_BRIDGE_TOKEN not set — skipping reverse-PATCH for card %s",
            card_id,
        )
        return

    payload: Dict[str, Any] = {"status": status}
    if description:
        payload["description"] = description[:1000]
    data = json.dumps(payload).encode()
    succeeded = False
    last_err = None
    for base in VECTOS_KANBAN_BASES:
        url = f"{base}/{card_id}"
        req = urllib.request.Request(
            url, data=data, method="PATCH",
            headers={
                "Content-Type": "application/json",
                "X-Service-Token": VECTOS_BRIDGE_TOKEN,
                "cf-access-authenticated-user-email": "henry@berliand.com",
                "User-Agent": "hermes-findings-emit/v3",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                logger.info(
                    "hermes_findings_emit: reverse-PATCH card=%s status=%s http=%d via=%s",
                    card_id, status, resp.status, base,
                )
                succeeded = True
                break
        except urllib.error.HTTPError as e:
            last_err = (base, e.code, e.read()[:200])
            if e.code == 404:
                continue
            logger.warning(
                "hermes_findings_emit: reverse-PATCH HTTP error card=%s status=%s code=%d via=%s body=%s",
                card_id, status, e.code, base, last_err[2],
            )
            break
        except Exception as e:
            last_err = (base, 0, str(e))
            logger.warning(
                "hermes_findings_emit: reverse-PATCH failed card=%s via=%s: %s",
                card_id, base, e,
            )
            break
    if not succeeded and last_err:
        logger.warning(
            "hermes_findings_emit: reverse-PATCH exhausted bases for card=%s last=%s",
            card_id, last_err,
        )


def _handle_kanban_terminal(tool_name: str, args: Any) -> None:
    """Extract card_id from kanban tool args and fire reverse-PATCH."""
    if not isinstance(args, dict):
        return

    card_id = (
        args.get("kanban_task_id")
        or args.get("task_id")
        or args.get("card_id")
        or os.environ.get("HERMES_KANBAN_TASK", "")
        or ""
    ).strip()
    if not card_id:
        logger.debug("hermes_findings_emit: kanban tool %s has no card_id (args or env)", tool_name)
        return

    if tool_name == "kanban_complete":
        outcome = args.get("outcome", "")
        if outcome in _QUARANTINE_OUTCOMES:
            _vectos_patch(card_id, "quarantine", description=f"Hermes outcome: {outcome}")
        else:
            _vectos_patch(card_id, "done")
    elif tool_name == "kanban_block":
        reason = args.get("reason", "")
        _vectos_patch(card_id, "review", description=f"Blocked: {reason}" if reason else None)
    elif tool_name == "kanban_fail":
        outcome = args.get("outcome", "failed")
        _vectos_patch(card_id, "quarantine", description=f"Hermes outcome: {outcome}")


_KANBAN_TERMINAL_TOOLS = frozenset({"kanban_complete", "kanban_block", "kanban_fail"})


# ── Plugin hooks ────────────────────────────────────────────────────────────


def on_pre_llm_call(
    *,
    task_id: str = "",
    session_id: str = "",
    platform: str = "",
    model: str = "",
    **_: Any,
) -> str:
    """Pre-hook: INSERT started row, return span_id for post-hook."""
    intent_id = _resolve_intent_id(task_id, session_id)
    span_id = _new_span_id()
    label = model or platform or "llm_call"
    with _SPAN_LOCK:
        _SPAN_TIMES[span_id] = _now_ms()
    _insert_row(intent_id=intent_id, span_id=span_id, kind="llm_call", label=label, status="started")
    return span_id


def on_post_llm_call(
    *,
    task_id: str = "",
    session_id: str = "",
    error: Optional[str] = None,
    model: str = "",
    platform: str = "",
    span_id: str = "",
    **_: Any,
) -> None:
    """Post-hook: INSERT terminal row (two-row pattern)."""
    intent_id = _resolve_intent_id(task_id, session_id)
    label = model or platform or "llm_call"
    # Use passed span_id or fall back to a fresh one (cross-subprocess case)
    if not span_id:
        span_id = _new_span_id()
    with _SPAN_LOCK:
        started_at = _SPAN_TIMES.pop(span_id, None)
    duration = max(0, _now_ms() - started_at) if started_at is not None else None
    status = "failed" if error else "ok"
    _insert_row(
        intent_id=intent_id,
        span_id=span_id,
        kind="llm_call",
        label=label,
        status=status,
        duration_ms=duration,
        error_message=str(error)[:500] if error else None,
    )


def on_pre_tool_call(
    *,
    tool_name: str = "",
    args: Any = None,
    task_id: str = "",
    session_id: str = "",
    mcp_server: str = "",
    **_: Any,
) -> str:
    """Pre-hook: INSERT started row, return span_id for post-hook."""
    intent_id = _resolve_intent_id(task_id, session_id)
    span_id = _new_span_id()
    kind = "mcp_call" if mcp_server else "tool_call"
    label = tool_name or "tool_call"
    with _SPAN_LOCK:
        _SPAN_TIMES[span_id] = _now_ms()
    _insert_row(
        intent_id=intent_id,
        span_id=span_id,
        kind=kind,
        label=label,
        status="started",
        tool_name=tool_name or None,
        mcp_server=mcp_server or None,
    )
    return span_id


def on_post_tool_call(
    *,
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    error: Optional[str] = None,
    task_id: str = "",
    session_id: str = "",
    mcp_server: str = "",
    span_id: str = "",
    **_: Any,
) -> None:
    """Post-hook: INSERT terminal row (two-row pattern) + kanban reverse-PATCH."""
    intent_id = _resolve_intent_id(task_id, session_id)
    kind = "mcp_call" if mcp_server else "tool_call"
    label = tool_name or "tool_call"
    if not span_id:
        span_id = _new_span_id()
    with _SPAN_LOCK:
        started_at = _SPAN_TIMES.pop(span_id, None)
    duration = max(0, _now_ms() - started_at) if started_at is not None else None
    status = "failed" if error else "ok"
    _insert_row(
        intent_id=intent_id,
        span_id=span_id,
        kind=kind,
        label=label,
        status=status,
        duration_ms=duration,
        error_message=str(error)[:500] if error else None,
        tool_name=tool_name or None,
        mcp_server=mcp_server or None,
    )
    # B-bis: reverse-PATCH-back for kanban terminal tools
    if tool_name in _KANBAN_TERMINAL_TOOLS:
        _handle_kanban_terminal(tool_name, args)


def register(ctx) -> None:
    """Hermes plugin entry point."""
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    ctx.register_hook("post_llm_call", on_post_llm_call)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
