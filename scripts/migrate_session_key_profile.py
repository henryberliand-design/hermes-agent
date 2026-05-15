#!/usr/bin/env python3
"""
migrate_session_key_profile.py — Gap 2 state.db migration script.

PURPOSE
-------
After the Gap 2 fix (feat/hermes-cap-gap-2-session-key-profile-prefix),
``build_session_key`` prepends the active profile name to the session key:

    OLD: agent:main:telegram:dm:12345
    NEW: agent:henry-personal:telegram:dm:12345

Existing ``state.db`` rows contain the old ``agent:main:`` prefix.  If the
migration is NOT run, the gateway boots with the new prefix and cannot find
historical sessions — every user gets a fresh session on first message after
the upgrade.

OPERATIONAL RISK (read before running)
---------------------------------------
- Per-profile state.db isolation is the existing firewall.  The old key shape
  (without profile) did NOT cause cross-profile data leakage because each
  profile writes to its OWN state.db file at:
      ~/.hermes/profiles/<profile>/state.db
  The migration ONLY rewrites keys within each profile's own file.

- The migration does NOT touch relay.db or any other database.

- The migration is IDEMPOTENT: rows that already carry the new prefix are
  skipped.

- DO NOT run this while hermes-agent is running.  Stop the relevant gateway
  process first.

USAGE
-----
    # Dry run (no writes):
    python3 scripts/migrate_session_key_profile.py --dry-run

    # Migrate all profiles (writes to each profile's state.db):
    python3 scripts/migrate_session_key_profile.py

    # Migrate a specific profile only:
    python3 scripts/migrate_session_key_profile.py --profile henry-personal

CUTOVER SEQUENCE (Henry's runbook)
-----------------------------------
1.  Stop the hermes-agent gateway for the target profile:
        systemctl --user stop hermes-henry-personal   (or the relevant unit)

2.  Dry-run the migration to confirm what will change:
        python3 ~/.hermes/hermes-agent/scripts/migrate_session_key_profile.py \\
            --profile henry-personal --dry-run

3.  Run the migration:
        python3 ~/.hermes/hermes-agent/scripts/migrate_session_key_profile.py \\
            --profile henry-personal

4.  Start the gateway:
        systemctl --user start hermes-henry-personal

5.  Smoke: send a message, confirm the bot responds with context from the
    last conversation (proves the migration linked the old session).

6.  If anything is wrong, the old state.db is backed up at
    <state.db>.pre-gap2-migration and can be restored with:
        cp state.db.pre-gap2-migration state.db

ROLLBACK
--------
The migration creates a backup of each state.db before writing.  To roll back:
    cp ~/.hermes/profiles/<profile>/state.db.pre-gap2-migration \\
       ~/.hermes/profiles/<profile>/state.db
Then restart the gateway WITHOUT the Gap 2 code (revert to main branch) so it
uses the old ``agent:main`` prefix again.
"""

import argparse
import logging
import shutil
import sqlite3
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("migrate_session_key_profile")

OLD_PREFIX = "agent:main:"
NEW_PREFIX_TEMPLATE = "agent:{profile}:"

# Tables that contain session_key columns to migrate.
# Extend this list if new tables are added to state.db in future.
SESSION_KEY_TABLES = [
    "sessions",
    # Add more table names here if state.db schema grows
]


def get_profiles_dir() -> Path:
    """Return the active Hermes profiles directory."""
    hermes_home = Path.home() / ".hermes" / "profiles"
    if hermes_home.is_dir():
        return hermes_home
    raise FileNotFoundError(
        f"Hermes profiles directory not found at {hermes_home}. "
        "Set HERMES_HOME if your profiles live elsewhere."
    )


def find_state_dbs(profiles_dir: Path, only_profile: str | None = None) -> list[tuple[str, Path]]:
    """Return [(profile_name, state_db_path), ...] for all profiles with a state.db."""
    results = []
    for profile_dir in sorted(profiles_dir.iterdir()):
        if not profile_dir.is_dir():
            continue
        profile = profile_dir.name
        if only_profile and profile != only_profile:
            continue
        db = profile_dir / "state.db"
        if db.is_file():
            results.append((profile, db))
    return results


def migrate_db(profile: str, db_path: Path, dry_run: bool) -> int:
    """Migrate session keys in a single state.db file.

    Returns the number of rows rewritten.
    """
    new_prefix = NEW_PREFIX_TEMPLATE.format(profile=profile)
    total_rewritten = 0

    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.cursor()

        # Discover which of the target tables actually exist in this db.
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = {row[0] for row in cursor.fetchall()}

        for table in SESSION_KEY_TABLES:
            if table not in existing_tables:
                log.debug("Table %r not in %s — skipping.", table, db_path)
                continue

            # Detect session_key column presence.
            cursor.execute(f"PRAGMA table_info({table})")
            columns = {row[1] for row in cursor.fetchall()}
            if "session_key" not in columns:
                log.debug("Table %r has no session_key column — skipping.", table)
                continue

            # Count rows that need migration.
            cursor.execute(
                f"SELECT COUNT(*) FROM {table} WHERE session_key LIKE ?",
                (OLD_PREFIX + "%",),
            )
            count = cursor.fetchone()[0]

            if count == 0:
                log.info("[%s] %s: no rows to migrate.", profile, table)
                continue

            log.info("[%s] %s: %d rows to migrate.", profile, table, count)

            if dry_run:
                # Show a sample of keys that would be rewritten.
                cursor.execute(
                    f"SELECT session_key FROM {table} WHERE session_key LIKE ? LIMIT 5",
                    (OLD_PREFIX + "%",),
                )
                for (key,) in cursor.fetchall():
                    new_key = new_prefix + key[len(OLD_PREFIX):]
                    log.info("  DRY-RUN  %r  →  %r", key, new_key)
                total_rewritten += count
            else:
                # Rewrite: replace agent:main: prefix with agent:<profile>:
                # Using printf is SQLite-portable; REPLACE() is also fine here.
                cursor.execute(
                    f"""
                    UPDATE {table}
                    SET session_key = ? || substr(session_key, ?)
                    WHERE session_key LIKE ?
                      AND session_key NOT LIKE ?
                    """,
                    (
                        new_prefix,
                        len(OLD_PREFIX) + 1,  # sqlite substr is 1-indexed
                        OLD_PREFIX + "%",
                        new_prefix + "%",     # idempotency guard
                    ),
                )
                rewritten = cursor.rowcount
                log.info("[%s] %s: rewritten %d rows.", profile, table, rewritten)
                total_rewritten += rewritten

        if not dry_run:
            conn.commit()
    finally:
        conn.close()

    return total_rewritten


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing anything.",
    )
    parser.add_argument(
        "--profile",
        metavar="PROFILE_NAME",
        help="Migrate only this profile (default: migrate all profiles).",
    )
    args = parser.parse_args()

    try:
        profiles_dir = get_profiles_dir()
    except FileNotFoundError as e:
        log.error("%s", e)
        sys.exit(1)

    state_dbs = find_state_dbs(profiles_dir, only_profile=args.profile)
    if not state_dbs:
        target = f"profile '{args.profile}'" if args.profile else "any profile"
        log.warning("No state.db found for %s under %s", target, profiles_dir)
        sys.exit(0)

    grand_total = 0
    for profile, db_path in state_dbs:
        log.info("Processing profile=%r db=%s", profile, db_path)

        if not args.dry_run:
            backup = db_path.with_suffix(".pre-gap2-migration")
            if not backup.exists():
                shutil.copy2(str(db_path), str(backup))
                log.info("[%s] Backup written to %s", profile, backup)
            else:
                log.info("[%s] Backup already exists at %s — skipping copy.", profile, backup)

        n = migrate_db(profile, db_path, dry_run=args.dry_run)
        grand_total += n

    mode = "DRY-RUN" if args.dry_run else "MIGRATED"
    log.info("Done. %s total rows affected: %d", mode, grand_total)


if __name__ == "__main__":
    main()
