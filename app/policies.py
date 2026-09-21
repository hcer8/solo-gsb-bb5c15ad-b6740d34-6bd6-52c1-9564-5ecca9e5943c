"""SQLite-backed persistent policy library.

A *policy* is a named, ordered list of redaction rules. Every PUT appends a new
immutable row to ``policy_versions``; old versions are never mutated or deleted,
so a redaction performed against a historical version is always reproducible.

Concurrency
-----------

Writers take an immediate write transaction (``BEGIN IMMEDIATE``); SQLite serializes
them and the second writer sees a locked database. On ``SQLITE_BUSY`` the whole
transaction is retried, where the optimistic ETag check is re-evaluated against
the now-current version. A process-local lock additionally coalesces writers in
the same uvicorn worker so updates never silently clobber each other.

Readers open short-lived read transactions; in WAL mode they never block writers.
The "latest version" lookup and the version-row fetch happen in one transaction,
so a concurrent PUT cannot interleave between the two -- the read is atomic.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, List, Optional

# Wildcard matching every existing version ("If-Match: *").
ANY_ETAG = "*"

# Max time to wait for a contended write lock before surfacing 503.
_BUSY_TIMEOUT_SECONDS = 5.0
_BUSY_RETRY_SLEEP = 0.02


class PolicyNotFound(LookupError):
    """Raised when a policy name (or a specific version) does not exist."""


class StalePolicyVersion(Exception):
    """Raised when an update carries an ETag that is no longer current."""


class PolicyStoreBusy(Exception):
    """Raised when the write lock could not be acquired in time."""


class PolicyStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._write_lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------ #
    # Connection / schema management
    # ------------------------------------------------------------------ #

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=_BUSY_TIMEOUT_SECONDS,
            isolation_level=None,  # autocommit; transactions are explicit
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    name        TEXT PRIMARY KEY,
                    version     INTEGER NOT NULL,
                    etag        TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_versions (
                    name        TEXT NOT NULL,
                    version     INTEGER NOT NULL,
                    etag        TEXT NOT NULL UNIQUE,
                    rules       TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    PRIMARY KEY (name, version),
                    FOREIGN KEY (name) REFERENCES policies(name)
                )
                """
            )

    def close(self) -> None:
        # Connections are short-lived per operation; nothing to release.
        return None

    # ------------------------------------------------------------------ #
    # Writes
    # ------------------------------------------------------------------ #

    def put(
        self,
        name: str,
        rules: List[dict[str, Any]],
        expected_etags: Optional[List[str]],
    ) -> dict[str, Any]:
        """Create a policy or append a new version.

        ``expected_etags`` semantics:

        * ``None``          -- create only; fails if the policy already exists.
        * ``["*"]``         -- update unconditionally; fails if it does not exist.
        * list of ETags     -- update only if the current ETag is one of them.

        Returns the stored snapshot of the new version.
        Raises ``StalePolicyVersion`` on a failed precondition.
        """
        payload = json.dumps(rules, ensure_ascii=False, sort_keys=True)
        # One process-local writer at a time; cross-process contention is handled
        # below via BEGIN IMMEDIATE + SQLITE_BUSY retries.
        with self._write_lock:
            deadline = time.monotonic() + _BUSY_TIMEOUT_SECONDS
            while True:
                try:
                    return self._put_once(name, payload, expected_etags)
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or time.monotonic() >= deadline:
                        raise PolicyStoreBusy(str(exc)) from exc
                    time.sleep(_BUSY_RETRY_SLEEP)

    def _put_once(
        self,
        name: str,
        payload: str,
        expected_etags: Optional[List[str]],
    ) -> dict[str, Any]:
        with self._connection() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT version, etag FROM policies WHERE name = ?", (name,)
                ).fetchone()

                if row is None:
                    if expected_etags is not None:
                        # Update against a policy that was never created.
                        raise StalePolicyVersion(
                            f"policy {name!r} does not exist; create it without If-Match"
                        )
                    version, current_etag = 1, uuid.uuid4().hex
                    conn.execute(
                        "INSERT INTO policies (name, version, etag) VALUES (?, ?, ?)",
                        (name, version, current_etag),
                    )
                else:
                    if expected_etags is None:
                        raise StalePolicyVersion(
                            f"policy {name!r} already exists; send its current ETag in If-Match"
                        )
                    if ANY_ETAG not in expected_etags and row["etag"] not in expected_etags:
                        raise StalePolicyVersion(
                            f"none of the If-Match ETags matches the current version "
                            f"({row['etag']!r})"
                        )
                    version, current_etag = row["version"] + 1, uuid.uuid4().hex
                    conn.execute(
                        "UPDATE policies SET version = ?, etag = ? WHERE name = ?",
                        (version, current_etag, name),
                    )

                created_at = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """
                    INSERT INTO policy_versions
                        (name, version, etag, rules, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (name, version, current_etag, payload, created_at),
                )
                conn.commit()
            except StalePolicyVersion:
                conn.rollback()
                raise
            except Exception:
                conn.rollback()
                raise

        return self.get_version(name, version)

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    @staticmethod
    def _snapshot(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "name": row["name"],
            "version": row["version"],
            "etag": row["etag"],
            "created_at": row["created_at"],
            "rules": json.loads(row["rules"]),
        }

    def get_version(self, name: str, version: int) -> dict[str, Any]:
        """Fetch an immutable snapshot by exact version."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT name, version, etag, rules, created_at "
                "FROM policy_versions WHERE name = ? AND version = ?",
                (name, version),
            ).fetchone()
        if row is None:
            raise PolicyNotFound(f"policy {name!r} version {version} not found")
        return self._snapshot(row)

    def get_latest(self, name: str) -> dict[str, Any]:
        """Atomically resolve and fetch the current version of a policy.

        The pointer lookup and the row fetch run in one deferred transaction:
        SQLite guarantees they see a single database snapshot, so a PUT that
        lands concurrently can never produce a version/ETag mismatch.
        """
        with self._connection() as conn:
            try:
                conn.execute("BEGIN")
                head = conn.execute(
                    "SELECT version FROM policies WHERE name = ?", (name,)
                ).fetchone()
                if head is None:
                    raise PolicyNotFound(f"policy {name!r} not found")
                row = conn.execute(
                    "SELECT name, version, etag, rules, created_at "
                    "FROM policy_versions WHERE name = ? AND version = ?",
                    (name, head["version"]),
                ).fetchone()
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return self._snapshot(row)
