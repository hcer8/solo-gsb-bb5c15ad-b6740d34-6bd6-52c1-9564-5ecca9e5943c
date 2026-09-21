"""Runtime configuration, sourced from environment variables."""

from __future__ import annotations

import os

# Salt prepended to the canonical JSON of a node before SHA-256 hashing.
REDACT_SALT_ENV = "REDACT_SALT"

# Location of the SQLite file holding immutable policy versions.
POLICY_DB_ENV = "POLICY_DB"

# Relative path keeps `uvicorn` usable on a dev machine; the Docker image sets
# POLICY_DB=/data/policies.db so the file lives on the mounted volume.
DEFAULT_DB_PATH = "data/policies.db"


def get_salt() -> str:
    return os.environ.get(REDACT_SALT_ENV, "")


def get_db_path() -> str:
    return os.environ.get(POLICY_DB_ENV, DEFAULT_DB_PATH)
