"""Runtime configuration, sourced from environment variables."""

from __future__ import annotations

import os

# Salt prepended to the canonical JSON of a node before SHA-256 hashing.
REDACT_SALT_ENV = "REDACT_SALT"


def get_salt() -> str:
    return os.environ.get(REDACT_SALT_ENV, "")
