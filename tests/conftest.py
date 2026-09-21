"""Shared pytest configuration.

Force every test into an isolated working directory *before* the app reads
``POLICY_DB``, so module-level ``TestClient`` instances (see ``test_api.py``)
can never create a real ``./data/policies.db`` during the test run.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("POLICY_DB", str(tmp_path / "policies.db"))
    yield
