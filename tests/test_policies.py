"""Tests for the versioned policy library and policy-backed /redact."""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.policies import PolicyStore


@pytest.fixture()
def client(tmp_path):
    """A TestClient backed by an isolated SQLite database."""
    store = PolicyStore(str(tmp_path / "policies.db"))
    app.state.store = store
    with TestClient(app) as c:
        yield c
    # Restore the lazy-default state for any subsequently imported client.
    if hasattr(app.state, "store"):
        del app.state.store


def create_policy(client, name="pii", rules=None):
    rules = rules or [
        {"pointer": "/users/*/email", "action": "mask"},
        {"pointer": "/users/*/ssn", "action": "sha256", "name": "ssn"},
    ]
    resp = client.put(f"/policies/{name}", json={"rules": rules})
    assert resp.status_code == 201, resp.text
    return resp, rules


# --------------------------------------------------------------------------- #
# PUT: create / update / ETags
# --------------------------------------------------------------------------- #


def test_put_creates_version_one_with_etag(client):
    resp, rules = create_policy(client)
    body = resp.json()
    assert body["name"] == "pii"
    assert body["version"] == 1
    assert body["rules"] == rules
    etag = resp.headers["ETag"]
    assert etag.startswith('"') and etag.endswith('"')
    assert len(etag) == 34  # 32 hex chars + quotes


def test_put_without_etag_on_existing_policy_is_412(client):
    create_policy(client)
    resp = client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/x", "action": "remove"}]},
    )
    assert resp.status_code == 412
    # The current ETag is returned so the client can re-read and retry.
    assert resp.headers["ETag"]


def test_put_with_stale_etag_is_412(client):
    resp, _ = create_policy(client)
    stale = resp.headers["ETag"]
    updated = client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/x", "action": "mask"}]},
        headers={"If-Match": stale},
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    assert updated.headers["ETag"] != stale

    # The first ETag is now stale.
    stale_again = client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/y", "action": "mask"}]},
        headers={"If-Match": stale},
    )
    assert stale_again.status_code == 412


def test_put_with_current_etag_appends_version(client):
    first, _ = create_policy(client)
    etag1 = first.headers["ETag"]
    second = client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/a", "action": "remove"}]},
        headers={"If-Match": etag1},
    )
    assert second.status_code == 200
    assert second.json()["version"] == 2
    etag2 = second.headers["ETag"]
    assert etag2 != etag1

    third = client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/b", "action": "mask"}]},
        headers={"If-Match": etag2},
    )
    assert third.status_code == 200
    assert third.json()["version"] == 3


def test_put_if_match_star(client):
    create_policy(client)
    resp = client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/a", "action": "mask"}]},
        headers={"If-Match": "*"},
    )
    assert resp.status_code == 200
    assert resp.json()["version"] == 2


def test_put_if_match_star_on_missing_policy_is_412(client):
    resp = client.put(
        "/policies/ghost",
        json={"rules": []},
        headers={"If-Match": "*"},
    )
    assert resp.status_code == 412


def test_put_malformed_if_match_is_412(client):
    create_policy(client)
    resp = client.put(
        "/policies/pii",
        json={"rules": []},
        headers={"If-Match": "not-a-valid-etag"},
    )
    assert resp.status_code == 412


def test_put_invalid_rule_body_is_422(client):
    resp = client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "bad-pointer", "action": "mask"}]},
    )
    assert resp.status_code == 422


def test_put_invalid_name_is_422(client):
    resp = client.put("/policies/bad name", json={"rules": []})
    assert resp.status_code in (404, 422)  # route-encoded names 404, bad shape 422


def test_versions_are_immutable(client):
    first, rules_v1 = create_policy(
        client,
        rules=[{"pointer": "/x", "action": "mask"}],
    )
    client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/x", "action": "remove"}]},
        headers={"If-Match": first.headers["ETag"]},
    )
    v1 = client.get("/policies/pii/versions/1")
    assert v1.status_code == 200
    assert v1.json()["rules"] == rules_v1
    # ETag of a historical version remains stable.
    assert v1.headers["ETag"] == first.headers["ETag"]


def test_get_unknown_version_404(client):
    create_policy(client)
    assert client.get("/policies/pii/versions/99").status_code == 404
    assert client.get("/policies/ghost/versions/1").status_code == 404


# --------------------------------------------------------------------------- #
# /redact with policies
# --------------------------------------------------------------------------- #

DATA = {
    "users": [
        {"email": "a@x.io", "ssn": "111"},
        {"email": "b@x.io", "ssn": "222"},
    ]
}


def test_redact_with_latest_policy(client):
    create_policy(client)
    resp = client.post(
        "/redact",
        json={"data": DATA, "policy": {"name": "pii"}},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["policy"] == {"name": "pii", "version": 1, "latest": True}
    assert all(u["email"] == "***REDACTED***" for u in body["redacted"]["users"])
    for entry in body["audit"]:
        assert entry["policy"] == {"name": "pii", "version": 1, "latest": True}


def test_redact_pins_and_reproduces_historical_version(client):
    first, _ = create_policy(
        client,
        rules=[{"pointer": "/users/*/email", "action": "mask"}],
    )
    client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/users/*/email", "action": "remove"}]},
        headers={"If-Match": first.headers["ETag"]},
    )

    # Latest removes the email keys...
    latest = client.post("/redact", json={"data": DATA, "policy": {"name": "pii"}}).json()
    assert latest["policy"]["version"] == 2
    assert all("email" not in u for u in latest["redacted"]["users"])

    # ...while the pinned v1 always masks them.
    pinned = client.post(
        "/redact",
        json={"data": DATA, "policy": {"name": "pii", "version": 1}},
    ).json()
    assert pinned["policy"] == {"name": "pii", "version": 1, "latest": False}
    assert all(u["email"] == "***REDACTED***" for u in pinned["redacted"]["users"])
    for entry in pinned["audit"]:
        assert entry["policy"]["latest"] is False


def test_redact_unknown_policy_is_404(client):
    resp = client.post(
        "/redact",
        json={"data": {}, "policy": {"name": "missing"}},
    )
    assert resp.status_code == 404


def test_redact_rules_and_policy_are_mutually_exclusive(client):
    create_policy(client)
    resp = client.post(
        "/redact",
        json={
            "data": {},
            "rules": [{"pointer": "/a", "action": "mask"}],
            "policy": {"name": "pii"},
        },
    )
    assert resp.status_code == 422


def test_redact_inline_still_works_and_has_no_policy_meta(client):
    resp = client.post(
        "/redact",
        json={"data": {"k": "v"}, "rules": [{"pointer": "/k", "action": "mask"}]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["redacted"] == {"k": "***REDACTED***"}
    assert body["policy"] is None
    assert all(e["policy"] is None for e in body["audit"])


def test_redact_empty_rules_backward_compatible(client):
    resp = client.post("/redact", json={"data": {"a": 1}})
    assert resp.status_code == 200
    assert resp.json()["redacted"] == {"a": 1}


# --------------------------------------------------------------------------- #
# Concurrency
# --------------------------------------------------------------------------- #


def test_concurrent_updates_one_wins_one_gets_412(client):
    first, _ = create_policy(client, rules=[{"pointer": "/a", "action": "mask"}])
    etag = first.headers["ETag"]

    results = []

    def update(action):
        resp = client.put(
            "/policies/pii",
            json={"rules": [{"pointer": "/a", "action": action}]},
            headers={"If-Match": etag},  # both race with the same stale-able ETag
        )
        results.append((action, resp.status_code))

    threads = [
        threading.Thread(target=update, args=("remove",)),
        threading.Thread(target=update, args=("sha256",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    statuses = sorted(status for _, status in results)
    assert statuses == [200, 412]

    # Only one new version exists.
    body = client.get("/policies/pii/versions/2").json()
    assert body["version"] == 2
    assert client.get("/policies/pii/versions/3").status_code == 404


def test_concurrent_retry_with_fresh_etag_succeeds(client):
    first, _ = create_policy(client)

    # Two writers update serially, each fetching the current ETag: the
    # optimistic scheme always allows progress.
    resp = first
    for expected_version in range(2, 6):
        resp = client.put(
            "/policies/pii",
            json={"rules": [{"pointer": f"/v{expected_version}", "action": "mask"}]},
            headers={"If-Match": resp.headers["ETag"]},
        )
        assert resp.status_code == 200
        assert resp.json()["version"] == expected_version


def test_policy_persists_across_store_connections(tmp_path):
    db_path = str(tmp_path / "policies.db")
    store_a = PolicyStore(db_path)
    snapshot = store_a.put(
        "durable",
        [{"pointer": "/x", "action": "mask", "name": None}],
        expected_etags=None,
    )
    assert snapshot["version"] == 1

    # A fresh store (simulating a container restart against the same volume)
    # sees every historical version.
    store_b = PolicyStore(db_path)
    assert store_b.get_version("durable", 1)["rules"] == snapshot["rules"]
    assert store_b.get_latest("durable")["etag"] == snapshot["etag"]
