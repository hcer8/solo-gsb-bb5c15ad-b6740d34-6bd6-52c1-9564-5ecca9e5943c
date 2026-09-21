"""FastAPI application: redaction engine plus the persistent policy library."""

from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from typing import Annotated, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request
from fastapi.responses import JSONResponse

from . import config
from .policies import (
    ANY_ETAG,
    PolicyNotFound,
    PolicyStore,
    PolicyStoreBusy,
    StalePolicyVersion,
)
from .redaction import redact
from .schemas import (
    PolicyName,
    PolicyRef,
    PolicySelector,
    PolicySnapshot,
    PolicyUpsert,
    RedactRequest,
    RedactResponse,
    RuleSpec,
    compile_specs,
)

# ETags are exchanged as opaque quoted strings, per RFC 9110.
ETAG_HEADER = "ETag"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.store = PolicyStore(config.get_db_path())
    yield
    app.state.store.close()


app = FastAPI(
    title="JSON Redaction API",
    version="2.0.0",
    description=(
        "Redact arbitrary JSON using JSON Pointer rules with * / ** globs. "
        "Rule sets can be sent inline or managed as versioned, immutable policies."
    ),
    lifespan=lifespan,
)


def get_store(request: Request) -> PolicyStore:
    # The lifespan sets this up; fall back to a lazy store so unit tests that
    # build a bare TestClient (without running lifespan) keep working.
    store = getattr(request.app.state, "store", None)
    if store is None:
        store = PolicyStore(config.get_db_path())
        request.app.state.store = store
    return store


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def quote_etag(etag: str) -> str:
    return f'"{etag}"'


def parse_if_match(value: Optional[str]) -> Optional[List[str]]:
    """Parse an If-Match header into unquoted ETags.

    Returns ``None`` when the header is absent, or a list of unquoted tags.
    ``*`` yields :data:`ANY_ETAG`. A malformed header yields an empty list,
    which never matches and therefore produces a 412.
    """
    if value is None:
        return None
    value = value.strip()
    if value == ANY_ETAG:
        return [ANY_ETAG]

    tags: List[str] = []
    for part in value.split(","):
        token = part.strip()
        # Weak validators ("W/...") are not supported for these state-changing
        # preconditions; treat them as non-matching.
        if not token or token.startswith(("W/", "w/")):
            continue
        if len(token) >= 2 and token.startswith('"') and token.endswith('"'):
            tags.append(token[1:-1])
    return tags


def _snapshot_response(snapshot: dict, status_code: int = 200) -> JSONResponse:
    body = PolicySnapshot.model_validate(snapshot).model_dump(mode="json")
    return JSONResponse(
        body,
        status_code=status_code,
        headers={ETAG_HEADER: quote_etag(snapshot["etag"])},
    )


# --------------------------------------------------------------------------- #
# Policy library
# --------------------------------------------------------------------------- #


@app.put(
    "/policies/{name}",
    response_model=PolicySnapshot,
    tags=["policies"],
    status_code=201,
    responses={
        200: {"description": "A new immutable version of an existing policy."},
        201: {"description": "Policy created (version 1)."},
        412: {"description": "Missing or stale If-Match ETag."},
    },
)
def put_policy(
    name: PolicyName,
    body: PolicyUpsert,
    if_match: Optional[str] = Header(default=None),
    store: PolicyStore = Depends(get_store),
) -> JSONResponse:
    expected = parse_if_match(if_match)

    created = expected is None
    try:
        snapshot = store.put(
            name,
            [rule.model_dump() for rule in body.rules],
            expected_etags=expected,
        )
    except StalePolicyVersion as exc:
        headers: dict[str, str] = {}
        # Surface the current ETag so the client can re-read and retry.
        try:
            headers[ETAG_HEADER] = quote_etag(store.get_latest(name)["etag"])
        except PolicyNotFound:
            pass
        raise HTTPException(status_code=412, detail=str(exc), headers=headers) from exc
    except PolicyStoreBusy as exc:
        raise HTTPException(
            status_code=503,
            detail="policy store is busy with another update; retry shortly",
            headers={"Retry-After": "1"},
        ) from exc

    return _snapshot_response(snapshot, status_code=201 if created else 200)


@app.get(
    "/policies/{name}/versions/{version}",
    response_model=PolicySnapshot,
    tags=["policies"],
    responses={404: {"description": "Unknown policy name or version."}},
)
def get_policy_version(
    name: PolicyName,
    version: Annotated[int, Path(ge=1)],
    store: PolicyStore = Depends(get_store),
) -> JSONResponse:
    try:
        snapshot = store.get_version(name, version)
    except PolicyNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _snapshot_response(snapshot)


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok"}


def _load_policy(selector: PolicySelector, store: PolicyStore):
    """Return (snapshot, policy_ref) for the requested policy reference."""
    if selector.version is None:
        snapshot = store.get_latest(selector.name)
        latest = True
    else:
        snapshot = store.get_version(selector.name, selector.version)
        latest = False
    policy_ref = PolicyRef(name=snapshot["name"], version=snapshot["version"], latest=latest)
    return snapshot, policy_ref


@app.post("/redact", response_model=RedactResponse, tags=["redact"])
def redact_endpoint(
    request: RedactRequest,
    http_request: Request,
) -> JSONResponse:
    policy_ref: Optional[PolicyRef] = None

    if request.policy is not None:
        # Only touch the policy database when the request actually references one;
        # purely inline requests must work even if the volume is unavailable.
        store = get_store(http_request)
        try:
            snapshot, policy_ref = _load_policy(request.policy, store)
        except PolicyNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        specs = [RuleSpec.model_validate(rule) for rule in snapshot["rules"]]
    else:
        specs = request.inline_rules

    # Compile specs inside the handler so an invalid pointer produces a clean
    # 422 (Pydantic ValidationError -> FastAPI) rather than a 500.
    rules = compile_specs(specs)
    redacted, audit = redact(request.data, rules, salt=config.get_salt())

    policy_payload = policy_ref.model_dump() if policy_ref is not None else None
    if policy_ref is not None:
        for entry in audit:
            entry["policy"] = policy_payload

    body = RedactResponse.model_validate(
        {"redacted": redacted, "audit": audit, "policy": policy_payload}
    )
    return JSONResponse(body.model_dump(mode="json"))
