"""FastAPI application exposing POST /redact."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import config
from .redaction import redact
from .schemas import RedactRequest, RedactResponse, compile_specs

app = FastAPI(
    title="JSON Redaction API",
    version="1.0.0",
    description="Redact arbitrary JSON using JSON Pointer rules with * / ** globs.",
)


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok"}


@app.post("/redact", response_model=RedactResponse, tags=["redact"])
def redact_endpoint(request: RedactRequest) -> JSONResponse:
    # Compile specs inside the handler so an invalid pointer produces a clean
    # 422 (Pydantic ValidationError -> FastAPI) rather than a 500.
    rules = compile_specs(request.rules)
    redacted, audit = redact(request.data, rules, salt=config.get_salt())
    return JSONResponse({"redacted": redacted, "audit": audit})
