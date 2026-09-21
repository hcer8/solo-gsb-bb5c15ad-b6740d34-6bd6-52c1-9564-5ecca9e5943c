"""Pydantic models for the redaction API."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .redaction import compile_rule, parse_pointer

Action = Literal["mask", "remove", "sha256"]


class RuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pointer: str = Field(
        ...,
        description="JSON Pointer (RFC 6901); '*' matches one segment, '**' matches any number.",
        examples=["/users/*/email"],
    )
    action: Action = Field(..., description="Action to apply to every matched node.")
    name: Optional[str] = Field(
        default=None, description="Optional human-readable name echoed into the audit trail."
    )

    @field_validator("pointer")
    @classmethod
    def _valid_pointer(cls, value: str) -> str:
        # Raises ValueError -> Pydantic ValidationError -> HTTP 422.
        parse_pointer(value)
        return value


class RedactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: Any = Field(..., description="Arbitrary JSON document to redact.")
    rules: List[RuleSpec] = Field(
        default_factory=list, description="Redaction rules evaluated in declaration order."
    )


class RuleRef(BaseModel):
    index: int = Field(..., description="Zero-based declaration index within request ``rules``.")
    pointer: str
    action: Action
    name: Optional[str] = None


class AuditEntry(BaseModel):
    pointer: str = Field(..., description="JSON Pointer of the node on the ORIGINAL document.")
    action: Action
    rule: RuleRef


class RedactResponse(BaseModel):
    redacted: Any
    audit: List[AuditEntry]


def compile_specs(rules: List[RuleSpec]):
    """Turn validated request specs into engine rules."""
    return [
        compile_rule(index=i, pointer=spec.pointer, action=spec.action, name=spec.name)
        for i, spec in enumerate(rules)
    ]
