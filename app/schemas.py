"""Pydantic models for the redaction API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Annotated, List, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .redaction import compile_rule, parse_pointer

Action = Literal["mask", "remove", "sha256"]

# Policy names are path-safe identifiers so they need no URL-encoding.
PolicyName = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"),
]


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


class PolicySelector(BaseModel):
    """Reference to a stored policy used by POST /redact."""

    model_config = ConfigDict(extra="forbid")

    name: PolicyName = Field(..., description="Name of the stored policy.")
    version: Optional[int] = Field(
        default=None,
        ge=1,
        description=(
            "Exact immutable version to apply. "
            "Omit to atomically read the latest version at request time."
        ),
    )


class RedactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: Any = Field(..., description="Arbitrary JSON document to redact.")
    rules: Optional[List[RuleSpec]] = Field(
        default=None,
        description="Inline redaction rules. Provide exactly one of 'rules' or 'policy'.",
    )
    policy: Optional[PolicySelector] = Field(
        default=None,
        description="Named stored policy to apply. Provide exactly one of 'rules' or 'policy'.",
    )

    @model_validator(mode="after")
    def _exactly_one_rule_source(self) -> "RedactRequest":
        if (self.rules is not None) and (self.policy is not None):
            raise ValueError("provide exactly one of 'rules' or 'policy', not both")
        return self

    @property
    def inline_rules(self) -> List[RuleSpec]:
        """Inline rules, defaulting to an empty list for backward compatibility."""
        return self.rules if self.rules is not None else []


class PolicyUpsert(BaseModel):
    """Body of PUT /policies/{name}: the rules of the new version."""

    model_config = ConfigDict(extra="forbid")

    rules: List[RuleSpec] = Field(
        ..., description="Redaction rules evaluated in declaration order."
    )


class RuleRef(BaseModel):
    index: int = Field(..., description="Zero-based declaration index within the policy/rules.")
    pointer: str
    action: Action
    name: Optional[str] = None


class PolicyRef(BaseModel):
    """Which stored policy a redaction actually used."""

    name: str
    version: int
    latest: bool = Field(
        ..., description="True when the request omitted 'version' and pinned the then-latest one."
    )


class AuditEntry(BaseModel):
    pointer: str = Field(..., description="JSON Pointer of the node on the ORIGINAL document.")
    action: Action
    rule: RuleRef
    # Present only when the redaction ran against a stored policy.
    policy: Optional[PolicyRef] = None


class RedactResponse(BaseModel):
    redacted: Any
    audit: List[AuditEntry]
    # Present only when the redaction ran against a stored policy.
    policy: Optional[PolicyRef] = Field(
        default=None, description="Actual policy name and version applied."
    )


class PolicySnapshot(BaseModel):
    """An immutable policy version, as stored and returned by the API."""

    name: str
    version: int
    etag: str
    created_at: datetime
    rules: List[RuleSpec]


def compile_specs(rules: List[RuleSpec]):
    """Turn validated request specs into engine rules."""
    return [
        compile_rule(index=i, pointer=spec.pointer, action=spec.action, name=spec.name)
        for i, spec in enumerate(rules)
    ]
