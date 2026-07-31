"""The rule schema.

This is the core data model. Everything else derives from it: the API, the UI forms, the
compiler, and the JSON Schema that agents read (D-47).

Design notes:
  - D-05: an ordered chain, first match wins. Each rule carries an action.
  - D-04: schema-agnostic. Any field name is valid, not just the 10 known ones.
  - D-06: 14 operators, no regular expressions.
  - D-07: comparisons ignore case by default.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# The 10 fields named in the task. The engine accepts any field (D-04); these are the ones
# the UI offers first-class. Do not treat this list as a constraint.
KNOWN_FIELDS: tuple[str, ...] = (
    "eventid",
    "filterhostname",
    "filterid",
    "filteripaddress",
    "filternodename",
    "filterpriority",
    "filtertype",
    "notificationtime",
    "name",
    "severity",
)

# CEF header fields, named exactly as Vector's parse_cef returns them once downcased.
#
# D-09 wanted a colliding extension key preserved as "ext.severity". That is not achievable:
# parse_cef returns a flat map and the header value wins, so a colliding extension is
# discarded inside the function before any of our code runs. See the decision register.
CEF_HEADER_FIELDS: tuple[str, ...] = (
    "cefversion",
    "devicevendor",
    "deviceproduct",
    "deviceversion",
    "deviceeventclassid",
    "name",
    "severity",
)

# Syslog fields, as parse_syslog returns them. They are addressed under the "syslog." prefix
# so they never collide with a CEF field of the same name (D-14).
#
# "severity" is the reason the namespace exists. A CEF severity is an integer from 0 to 10
# where higher is worse; a syslog severity is a word like "info" or "err". Merging them flat
# would give one field name two types and two directions.
SYSLOG_FIELDS: tuple[str, ...] = (
    "syslog.appname",
    "syslog.facility",
    "syslog.hostname",
    "syslog.message",
    "syslog.msgid",
    "syslog.procid",
    "syslog.severity",
    "syslog.timestamp",
)


class Operator(StrEnum):
    """The 14 operators from D-06. Deliberately no regular expression operator."""

    EQ = "eq"
    NE = "ne"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    GLOB = "glob"
    CIDR = "cidr"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


#: Operators that take no value.
NULLARY_OPERATORS: frozenset[Operator] = frozenset({Operator.EXISTS, Operator.NOT_EXISTS})
#: Operators whose value is a list.
LIST_OPERATORS: frozenset[Operator] = frozenset({Operator.IN, Operator.NOT_IN})
#: Operators that compare numerically.
NUMERIC_OPERATORS: frozenset[Operator] = frozenset(
    {Operator.LT, Operator.LTE, Operator.GT, Operator.GTE}
)
#: Operators that only make sense on strings.
STRING_OPERATORS: frozenset[Operator] = frozenset(
    {Operator.CONTAINS, Operator.STARTS_WITH, Operator.ENDS_WITH, Operator.GLOB}
)


class Action(StrEnum):
    FORWARD = "forward"
    DROP = "drop"


ScalarValue = str | int | float | bool


class Condition(BaseModel):
    """One test against one field of an event.

    Conditions within a rule combine with AND (D-05). Express OR with `in`, or with a
    second rule.
    """

    model_config = ConfigDict(extra="forbid")

    field: Annotated[str, Field(min_length=1, max_length=256)]
    operator: Operator
    value: ScalarValue | list[ScalarValue] | None = None
    case_sensitive: bool = False
    """D-07: comparisons ignore case unless you opt in."""

    @field_validator("field")
    @classmethod
    def _normalize_field(cls, v: str) -> str:
        # Field names are matched case-insensitively (D-07). Normalize at the boundary so
        # the compiler never has to think about it.
        #
        # A dot separates path segments, so "syslog.appname" addresses the syslog namespace.
        # Normalize per segment, and reject an empty one here rather than letting it reach
        # the compiler: a rejected rule is a 422, a compile failure is a 500.
        segments = [segment.strip().lower() for segment in v.strip().split(".")]
        if any(not segment for segment in segments):
            raise ValueError(f"empty path segment in field name: {v!r}")
        return ".".join(segments)

    @model_validator(mode="after")
    def _check_value_shape(self) -> Condition:
        op = self.operator

        if op in NULLARY_OPERATORS:
            if self.value is not None:
                raise ValueError(f"operator '{op}' takes no value")
            return self

        if self.value is None:
            raise ValueError(f"operator '{op}' requires a value")

        if op in LIST_OPERATORS:
            if not isinstance(self.value, list):
                raise ValueError(f"operator '{op}' requires a list value")
            if not self.value:
                raise ValueError(f"operator '{op}' requires a non-empty list")
            return self

        if isinstance(self.value, list):
            raise ValueError(f"operator '{op}' does not accept a list value")

        if op in NUMERIC_OPERATORS and isinstance(self.value, str):
            raise ValueError(f"operator '{op}' requires a numeric value")

        if op in STRING_OPERATORS and not isinstance(self.value, str):
            raise ValueError(f"operator '{op}' requires a string value")

        if op is Operator.CIDR:
            if not isinstance(self.value, str):
                raise ValueError("operator 'cidr' requires a string value")
            try:
                ipaddress.ip_network(self.value, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR: {exc}") from exc

        if op is Operator.GLOB:
            assert isinstance(self.value, str)
            if len(self.value) > 512:
                raise ValueError("glob pattern too long (max 512)")

        return self


class Rule(BaseModel):
    """One rule in the chain.

    Rule order is explicit and it matters: the first rule whose conditions all match
    decides the event (D-05).
    """

    model_config = ConfigDict(extra="forbid")

    id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]
    name: Annotated[str, Field(min_length=1, max_length=200)]
    description: str = ""
    enabled: bool = True
    order: Annotated[int, Field(ge=0)]
    action: Action
    conditions: Annotated[list[Condition], Field(min_length=1, max_length=64)]

    output: str = "default"
    """D-12: named output. Version 1 ships one, but the model carries the name."""

    retain_payload: bool = False
    """D-02: keep the full event in the drop audit record, not just metadata."""

    shadow: bool = False
    """D-29: evaluate and record, but do not enforce."""

    version: int = 1
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _check_retain_payload(self) -> Rule:
        if self.retain_payload and self.action is not Action.DROP:
            raise ValueError("retain_payload only applies to drop rules")
        return self


class RuleChain(BaseModel):
    """The complete, ordered rule set plus the chain-level defaults."""

    model_config = ConfigDict(extra="forbid")

    rules: list[Rule] = Field(default_factory=list)

    default_action: Action = Action.FORWARD
    """D-01: required, with no implicit fallback. Fail open is the shipped default, but the
    value is always written explicitly into the bundle so the choice is visible."""

    shadow_mode: bool = False
    """D-29: chain-wide shadow mode. Evaluate everything, enforce nothing."""

    @model_validator(mode="after")
    def _check_unique_and_sorted(self) -> RuleChain:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id}")
            seen.add(rule.id)
        return self

    def active(self) -> list[Rule]:
        """Enabled rules in evaluation order."""
        return sorted((r for r in self.rules if r.enabled), key=lambda r: (r.order, r.id))


class RuleCreate(BaseModel):
    """What the API accepts when creating a rule. The server owns id, version, and time.

    The cross-field checks are repeated here rather than only on :class:`Rule`. Validation
    has to happen at the boundary: if it only happened on the way out of the database, an
    invalid payload would be stored first and fail later as a server error.
    """

    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(min_length=1, max_length=200)]
    description: str = ""
    enabled: bool = True
    order: Annotated[int, Field(ge=0)] = 0
    action: Action
    conditions: Annotated[list[Condition], Field(min_length=1, max_length=64)]
    output: str = "default"
    retain_payload: bool = False
    shadow: bool = False

    @model_validator(mode="after")
    def _check_retain_payload(self) -> RuleCreate:
        if self.retain_payload and self.action is not Action.DROP:
            raise ValueError("retain_payload only applies to drop rules")
        return self


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(min_length=1, max_length=200)] | None = None
    description: str | None = None
    enabled: bool | None = None
    order: Annotated[int, Field(ge=0)] | None = None
    action: Action | None = None
    conditions: Annotated[list[Condition], Field(min_length=1, max_length=64)] | None = None
    output: str | None = None
    retain_payload: bool | None = None
    shadow: bool | None = None


class Decision(StrEnum):
    """What the data plane did with an event."""

    FORWARD = "forward"
    DROP = "drop"
    FORWARD_PARSE_ERROR = "forward_parse_error"
    """D-18: unparseable input is forwarded, counted, and sampled into the log."""


class DecisionRecord(BaseModel):
    """One sampled decision, posted from Vector to the control plane.

    Vector samples at the node (D-37), so this never arrives at event rate.
    """

    model_config = ConfigDict(extra="allow")

    ts: datetime
    decision: Decision
    rule_id: str | None = None
    rule_version: int | None = None
    reason: Literal["rule", "default", "parse_error", "shadow"] = "rule"
    source: str | None = None
    event_id: str | None = None
    node: str | None = None
    fields: dict[str, str] = Field(default_factory=dict)
    raw: str | None = None
    """Only populated when the role viewing it is allowed contents (D-36)."""
