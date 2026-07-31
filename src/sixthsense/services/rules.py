"""Rule storage and the audit trail.

Every mutation writes an audit row in the same transaction as the change itself (D-31). If
the audit write fails, the change fails. That ordering is the point: an unaudited rule
change is worse than a rejected one.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from sixthsense.db.models import AuditRow, ChainSettingsRow, RuleRow
from sixthsense.models.rule import (
    Action,
    Rule,
    RuleChain,
    RuleCreate,
    RuleUpdate,
)

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


class RuleNotFound(LookupError):
    pass


class DuplicateRule(ValueError):
    pass


class InvalidRule(ValueError):
    """A merged update produced a rule that violates the model's cross-field rules."""


def _slugify(name: str) -> str:
    slug = _SLUG_STRIP.sub("-", name.lower()).strip("-")[:48]
    return slug or "rule"


def _row_to_rule(row: RuleRow) -> Rule:
    return Rule.model_validate(
        {
            "id": row.id,
            "name": row.name,
            "description": row.description,
            "enabled": row.enabled,
            "order": row.order,
            "action": row.action,
            "conditions": row.conditions,
            "output": row.output,
            "retain_payload": row.retain_payload,
            "shadow": row.shadow,
            "version": row.version,
            "updated_at": row.updated_at,
        }
    )


def _snapshot(row: RuleRow) -> dict[str, Any]:
    return _row_to_rule(row).model_dump(mode="json")


def write_audit(
    session: Session,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    note: str = "",
) -> None:
    session.add(
        AuditRow(
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            before=before,
            after=after,
            note=note,
        )
    )


def list_rules(session: Session) -> list[Rule]:
    rows = session.scalars(select(RuleRow).order_by(RuleRow.order, RuleRow.id))
    return [_row_to_rule(r) for r in rows]


def get_rule(session: Session, rule_id: str) -> Rule:
    row = session.get(RuleRow, rule_id)
    if row is None:
        raise RuleNotFound(rule_id)
    return _row_to_rule(row)


def get_chain_settings(session: Session) -> ChainSettingsRow:
    row = session.get(ChainSettingsRow, 1)
    if row is None:
        row = ChainSettingsRow(id=1, default_action=Action.FORWARD.value, shadow_mode=False)
        session.add(row)
        session.flush()
    return row


def load_chain(session: Session) -> RuleChain:
    settings = get_chain_settings(session)
    return RuleChain(
        rules=list_rules(session),
        default_action=Action(settings.default_action),
        shadow_mode=settings.shadow_mode,
    )


def _unique_id(session: Session, name: str) -> str:
    base = _slugify(name)
    candidate = base
    suffix = 2
    while session.get(RuleRow, candidate) is not None:
        candidate = f"{base}-{suffix}"[:63]
        suffix += 1
    return candidate


def create_rule(session: Session, payload: RuleCreate, *, actor: str) -> Rule:
    rule_id = _unique_id(session, payload.name)
    row = RuleRow(
        id=rule_id,
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        order=payload.order,
        action=payload.action.value,
        conditions=[c.model_dump(mode="json") for c in payload.conditions],
        output=payload.output,
        retain_payload=payload.retain_payload,
        shadow=payload.shadow,
        version=1,
        updated_at=datetime.now(UTC),
    )
    session.add(row)
    session.flush()

    rule = _row_to_rule(row)
    write_audit(
        session,
        actor=actor,
        action="rule.create",
        target_type="rule",
        target_id=rule_id,
        after=rule.model_dump(mode="json"),
    )
    return rule


def update_rule(session: Session, rule_id: str, payload: RuleUpdate, *, actor: str) -> Rule:
    row = session.get(RuleRow, rule_id)
    if row is None:
        raise RuleNotFound(rule_id)

    before = _snapshot(row)
    data = payload.model_dump(exclude_unset=True)

    for key, value in data.items():
        if value is None:
            continue
        if key == "action":
            row.action = Action(value).value
        elif key == "conditions":
            row.conditions = [
                c if isinstance(c, dict) else c.model_dump(mode="json") for c in value
            ]
        else:
            setattr(row, key, value)

    row.version += 1
    row.updated_at = datetime.now(UTC)

    # Validate the merged result before it is flushed. A partial update can produce an
    # invalid combination even when every individual field is fine, for example clearing
    # the drop action while retain_payload is still set.
    try:
        rule = _row_to_rule(row)
    except PydanticValidationError as exc:
        session.rollback()
        raise InvalidRule(str(exc)) from exc

    session.flush()

    write_audit(
        session,
        actor=actor,
        action="rule.update",
        target_type="rule",
        target_id=rule_id,
        before=before,
        after=rule.model_dump(mode="json"),
    )
    return rule


def disable_rule(session: Session, rule_id: str, *, actor: str) -> Rule:
    """D-31: there is no hard delete. Disabling is the only removal path."""
    row = session.get(RuleRow, rule_id)
    if row is None:
        raise RuleNotFound(rule_id)

    before = _snapshot(row)
    row.enabled = False
    row.version += 1
    row.updated_at = datetime.now(UTC)
    session.flush()

    rule = _row_to_rule(row)
    write_audit(
        session,
        actor=actor,
        action="rule.disable",
        target_type="rule",
        target_id=rule_id,
        before=before,
        after=rule.model_dump(mode="json"),
        note="rules are disabled, never deleted",
    )
    return rule


def set_chain_settings(
    session: Session,
    *,
    actor: str,
    default_action: Action | None = None,
    shadow_mode: bool | None = None,
) -> RuleChain:
    row = get_chain_settings(session)
    before = {"default_action": row.default_action, "shadow_mode": row.shadow_mode}

    if default_action is not None:
        row.default_action = default_action.value
    if shadow_mode is not None:
        row.shadow_mode = shadow_mode
    session.flush()

    write_audit(
        session,
        actor=actor,
        action="chain.settings",
        target_type="chain",
        target_id="1",
        before=before,
        after={"default_action": row.default_action, "shadow_mode": row.shadow_mode},
    )
    return load_chain(session)


def list_audit(session: Session, *, limit: int = 200) -> list[AuditRow]:
    stmt = select(AuditRow).order_by(AuditRow.id.desc()).limit(limit)
    return list(session.scalars(stmt))
