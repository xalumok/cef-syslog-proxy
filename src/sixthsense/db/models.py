"""SQLAlchemy models.

Two properties matter here and are enforced rather than documented:

* The audit log is append-only (D-31). There is no update or delete path in the API.
* Rules are never hard deleted (D-31). Deleting sets ``enabled = false`` and records it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class RuleRow(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    output: Mapped[str] = mapped_column(String(64), default="default")
    retain_payload: Mapped[bool] = mapped_column(Boolean, default=False)
    shadow: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ChainSettingsRow(Base):
    """Chain-level settings. Exactly one row, id = 1."""

    __tablename__ = "chain_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    default_action: Mapped[str] = mapped_column(String(16), default="forward")
    shadow_mode: Mapped[bool] = mapped_column(Boolean, default=False)


class BundleRow(Base):
    __tablename__ = "bundles"
    __table_args__ = (UniqueConstraint("version", name="uq_bundle_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    config_toml: Mapped[str] = mapped_column(Text, nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    note: Mapped[str] = mapped_column(Text, default="")


class AuditRow(Base):
    """Append-only change log (D-31). No update path exists anywhere in the codebase."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    before: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")


class UserRow(Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(128), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)


class SampleEventRow(Base):
    """Persisted traffic sample.

    This is the store the impact preview (D-27) and the offline replay (D-29) read from.
    The live view's ring buffer is in memory and far too short-lived for either.

    Bounded by ``sample_store_max_events``: the oldest rows are trimmed on insert.
    """

    __tablename__ = "sample_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    node: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fields: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)
