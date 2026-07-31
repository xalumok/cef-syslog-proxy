"""Compile, validate, publish, and roll back config bundles.

The publish path is the rules pipeline from the DevSecOps document. Every gate below stands
in for a control that the code path gets from CI:

1. Pydantic validated the rule on the way in.
2. The compiler emits VRL through the typed encoder only.
3. ``vector validate`` checks the generated config before it is ever stored.
4. Activation is atomic and the previous bundle stays available for rollback.
"""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from sixthsense.compiler.compiler import compile_or_raise
from sixthsense.compiler.validate import validate_config
from sixthsense.compiler.vector_config import (
    MIN_VECTOR_VERSION,
    VectorSettings,
    render_toml,
)
from sixthsense.config import get_settings
from sixthsense.db.models import BundleRow
from sixthsense.models.bundle import Bundle, BundleManifest, BundleSummary, checksum
from sixthsense.models.rule import RuleChain
from sixthsense.services.rules import load_chain, write_audit


class BundleValidationError(ValueError):
    """The generated config did not pass ``vector validate``."""


def vector_settings_from_config() -> VectorSettings:
    cfg = get_settings()
    return VectorSettings(
        listen_address=cfg.vector_listen_address,
        elk_address=cfg.vector_elk_address,
        drop_audit_address=cfg.vector_drop_audit_address,
        control_plane_url=cfg.control_plane_url,
        receive_buffer_bytes=cfg.vector_receive_buffer_bytes,
        sample_rate=cfg.vector_sample_rate,
    )


def next_version(session: Session) -> int:
    current = session.scalar(select(BundleRow.version).order_by(BundleRow.version.desc()))
    return (current or 0) + 1


def build_bundle(chain: RuleChain, version: int, *, created_by: str, note: str = "") -> Bundle:
    toml_text = render_toml(chain, vector_settings_from_config(), chain_version=version)
    manifest = BundleManifest(
        version=version,
        checksum=checksum(toml_text),
        created_by=created_by,
        rule_ids=[r.id for r in chain.active()],
        default_action=chain.default_action.value,
        shadow_mode=chain.shadow_mode,
        vector_min_version=MIN_VECTOR_VERSION,
        note=note,
    )
    return Bundle(manifest=manifest, config_toml=toml_text)


def publish(
    session: Session,
    *,
    actor: str,
    note: str = "",
    require_vector: bool | None = None,
) -> BundleSummary:
    """Compile the current chain, validate it, store it, and make it active.

    ``require_vector`` defaults to the ``SS_REQUIRE_VECTOR_ON_PUBLISH`` setting, which is on.
    Pass it explicitly only in tests. Leaving the gate optional is how an unvalidated bundle
    reaches a node: the publish succeeds, the node fetches it, Vector refuses to start, and
    the rollout silently does nothing.
    """
    if require_vector is None:
        require_vector = get_settings().require_vector_on_publish
    chain = load_chain(session)
    version = next_version(session)
    bundle = build_bundle(chain, version, created_by=actor, note=note)

    # Pass the VRL program explicitly. `vector validate` alone does not compile it, so
    # without this an undefined-variable bug would pass the gate and only surface when a
    # node refused to start.
    result = validate_config(
        bundle.config_toml,
        vrl_program=compile_or_raise(chain, chain_version=version),
    )
    if result.skipped and require_vector:
        raise BundleValidationError(
            "vector binary is required to publish but was not found on PATH"
        )
    if not result.ok:
        raise BundleValidationError(f"vector {result.stage} check failed: {result.output[:2000]}")

    session.execute(update(BundleRow).where(BundleRow.active.is_(True)).values(active=False))

    row = BundleRow(
        version=version,
        checksum=bundle.manifest.checksum,
        config_toml=bundle.config_toml,
        manifest=bundle.manifest.model_dump(mode="json"),
        created_by=actor,
        active=True,
        note=note,
    )
    session.add(row)
    session.flush()

    write_audit(
        session,
        actor=actor,
        action="bundle.publish",
        target_type="bundle",
        target_id=str(version),
        after=bundle.manifest.model_dump(mode="json"),
        note="validate skipped (no vector binary)" if result.skipped else "",
    )

    return _summary(row)


def rollback(session: Session, target_version: int, *, actor: str) -> BundleSummary:
    """Reactivate a previous bundle. One click in the UI, per D-30.

    Nothing is rebuilt: the exact bytes that were running before are restored, so a rollback
    cannot be affected by a rule edit made since.
    """
    row = session.scalar(select(BundleRow).where(BundleRow.version == target_version))
    if row is None:
        raise LookupError(f"no bundle with version {target_version}")

    previous = active_bundle_row(session)
    session.execute(update(BundleRow).where(BundleRow.active.is_(True)).values(active=False))
    row.active = True
    session.flush()

    write_audit(
        session,
        actor=actor,
        action="bundle.rollback",
        target_type="bundle",
        target_id=str(target_version),
        before={"version": previous.version} if previous else None,
        after={"version": target_version},
    )
    return _summary(row)


def active_bundle_row(session: Session) -> BundleRow | None:
    return session.scalar(select(BundleRow).where(BundleRow.active.is_(True)))


def get_active_bundle(session: Session) -> Bundle | None:
    row = active_bundle_row(session)
    if row is None:
        return None
    return Bundle(
        manifest=BundleManifest.model_validate(row.manifest),
        config_toml=row.config_toml,
    )


def list_bundles(session: Session, *, limit: int = 50) -> list[BundleSummary]:
    stmt = select(BundleRow).order_by(BundleRow.version.desc()).limit(limit)
    return [_summary(r) for r in session.scalars(stmt)]


def _summary(row: BundleRow) -> BundleSummary:
    manifest = row.manifest or {}
    return BundleSummary(
        version=row.version,
        checksum=row.checksum,
        created_at=row.created_at,
        created_by=row.created_by,
        rule_count=len(manifest.get("rule_ids", [])),
        active=row.active,
        note=row.note or "",
    )
