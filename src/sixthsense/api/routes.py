"""HTTP routes.

Grouped by concern rather than split across files, because the whole surface is small enough
to read in one sitting and that is worth more than tidy file boundaries.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Response, WebSocket, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sixthsense.api.auth import (
    WS_SUBPROTOCOL,
    Principal,
    RequireAdmin,
    RequireEditor,
    RequireViewer,
    Role,
    authenticate,
    current_principal,
    issue_token,
    principal_from_token,
    websocket_token,
)
from sixthsense.config import get_settings
from sixthsense.db.session import get_session, session_scope
from sixthsense.models.rule import (
    Action,
    DecisionRecord,
    Rule,
    RuleCreate,
    RuleUpdate,
)
from sixthsense.sampling.store import get_tail_buffer, load_samples, record_samples
from sixthsense.services import bundles as bundle_service
from sixthsense.services import rules as rule_service
from sixthsense.services.simulate import simulate

SessionDep = Annotated[Session, Depends(get_session)]

router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------- auth ----


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 field name, not a credential
    role: Role
    username: str


@router.post("/auth/token", response_model=TokenResponse, tags=["auth"])
def login(
    session: SessionDep,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> TokenResponse:
    principal = authenticate(session, form.username, form.password)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    token = issue_token(principal, get_settings())
    return TokenResponse(access_token=token, role=principal.role, username=principal.username)


@router.get("/auth/me", tags=["auth"])
def whoami(principal: Annotated[Principal, Depends(current_principal)]) -> dict[str, Any]:
    return {
        "username": principal.username,
        "role": principal.role,
        "may_see_event_contents": principal.may_see_event_contents,
    }


# --------------------------------------------------------------------------- rules ----


@router.get("/rules", response_model=list[Rule], tags=["rules"])
def get_rules(session: SessionDep, _: RequireViewer) -> list[Rule]:
    return rule_service.list_rules(session)


@router.post("/rules", response_model=Rule, status_code=status.HTTP_201_CREATED, tags=["rules"])
def post_rule(session: SessionDep, principal: RequireEditor, payload: RuleCreate) -> Rule:
    rule = rule_service.create_rule(session, payload, actor=principal.username)
    session.commit()
    return rule


@router.patch("/rules/{rule_id}", response_model=Rule, tags=["rules"])
def patch_rule(
    session: SessionDep, principal: RequireEditor, rule_id: str, payload: RuleUpdate
) -> Rule:
    try:
        rule = rule_service.update_rule(session, rule_id, payload, actor=principal.username)
    except rule_service.RuleNotFound as exc:
        raise HTTPException(status_code=404, detail=f"no rule {rule_id}") from exc
    except rule_service.InvalidRule as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return rule


@router.delete("/rules/{rule_id}", response_model=Rule, tags=["rules"])
def delete_rule(session: SessionDep, principal: RequireEditor, rule_id: str) -> Rule:
    """Disables the rule. D-31: there is no hard delete anywhere in this system."""
    try:
        rule = rule_service.disable_rule(session, rule_id, actor=principal.username)
    except rule_service.RuleNotFound as exc:
        raise HTTPException(status_code=404, detail=f"no rule {rule_id}") from exc
    session.commit()
    return rule


class ChainSettingsPayload(BaseModel):
    default_action: Action | None = None
    shadow_mode: bool | None = None


@router.get("/chain", tags=["rules"])
def get_chain(session: SessionDep, _: RequireViewer) -> dict[str, Any]:
    chain = rule_service.load_chain(session)
    return {
        "default_action": chain.default_action,
        "shadow_mode": chain.shadow_mode,
        "rule_count": len(chain.rules),
        "active_rule_count": len(chain.active()),
    }


@router.put("/chain", tags=["rules"])
def put_chain(
    session: SessionDep, principal: RequireAdmin, payload: ChainSettingsPayload
) -> dict[str, Any]:
    """Chain-level settings are admin-only.

    D-01 and the DevSecOps separation-of-duties table: flipping the whole system to
    fail-closed must not be a two-click operation for a rule editor.
    """
    chain = rule_service.set_chain_settings(
        session,
        actor=principal.username,
        default_action=payload.default_action,
        shadow_mode=payload.shadow_mode,
    )
    session.commit()
    return {"default_action": chain.default_action, "shadow_mode": chain.shadow_mode}


# ------------------------------------------------------------------------- bundles ----


@router.get("/bundles", tags=["bundles"])
def get_bundles(session: SessionDep, _: RequireViewer) -> list[Any]:
    return bundle_service.list_bundles(session)


@router.post("/bundles/publish", tags=["bundles"])
def publish_bundle(
    session: SessionDep,
    principal: RequireEditor,
    note: Annotated[str, Body(embed=True)] = "",
) -> Any:
    try:
        summary = bundle_service.publish(session, actor=principal.username, note=note)
    except bundle_service.BundleValidationError as exc:
        # The gate did its job. Surface the Vector output verbatim: it is the most useful
        # thing we can show, and paraphrasing it would lose the line number.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return summary


@router.post("/bundles/{version}/rollback", tags=["bundles"])
def rollback_bundle(session: SessionDep, principal: RequireEditor, version: int) -> Any:
    try:
        summary = bundle_service.rollback(session, version, actor=principal.username)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    session.commit()
    return summary


@router.get("/bundles/active/config", tags=["bundles"])
def get_active_config(session: SessionDep, _: RequireViewer) -> Response:
    """The exact TOML a node would fetch. Useful for review and for debugging."""
    bundle = bundle_service.get_active_bundle(session)
    if bundle is None:
        raise HTTPException(status_code=404, detail="no active bundle")
    return Response(content=bundle.config_toml, media_type="text/plain")


@router.get("/agent/bundle", tags=["agent"])
def agent_bundle(session: SessionDep, since: int = 0) -> Any:
    """Endpoint the node agent polls.

    Returns 304-equivalent (``{"changed": false}``) when the node already has the active
    version, so the common case costs one small response.

    Transport security is mutual TLS at the ingress, not a token here. See the readme.
    """
    bundle = bundle_service.get_active_bundle(session)
    if bundle is None:
        raise HTTPException(status_code=404, detail="no active bundle")
    if bundle.manifest.version == since:
        return {"changed": False, "version": since}
    return {
        "changed": True,
        "manifest": bundle.manifest.model_dump(mode="json"),
        "config_toml": bundle.config_toml,
    }


# ----------------------------------------------------------------------- decisions ----


@router.post("/decisions/intake", status_code=204, tags=["decisions"])
def intake(records: list[DecisionRecord]) -> Response:
    """Sampled decisions posted by Vector.

    Unauthenticated by design and reachable only from the node network. Adding a round trip
    to the control plane's auth path here would put the control plane closer to the data
    path, which is the one thing this architecture will not do.

    The trust boundary is the network, and it is worth stating what that buys an attacker who
    crosses it. This endpoint feeds two things: the live view, and the persisted sample store
    that the impact preview reads. So whoever can reach this port can both fabricate decisions
    in the live view and skew the drop-share estimate an analyst uses to decide whether a rule
    is safe to publish, including pushing real traffic out of the bounded sample ring.

    D-35 calls for this listener to be separate from the admin API. It is not: both are served
    by one app on one port, and the separation is currently a network-policy question rather
    than an application one. That gap is recorded in the decision register.
    """
    settings = get_settings()
    buffer = get_tail_buffer()
    for record in records:
        buffer.publish(record)

    with session_scope() as session:
        record_samples(
            session,
            records,
            max_events=settings.sample_store_max_events,
            retain_raw=settings.sample_store_retain_raw,
        )
    return Response(status_code=204)


@router.get("/decisions/recent", response_model=list[DecisionRecord], tags=["decisions"])
def recent_decisions(principal: RequireViewer, limit: int = 100) -> list[DecisionRecord]:
    records = get_tail_buffer().recent(limit=limit)
    return [_redact(r, principal) for r in records]


def _redact(record: DecisionRecord, principal: Principal) -> DecisionRecord:
    """D-36: strip payloads before serialization, not in the browser."""
    if principal.may_see_event_contents:
        return record
    return record.model_copy(update={"raw": None, "fields": {}})


@router.websocket("/decisions/tail")
async def tail_ws(websocket: WebSocket, session: SessionDep) -> None:
    """Live view.

    Strictly non-blocking (D-37). A browser that cannot keep up loses frames; the publisher
    is never slowed, because it sits on the path from the data plane.

    Authenticated and redacted exactly like ``/decisions/recent`` (D-34, D-36). This socket
    streams the same records that endpoint returns, so anything less here would make the
    redaction on that endpoint decorative.
    """
    try:
        principal = principal_from_token(websocket_token(websocket), session)
    except HTTPException:
        # Close during the handshake rather than accepting first. An accepted socket that
        # immediately closes looks like a transient network fault to the client, and the UI
        # would reconnect against it forever.
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="not authenticated")
        return

    # Echoing the subprotocol is required: a browser closes the connection when the server
    # accepts without selecting one of the protocols it offered.
    await websocket.accept(subprotocol=WS_SUBPROTOCOL)
    buffer = get_tail_buffer()
    queue = buffer.subscribe()
    try:
        while True:
            record = await queue.get()
            await websocket.send_json(_redact(record, principal).model_dump(mode="json"))
    except Exception:
        # A disconnected browser is the normal way out of this loop, not an error worth
        # logging. CancelledError is deliberately not caught: it is a BaseException, and
        # swallowing it would stop shutdown from propagating through this task.
        return
    finally:
        buffer.unsubscribe(queue)


# ------------------------------------------------------------------------ simulate ----


class SimulatePayload(BaseModel):
    limit: int = 2000


@router.post("/simulate", tags=["simulate"])
def post_simulate(
    session: SessionDep, _: RequireEditor, payload: SimulatePayload
) -> dict[str, Any]:
    """Impact preview for the current chain against the stored traffic sample.

    Runs real Vector. If Vector is unavailable it reports that rather than approximating,
    because an approximate preview is worse than an honest refusal (D-29).
    """
    chain = rule_service.load_chain(session)
    rows = load_samples(session, limit=payload.limit)
    events = [r.raw for r in rows if r.raw]

    result = simulate(chain, events)
    return {
        "available": result.available,
        "detail": result.detail,
        "total": result.total,
        "forwarded": result.forwarded,
        "dropped": result.dropped,
        "parse_errors": result.parse_errors,
        "per_rule": result.per_rule,
        "drop_share": round(result.drop_share, 4),
        "requires_confirmation": result.exceeds_confirmation_threshold,
        "sample_size": len(events),
    }


# --------------------------------------------------------------------------- audit ----


@router.get("/audit", tags=["audit"])
def get_audit(session: SessionDep, _: RequireViewer, limit: int = 200) -> list[dict[str, Any]]:
    return [
        {
            "id": row.id,
            "ts": row.ts,
            "actor": row.actor,
            "action": row.action,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "before": row.before,
            "after": row.after,
            "note": row.note,
        }
        for row in rule_service.list_audit(session, limit=limit)
    ]


# -------------------------------------------------------------------------- health ----


@router.get("/health", tags=["health"])
def health(session: SessionDep) -> dict[str, Any]:
    active = bundle_service.active_bundle_row(session)
    settings = get_settings()
    return {
        "status": "ok",
        "active_bundle_version": active.version if active else None,
        "default_action": rule_service.get_chain_settings(session).default_action,
        "tail_subscribers": get_tail_buffer().subscriber_count,
        "auth_mode": settings.auth_mode,
        "dev_auth_bypass": settings.dev_auth_bypass,
    }
