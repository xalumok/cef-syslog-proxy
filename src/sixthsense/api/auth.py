"""Authentication and role checks.

D-34: roles are enforced here, in FastAPI dependencies, and never in React. The UI hides
controls for usability. This file is what makes them unreachable.

Scope note: the prototype implements local accounts fully. OpenID Connect is the intended
production mode and the :class:`Role` model and dependency structure are built for it, but
the OIDC backend is deliberately not implemented here rather than shipped untested. See the
readme for what that means for deployment.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, Request, WebSocket, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sixthsense.config import Settings, get_settings
from sixthsense.db.models import UserRow
from sixthsense.db.session import get_session

_hasher = PasswordHasher()
_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


class Role(StrEnum):
    VIEWER = "viewer"
    RULE_EDITOR = "rule-editor"
    ADMIN = "admin"


_RANK: dict[Role, int] = {Role.VIEWER: 0, Role.RULE_EDITOR: 1, Role.ADMIN: 2}


class Principal(BaseModel):
    username: str
    role: Role

    def at_least(self, role: Role) -> bool:
        return _RANK[self.role] >= _RANK[role]

    @property
    def may_see_event_contents(self) -> bool:
        """D-36: viewers get metadata and counts, not payloads."""
        return self.at_least(Role.RULE_EDITOR)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False
    return True


def issue_token(principal: Principal, settings: Settings) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": principal.username,
        "role": principal.role.value,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.jwt_ttl_seconds)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def authenticate(session: Session, username: str, password: str) -> Principal | None:
    row = session.get(UserRow, username)
    if row is None or row.disabled:
        # Hash anyway so a missing user and a wrong password take similar time.
        _hasher.hash(password)
        return None
    if not verify_password(row.password_hash, password):
        return None
    return Principal(username=row.username, role=Role(row.role))


def principal_from_token(token: str | None, session: Session) -> Principal:
    """Resolve a bearer token to a principal, or raise 401.

    Every authenticated entry point goes through here, HTTP and WebSocket alike. Keeping one
    implementation is the point: the live-tail socket shipped once with no check at all, and
    a second copy of this logic is how that happens again.
    """
    settings = get_settings()

    if settings.dev_auth_bypass:
        # Settings validation already guarantees this can only be on when bound to
        # loopback. See config.Settings._guard_dev_bypass.
        return Principal(username="dev", role=Role.ADMIN)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"invalid token: {exc}"
        ) from exc

    username = payload.get("sub")
    role = payload.get("role")
    if not username or role not in set(Role):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="malformed token")

    row = session.get(UserRow, username)
    if row is None or row.disabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user disabled")

    # The role comes from the row, not from the token claim. A token carries the role it was
    # issued with, so trusting the claim would let a demoted admin keep admin rights until the
    # token expired, 8 hours by default, while disabling took effect immediately. The row is
    # already loaded for the check above, so reading the current role costs nothing.
    return Principal(username=username, role=Role(row.role))


async def current_principal(
    request: Request,
    token: Annotated[str | None, Depends(_oauth2)] = None,
    session: Annotated[Session, Depends(get_session)] = None,  # type: ignore[assignment]
) -> Principal:
    if token is None:
        token = request.cookies.get("ss_token")
    return principal_from_token(token, session)


#: WebSocket subprotocol carrying the bearer token, as ["ss.bearer", "<token>"].
WS_SUBPROTOCOL = "ss.bearer"


def websocket_token(websocket: WebSocket) -> str | None:
    """Extract the bearer token a browser sent with a WebSocket handshake.

    The browser WebSocket API cannot set an Authorization header, so the token has to travel
    some other way. It goes in ``Sec-WebSocket-Protocol`` rather than the query string
    because a query string is written to access logs and proxy logs verbatim, and this token
    is a full admin credential for eight hours. The subprotocol header is not logged by
    default anywhere in the usual stack.

    The handshake must echo the protocol name back, or the browser closes the connection.
    """
    header = websocket.headers.get("sec-websocket-protocol", "")
    offered = [part.strip() for part in header.split(",") if part.strip()]
    if len(offered) < 2 or offered[0] != WS_SUBPROTOCOL:
        return None
    return offered[1]


def require(role: Role) -> Callable[..., Awaitable[Principal]]:
    """Dependency factory enforcing a minimum role."""

    async def _dep(
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> Principal:
        if not principal.at_least(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role {role.value} or higher",
            )
        return principal

    return _dep


RequireViewer = Annotated[Principal, Depends(require(Role.VIEWER))]
RequireEditor = Annotated[Principal, Depends(require(Role.RULE_EDITOR))]
RequireAdmin = Annotated[Principal, Depends(require(Role.ADMIN))]
