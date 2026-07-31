"""Command line entry points for the control plane."""

from __future__ import annotations

import argparse
import secrets
import sys

import uvicorn

from sixthsense.api.auth import Role, hash_password
from sixthsense.config import get_settings
from sixthsense.db.models import UserRow
from sixthsense.db.session import init_db, session_scope


def _cmd_serve(args: argparse.Namespace) -> int:
    settings = get_settings()
    uvicorn.run(
        "sixthsense.api.app:app",
        host=args.host or settings.bind_host,
        port=args.port or settings.bind_port,
        reload=args.reload,
    )
    return 0


def _cmd_init(_: argparse.Namespace) -> int:
    init_db()
    print("database initialized")
    return 0


def _cmd_adduser(args: argparse.Namespace) -> int:
    init_db()
    password = args.password or secrets.token_urlsafe(18)
    with session_scope() as session:
        if session.get(UserRow, args.username) is not None:
            print(f"user {args.username} already exists", file=sys.stderr)
            return 1
        session.add(
            UserRow(
                username=args.username,
                password_hash=hash_password(password),
                role=Role(args.role).value,
            )
        )
    print(f"created {args.username} with role {args.role}")
    if not args.password:
        print(f"generated password: {password}")
    return 0


def _cmd_compile(_: argparse.Namespace) -> int:
    """Print the Vector config the current chain would produce, without publishing."""
    from sixthsense.services.bundles import build_bundle
    from sixthsense.services.rules import load_chain

    init_db()
    with session_scope() as session:
        chain = load_chain(session)
    bundle = build_bundle(chain, 0, created_by="cli")
    print(bundle.config_toml)
    return 0


def ssctl() -> int:
    parser = argparse.ArgumentParser(prog="ssctl", description="sixthsense control plane")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the API and UI")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=_cmd_serve)

    sub.add_parser("init-db", help="create tables").set_defaults(func=_cmd_init)

    p_user = sub.add_parser("adduser", help="create a local account")
    p_user.add_argument("username")
    p_user.add_argument("--role", choices=[r.value for r in Role], default=Role.VIEWER.value)
    p_user.add_argument("--password", default=None)
    p_user.set_defaults(func=_cmd_adduser)

    sub.add_parser("compile", help="print the generated Vector config").set_defaults(
        func=_cmd_compile
    )

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(ssctl())
