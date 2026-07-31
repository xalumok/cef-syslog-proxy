from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture(autouse=True)
def _isolated_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give every test its own database and a known secret."""
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "test.db"
    monkeypatch.setenv("SS_DATABASE_URL", f"sqlite+pysqlite:///{db_path}")
    monkeypatch.setenv("SS_JWT_SECRET", "test-secret-value-at-least-32-bytes-long")
    monkeypatch.setenv("SS_BIND_HOST", "127.0.0.1")
    monkeypatch.delenv("SS_DEV_AUTH_BYPASS", raising=False)

    from sixthsense.config import reset_settings_cache
    from sixthsense.db.session import reset_engine_cache

    reset_settings_cache()
    reset_engine_cache()
    yield
    reset_settings_cache()
    reset_engine_cache()


@pytest.fixture
def session() -> Iterator[Session]:
    from sixthsense.db.session import init_db, session_scope

    init_db()
    with session_scope() as s:
        yield s


@pytest.fixture
def client() -> Iterator[TestClient]:
    from sixthsense.api.app import create_app
    from sixthsense.api.auth import Role, hash_password
    from sixthsense.db.models import UserRow
    from sixthsense.db.session import init_db, session_scope

    init_db()
    with session_scope() as s:
        for username, role in [
            ("viewer", Role.VIEWER),
            ("editor", Role.RULE_EDITOR),
            ("admin", Role.ADMIN),
        ]:
            s.add(
                UserRow(
                    username=username,
                    password_hash=hash_password(f"{username}-pw"),
                    role=role.value,
                )
            )

    app = create_app()
    with TestClient(app) as c:
        yield c


def login(client: TestClient, username: str) -> dict[str, str]:
    response = client.post(
        "/api/auth/token",
        data={"username": username, "password": f"{username}-pw"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def vector_available() -> bool:
    import shutil

    return shutil.which("vector") is not None


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "needs_vector: requires the vector binary on PATH")
    os.environ.setdefault("SS_JWT_SECRET", "test-secret-value-at-least-32-bytes-long")
