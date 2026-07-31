"""API tests, focused on the guarantees the design documents claim."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from tests.conftest import login


def _raw_asgi_get(app: object, path: str) -> bytes:
    """Send one GET straight into the ASGI app, with the path exactly as written.

    Every HTTP client in the test stack normalizes "../" away, so a traversal test written
    against `TestClient` proves nothing. Uvicorn passes the raw path through, which is what
    makes the confinement check in the catch-all load-bearing.
    """
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 1),
        "server": ("testserver", 80),
        "scheme": "http",
        "root_path": "",
    }
    chunks: list[bytes] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        if message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))  # type: ignore[arg-type]

    asyncio.run(app(scope, receive, send))  # type: ignore[operator]
    return b"".join(chunks)


RULE = {
    "name": "Suppress nightly scanner",
    "action": "drop",
    "order": 0,
    "conditions": [
        {"field": "filterhostname", "operator": "eq", "value": "scanner01"},
        {"field": "severity", "operator": "lte", "value": 3},
    ],
}


class TestAuth:
    def test_anonymous_is_rejected(self, client: TestClient) -> None:
        assert client.get("/api/rules").status_code == 401

    def test_bad_password_is_rejected(self, client: TestClient) -> None:
        response = client.post("/api/auth/token", data={"username": "admin", "password": "wrong"})
        assert response.status_code == 401

    def test_login_returns_role(self, client: TestClient) -> None:
        response = client.post(
            "/api/auth/token", data={"username": "editor", "password": "editor-pw"}
        )
        assert response.json()["role"] == "rule-editor"


class TestRoleEnforcement:
    """D-34: roles are enforced on the server. Hiding a button is not access control."""

    def test_viewer_cannot_create_rules(self, client: TestClient) -> None:
        response = client.post("/api/rules", json=RULE, headers=login(client, "viewer"))
        assert response.status_code == 403

    def test_editor_can_create_rules(self, client: TestClient) -> None:
        response = client.post("/api/rules", json=RULE, headers=login(client, "editor"))
        assert response.status_code == 201

    def test_editor_cannot_change_chain_defaults(self, client: TestClient) -> None:
        """Flipping the system to fail-closed is an admin action, not an editor one."""
        response = client.put(
            "/api/chain", json={"default_action": "drop"}, headers=login(client, "editor")
        )
        assert response.status_code == 403

    def test_admin_can_change_chain_defaults(self, client: TestClient) -> None:
        response = client.put(
            "/api/chain", json={"default_action": "drop"}, headers=login(client, "admin")
        )
        assert response.status_code == 200
        assert response.json()["default_action"] == "drop"

    def test_demoting_a_user_takes_effect_on_the_next_request(self, client: TestClient) -> None:
        """A token carries the role it was issued with. The server must not trust that.

        Otherwise revoking someone's admin rights does nothing until their token expires,
        eight hours later, while disabling the same account takes effect immediately.
        """
        from sixthsense.api.auth import Role
        from sixthsense.db.models import UserRow
        from sixthsense.db.session import session_scope

        headers = login(client, "admin")
        assert (
            client.put("/api/chain", json={"shadow_mode": True}, headers=headers).status_code == 200
        )

        with session_scope() as session:
            session.get(UserRow, "admin").role = Role.VIEWER.value

        # Same token, now a viewer.
        assert (
            client.put("/api/chain", json={"shadow_mode": False}, headers=headers).status_code
            == 403
        )
        assert client.get("/api/auth/me", headers=headers).json()["role"] == "viewer"


class TestRuleLifecycle:
    def test_create_read_update(self, client: TestClient) -> None:
        headers = login(client, "editor")
        created = client.post("/api/rules", json=RULE, headers=headers).json()
        rule_id = created["id"]
        assert created["version"] == 1

        updated = client.patch(
            f"/api/rules/{rule_id}", json={"name": "Renamed"}, headers=headers
        ).json()
        assert updated["name"] == "Renamed"
        assert updated["version"] == 2

    def test_delete_disables_and_never_removes(self, client: TestClient) -> None:
        """D-31: there is no hard delete. The row must survive with enabled=false."""
        headers = login(client, "editor")
        rule_id = client.post("/api/rules", json=RULE, headers=headers).json()["id"]

        response = client.delete(f"/api/rules/{rule_id}", headers=headers)
        assert response.status_code == 200
        assert response.json()["enabled"] is False

        listed = client.get("/api/rules", headers=headers).json()
        assert any(r["id"] == rule_id for r in listed)

    def test_invalid_rule_is_rejected_at_the_boundary(self, client: TestClient) -> None:
        headers = login(client, "editor")
        bad = {**RULE, "conditions": [{"field": "x", "operator": "cidr", "value": "not-a-cidr"}]}
        assert client.post("/api/rules", json=bad, headers=headers).status_code == 422

    def test_retain_payload_requires_a_drop_rule(self, client: TestClient) -> None:
        headers = login(client, "editor")
        bad = {**RULE, "action": "forward", "retain_payload": True}
        assert client.post("/api/rules", json=bad, headers=headers).status_code == 422


class TestAudit:
    """D-31: every mutation is recorded with actor, before, and after."""

    def test_create_and_update_are_recorded(self, client: TestClient) -> None:
        headers = login(client, "editor")
        rule_id = client.post("/api/rules", json=RULE, headers=headers).json()["id"]
        client.patch(f"/api/rules/{rule_id}", json={"name": "Renamed"}, headers=headers)

        entries = client.get("/api/audit", headers=headers).json()
        actions = [e["action"] for e in entries]
        assert "rule.create" in actions
        assert "rule.update" in actions

        update_entry = next(e for e in entries if e["action"] == "rule.update")
        assert update_entry["actor"] == "editor"
        assert update_entry["before"]["name"] == RULE["name"]
        assert update_entry["after"]["name"] == "Renamed"

    def test_audit_has_no_write_endpoint(self, client: TestClient) -> None:
        """Append-only is enforced by absence: there is nothing to call."""
        headers = login(client, "admin")
        assert client.post("/api/audit", json={}, headers=headers).status_code in (404, 405)
        assert client.delete("/api/audit", headers=headers).status_code in (404, 405)


class TestBundles:
    def test_publish_produces_a_config(self, client: TestClient) -> None:
        headers = login(client, "editor")
        client.post("/api/rules", json=RULE, headers=headers)

        response = client.post("/api/bundles/publish", json={"note": "first"}, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["version"] == 1
        assert response.json()["active"] is True

        config = client.get("/api/bundles/active/config", headers=headers)
        assert "[sources.ingest]" in config.text
        assert "scanner01" in config.text

    def test_rollback_restores_the_earlier_bytes(self, client: TestClient) -> None:
        headers = login(client, "editor")
        client.post("/api/rules", json=RULE, headers=headers)
        client.post("/api/bundles/publish", json={"note": "v1"}, headers=headers)
        first_config = client.get("/api/bundles/active/config", headers=headers).text

        client.post(
            "/api/rules",
            json={**RULE, "name": "Second rule", "order": 1},
            headers=headers,
        )
        client.post("/api/bundles/publish", json={"note": "v2"}, headers=headers)
        assert "Second rule" in client.get("/api/bundles/active/config", headers=headers).text

        client.post("/api/bundles/1/rollback", headers=headers)
        assert client.get("/api/bundles/active/config", headers=headers).text == first_config

    def test_agent_endpoint_reports_no_change(self, client: TestClient) -> None:
        headers = login(client, "editor")
        client.post("/api/rules", json=RULE, headers=headers)
        client.post("/api/bundles/publish", json={"note": ""}, headers=headers)

        assert client.get("/api/agent/bundle", params={"since": 0}).json()["changed"] is True
        assert client.get("/api/agent/bundle", params={"since": 1}).json()["changed"] is False


class TestDecisions:
    def _record(self, decision: str = "drop") -> dict[str, object]:
        return {
            "ts": "2026-07-30T12:00:00Z",
            "decision": decision,
            "rule_id": "r-x",
            "node": "node-1",
            "fields": {"severity": "9"},
            "raw": "<134>Jul 30 12:00:00 host CEF:0|v|p|1|100|Name|9|",
        }

    def test_intake_is_unauthenticated_by_design(self, client: TestClient) -> None:
        """Vector posts here. Adding auth would move the control plane toward the data path."""
        assert client.post("/api/decisions/intake", json=[self._record()]).status_code == 204

    def test_viewer_cannot_see_event_contents(self, client: TestClient) -> None:
        """D-36: redaction happens on the server, before serialization."""
        client.post("/api/decisions/intake", json=[self._record()])

        as_viewer = client.get("/api/decisions/recent", headers=login(client, "viewer")).json()
        assert as_viewer[0]["raw"] is None
        assert as_viewer[0]["fields"] == {}

        as_editor = client.get("/api/decisions/recent", headers=login(client, "editor")).json()
        assert as_editor[0]["raw"] is not None
        assert as_editor[0]["fields"]["severity"] == "9"


class TestTailSocketAuthorization:
    """D-34 and D-36 on the live-tail socket.

    This socket streams the same records `/decisions/recent` returns. It shipped once with
    no authentication and no redaction at all, which made the redaction on that endpoint
    decorative: anyone who could reach the port got every payload continuously.
    """

    RECORD: ClassVar[dict[str, object]] = {
        "ts": "2026-07-30T12:00:00Z",
        "decision": "drop",
        "rule_id": "r-x",
        "fields": {"severity": "9"},
        "raw": "<134>Jul 30 12:00:00 host CEF:0|v|p|1|100|Name|9|",
    }

    def _publish(self) -> None:
        from sixthsense.models.rule import DecisionRecord
        from sixthsense.sampling.store import get_tail_buffer

        get_tail_buffer().publish(DecisionRecord.model_validate(self.RECORD))

    def _token(self, client: TestClient, username: str) -> str:
        return login(client, username)["Authorization"].removeprefix("Bearer ")

    def test_anonymous_is_rejected(self, client: TestClient) -> None:
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect("/api/decisions/tail") as ws,
        ):
            ws.receive_json()

    def test_a_forged_token_is_rejected(self, client: TestClient) -> None:
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect(
                "/api/decisions/tail", subprotocols=["ss.bearer", "not-a-real-token"]
            ) as ws,
        ):
            ws.receive_json()

    def test_viewer_gets_the_stream_without_contents(self, client: TestClient) -> None:
        token = self._token(client, "viewer")
        with client.websocket_connect(
            "/api/decisions/tail", subprotocols=["ss.bearer", token]
        ) as ws:
            self._publish()
            frame = ws.receive_json()
        assert frame["decision"] == "drop"
        assert frame["raw"] is None
        assert frame["fields"] == {}

    def test_editor_gets_contents(self, client: TestClient) -> None:
        token = self._token(client, "editor")
        with client.websocket_connect(
            "/api/decisions/tail", subprotocols=["ss.bearer", token]
        ) as ws:
            self._publish()
            frame = ws.receive_json()
        assert frame["raw"] == self.RECORD["raw"]
        assert frame["fields"]["severity"] == "9"


class TestWebApp:
    """The control plane serves the UI. Nothing else in the suite would notice if it stopped.

    The API answered every request while `/` returned 404 in the container, because the path
    to the built assets is computed differently for a source checkout and an installed
    package, and a missing directory was skipped without a word.
    """

    def test_ui_is_located_and_served(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        dist = tmp_path / "dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text("<title>sixthsense</title>", encoding="utf-8")
        monkeypatch.setenv("SS_UI_DIST", str(dist))

        import sixthsense.api.app as app_module

        monkeypatch.setattr(app_module, "UI_DIST", app_module._find_ui_dist())
        with TestClient(app_module.create_app()) as ui_client:
            response = ui_client.get("/")
            assert response.status_code == 200
            assert "sixthsense" in response.text

    def test_unknown_paths_fall_through_to_the_spa(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A client-side route must return the app, not a 404."""
        dist = tmp_path / "dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text("<title>sixthsense</title>", encoding="utf-8")
        monkeypatch.setenv("SS_UI_DIST", str(dist))

        import sixthsense.api.app as app_module

        monkeypatch.setattr(app_module, "UI_DIST", app_module._find_ui_dist())
        with TestClient(app_module.create_app()) as ui_client:
            assert ui_client.get("/rules").status_code == 200

    def test_the_spa_catch_all_cannot_escape_the_asset_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The catch-all must not serve files outside the built UI.

        This drives the ASGI app directly with a raw path instead of going through
        `TestClient`. That is not incidental: httpx normalizes "../" out of the path before
        it is sent, so a `TestClient` request cannot reach this code path and the same test
        written against `client` passes whether or not the check exists. Uvicorn does not
        normalize, so the raw path is what a real deployment receives.

        The files at risk are the ones next to the assets: the database, holding every
        password hash, and .env, holding the token signing key.
        """
        dist = tmp_path / "ui" / "dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text("<title>sixthsense</title>", encoding="utf-8")
        (tmp_path / "secret.txt").write_text("password hashes live here", encoding="utf-8")
        monkeypatch.setenv("SS_UI_DIST", str(dist))

        import sixthsense.api.app as app_module

        monkeypatch.setattr(app_module, "UI_DIST", app_module._find_ui_dist())
        app = app_module.create_app()

        escapes = (
            "/../../secret.txt",
            "/../../../../../../../../etc/hosts",
            # Through the StaticFiles mount rather than the catch-all. That one was already
            # safe, and this keeps it that way.
            "/assets/../../../secret.txt",
        )
        for path in escapes:
            body = _raw_asgi_get(app, path)
            assert b"password hashes" not in body, f"{path} escaped the asset directory"
            assert b"root:" not in body, f"{path} escaped the asset directory"

        # The catch-all answers a non-asset path with the SPA, so a traversal attempt is
        # indistinguishable from a client-side route. The /assets mount 404s instead, which
        # is equally fine: neither one serves the file.
        assert b"sixthsense" in _raw_asgi_get(app, "/../../secret.txt")

    def test_api_still_wins_over_the_spa_catch_all(self, client: TestClient) -> None:
        """The catch-all must not swallow API routes, including unauthenticated ones."""
        assert client.get("/api/rules").status_code == 401

    def test_a_missing_ui_is_reported_not_swallowed(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Serving the API only is a valid mode, but it has to say so.

        The previous version skipped the mount without logging, so a container that could not
        find its own assets looked healthy on every signal an operator checks.
        """
        import sixthsense.api.app as app_module

        monkeypatch.setattr(app_module, "UI_DIST", None)
        with caplog.at_level("WARNING", logger="sixthsense"):
            app = app_module.create_app()

        assert any("no built UI found" in record.message for record in caplog.records)
        with TestClient(app) as api_only:
            assert api_only.get("/api/health").status_code == 200
            assert api_only.get("/").status_code == 404


class TestHealth:
    def test_reports_active_mode(self, client: TestClient) -> None:
        """D-01: the active default action must be visible without reading config."""
        body = client.get("/api/health").json()
        assert body["default_action"] == "forward"
        assert body["dev_auth_bypass"] is False


class TestDevBypassGuard:
    """D-34: the guard is in code, so 'the dev flag reached production' cannot happen."""

    def test_bypass_on_public_interface_refuses_to_start(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sixthsense.config import Settings

        monkeypatch.setenv("SS_DEV_AUTH_BYPASS", "true")
        monkeypatch.setenv("SS_BIND_HOST", "0.0.0.0")
        with pytest.raises(ValueError, match="non-loopback"):
            Settings()

    def test_bypass_on_loopback_is_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from sixthsense.config import Settings

        monkeypatch.setenv("SS_DEV_AUTH_BYPASS", "true")
        monkeypatch.setenv("SS_BIND_HOST", "127.0.0.1")
        assert Settings().dev_auth_bypass is True


class TestDefaultSecretGuard:
    """The signing key gets the same hard guard as the bypass flag, for the same reason.

    The default is published in this repository, so a deployment that kept it can be handed
    an admin token by anyone who has read the source. That is as fatal as the bypass flag,
    and a docstring warning is not a control.
    """

    def test_default_secret_on_a_public_interface_refuses_to_start(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sixthsense.config import DEV_JWT_SECRET, Settings

        monkeypatch.setenv("SS_JWT_SECRET", DEV_JWT_SECRET)
        monkeypatch.setenv("SS_BIND_HOST", "0.0.0.0")
        with pytest.raises(ValueError, match="development default"):
            Settings()

    def test_default_secret_on_loopback_is_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Local development must stay a zero-configuration experience."""
        from sixthsense.config import DEV_JWT_SECRET, Settings

        monkeypatch.setenv("SS_JWT_SECRET", DEV_JWT_SECRET)
        monkeypatch.setenv("SS_BIND_HOST", "127.0.0.1")
        assert Settings().jwt_secret == DEV_JWT_SECRET

    def test_a_real_secret_on_a_public_interface_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sixthsense.config import Settings

        monkeypatch.setenv("SS_JWT_SECRET", "a-real-deployment-secret-over-32-bytes")
        monkeypatch.setenv("SS_BIND_HOST", "0.0.0.0")
        assert Settings().bind_host == "0.0.0.0"
