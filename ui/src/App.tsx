import { useCallback, useEffect, useState } from "react";
import { ApiError, api, getToken, setToken } from "./api";
import type { Health, Me } from "./types";
import Rules from "./pages/Rules";
import LiveTail from "./pages/LiveTail";
import Bundles from "./pages/Bundles";
import Audit from "./pages/Audit";

type Page = "rules" | "tail" | "bundles" | "audit";

const PAGES: { id: Page; label: string }[] = [
  { id: "rules", label: "Rules" },
  { id: "tail", label: "Live decisions" },
  { id: "bundles", label: "Bundles" },
  { id: "audit", label: "Audit log" },
];

function Login({ onSignedIn }: { onSignedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.login(username, password);
      onSignedIn();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <h1>sixthsense</h1>
        <p className="muted">CEF and syslog filtering proxy</p>
        <input
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && <div className="error">{error}</div>}
        <button className="primary" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [page, setPage] = useState<Page>("rules");
  const [ready, setReady] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [meResult, healthResult] = await Promise.all([api.me(), api.health()]);
      setMe(meResult);
      setHealth(healthResult);
    } catch {
      setMe(null);
    } finally {
      setReady(true);
    }
  }, []);

  useEffect(() => {
    if (!getToken()) {
      // The dev bypass makes /api/auth/me succeed without a token, so try regardless.
      void refresh();
      return;
    }
    void refresh();
  }, [refresh]);

  if (!ready) return <div className="main muted">Loading…</div>;
  if (!me) return <Login onSignedIn={() => void refresh()} />;

  const canEdit = me.role === "rule-editor" || me.role === "admin";

  return (
    <div className="app">
      <aside className="sidebar">
        <h1>sixthsense</h1>
        <p className="sub">
          {me.username} · {me.role}
        </p>
        <nav className="nav">
          {PAGES.map((p) => (
            <button
              key={p.id}
              className={page === p.id ? "active" : ""}
              onClick={() => setPage(p.id)}
            >
              {p.label}
            </button>
          ))}
        </nav>
        <div style={{ marginTop: 24 }}>
          <button
            onClick={() => {
              setToken(null);
              setMe(null);
            }}
          >
            Sign out
          </button>
        </div>
      </aside>

      <main className="main">
        {health && (
          <div className="banner">
            {/* D-01: the active default action is visible at all times. A fail-closed
                proxy that nobody realized was fail-closed is the failure this prevents. */}
            <span>
              Default action:{" "}
              <span className={health.default_action === "drop" ? "warn" : "ok"}>
                {health.default_action === "drop" ? "DROP (fail closed)" : "forward (fail open)"}
              </span>
            </span>
            <span className="muted">
              Active bundle: {health.active_bundle_version ?? "none published"}
            </span>
            {health.dev_auth_bypass && (
              <span className="warn">DEV AUTH BYPASS ENABLED — loopback only</span>
            )}
          </div>
        )}

        {page === "rules" && <Rules canEdit={canEdit} onChanged={() => void refresh()} />}
        {page === "tail" && <LiveTail canSeeContents={me.may_see_event_contents} />}
        {page === "bundles" && <Bundles canEdit={canEdit} onChanged={() => void refresh()} />}
        {page === "audit" && <Audit />}
      </main>
    </div>
  );
}
