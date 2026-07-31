import { useCallback, useEffect, useState } from "react";
import { ApiError, api } from "./../api";
import type { BundleSummary } from "./../types";

export default function Bundles({
  canEdit,
  onChanged,
}: {
  canEdit: boolean;
  onChanged: () => void;
}) {
  const [bundles, setBundles] = useState<BundleSummary[]>([]);
  const [config, setConfig] = useState<string>("");
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setBundles(await api.bundles());
      setConfig(await api.activeConfig());
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) setConfig("");
      else setError(err instanceof ApiError ? err.message : "Could not load bundles");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function publish() {
    setBusy(true);
    setError("");
    try {
      await api.publish(note);
      setNote("");
      await load();
      onChanged();
    } catch (err) {
      // A validation failure here means `vector validate` rejected the generated config.
      // Show it verbatim: paraphrasing would lose the line number.
      setError(err instanceof ApiError ? err.message : "Publish failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="row">
          <h2 style={{ margin: 0 }}>Bundles</h2>
          <span className="muted">
            Each publish compiles the chain, validates it with Vector, and stores the exact bytes.
          </span>
        </div>
        {error && <div className="error">{error}</div>}
        {canEdit && (
          <div className="row" style={{ marginTop: 10 }}>
            <input
              placeholder="Note (optional)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              style={{ minWidth: 280 }}
            />
            <button className="primary" onClick={() => void publish()} disabled={busy}>
              Publish current chain
            </button>
          </div>
        )}
      </div>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Version</th>
              <th>Created</th>
              <th>By</th>
              <th>Rules</th>
              <th>Checksum</th>
              <th>Note</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {bundles.map((b) => (
              <tr key={b.version}>
                <td>
                  {b.version} {b.active && <span className="pill forward">active</span>}
                </td>
                <td className="muted">{new Date(b.created_at).toLocaleString()}</td>
                <td className="mono">{b.created_by}</td>
                <td>{b.rule_count}</td>
                <td className="mono muted">{b.checksum.slice(0, 12)}</td>
                <td className="muted">{b.note}</td>
                <td>
                  {canEdit && !b.active && (
                    <button
                      onClick={async () => {
                        await api.rollback(b.version);
                        await load();
                        onChanged();
                      }}
                      title="Restores the exact bytes that were running"
                    >
                      Roll back
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {bundles.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  Nothing published yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {config && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Active Vector configuration</h3>
          <p className="muted">
            Exactly what a node fetches and runs. Generated, never hand-edited.
          </p>
          <pre className="mono">{config}</pre>
        </div>
      )}
    </>
  );
}
