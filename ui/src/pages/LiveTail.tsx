import { useEffect, useRef, useState } from "react";
import { api, tailSocket } from "./../api";
import type { DecisionRecord } from "./../types";

const MAX_ROWS = 300;

export default function LiveTail({ canSeeContents }: { canSeeContents: boolean }) {
  const [rows, setRows] = useState<DecisionRecord[]>([]);
  const [connected, setConnected] = useState(false);
  const [rejected, setRejected] = useState(false);
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  // Seed with what the server already buffered, so the page is not empty on open.
  useEffect(() => {
    void api.decisionsRecent().then(setRows).catch(() => setRows([]));
  }, []);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let closed = false;

    function connect() {
      socket = tailSocket((raw) => {
        // Dropping frames while paused is the same policy the server uses when a client
        // falls behind: the viewer loses frames, the proxy never does.
        if (pausedRef.current) return;
        setRows((prev) => [raw as DecisionRecord, ...prev].slice(0, MAX_ROWS));
      });
      socket.onopen = () => setConnected(true);
      socket.onclose = (event) => {
        setConnected(false);
        // 1008 is the server rejecting the token. Retrying cannot fix that, and a two-second
        // loop against an expired session is a reconnect storm rather than a recovery.
        if (event.code === 1008) {
          setRejected(true);
          return;
        }
        if (!closed) setTimeout(connect, 2000);
      };
    }

    connect();
    return () => {
      closed = true;
      socket?.close();
    };
  }, []);

  return (
    <>
      <div className="card">
        <div className="row">
          <h2 style={{ margin: 0 }}>Live decisions</h2>
          <span className={connected ? "ok" : "muted"}>
            {connected ? "connected" : rejected ? "signed out — reload to reconnect" : "reconnecting…"}
          </span>
          <span className="muted">
            Sampled at the node. Drops are never sampled out.
          </span>
          <span className="spacer" />
          <button onClick={() => setPaused((v) => !v)}>{paused ? "Resume" : "Pause"}</button>
          <button onClick={() => setRows([])}>Clear</button>
        </div>
        {!canSeeContents && (
          // D-36: redaction happens server-side. This only explains the empty columns.
          <p className="muted">
            Your role sees metadata and counts. Event contents are removed before they leave
            the server.
          </p>
        )}
      </div>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Decision</th>
              <th>Rule</th>
              <th>Reason</th>
              <th>Node</th>
              {canSeeContents && <th>Event</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={`${row.ts}-${index}`}>
                <td className="mono muted">{new Date(row.ts).toLocaleTimeString()}</td>
                <td>
                  <span
                    className={`pill ${
                      row.decision === "drop"
                        ? "drop"
                        : row.decision === "forward_parse_error"
                          ? "parse"
                          : "forward"
                    }`}
                  >
                    {row.decision}
                  </span>
                </td>
                <td className="mono">{row.rule_id ?? "—"}</td>
                <td className="muted">{row.reason}</td>
                <td className="mono muted">{row.node ?? "—"}</td>
                {canSeeContents && (
                  <td className="mono tail-raw" title={row.raw ?? ""}>
                    {row.raw ?? ""}
                  </td>
                )}
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={canSeeContents ? 6 : 5} className="muted">
                  Waiting for decisions. Send traffic with{" "}
                  <span className="mono">cefgen send 127.0.0.1:5514</span>.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
