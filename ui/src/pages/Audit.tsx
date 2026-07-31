import { useEffect, useState } from "react";
import { api } from "./../api";
import type { AuditEntry } from "./../types";

function summarize(entry: AuditEntry): string {
  if (!entry.before || !entry.after) return "";
  const changed: string[] = [];
  for (const key of Object.keys(entry.after)) {
    const before = JSON.stringify(entry.before[key]);
    const after = JSON.stringify(entry.after[key]);
    if (before !== after && key !== "version" && key !== "updated_at") {
      changed.push(`${key}: ${before} → ${after}`);
    }
  }
  return changed.join("; ");
}

export default function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);

  useEffect(() => {
    void api.audit().then(setEntries);
  }, []);

  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>Audit log</h2>
      <p className="muted">
        Append-only. Changing a filter rule changes which security telemetry you keep, so
        every change records who, when, and the full difference.
      </p>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Change</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.id}>
              <td className="mono muted">{new Date(entry.ts).toLocaleString()}</td>
              <td className="mono">{entry.actor}</td>
              <td>{entry.action}</td>
              <td className="mono">{entry.target_id}</td>
              <td className="muted">
                {summarize(entry)}
                {entry.note && <em> {entry.note}</em>}
              </td>
            </tr>
          ))}
          {entries.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                No changes recorded yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
