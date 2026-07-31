import { useCallback, useEffect, useState } from "react";
import { ApiError, api } from "./../api";
import {
  CEF_FIELDS,
  SYSLOG_FIELDS,
  LIST_OPERATORS,
  NULLARY_OPERATORS,
  type Condition,
  type Operator,
  type Rule,
  type SimulationResult,
} from "./../types";

const OPERATORS: Operator[] = [
  "eq",
  "ne",
  "in",
  "not_in",
  "contains",
  "starts_with",
  "ends_with",
  "glob",
  "cidr",
  "lt",
  "lte",
  "gt",
  "gte",
  "exists",
  "not_exists",
];

function emptyCondition(): Condition {
  return { field: "filterhostname", operator: "eq", value: "", case_sensitive: false };
}

function ConditionEditor({
  condition,
  onChange,
  onRemove,
}: {
  condition: Condition;
  onChange: (c: Condition) => void;
  onRemove: () => void;
}) {
  const nullary = NULLARY_OPERATORS.includes(condition.operator);
  const isList = LIST_OPERATORS.includes(condition.operator);

  return (
    <div className="condition-row">
      <input
        list="known-fields"
        value={condition.field}
        placeholder="field"
        onChange={(e) => onChange({ ...condition, field: e.target.value })}
      />
      <select
        value={condition.operator}
        onChange={(e) => {
          const operator = e.target.value as Operator;
          const value = NULLARY_OPERATORS.includes(operator)
            ? null
            : LIST_OPERATORS.includes(operator)
              ? []
              : "";
          onChange({ ...condition, operator, value });
        }}
      >
        {OPERATORS.map((op) => (
          <option key={op} value={op}>
            {op}
          </option>
        ))}
      </select>
      <input
        disabled={nullary}
        placeholder={isList ? "comma-separated" : nullary ? "—" : "value"}
        value={
          condition.value === null || condition.value === undefined
            ? ""
            : Array.isArray(condition.value)
              ? condition.value.join(", ")
              : String(condition.value)
        }
        onChange={(e) => {
          const raw = e.target.value;
          if (isList) {
            onChange({
              ...condition,
              value: raw
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
            });
          } else {
            const numeric = raw !== "" && !Number.isNaN(Number(raw));
            onChange({ ...condition, value: numeric ? Number(raw) : raw });
          }
        }}
      />
      <label className="muted" title="Comparisons ignore case unless you opt in">
        <input
          type="checkbox"
          checked={condition.case_sensitive}
          onChange={(e) => onChange({ ...condition, case_sensitive: e.target.checked })}
        />{" "}
        Aa
      </label>
      <button className="danger" onClick={onRemove} type="button">
        ×
      </button>
    </div>
  );
}

export default function Rules({
  canEdit,
  onChanged,
}: {
  canEdit: boolean;
  onChanged: () => void;
}) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [action, setAction] = useState<"drop" | "forward">("drop");
  const [shadow, setShadow] = useState(true);
  const [conditions, setConditions] = useState<Condition[]>([emptyCondition()]);
  const [sim, setSim] = useState<SimulationResult | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setRules(await api.rules());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load rules");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function create() {
    setBusy(true);
    setError("");
    try {
      await api.createRule({
        name,
        action,
        order: rules.length,
        conditions,
        shadow,
      });
      setName("");
      setConditions([emptyCondition()]);
      setCreating(false);
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the rule");
    } finally {
      setBusy(false);
    }
  }

  async function runSimulation() {
    setBusy(true);
    try {
      setSim(await api.simulate());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Simulation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {/*
        Suggestions only. Any field name is valid (D-04), so this is an input with a
        datalist rather than a select. The labels matter: `severity` and `syslog.severity`
        are different fields on different scales, and an analyst picking from a flat list
        would have no way to tell.
      */}
      <datalist id="known-fields">
        {CEF_FIELDS.map((f) => (
          <option key={f} value={f} label="CEF" />
        ))}
        {SYSLOG_FIELDS.map((f) => (
          <option key={f} value={f} label="syslog" />
        ))}
      </datalist>

      <div className="card">
        <div className="row">
          <h2 style={{ margin: 0 }}>Rule chain</h2>
          <span className="muted">First match wins, evaluated top to bottom</span>
          <span className="spacer" />
          <button onClick={() => void runSimulation()} disabled={busy}>
            Preview impact
          </button>
          {canEdit && (
            <button className="primary" onClick={() => setCreating((v) => !v)}>
              {creating ? "Cancel" : "New rule"}
            </button>
          )}
        </div>
        {error && <div className="error">{error}</div>}
      </div>

      {sim && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Impact preview</h3>
          {!sim.available ? (
            // D-29: no Python fallback. An honest refusal beats an approximate answer.
            <p className="muted">{sim.detail}</p>
          ) : (
            <>
              <p>
                Of {sim.total} sampled events, this chain drops <strong>{sim.dropped}</strong> (
                {(sim.drop_share * 100).toFixed(1)}%) and forwards {sim.forwarded}.{" "}
                {sim.parse_errors > 0 && (
                  <span className="muted">{sim.parse_errors} could not be parsed and are forwarded.</span>
                )}
              </p>
              {sim.requires_confirmation && (
                <p className="error">
                  This chain would drop more than 5% of traffic. Confirm before publishing.
                </p>
              )}
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Events dropped</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(sim.per_rule).map(([id, count]) => (
                    <tr key={id}>
                      <td className="mono">{id}</td>
                      <td>{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}

      {creating && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>New rule</h3>
          <div className="row" style={{ marginBottom: 10 }}>
            <input
              placeholder="Rule name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              style={{ minWidth: 260 }}
            />
            <select value={action} onChange={(e) => setAction(e.target.value as "drop" | "forward")}>
              <option value="drop">drop</option>
              <option value="forward">forward</option>
            </select>
            <label className="muted">
              <input
                type="checkbox"
                checked={shadow}
                onChange={(e) => setShadow(e.target.checked)}
              />{" "}
              Start in shadow mode
            </label>
          </div>

          {conditions.map((c, index) => (
            <ConditionEditor
              key={index}
              condition={c}
              onChange={(next) =>
                setConditions((prev) => prev.map((p, i) => (i === index ? next : p)))
              }
              onRemove={() => setConditions((prev) => prev.filter((_, i) => i !== index))}
            />
          ))}

          <div className="row">
            <button onClick={() => setConditions((prev) => [...prev, emptyCondition()])}>
              Add condition
            </button>
            <span className="muted">All conditions must match</span>
            <span className="spacer" />
            <button className="primary" onClick={() => void create()} disabled={busy || !name}>
              Create
            </button>
          </div>
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Name</th>
              <th>Action</th>
              <th>Conditions</th>
              <th>State</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.id} style={{ opacity: rule.enabled ? 1 : 0.45 }}>
                <td className="muted">{rule.order}</td>
                <td>
                  <div>{rule.name}</div>
                  <div className="mono muted">{rule.id} · v{rule.version}</div>
                </td>
                <td>
                  <span className={`pill ${rule.action}`}>{rule.action}</span>
                </td>
                <td className="mono">
                  {rule.conditions
                    .map((c) =>
                      NULLARY_OPERATORS.includes(c.operator)
                        ? `${c.field} ${c.operator}`
                        : `${c.field} ${c.operator} ${
                            Array.isArray(c.value) ? `[${c.value.join(", ")}]` : c.value
                          }`,
                    )
                    .join("  AND  ")}
                </td>
                <td>
                  {!rule.enabled && <span className="pill">disabled</span>}
                  {rule.shadow && <span className="pill shadow">shadow</span>}
                  {rule.retain_payload && <span className="pill">retains payload</span>}
                </td>
                <td>
                  {canEdit && rule.enabled && (
                    <button
                      className="danger"
                      onClick={async () => {
                        await api.disableRule(rule.id);
                        await load();
                      }}
                      title="Rules are disabled, never deleted"
                    >
                      Disable
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {rules.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  No rules yet. Everything is forwarded.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
