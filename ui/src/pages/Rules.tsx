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

/** What the editor form holds. A subset of `Rule`: the server owns id, version, and time. */
interface RuleDraft {
  name: string;
  action: "drop" | "forward";
  order: number;
  shadow: boolean;
  retain_payload: boolean;
  conditions: Condition[];
}

function RuleForm({
  title,
  initial,
  submitLabel,
  busy,
  showOrder,
  onSubmit,
  onCancel,
}: {
  title: string;
  initial: RuleDraft;
  submitLabel: string;
  busy: boolean;
  showOrder: boolean;
  onSubmit: (draft: RuleDraft) => void;
  onCancel: () => void;
}) {
  const [draft, setDraft] = useState<RuleDraft>(initial);
  const set = <K extends keyof RuleDraft>(key: K, value: RuleDraft[K]) =>
    setDraft((prev) => ({ ...prev, [key]: value }));

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>{title}</h3>
      <div className="row" style={{ marginBottom: 10 }}>
        <input
          placeholder="Rule name"
          value={draft.name}
          onChange={(e) => set("name", e.target.value)}
          style={{ minWidth: 260 }}
        />
        <select
          value={draft.action}
          onChange={(e) => {
            const action = e.target.value as "drop" | "forward";
            // retain_payload only applies to drop rules, and the server rejects the pair
            // outright. Clear it here so the form cannot submit a combination that is
            // guaranteed to 422.
            setDraft((prev) => ({
              ...prev,
              action,
              retain_payload: action === "drop" ? prev.retain_payload : false,
            }));
          }}
        >
          <option value="drop">drop</option>
          <option value="forward">forward</option>
        </select>
        {showOrder && (
          <label className="muted" title="Lower runs first. The first match decides the event">
            Order{" "}
            <input
              type="number"
              min={0}
              value={draft.order}
              onChange={(e) => set("order", Math.max(0, Number(e.target.value) || 0))}
              style={{ width: 70 }}
            />
          </label>
        )}
        <label className="muted">
          <input
            type="checkbox"
            checked={draft.shadow}
            onChange={(e) => set("shadow", e.target.checked)}
          />{" "}
          Shadow mode
        </label>
        {draft.action === "drop" && (
          <label className="muted" title="Keep the whole event in the drop audit record (D-02)">
            <input
              type="checkbox"
              checked={draft.retain_payload}
              onChange={(e) => set("retain_payload", e.target.checked)}
            />{" "}
            Retain payload
          </label>
        )}
      </div>

      {draft.conditions.map((c, index) => (
        <ConditionEditor
          key={index}
          condition={c}
          onChange={(next) =>
            set(
              "conditions",
              draft.conditions.map((p, i) => (i === index ? next : p)),
            )
          }
          onRemove={() =>
            set(
              "conditions",
              draft.conditions.filter((_, i) => i !== index),
            )
          }
        />
      ))}

      <div className="row">
        <button onClick={() => set("conditions", [...draft.conditions, emptyCondition()])}>
          Add condition
        </button>
        <span className="muted">All conditions must match</span>
        <span className="spacer" />
        <button onClick={onCancel}>Cancel</button>
        <button
          className="primary"
          onClick={() => onSubmit(draft)}
          // A rule with no conditions matches everything, and the server rejects it. Say
          // so by disabling the button rather than by round-tripping a 422.
          disabled={busy || !draft.name || draft.conditions.length === 0}
        >
          {submitLabel}
        </button>
      </div>
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
  const [editing, setEditing] = useState<Rule | null>(null);
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

  /** Run a mutation, then reload and tell the shell the chain is out of date.
   *
   * Every change here makes the published bundle stale, so `onChanged` is not optional:
   * without it the header keeps claiming the running config matches the rules on screen.
   */
  async function mutate(what: string, fn: () => Promise<unknown>) {
    setBusy(true);
    setError("");
    try {
      await fn();
      await load();
      onChanged();
      return true;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : `Could not ${what}`);
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function create(draft: RuleDraft) {
    const ok = await mutate("create the rule", () =>
      api.createRule({
        name: draft.name,
        action: draft.action,
        order: draft.order,
        conditions: draft.conditions,
        shadow: draft.shadow,
        retain_payload: draft.retain_payload,
      }),
    );
    if (ok) setCreating(false);
  }

  async function save(rule: Rule, draft: RuleDraft) {
    const ok = await mutate("save the rule", () => api.updateRule(rule.id, draft));
    if (ok) setEditing(null);
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
            <button
              className="primary"
              onClick={() => {
                setEditing(null);
                setCreating((v) => !v);
              }}
            >
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
        <RuleForm
          title="New rule"
          submitLabel="Create"
          busy={busy}
          showOrder={false}
          initial={{
            name: "",
            action: "drop",
            order: rules.length,
            // New rules start shadowed on purpose: a rule that starts dropping the moment
            // it is published has no chance to be checked against real traffic first.
            shadow: true,
            retain_payload: false,
            conditions: [emptyCondition()],
          }}
          onSubmit={(draft) => void create(draft)}
          onCancel={() => setCreating(false)}
        />
      )}

      {editing && (
        <RuleForm
          // Remount on a different rule. Without the key, the form keeps the draft state
          // of whichever rule was opened first.
          key={editing.id}
          title={`Edit ${editing.name}`}
          submitLabel="Save"
          busy={busy}
          showOrder
          initial={{
            name: editing.name,
            action: editing.action,
            order: editing.order,
            shadow: editing.shadow,
            retain_payload: editing.retain_payload,
            conditions: editing.conditions,
          }}
          onSubmit={(draft) => void save(editing, draft)}
          onCancel={() => setEditing(null)}
        />
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
                  {canEdit && (
                    <div className="row" style={{ flexWrap: "nowrap", justifyContent: "flex-end" }}>
                      <button
                        onClick={() => {
                          setCreating(false);
                          setEditing(rule);
                        }}
                        disabled={busy}
                      >
                        Edit
                      </button>
                      {rule.enabled ? (
                        <button
                          className="danger"
                          onClick={() => void mutate("disable the rule", () => api.disableRule(rule.id))}
                          disabled={busy}
                          title="Rules are disabled, never deleted (D-31)"
                        >
                          Disable
                        </button>
                      ) : (
                        <button
                          onClick={() =>
                            void mutate("enable the rule", () =>
                              api.updateRule(rule.id, { enabled: true }),
                            )
                          }
                          disabled={busy}
                          title="Put this rule back into the chain"
                        >
                          Enable
                        </button>
                      )}
                    </div>
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
        {/*
          D-31. Worth stating on the page: an analyst who wants a rule gone looks for a
          delete button, doesn't find one, and needs to know that disabling is the removal
          path rather than a step on the way to one.
        */}
        <p className="muted">
          Disabling takes a rule out of the chain. There is no delete: rules and their
          history are kept so an old decision can still be explained.
        </p>
      </div>
    </>
  );
}
