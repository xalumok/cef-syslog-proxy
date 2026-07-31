// Mirrors the Pydantic models in src/sixthsense/models/rule.py.
// The generated JSON Schema at /openapi.json is the source of truth; regenerate these
// types from it rather than editing both by hand when the schema changes.

export type Action = "forward" | "drop";

export type Operator =
  | "eq"
  | "ne"
  | "in"
  | "not_in"
  | "contains"
  | "starts_with"
  | "ends_with"
  | "glob"
  | "cidr"
  | "lt"
  | "lte"
  | "gt"
  | "gte"
  | "exists"
  | "not_exists";

export const NULLARY_OPERATORS: Operator[] = ["exists", "not_exists"];
export const LIST_OPERATORS: Operator[] = ["in", "not_in"];

// CEF fields, offered first. Any other field name is still valid (D-04); this is a
// suggestion list, not a constraint.
export const CEF_FIELDS = [
  "eventid",
  "filterhostname",
  "filterid",
  "filteripaddress",
  "filternodename",
  "filterpriority",
  "filtertype",
  "notificationtime",
  "name",
  "severity",
] as const;

// Syslog fields, addressed under the "syslog." prefix so they never collide with a CEF
// field of the same name. `severity` is the one that matters: a CEF severity is 0-10 with
// higher meaning worse, a syslog severity is a word like "info". They are not interchangeable.
export const SYSLOG_FIELDS = [
  "syslog.appname",
  "syslog.facility",
  "syslog.hostname",
  "syslog.message",
  "syslog.msgid",
  "syslog.procid",
  "syslog.severity",
  "syslog.timestamp",
] as const;

export const KNOWN_FIELDS = [...CEF_FIELDS, ...SYSLOG_FIELDS] as const;

export type ScalarValue = string | number | boolean;

export interface Condition {
  field: string;
  operator: Operator;
  value?: ScalarValue | ScalarValue[] | null;
  case_sensitive: boolean;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  order: number;
  action: Action;
  conditions: Condition[];
  output: string;
  retain_payload: boolean;
  shadow: boolean;
  version: number;
  updated_at: string;
}

export type Decision = "forward" | "drop" | "forward_parse_error";

export interface DecisionRecord {
  ts: string;
  decision: Decision;
  rule_id: string | null;
  rule_version: number | null;
  reason: string;
  node: string | null;
  event_id: string | null;
  fields: Record<string, string>;
  raw: string | null;
  // Which parser produced the fields this decision was made from. Both can be true: CEF
  // usually arrives inside a syslog frame.
  cef_ok?: boolean;
  syslog_ok?: boolean;
}

export interface BundleSummary {
  version: number;
  checksum: string;
  created_at: string;
  created_by: string;
  rule_count: number;
  active: boolean;
  note: string;
}

export interface SimulationResult {
  available: boolean;
  detail: string;
  total: number;
  forwarded: number;
  dropped: number;
  parse_errors: number;
  per_rule: Record<string, number>;
  drop_share: number;
  requires_confirmation: boolean;
  sample_size: number;
}

export interface Health {
  status: string;
  active_bundle_version: number | null;
  default_action: Action;
  tail_subscribers: number;
  auth_mode: string;
  dev_auth_bypass: boolean;
}

export interface Me {
  username: string;
  role: "viewer" | "rule-editor" | "admin";
  may_see_event_contents: boolean;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  action: string;
  target_type: string;
  target_id: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  note: string;
}
