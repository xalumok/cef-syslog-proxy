import type {
  AuditEntry,
  BundleSummary,
  Condition,
  DecisionRecord,
  Health,
  Me,
  Rule,
  SimulationResult,
} from "./types";

const TOKEN_KEY = "ss_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, { ...init, headers });
  if (response.status === 401) {
    setToken(null);
    throw new ApiError(401, "Session expired. Sign in again.");
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* keep statusText */
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const api = {
  async login(username: string, password: string): Promise<Me> {
    const body = new URLSearchParams({ username, password });
    const response = await fetch("/api/auth/token", { method: "POST", body });
    if (!response.ok) throw new ApiError(response.status, "Invalid credentials");
    const data = await response.json();
    setToken(data.access_token);
    return { username: data.username, role: data.role, may_see_event_contents: false };
  },

  me: () => request<Me>("/api/auth/me"),
  health: () => request<Health>("/api/health"),

  rules: () => request<Rule[]>("/api/rules"),
  createRule: (payload: {
    name: string;
    description?: string;
    action: string;
    order: number;
    conditions: Condition[];
    shadow?: boolean;
    retain_payload?: boolean;
  }) => request<Rule>("/api/rules", { method: "POST", body: JSON.stringify(payload) }),
  updateRule: (id: string, payload: Partial<Rule>) =>
    request<Rule>(`/api/rules/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  disableRule: (id: string) => request<Rule>(`/api/rules/${id}`, { method: "DELETE" }),

  bundles: () => request<BundleSummary[]>("/api/bundles"),
  publish: (note: string) =>
    request<BundleSummary>("/api/bundles/publish", {
      method: "POST",
      body: JSON.stringify({ note }),
    }),
  rollback: (version: number) =>
    request<BundleSummary>(`/api/bundles/${version}/rollback`, { method: "POST" }),
  activeConfig: async (): Promise<string> => {
    const token = getToken();
    const response = await fetch("/api/bundles/active/config", {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!response.ok) throw new ApiError(response.status, "No active bundle");
    return response.text();
  },

  simulate: (limit = 2000) =>
    request<SimulationResult>("/api/simulate", {
      method: "POST",
      body: JSON.stringify({ limit }),
    }),

  decisionsRecent: (limit = 100) =>
    request<DecisionRecord[]>(`/api/decisions/recent?limit=${limit}`),

  audit: () => request<AuditEntry[]>("/api/audit"),
};

// The browser WebSocket API cannot set an Authorization header, so the token rides in the
// subprotocol. Not the query string: that lands in every access log along the way, and this
// token is a full credential. The server echoes "ss.bearer" back to complete the handshake.
const WS_SUBPROTOCOL = "ss.bearer";

export function tailSocket(onMessage: (raw: unknown) => void): WebSocket {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  const token = getToken();
  const socket = new WebSocket(`${scheme}://${location.host}/api/decisions/tail`, [
    WS_SUBPROTOCOL,
    token ?? "",
  ]);
  socket.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data));
    } catch {
      /* ignore malformed frames */
    }
  };
  return socket;
}
