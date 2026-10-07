// Thin HTTP client the MCP admin server uses. It holds no policy logic and no
// database access: every action is an authenticated call to the secure gateway,
// so roles, separation of duties and audit logging apply exactly as for any
// other client. If the gateway cannot be reached the call FAILS CLOSED.

export class GatewayError extends Error {
  constructor(message: string, readonly status?: number, readonly body?: unknown) {
    super(message);
  }
}

export class GatewayClient {
  constructor(private baseUrl: string, private token: string, private timeoutMs = 10_000) {
    if (!baseUrl) throw new GatewayError("GOVERNAI_GATEWAY_URL is not set");
    if (!token) throw new GatewayError("GOVERNAI_USER_TOKEN is not set");
  }

  async request(method: string, path: string, body?: unknown): Promise<unknown> {
    let res: Response;
    try {
      res = await fetch(new URL(path, this.baseUrl), {
        method,
        headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch {
      // Never fall back to a direct database or tool call.
      throw new GatewayError("governAI gateway unreachable - refusing to act");
    }
    const text = await res.text();
    let json: unknown;
    try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
    if (!res.ok) throw new GatewayError(`gateway returned ${res.status}`, res.status, json);
    return json;
  }
}
