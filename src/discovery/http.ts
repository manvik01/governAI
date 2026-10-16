// Read-only HTTP for discovery connectors.
//
// Connectors must never change anything in the systems they inspect. Every
// connector gets its fetch through readOnlyFetch(), which refuses any method
// other than GET, with one exception: the OAuth2 token request to an
// identity provider's token endpoint (Entra ID), which is a POST by protocol
// but only obtains a read token. The exception is per-URL and exact.
//
// Credentials are read from environment variables whose NAMES are configured;
// values are read at run time, used for one request and never stored on the
// connector, in the database or in error messages.

export interface FetchResponse {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<any>;
  text(): Promise<string>;
}
export interface FetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}
export type FetchLike = (url: string, init?: FetchInit) => Promise<FetchResponse>;

export class ReadOnlyViolation extends Error {}
export class ConnectorConfigError extends Error {}
export class ConnectorHttpError extends Error {
  constructor(public status: number, public url: string, detail = "") {
    // URL query strings can carry search terms; never secrets (those go in headers).
    super(`HTTP ${status} from ${url.split("?")[0]}${detail ? `: ${detail.slice(0, 200)}` : ""}`);
  }
}

export const defaultFetch: FetchLike = (url, init) => fetch(url, init as RequestInit) as unknown as Promise<FetchResponse>;

/** Wraps a fetch so only GET (and POST to the listed token endpoints) can pass. */
export function readOnlyFetch(inner: FetchLike, tokenEndpoints: string[] = []): FetchLike {
  return (url, init = {}) => {
    const method = (init.method ?? "GET").toUpperCase();
    if (method === "GET") return inner(url, { ...init, method });
    if (method === "POST" && tokenEndpoints.includes(url)) return inner(url, { ...init, method });
    return Promise.reject(new ReadOnlyViolation(`discovery connectors are read-only: refused ${method} ${url.split("?")[0]}`));
  };
}

export type Env = Record<string, string | undefined>;

export function requireEnv(env: Env, names: string[]): Record<string, string> {
  const missing = names.filter((n) => !env[n]?.trim());
  if (missing.length) throw new ConnectorConfigError(`missing environment variable(s): ${missing.join(", ")}`);
  return Object.fromEntries(names.map((n) => [n, env[n]!.trim()]));
}

export async function getJson(f: FetchLike, url: string, headers: Record<string, string>): Promise<any> {
  const res = await f(url, { method: "GET", headers: { accept: "application/json", ...headers } });
  if (!res.ok) throw new ConnectorHttpError(res.status, url, await safeText(res));
  return res.json();
}

export async function getText(f: FetchLike, url: string, headers: Record<string, string>): Promise<string> {
  const res = await f(url, { method: "GET", headers });
  if (!res.ok) throw new ConnectorHttpError(res.status, url);
  return res.text();
}

async function safeText(res: FetchResponse): Promise<string> {
  try {
    return (await res.text()).replace(/\s+/g, " ");
  } catch {
    return "";
  }
}

/** Follows OData @odata.nextLink paging (Microsoft Graph, Dataverse). */
export async function getODataAll(f: FetchLike, url: string, headers: Record<string, string>, maxPages = 50): Promise<any[]> {
  const out: any[] = [];
  let next: string | undefined = url;
  for (let i = 0; next && i < maxPages; i++) {
    const page: any = await getJson(f, next, headers);
    out.push(...(page.value ?? []));
    next = page["@odata.nextLink"];
  }
  return out;
}

/** Microsoft identity platform client-credentials token (the one allowed POST). */
export async function entraToken(f: FetchLike, tenantId: string, clientId: string, clientSecret: string, scope: string): Promise<string> {
  const url = entraTokenUrl(tenantId);
  const body = new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret, scope }).toString();
  const res = await f(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
  if (!res.ok) throw new ConnectorHttpError(res.status, url, "token request failed");
  const j = await res.json();
  if (typeof j.access_token !== "string") throw new ConnectorHttpError(res.status, url, "no access_token in response");
  return j.access_token;
}

export const entraTokenUrl = (tenantId: string) => `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
