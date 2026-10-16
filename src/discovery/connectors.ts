// Discovery connectors: read-only inventory of agents that live in other
// systems, so an agent nobody registered still shows up in the triage queue.
//
//   entra_id          Microsoft Entra Agent ID identities (Graph beta) and,
//                     optionally, application service principals (Graph v1.0)
//   okta              Okta service apps (OAuth client-credentials apps)
//   copilot_studio    Copilot Studio agents (Dataverse `bots` table)
//   gemini_enterprise Gemini Enterprise agents (Discovery Engine v1alpha)
//   github            MCP server configs and LLM API keys committed to repos
//
// Rules every connector follows:
//   - READ-ONLY: its fetch is wrapped by readOnlyFetch(), so a bug cannot
//     create, change or delete anything in the inspected system.
//   - Credentials come from environment variables whose NAMES are configured
//     (defaults below); values are read inside run() and never kept.
//   - It returns DiscoveredItems (sightings). It never writes to the database
//     itself; the runner records items through DiscoveryService, which scrubs
//     every attribute again before storing it.
//   - Found API keys are reduced to provider + repo + path + line + a 4-hex
//     SHA-256 fingerprint inside the connector; the key text never leaves
//     the function that read the file.
//   - Tested with fixture responses through an injected fetch; no live calls.

import type { Sighting } from "./discovery.js";
import { findKeys } from "../control/secret-patterns.js";
import {
  defaultFetch, entraToken, entraTokenUrl, getJson, getODataAll, getText, readOnlyFetch, requireEnv,
  ConnectorConfigError, type Env, type FetchLike,
} from "./http.js";

export type DiscoveredItem = Sighting;

export interface DiscoveryConnector {
  /** Unique id; also the scheduler's lock key. */
  id: string;
  /** Which system it reads (matches DiscoverySource). */
  kind: Sighting["source"];
  run(): Promise<DiscoveredItem[]>;
}

export interface ConnectorDeps {
  fetch?: FetchLike;
  env?: Env;
}

// ------------------------------------------------------------------ Entra ID

export interface EntraConfig {
  tenantIdEnv?: string;
  clientIdEnv?: string;
  clientSecretEnv?: string;
  /** Also list application service principals (can be large). Default false. */
  includeServicePrincipals?: boolean;
  graphBase?: string;
}

/** Microsoft Graph, app-only (client credentials). Needs Application.Read.All
 * (and AgentIdentity.Read.All where the tenant has Agent ID). */
export class EntraIdConnector implements DiscoveryConnector {
  readonly kind = "entra_id" as const;
  private f: FetchLike;
  private env: Env;
  constructor(private cfg: EntraConfig = {}, deps: ConnectorDeps = {}, readonly id = "entra_id") {
    this.env = deps.env ?? process.env;
    const tenant = this.env[cfg.tenantIdEnv ?? "ZENAI4_ENTRA_TENANT_ID"] ?? "";
    this.f = readOnlyFetch(deps.fetch ?? defaultFetch, [entraTokenUrl(tenant)]);
  }

  async run(): Promise<DiscoveredItem[]> {
    const tEnv = this.cfg.tenantIdEnv ?? "ZENAI4_ENTRA_TENANT_ID";
    const cEnv = this.cfg.clientIdEnv ?? "ZENAI4_ENTRA_CLIENT_ID";
    const sEnv = this.cfg.clientSecretEnv ?? "ZENAI4_ENTRA_CLIENT_SECRET";
    const v = requireEnv(this.env, [tEnv, cEnv, sEnv]);
    const graph = this.cfg.graphBase ?? "https://graph.microsoft.com";
    const token = await entraToken(this.f, v[tEnv], v[cEnv], v[sEnv], `${graph}/.default`);
    const h = { authorization: `Bearer ${token}` };
    const items: DiscoveredItem[] = [];

    // Entra Agent ID (preview, beta endpoint). A tenant without Agent ID answers 400/404: not an error for us.
    try {
      const agents = await getODataAll(this.f, `${graph}/beta/servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,agentIdentityBlueprintId,accountEnabled,createdDateTime&$top=999`, h);
      for (const a of agents) {
        items.push({
          source: "entra_id", kind: "agent_identity", identity: [v[tEnv], String(a.id)],
          displayName: String(a.displayName ?? a.appId ?? a.id),
          attributes: { tenantId: v[tEnv], objectId: a.id, appId: a.appId, blueprintId: a.agentIdentityBlueprintId, accountEnabled: a.accountEnabled, createdAt: a.createdDateTime },
        });
      }
    } catch (e) {
      if (!/HTTP (400|403|404)/.test((e as Error).message)) throw e;
    }

    if (this.cfg.includeServicePrincipals) {
      const sps = await getODataAll(this.f, `${graph}/v1.0/servicePrincipals?$filter=servicePrincipalType eq 'Application'&$select=id,appId,displayName,accountEnabled,tags,appOwnerOrganizationId,createdDateTime&$top=999`, h);
      for (const sp of sps) {
        // Microsoft first-party apps are noise; keep the tenant's own apps.
        if (sp.appOwnerOrganizationId && sp.appOwnerOrganizationId !== v[tEnv]) continue;
        items.push({
          source: "entra_id", kind: "service_principal", identity: [v[tEnv], String(sp.id)],
          displayName: String(sp.displayName ?? sp.appId),
          attributes: { tenantId: v[tEnv], objectId: sp.id, appId: sp.appId, accountEnabled: sp.accountEnabled, tags: sp.tags, createdAt: sp.createdDateTime },
        });
      }
    }
    return items;
  }
}

// ------------------------------------------------------------------ Okta

export interface OktaConfig {
  domainEnv?: string;
  apiTokenEnv?: string;
}

/** Okta Management API, read-only API token (SSWS) with okta.apps.read. Lists
 * service apps: OAuth apps whose type is "service" or that use the
 * client_credentials grant - the machine identities agents run under. */
export class OktaConnector implements DiscoveryConnector {
  readonly kind = "okta" as const;
  private f: FetchLike;
  private env: Env;
  constructor(private cfg: OktaConfig = {}, deps: ConnectorDeps = {}, readonly id = "okta") {
    this.f = readOnlyFetch(deps.fetch ?? defaultFetch);
    this.env = deps.env ?? process.env;
  }

  async run(): Promise<DiscoveredItem[]> {
    const dEnv = this.cfg.domainEnv ?? "ZENAI4_OKTA_DOMAIN";
    const tEnv = this.cfg.apiTokenEnv ?? "ZENAI4_OKTA_API_TOKEN";
    const v = requireEnv(this.env, [dEnv, tEnv]);
    const domain = v[dEnv].replace(/^https?:\/\//, "").replace(/\/+$/, "");
    if (!/^[a-z0-9.-]+$/i.test(domain)) throw new ConnectorConfigError(`${dEnv} must be a host name such as acme.okta.com`);
    const h = { authorization: `SSWS ${v[tEnv]}`, accept: "application/json" };
    const items: DiscoveredItem[] = [];
    let url: string | undefined = `https://${domain}/api/v1/apps?limit=200`;
    for (let page = 0; url && page < 50; page++) {
      const res = await this.f(url, { method: "GET", headers: h });
      if (!res.ok) throw new Error(`HTTP ${res.status} from https://${domain}/api/v1/apps`);
      const apps = (await res.json()) as any[];
      for (const app of apps) {
        const oc = app.settings?.oauthClient ?? {};
        const grants: string[] = app.settings?.oauthClient?.grant_types ?? app.credentials?.oauthClient?.grant_types ?? [];
        const isService = oc.application_type === "service" || grants.includes("client_credentials");
        if (!isService) continue;
        items.push({
          source: "okta", kind: "service_app", identity: [domain, String(app.id)],
          displayName: String(app.label ?? app.name ?? app.id),
          attributes: { oktaDomain: domain, appId: app.id, status: app.status, signOnMode: app.signOnMode, created: app.created, lastUpdated: app.lastUpdated, grantTypes: grants },
        });
      }
      url = nextLink(res.headers.get("link"));
      if (url && !url.startsWith(`https://${domain}/`)) url = undefined; // never follow a link off-tenant
    }
    return items;
  }
}

function nextLink(header: string | null): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(",")) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="?next"?/);
    if (m) return m[1];
  }
  return undefined;
}

// ------------------------------------------------------------------ Copilot Studio

export interface CopilotStudioConfig {
  /** Dataverse environment URL, e.g. https://contoso.crm.dynamics.com */
  dataverseUrlEnv?: string;
  tenantIdEnv?: string;
  clientIdEnv?: string;
  clientSecretEnv?: string;
}

/** Copilot Studio agents are rows in the Dataverse `bots` table of each Power
 * Platform environment. App-only access needs an application user in that
 * environment with read on bots. One connector instance per environment. */
export class CopilotStudioConnector implements DiscoveryConnector {
  readonly kind = "copilot_studio" as const;
  private f: FetchLike;
  private env: Env;
  constructor(private cfg: CopilotStudioConfig = {}, deps: ConnectorDeps = {}, readonly id = "copilot_studio") {
    this.env = deps.env ?? process.env;
    const tenant = this.env[cfg.tenantIdEnv ?? "ZENAI4_ENTRA_TENANT_ID"] ?? "";
    this.f = readOnlyFetch(deps.fetch ?? defaultFetch, [entraTokenUrl(tenant)]);
  }

  async run(): Promise<DiscoveredItem[]> {
    const uEnv = this.cfg.dataverseUrlEnv ?? "ZENAI4_DATAVERSE_URL";
    const tEnv = this.cfg.tenantIdEnv ?? "ZENAI4_ENTRA_TENANT_ID";
    const cEnv = this.cfg.clientIdEnv ?? "ZENAI4_ENTRA_CLIENT_ID";
    const sEnv = this.cfg.clientSecretEnv ?? "ZENAI4_ENTRA_CLIENT_SECRET";
    const v = requireEnv(this.env, [uEnv, tEnv, cEnv, sEnv]);
    const base = v[uEnv].replace(/\/+$/, "");
    if (!/^https:\/\/[a-z0-9.-]+\.dynamics\.com$/i.test(base)) throw new ConnectorConfigError(`${uEnv} must look like https://<org>.crm.dynamics.com`);
    const token = await entraToken(this.f, v[tEnv], v[cEnv], v[sEnv], `${base}/.default`);
    const bots = await getODataAll(this.f, `${base}/api/data/v9.2/bots?$select=botid,name,schemaname,statecode,statuscode,createdon,modifiedon,_ownerid_value,_createdby_value`, {
      authorization: `Bearer ${token}`, "OData-Version": "4.0", "OData-MaxVersion": "4.0",
      prefer: 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"',
    });
    return bots.map((b) => ({
      source: "copilot_studio" as const, kind: "copilot_agent", identity: [base, String(b.botid)],
      displayName: String(b.name ?? b.schemaname ?? b.botid),
      attributes: {
        environmentUrl: base, botId: b.botid, schemaName: b.schemaname, state: b.statecode, status: b.statuscode,
        createdOn: b.createdon, modifiedOn: b.modifiedon, ownerId: b._ownerid_value,
        ownerName: b["_ownerid_value@OData.Community.Display.V1.FormattedValue"],
      },
    }));
  }
}

// ------------------------------------------------------------------ Gemini Enterprise

export interface GeminiEnterpriseConfig {
  projectEnv?: string;
  /** global | us | eu (default global). */
  locationEnv?: string;
  /** Comma-separated Gemini Enterprise app (engine) ids. */
  appIdsEnv?: string;
  /** OAuth access token with cloud-platform scope (e.g. from workload identity). */
  accessTokenEnv?: string;
}

/** Lists agents registered in each Gemini Enterprise app via the Discovery
 * Engine v1alpha API (preview). */
export class GeminiEnterpriseConnector implements DiscoveryConnector {
  readonly kind = "gemini_enterprise" as const;
  private f: FetchLike;
  private env: Env;
  constructor(private cfg: GeminiEnterpriseConfig = {}, deps: ConnectorDeps = {}, readonly id = "gemini_enterprise") {
    this.f = readOnlyFetch(deps.fetch ?? defaultFetch);
    this.env = deps.env ?? process.env;
  }

  async run(): Promise<DiscoveredItem[]> {
    const pEnv = this.cfg.projectEnv ?? "ZENAI4_GEMINI_PROJECT";
    const aEnv = this.cfg.appIdsEnv ?? "ZENAI4_GEMINI_APP_IDS";
    const tEnv = this.cfg.accessTokenEnv ?? "ZENAI4_GEMINI_ACCESS_TOKEN";
    const v = requireEnv(this.env, [pEnv, aEnv, tEnv]);
    const location = (this.env[this.cfg.locationEnv ?? "ZENAI4_GEMINI_LOCATION"] ?? "global").trim() || "global";
    if (!["global", "us", "eu"].includes(location)) throw new ConnectorConfigError("Gemini location must be global, us or eu");
    const host = location === "global" ? "https://discoveryengine.googleapis.com" : `https://${location}-discoveryengine.googleapis.com`;
    const project = v[pEnv];
    const h = { authorization: `Bearer ${v[tEnv]}`, "x-goog-user-project": project };
    const items: DiscoveredItem[] = [];
    for (const app of v[aEnv].split(",").map((s) => s.trim()).filter(Boolean)) {
      const base = `${host}/v1alpha/projects/${encodeURIComponent(project)}/locations/${location}/collections/default_collection/engines/${encodeURIComponent(app)}/assistants/default_assistant/agents`;
      let pageToken: string | undefined;
      for (let page = 0; page < 50; page++) {
        const j = await getJson(this.f, pageToken ? `${base}?pageToken=${encodeURIComponent(pageToken)}` : base, h);
        for (const a of j.agents ?? []) {
          const kind = a.a2aAgentDefinition ? "a2a_agent" : a.adkAgentDefinition ? "adk_agent" : a.dialogflowAgentDefinition ? "dialogflow_agent" : "gemini_agent";
          items.push({
            source: "gemini_enterprise", kind, identity: [String(a.name)],
            displayName: String(a.displayName ?? String(a.name).split("/").pop()),
            attributes: { resourceName: a.name, appId: app, description: a.description, state: a.state, createTime: a.createTime, updateTime: a.updateTime },
          });
        }
        pageToken = j.nextPageToken;
        if (!pageToken) break;
      }
    }
    return items;
  }
}

// ------------------------------------------------------------------ GitHub

export interface GitHubConfig {
  tokenEnv?: string;
  /** Organisation (or user) to search; code search is scoped to it. */
  orgEnv?: string;
  apiBase?: string;
  /** Max files fetched per run (code search is rate limited). */
  maxFiles?: number;
}

export const MCP_CONFIG_FILENAMES = ["mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json"];

/** GitHub REST code search (needs a token with read access to the org's
 * repos). Finds MCP server configs and committed LLM provider keys. */
export class GitHubConnector implements DiscoveryConnector {
  readonly kind = "github" as const;
  private f: FetchLike;
  private env: Env;
  constructor(private cfg: GitHubConfig = {}, deps: ConnectorDeps = {}, readonly id = "github") {
    this.f = readOnlyFetch(deps.fetch ?? defaultFetch);
    this.env = deps.env ?? process.env;
  }

  async run(): Promise<DiscoveredItem[]> {
    const tEnv = this.cfg.tokenEnv ?? "ZENAI4_GITHUB_TOKEN";
    const oEnv = this.cfg.orgEnv ?? "ZENAI4_GITHUB_ORG";
    const v = requireEnv(this.env, [tEnv, oEnv]);
    const org = v[oEnv];
    if (!/^[A-Za-z0-9-]+$/.test(org)) throw new ConnectorConfigError(`${oEnv} must be a GitHub organisation or user name`);
    const api = this.cfg.apiBase ?? "https://api.github.com";
    const h = { authorization: `Bearer ${v[tEnv]}`, "x-github-api-version": "2022-11-28", accept: "application/vnd.github+json" };
    const maxFiles = this.cfg.maxFiles ?? 200;

    // 1. Collect candidate files: MCP configs by filename, key-bearing files by literal prefix.
    const files = new Map<string, { repo: string; path: string; sha?: string; why: Set<string> }>();
    const search = async (q: string, why: string) => {
      const j = await getJson(this.f, `${api}/search/code?q=${encodeURIComponent(q)}&per_page=100`, h);
      for (const it of j.items ?? []) {
        const repo = it.repository?.full_name;
        if (typeof repo !== "string" || typeof it.path !== "string") continue;
        const k = `${repo}:${it.path}`;
        const e = files.get(k) ?? { repo, path: it.path, sha: it.sha, why: new Set<string>() };
        e.why.add(why);
        files.set(k, e);
      }
    };
    for (const name of MCP_CONFIG_FILENAMES) await search(`filename:${name} org:${org}`, "mcp");
    await search(`path:.vscode filename:mcp.json org:${org}`, "mcp");
    for (const hint of ["sk-ant-", "sk-proj-", "T3BlbkFJ", "AIza", "gsk_", "hf_", "xai-"]) await search(`"${hint}" org:${org}`, "key");

    // 2. Read each file once; report MCP servers and key FINGERPRINTS only.
    const items: DiscoveredItem[] = [];
    let n = 0;
    for (const file of files.values()) {
      if (n++ >= maxFiles) break;
      const contentUrl = `${api}/repos/${file.repo.split("/").map(encodeURIComponent).join("/")}/contents/${file.path.split("/").map(encodeURIComponent).join("/")}`;
      let text: string;
      try {
        text = await getText(this.f, contentUrl, { ...h, accept: "application/vnd.github.raw+json" });
      } catch {
        continue; // deleted since indexing, or no access: skip quietly
      }
      if (file.why.has("mcp") || MCP_CONFIG_FILENAMES.some((f) => file.path.endsWith(f))) {
        items.push(...mcpServersIn(text, file.repo, file.path));
      }
      for (const hit of findKeys(text)) {
        items.push({
          source: "github", kind: "llm_api_key",
          identity: [file.repo, file.path, hit.provider, hit.fingerprint],
          displayName: `${hit.provider} API key in ${file.repo}/${file.path}:${hit.line}`,
          attributes: { repo: file.repo, path: file.path, line: hit.line, provider: hit.provider, keyFingerprint: hit.fingerprint },
        });
      }
    }
    return items;
  }
}

/** Extracts MCP server declarations from a config file. Records the server
 * name, transport and command/URL host, and the NAMES of env vars it is
 * given - never env values, args (which can hold tokens) or headers. */
export function mcpServersIn(text: string, repo: string, path: string): DiscoveredItem[] {
  let j: any;
  try {
    j = JSON.parse(stripJsonComments(text));
  } catch {
    return [];
  }
  const servers = j?.mcpServers ?? j?.servers ?? j?.mcp?.servers;
  if (!servers || typeof servers !== "object") return [];
  return Object.entries(servers as Record<string, any>).map(([name, s]) => {
    let urlHost: string | undefined;
    try {
      if (typeof s?.url === "string") urlHost = new URL(s.url).host;
    } catch { /* not a URL */ }
    const transport = s?.type ?? (s?.url ? "http" : s?.command ? "stdio" : "unknown");
    return {
      source: "github" as const, kind: "mcp_server",
      identity: [repo, path, name],
      displayName: `MCP server "${name}" in ${repo}/${path}`,
      attributes: {
        repo, path, serverName: name, transport,
        command: typeof s?.command === "string" ? s.command.split(/[\\/]/).pop() : undefined,
        package: Array.isArray(s?.args) ? s.args.find((a: unknown) => typeof a === "string" && /^@?[a-z0-9][\w.-]*(\/[\w.-]+)?(@[\w.^~-]+)?$/i.test(a) && !a.startsWith("-")) : undefined,
        urlHost,
        envVarNames: s?.env && typeof s.env === "object" ? Object.keys(s.env) : [],
      },
    };
  });
}

function stripJsonComments(s: string): string {
  // VS Code's mcp.json allows comments and trailing commas.
  return s.replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m, str) => str ?? "").replace(/,(\s*[}\]])/g, "$1");
}

// ------------------------------------------------------------------ factory

/** Builds the connectors named in ZENAI4_DISCOVERY_CONNECTORS (comma list of
 * entra_id, okta, copilot_studio, gemini_enterprise, github). */
export function connectorsFromEnv(env: Env = process.env, deps: ConnectorDeps = {}): DiscoveryConnector[] {
  const wanted = (env.ZENAI4_DISCOVERY_CONNECTORS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const d = { env, ...deps };
  const out: DiscoveryConnector[] = [];
  for (const w of wanted) {
    switch (w) {
      case "entra_id": out.push(new EntraIdConnector({ includeServicePrincipals: env.ZENAI4_ENTRA_INCLUDE_SERVICE_PRINCIPALS === "1" }, d)); break;
      case "okta": out.push(new OktaConnector({}, d)); break;
      case "copilot_studio": out.push(new CopilotStudioConnector({}, d)); break;
      case "gemini_enterprise": out.push(new GeminiEnterpriseConnector({}, d)); break;
      case "github": out.push(new GitHubConnector({}, d)); break;
      default: throw new ConnectorConfigError(`unknown connector "${w}" in ZENAI4_DISCOVERY_CONNECTORS`);
    }
  }
  return out;
}

