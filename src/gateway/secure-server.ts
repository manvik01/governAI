// Secure gateway: the one HTTP entry point to the control plane.
//
// Design for the deployment the PRD asks for - a container on-prem or a
// small cloud VM, scaling up and down:
//   - STATELESS process: all state (registry, credentials, audit, ledger)
//     lives in the database, so any number of replicas can sit behind a
//     load balancer and be added or removed freely. (Two pieces still need
//     shared state before running >1 replica: the rate-limit counters and
//     the security-monitor windows - both noted in their files - and the
//     database must move from SQLite to Postgres.)
//   - /healthz (liveness) and /readyz (readiness: checks the database) for
//     orchestrator probes and autoscaler decisions.
//   - Configuration from environment (see main() at the bottom), no local files.
//
// Security behaviour:
//   - Every route except health checks requires a bearer credential.
//   - Agents authenticate with their own issued credential; the agent's
//     identity comes from the credential, never from the request body. An
//     agent naming a different agent in the body is refused and alerted.
//   - Humans authenticate with a user token; roles come from the directory,
//     so a deactivated person loses access immediately.
//   - All authentication failures return the same 401; the precise reason
//     goes only to the audit log (no oracle for attackers).
//   - Body size limits, rate limiting by source (pre-auth) and subject
//     (post-auth), and an audit event for every request outcome, including
//     failures and denials.
//
// Phase 1 (registration and discovery):
//   - A call with an unknown, failed, revoked or expired AGENT credential is
//     also recorded as a discovery sighting ("possible unregistered agent"),
//     fingerprinted from source address, user agent and the public key-id
//     prefix only. The presented token never reaches discovery or the log.
//   - An agent past its expiry date is refused at authentication even if
//     the expiry sweep has not run yet (reason "agent_expired", same 401).
//   - Routes for drafts, updates, registration as code (apply), lifecycle
//     transitions, risk tier, recertification, the discovery triage queue,
//     egress-log import and connector status. See
//     docs/phase1-registration-discovery.md.
//
// Phase 1.1 (telemetry and reconciliation):
//   - POST /v1/intake/steps and /v1/intake/otlp accept telemetry from an
//     intake source (zsrc.<id>.<secret> token, created with the admin CLI;
//     only its hash is stored) or from an active agent's own credential.
//     Authentication runs BEFORE the body is read, so an unauthenticated
//     batch is refused with 401 and nothing about it is stored except the
//     auth failure; failed source tokens feed discovery like failed agent
//     credentials (non-secret shape only). Body size and item count are
//     capped; every batch, refused or not, is recorded and audited.
//   - Governed calls the policy engine denies or holds are also written to
//     the hash-chained policy-violation log.
//   - Telemetry alerts, dormant agents, violations, activity summaries and
//     an on-demand reconciliation run. See docs/phase1.1-telemetry-reconciliation.md.
//   - Errors never carry exception text to the caller: a final error handler
//     logs details server-side with the request id and answers
//     {"error":"internal_error","requestId":...}.

import "../config/env-compat.js";
import express, { type NextFunction, type Request, type Response } from "express";
import { nanoid } from "nanoid";
import { hasRole, type DirectoryUser, type Role } from "../control/identity.js";
import type { ControlPlane } from "../control/control-plane.js";
import type { RegistrationRequest } from "../control/registration.js";
import { parsePolicy } from "../policy/schema.js";
import { LLM_KEY_PATTERNS } from "../control/secret-patterns.js";
import { DISCOVERY_STATUSES, type DiscoveryStatus } from "../discovery/discovery.js";
import type { LifecycleState, RiskTier } from "../types.js";
import { itemCount, parseOtlpTraces, parseStepsBatch } from "../telemetry/mapping.js";
import type { IntakePrincipal, IntakeResult } from "../telemetry/intake.js";
import type { AlertKind } from "../telemetry/store.js";
import { redactPayload } from "../telemetry/redact.js";

/** Non-secret description of a presented credential, for discovery fingerprints. */
export function credentialShape(token: string | undefined): { scheme: string; keyIdPrefix?: string; provider?: string } {
  if (!token) return { scheme: "none" };
  const parts = token.split(".");
  if (parts[0] === "gai" && (parts[1] === "a" || parts[1] === "u") && parts[2]) {
    return { scheme: parts[1] === "a" ? "zenai4-agent" : "zenai4-user", keyIdPrefix: parts[2].slice(0, 6) };
  }
  if (parts[0] === "zsrc" && parts[1]) return { scheme: "zenai4-source", keyIdPrefix: parts[1].slice(0, 6) };
  const p = LLM_KEY_PATTERNS.find((k) => new RegExp(`^${k.re.source}$`).test(token));
  if (p) return { scheme: "provider-key", provider: p.provider };
  return { scheme: "opaque" };
}

const FORBIDDEN_HINT = /^(only |not permitted|separation of duties|reviewer must)/;
const statusFor = (violations: string[], notFound?: boolean) =>
  notFound || violations.some((v) => v.startsWith("unknown agent") || v.startsWith("unknown discovery")) ? 404
    : violations.some((v) => FORBIDDEN_HINT.test(v)) ? 403 : 422;

export interface SecureGatewayOptions {
  /** Max requests per minute per authenticated subject. */
  rateLimitPerMin?: number;
  /** Max requests per minute per source address, checked before authentication. */
  ipRateLimitPerMin?: number;
  maxBodyBytes?: number;
  /** Max size of an egress-log CSV import (default 5 MiB). */
  maxCsvBytes?: number;
  /** Trust X-Forwarded-For (only behind a proxy/load balancer you control). */
  trustProxy?: boolean;
}

type Principal =
  | { kind: "agent"; agentId: string }
  | { kind: "user"; email: string; user: DirectoryUser }
  | { kind: "source"; sourceId: string };

const actorTypeOf = (p: Principal | undefined) => (p?.kind === "source" ? "system" : p?.kind ?? "anonymous");
const isIntakePath = (p: string) => p === "/v1/intake/steps" || p === "/v1/intake/otlp";

interface Locals {
  ip: string;
  requestId: string;
  principal?: Principal;
}
const L = (res: Response) => res.locals as Locals;

class FixedWindowLimiter {
  private buckets = new Map<string, { start: number; count: number }>();
  constructor(private limit: number, private windowMs = 60_000) {}
  /** Returns true if the request is allowed. */
  allow(key: string, now = Date.now()): boolean {
    const b = this.buckets.get(key);
    if (!b || now - b.start >= this.windowMs) {
      this.buckets.set(key, { start: now, count: 1 });
      return true;
    }
    b.count++;
    return b.count <= this.limit;
  }
}

export function createSecureGateway(cp: ControlPlane, options: SecureGatewayOptions = {}) {
  const app = express();
  app.disable("x-powered-by");
  const subjectLimiter = new FixedWindowLimiter(options.rateLimitPerMin ?? 120);
  const intakeLimiter = new FixedWindowLimiter(cp.telemetryConfig.intakeRateLimitPerMin);
  const ipLimiter = new FixedWindowLimiter(options.ipRateLimitPerMin ?? 300);

  // ---- request context
  app.use((req, res, next) => {
    const xff = options.trustProxy ? String(req.headers["x-forwarded-for"] ?? "").split(",")[0].trim() : "";
    L(res).ip = xff || req.socket.remoteAddress || "unknown";
    L(res).requestId = String(req.headers["x-request-id"] ?? nanoid(12));
    res.setHeader("x-request-id", L(res).requestId);
    next();
  });

  // ---- health (unauthenticated, no data)
  app.get("/healthz", (_req, res) => res.json({ status: "ok" }));
  app.get("/readyz", (_req, res) => {
    try {
      cp.db.prepare("SELECT 1").get();
      res.json({ ready: true });
    } catch {
      res.status(503).json({ ready: false });
    }
  });

  // ---- body parsing with a hard size cap; malformed input is evidence
  const jsonParser = express.json({ limit: options.maxBodyBytes ?? 64 * 1024 });
  // Intake bodies are read later, after authentication, with their own cap.
  app.use((req, res, next) => (isIntakePath(req.path) ? next() : jsonParser(req, res, next)));
  // agent.yaml manifests and egress CSVs may be posted raw.
  app.use(express.text({ type: ["application/yaml", "application/x-yaml", "text/yaml"], limit: options.maxBodyBytes ?? 64 * 1024 }));
  app.use(express.text({ type: ["text/csv"], limit: options.maxCsvBytes ?? 5 * 1024 * 1024 }));
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (!err) return next();
    cp.audit.append({
      stream: "audit", actorType: "anonymous", actorId: "unknown", action: "request.malformed", outcome: "denied",
      sourceIp: L(res).ip, requestId: L(res).requestId, details: { path: req.path, type: err.type ?? "parse_error" },
    });
    res.status(err.type === "entity.too.large" ? 413 : 400).json({ error: "bad_request" });
  });

  // ---- pre-auth rate limit by source address
  app.use((req, res, next) => {
    if (ipLimiter.allow(`ip:${L(res).ip}`)) return next();
    cp.audit.append({
      stream: "audit", actorType: "anonymous", actorId: L(res).ip, action: "rate_limit.exceeded", outcome: "denied",
      sourceIp: L(res).ip, requestId: L(res).requestId, details: { scope: "ip", path: req.path },
    });
    res.status(429).json({ error: "rate_limited" });
  });

  // ---- authentication
  app.use((req, res, next) => {
    if (req.path === "/healthz" || req.path === "/readyz") return next();
    const ctx = L(res);
    const header = req.headers.authorization ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : undefined;
    const fail = (reason: string, subject?: string) => {
      cp.audit.append({
        stream: "audit", actorType: "anonymous", actorId: subject ?? "unknown", action: "auth.failed", outcome: "denied",
        sourceIp: ctx.ip, requestId: ctx.requestId, details: { reason, subject, path: req.path, method: req.method },
      });
      noteUnregistered(reason, subject);
      res.status(401).json({ error: "unauthorized" }); // identical for every reason
    };
    // Possible unregistered agent: anything that is not a human token, except
    // a bare unauthenticated request to a non-agent route (that is just noise).
    const noteUnregistered = (reason: string, subject?: string) => {
      const shape = credentialShape(token);
      if (shape.scheme === "zenai4-user" || reason === "user_inactive") return;
      if (shape.scheme === "none" && req.path !== "/v1/call" && !isIntakePath(req.path)) return;
      const ua = String(req.headers["user-agent"] ?? "").slice(0, 200);
      const linked = subject && cp.registry.get(subject) ? subject : undefined;
      try {
        cp.discovery.record({
          source: "gateway", kind: "failed_credential",
          identity: [ctx.ip, ua, shape.scheme, shape.keyIdPrefix ?? shape.provider ?? ""],
          displayName: `${shape.scheme} caller from ${ctx.ip}${ua ? ` (${ua.slice(0, 60)})` : ""}`,
          agentId: linked,
          attributes: { sourceIp: ctx.ip, userAgent: ua, credentialScheme: shape.scheme, keyIdPrefix: shape.keyIdPrefix, provider: shape.provider, lastReason: reason, lastPath: req.path },
        }, { sourceIp: ctx.ip, requestId: ctx.requestId });
      } catch {
        /* discovery must never break the authentication path */
      }
    };

    if (!token) return fail("missing_credentials");
    if (token.startsWith("zsrc.")) {
      // Intake-source tokens are valid only on the intake routes.
      if (!isIntakePath(req.path)) return fail("source_token_wrong_route");
      const sv = cp.telemetry.verifySourceToken(token);
      if (!sv.ok) return fail(`source_${sv.reason}`, sv.sourceId ? `source:${sv.sourceId}` : undefined);
      ctx.principal = { kind: "source", sourceId: sv.source.id };
      if (!intakeLimiter.allow(`src:${sv.source.id}`)) {
        cp.audit.append({ stream: "audit", actorType: "system", actorId: `source:${sv.source.id}`, action: "rate_limit.exceeded", outcome: "denied", sourceIp: ctx.ip, requestId: ctx.requestId, details: { scope: "source", path: req.path } });
        return void res.status(429).json({ error: "rate_limited" });
      }
      cp.audit.append({ stream: "audit", actorType: "system", actorId: `source:${sv.source.id}`, action: "auth.success", outcome: "success", sourceIp: ctx.ip, requestId: ctx.requestId, details: { path: req.path, method: req.method } });
      return next();
    }
    const v = cp.credentials.verify(token);
    if (!v.ok) return fail(v.reason, v.subject);

    if (v.kind === "agent") {
      const agent = cp.registry.get(v.subject);
      if (agent?.lifecycleState === "active" && cp.registry.isExpired(agent)) return fail("agent_expired", v.subject);
      if (!cp.registry.isActive(v.subject)) return fail("agent_not_active", v.subject);
      ctx.principal = { kind: "agent", agentId: v.subject };
    } else {
      const user = cp.directory.lookup(v.subject);
      if (!user || !user.active) return fail("user_inactive", v.subject);
      ctx.principal = { kind: "user", email: user.email, user };
    }
    const subject = ctx.principal.kind === "agent" ? ctx.principal.agentId : ctx.principal.email;
    const limiter = isIntakePath(req.path) ? intakeLimiter : subjectLimiter;
    if (!limiter.allow(`sub:${subject}`)) {
      cp.audit.append({
        stream: "audit", actorType: ctx.principal.kind, actorId: subject, action: "rate_limit.exceeded", outcome: "denied",
        sourceIp: ctx.ip, requestId: ctx.requestId, details: { scope: "subject", path: req.path },
      });
      return void res.status(429).json({ error: "rate_limited" });
    }
    cp.audit.append({
      stream: "audit", actorType: ctx.principal.kind, actorId: subject, action: "auth.success", outcome: "success",
      sourceIp: ctx.ip, requestId: ctx.requestId, details: { path: req.path, method: req.method },
    });
    next();
  });

  // ---- helpers
  const requireUser = (res: Response, req: Request, ...roles: Role[]): DirectoryUser | undefined => {
    const p = L(res).principal;
    if (p?.kind === "user" && hasRole(p.user, ...roles)) return p.user;
    cp.audit.append({
      stream: "audit", actorType: actorTypeOf(p), actorId: p?.kind === "user" ? p.email : p?.kind === "agent" ? p.agentId : p?.kind === "source" ? `source:${p.sourceId}` : "unknown",
      action: "access.denied", outcome: "denied", sourceIp: L(res).ip, requestId: L(res).requestId,
      details: { path: req.path, method: req.method, requiredRoles: roles },
    });
    res.status(403).json({ error: "forbidden" });
    return undefined;
  };
  const ctxOf = (res: Response) => ({ sourceIp: L(res).ip, requestId: L(res).requestId });
  const principalId = (p: Principal | undefined) => p?.kind === "user" ? p.email : p?.kind === "agent" ? p.agentId : p?.kind === "source" ? `source:${p.sourceId}` : "unknown";
  /** Owner/sub-owner of the agent, or a role that sees every agent. */
  const canSeeAgent = (user: DirectoryUser, agentId: string | undefined) => {
    if (hasRole(user, "admin", "auditor", "security_reviewer")) return true;
    const a = agentId ? cp.registry.get(agentId) : undefined;
    const mine = (e?: string) => e?.toLowerCase() === user.email;
    return Boolean(a && hasRole(user, "agent_owner") && (mine(a.ownerEmail) || mine(a.subOwnerEmail)));
  };

  // ---- telemetry intake (phase 1.1)
  const intakeRaw = express.raw({ type: () => true, limit: cp.telemetryConfig.maxBatchBytes, inflate: true });
  const intakeHandler = (endpoint: "steps" | "otlp") => (req: Request, res: Response, next: NextFunction) => {
    const p = L(res).principal;
    if (p?.kind !== "agent" && p?.kind !== "source") {
      cp.audit.append({ stream: "audit", actorType: actorTypeOf(p), actorId: principalId(p), action: "access.denied", outcome: "denied", sourceIp: L(res).ip, requestId: L(res).requestId, details: { path: req.path, method: req.method, reason: "intake requires a source token or an agent credential" } });
      return void res.status(403).json({ error: "forbidden" });
    }
    const source = p.kind === "source" ? cp.telemetry.getSource(p.sourceId) : undefined;
    const principal: IntakePrincipal = p.kind === "source" ? { kind: "source", source: source! } : { kind: "agent", agentId: p.agentId };
    const declared = Number(req.headers["content-length"] ?? 0) || 0;
    intakeRaw(req, res, (err?: any) => {
      // This callback runs outside Express's own try/catch: hand failures to the error handler.
      try { handleBody(err); } catch (e) { next(e); }
    });
    const handleBody = (err?: any) => {
      if (err) {
        const tooLarge = err.type === "entity.too.large";
        cp.intake.rejectBatch(principal, endpoint, declared, tooLarge ? "body exceeds the intake size limit" : "body could not be read", ctxOf(res));
        return void res.status(tooLarge ? 413 : 400).json({ error: tooLarge ? "batch_too_large" : "bad_request", maxBytes: tooLarge ? cp.telemetryConfig.maxBatchBytes : undefined });
      }
      const ctype = String(req.headers["content-type"] ?? "").toLowerCase();
      if (!ctype.includes("json")) {
        cp.intake.rejectBatch(principal, endpoint, declared, `unsupported content type`, ctxOf(res));
        return void res.status(415).json({ error: "unsupported_media_type", detail: endpoint === "otlp" ? "send OTLP/HTTP with JSON encoding (collector otlphttp exporter: encoding: json)" : "send application/json" });
      }
      const raw: Buffer = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      let body: unknown;
      try { body = JSON.parse(raw.toString("utf8")); } catch {
        cp.intake.rejectBatch(principal, endpoint, raw.length, "body is not valid JSON", ctxOf(res));
        return void res.status(400).json({ error: "bad_request", detail: "body is not valid JSON" });
      }
      const n = itemCount(endpoint, body);
      if (n > cp.telemetryConfig.maxBatchSteps) {
        cp.intake.rejectBatch(principal, endpoint, raw.length, `batch has ${n} items; the limit is ${cp.telemetryConfig.maxBatchSteps}`, ctxOf(res), n);
        return void res.status(413).json({ error: "batch_too_large", maxItems: cp.telemetryConfig.maxBatchSteps });
      }
      const parsed = endpoint === "steps" ? parseStepsBatch(body) : parseOtlpTraces(body);
      if (!parsed.ok) {
        cp.intake.rejectBatch(principal, endpoint, raw.length, parsed.reason, ctxOf(res), n);
        return void res.status(400).json({ error: "bad_request", detail: parsed.reason });
      }
      const out: IntakeResult = cp.intake.ingest(principal, endpoint, parsed.batch, raw, ctxOf(res));
      if (endpoint === "otlp") {
        // OTLP/HTTP ExportTraceServiceResponse; 200 so a collector does not retry accepted data.
        return void res.status(out.status === "rejected" && out.ignored === 0 ? 400 : 200).json({
          partialSuccess: out.rejected ? { rejectedSpans: out.rejected, errorMessage: out.errors.slice(0, 5).map((e) => `span ${e.index}: ${e.reason}`).join("; ") } : {},
          batchId: out.batchId,
        });
      }
      res.status(out.status === "rejected" ? 422 : 200).json(out);
    };
  };
  app.post("/v1/intake/steps", intakeHandler("steps"));
  app.post("/v1/intake/otlp", intakeHandler("otlp"));

  app.get("/v1/intake/sources", (req, res) => {
    const user = requireUser(res, req, "admin", "security_reviewer", "auditor");
    if (!user) return;
    res.json({ sources: cp.telemetry.listSources() });
  });

  app.get("/v1/intake/batches", (req, res) => {
    const user = requireUser(res, req, "admin", "security_reviewer", "auditor");
    if (!user) return;
    res.json({ batches: cp.telemetry.listBatches(Math.min(Number(req.query.limit) || 100, 1000)) });
  });

  // ---- telemetry reconciliation (phase 1.1)
  const ALERT_KINDS: AlertKind[] = ["drift", "bypass", "dormant", "telemetry_gap", "violation_threshold", "review_required"];
  app.get("/v1/telemetry/alerts", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin", "auditor", "agent_owner");
    if (!user) return;
    const status = req.query.status === "open" || req.query.status === "acknowledged" ? req.query.status : undefined;
    const kind = ALERT_KINDS.includes(req.query.kind as AlertKind) ? (req.query.kind as AlertKind) : undefined;
    const agentId = typeof req.query.agent === "string" ? req.query.agent : undefined;
    const all = hasRole(user, "security_reviewer", "admin", "auditor");
    const alerts = cp.telemetry.listAlerts({ status, kind, agentId, limit: Number(req.query.limit) || 200 }).filter((a) => all || (a.agentId && canSeeAgent(user, a.agentId)));
    res.json({ alerts });
  });

  app.post("/v1/telemetry/alerts/:id/ack", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin");
    if (!user) return;
    const reason = typeof req.body?.reason === "string" ? req.body.reason.trim() : "";
    const alert = cp.telemetry.getAlert(req.params.id);
    const violations: string[] = [];
    if (!alert) violations.push(`unknown alert ${req.params.id}`);
    else if (alert.status !== "open") violations.push(`alert is already ${alert.status}`);
    if (!reason) violations.push("a reason is required to acknowledge an alert");
    if (violations.length) {
      cp.audit.append({ stream: "user", actorType: "user", actorId: user.email, action: "telemetry.alert.ack", targetType: "telemetry_alert", targetId: req.params.id, outcome: "denied", sourceIp: L(res).ip, requestId: L(res).requestId, details: { violations } });
      return void res.status(!alert ? 404 : 422).json({ error: "validation_failed", violations });
    }
    const updated = cp.telemetry.ackAlert(req.params.id, user.email, reason.slice(0, 1000));
    cp.audit.append({ stream: "user", actorType: "user", actorId: user.email, action: "telemetry.alert.ack", targetType: "telemetry_alert", targetId: req.params.id, outcome: "success", sourceIp: L(res).ip, requestId: L(res).requestId, details: { kind: alert!.kind, agentId: alert!.agentId, reason } });
    res.json({ alert: updated });
  });

  app.get("/v1/telemetry/dormant", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin", "auditor", "agent_owner");
    if (!user) return;
    const agents = cp.reconcile.dormantAgents().filter((d) => canSeeAgent(user, d.agent.id));
    res.json({ thresholdDays: cp.telemetryConfig.dormantDays, agents: agents.map((d) => ({ id: d.agent.id, name: d.agent.name, owner: d.agent.ownerEmail, lastSeen: d.lastSeen ?? null, idleDays: d.idleDays, expiresAt: d.agent.expiresAt })) });
  });

  app.get("/v1/telemetry/violations", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin", "auditor");
    if (!user) return;
    const agentId = typeof req.query.agent === "string" ? req.query.agent : undefined;
    const days = Number(req.query.days);
    const sinceIso = Number.isFinite(days) && days > 0 ? new Date(Date.now() - days * 86_400_000).toISOString() : undefined;
    res.json({ violations: cp.telemetry.listViolations({ agentId, sinceIso, limit: Math.min(Number(req.query.limit) || 500, 5000) }) });
  });

  app.get("/v1/telemetry/violations/verify", (req, res) => {
    const user = requireUser(res, req, "auditor", "admin", "security_reviewer");
    if (!user) return;
    const broken = cp.telemetry.verifyViolationChain();
    res.json({ intact: broken === -1, firstBrokenSeq: broken === -1 ? null : broken });
  });

  app.post("/v1/telemetry/reconcile", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin");
    if (!user) return;
    cp.audit.append({ stream: "user", actorType: "user", actorId: user.email, action: "telemetry.reconcile_requested", outcome: "success", sourceIp: L(res).ip, requestId: L(res).requestId });
    res.json({ summary: cp.reconcile.run() });
  });

  app.get("/v1/agents/:id/activity", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    if (!canSeeAgent(p.user, req.params.id)) return void res.status(404).json({ error: "not_found" });
    const days = Math.min(Math.max(Number(req.query.days) || 90, 1), 365);
    const summary = cp.reconcile.activitySummary(req.params.id, days);
    if (!summary) return void res.status(404).json({ error: "not_found" });
    cp.audit.append({ stream: "user", actorType: "user", actorId: p.email, action: "agent.activity.view", targetType: "agent", targetId: req.params.id, outcome: "success", sourceIp: L(res).ip, requestId: L(res).requestId, details: { days } });
    res.json({ activity: summary });
  });

  // ---- agent route: governed tool call
  app.post("/v1/call", async (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "agent") return void res.status(403).json({ error: "forbidden" });
    const { agentId: claimed, toolName, parameters, principal } = req.body ?? {};
    if (claimed !== undefined && claimed !== p.agentId) {
      cp.audit.append({
        stream: "audit", actorType: "agent", actorId: p.agentId, action: "identity.mismatch", outcome: "denied",
        sourceIp: L(res).ip, requestId: L(res).requestId, details: { claimedAgentId: claimed },
      });
      return void res.status(403).json({ error: "forbidden" });
    }
    if (typeof toolName !== "string" || typeof principal !== "string" || (parameters !== undefined && (typeof parameters !== "object" || parameters === null))) {
      return void res.status(400).json({ error: "bad_request", detail: "toolName (string), principal (string) and parameters (object) are required" });
    }
    const result = await cp.gateway.call({ agentId: p.agentId, principal, toolName, parameters: parameters ?? {} });
    const decision = result.event.decision;
    if (decision !== "allow") {
      const cfg = cp.telemetryConfig;
      const params = redactPayload(parameters ?? {}, { piiKinds: cfg.piiKinds, maxChars: 512 });
      cp.telemetry.appendViolation({
        agentId: p.agentId, observedAgentKey: `agent:${p.agentId}`, policyId: result.event.policyId, policyVersion: result.event.policyVersion,
        rule: result.event.ruleTriggered, decision, source: "gateway",
        blockedAction: `tool_call ${toolName}${params ? `: ${params.text}` : ""}`,
        details: { runId: result.event.runId, ledgerEventId: result.event.id },
      });
    }
    cp.audit.append({
      stream: "audit", actorType: "agent", actorId: p.agentId, action: "gateway.call", targetType: "tool", targetId: toolName,
      outcome: decision === "deny" ? "denied" : "success", sourceIp: L(res).ip, requestId: L(res).requestId,
      details: { decision, ledgerEventId: result.event.id, policyId: result.event.policyId, policyVersion: result.event.policyVersion, rule: result.event.ruleTriggered },
    });
    res.json({ decision, allowed: result.allowed, eventId: result.event.id, approvalId: result.pendingApproval?.id });
  });

  // ---- human routes: registration lifecycle
  app.post("/v1/agents", (req, res) => {
    const user = requireUser(res, req, "agent_owner", "admin");
    if (!user) return;
    if (req.body?.draft === true) {
      const { draft: _d, ...rest } = req.body;
      const d = cp.registration.createDraft({ ...rest, ownerEmail: String(rest.ownerEmail ?? user.email) }, user.email, ctxOf(res));
      if (!d.ok) return void res.status(statusFor(d.violations)).json({ error: "validation_failed", violations: d.violations });
      return void res.status(201).json({ agentId: d.agent.id, lifecycleState: d.agent.lifecycleState, riskTier: d.agent.riskTier, expiresAt: d.agent.expiresAt });
    }
    const out = cp.registration.submit(req.body as RegistrationRequest, user.email, ctxOf(res));
    if (!out.ok) return void res.status(422).json({ error: "validation_failed", violations: out.violations });
    res.status(201).json({
      expiresAt: out.agent.expiresAt,
      agentId: out.agent.id, lifecycleState: out.agent.lifecycleState, riskTier: out.agent.riskTier, needsReview: out.needsReview,
      credential: out.credential ? { token: out.credential.token, expiresAt: out.credential.expiresAt, note: "shown once - store it now" } : undefined,
    });
  });

  app.get("/v1/agents", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    const all = hasRole(p.user, "admin", "auditor", "security_reviewer");
    if (!all && !hasRole(p.user, "agent_owner")) return void requireUser(res, req, "admin");
    const mine = (e?: string) => e?.toLowerCase() === p.email;
    const agents = cp.registry.list().filter((a) => all || mine(a.ownerEmail) || mine(a.subOwnerEmail));
    res.json({ agents: agents.map((a) => ({ id: a.id, name: a.name, owner: a.ownerEmail, subOwner: a.subOwnerEmail, lifecycleState: a.lifecycleState, riskTier: a.riskTier, computedRiskTier: a.computedRiskTier ?? a.riskTier, accessProfileId: a.accessProfileId, expiresAt: a.expiresAt, manifestId: a.manifestId })) });
  });

  // ---- registration as code: idempotent apply of an agent.yaml manifest
  app.post("/v1/agents/apply", (req, res) => {
    const user = requireUser(res, req, "agent_owner", "admin", "ci_registrar");
    if (!user) return;
    const body = req.body;
    const out = typeof body === "string" ? cp.manifests.applyText(body, user.email, ctxOf(res))
      : typeof body?.manifest === "string" ? cp.manifests.applyText(body.manifest, user.email, ctxOf(res))
      : cp.manifests.applyObject(body, user.email, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations)).json({ error: "validation_failed", violations: out.violations });
    res.status(out.action === "created" || out.action === "drafted" ? 201 : 200).json({
      action: out.action, agentId: out.agent.id, lifecycleState: out.agent.lifecycleState, riskTier: out.agent.riskTier,
      expiresAt: out.agent.expiresAt, widened: out.widened, reReview: out.reReview, missing: out.missing,
      note: out.agent.lifecycleState === "active" && out.action === "created" ? "no credential is issued by apply; the owner rotates one via POST /v1/agents/:id/credentials/rotate" : undefined,
    });
  });

  app.get("/v1/agents/expiring", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    const all = hasRole(p.user, "admin", "auditor", "security_reviewer");
    if (!all && !hasRole(p.user, "agent_owner")) return void requireUser(res, req, "admin");
    const days = Math.min(Math.max(Number(req.query.days) || 14, 1), 365);
    const mine = (e?: string) => e?.toLowerCase() === p.email;
    const agents = cp.registration.expiringWithin(days).filter((a) => all || mine(a.ownerEmail) || mine(a.subOwnerEmail));
    res.json({ days, agents: agents.map((a) => ({ id: a.id, name: a.name, owner: a.ownerEmail, subOwner: a.subOwnerEmail, expiresAt: a.expiresAt, riskTier: a.riskTier })) });
  });

  app.get("/v1/agents/:id", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    const a = cp.registry.get(req.params.id);
    const mine = (e?: string) => e?.toLowerCase() === p.email;
    if (!a || !(hasRole(p.user, "admin", "auditor", "security_reviewer") || mine(a.ownerEmail) || mine(a.subOwnerEmail))) {
      return void res.status(404).json({ error: "not_found" });
    }
    res.json({ agent: a, tools: cp.registry.grantsFor(a.id).map(({ agentId: _x, ...t }) => t), telemetry: cp.reconcile.agentTelemetry(a.id) });
  });

  app.patch("/v1/agents/:id", (req, res) => {
    const user = requireUser(res, req, "agent_owner", "admin");
    if (!user) return;
    const out = cp.registration.updateRegistration(req.params.id, (req.body ?? {}) as Partial<RegistrationRequest>, user.email, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations)).json({ error: "validation_failed", violations: out.violations });
    res.json({ agentId: out.agent.id, lifecycleState: out.agent.lifecycleState, riskTier: out.agent.riskTier, widened: out.widened, reReview: out.reReview });
  });

  app.post("/v1/agents/:id/submit", (req, res) => {
    const user = requireUser(res, req, "agent_owner", "admin");
    if (!user) return;
    const out = cp.registration.submitDraft(req.params.id, user.email, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations)).json({ error: "validation_failed", violations: out.violations });
    res.json({
      agentId: out.agent.id, lifecycleState: out.agent.lifecycleState, riskTier: out.agent.riskTier, needsReview: out.needsReview, expiresAt: out.agent.expiresAt,
      credential: out.credential ? { token: out.credential.token, expiresAt: out.credential.expiresAt, note: "shown once - store it now" } : undefined,
    });
  });

  app.post("/v1/agents/:id/transition", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    const to = String(req.body?.to ?? "") as LifecycleState;
    if (!["draft", "pending_approval", "active", "suspended", "rejected", "retired"].includes(to)) {
      return void res.status(400).json({ error: "bad_request", detail: "to must be a lifecycle state" });
    }
    const out = cp.registration.transition(req.params.id, to, p.email, req.body?.reason, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations)).json({ error: "validation_failed", violations: out.violations });
    res.json({
      agentId: out.agent.id, lifecycleState: out.agent.lifecycleState,
      credential: out.credential ? { token: out.credential.token, expiresAt: out.credential.expiresAt, note: "shown once - store it now" } : undefined,
    });
  });

  app.post("/v1/agents/:id/retire", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    const out = cp.registration.retire(req.params.id, p.email, String(req.body?.reason ?? "retired via API"), ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations)).json({ error: "validation_failed", violations: out.violations });
    res.json({ agentId: out.agent.id, lifecycleState: out.agent.lifecycleState });
  });

  app.post("/v1/agents/:id/risk-tier", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    const tier = String(req.body?.tier ?? "") as RiskTier;
    const out = cp.registration.setRiskTier(req.params.id, tier, p.email, req.body?.reason, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations)).json({ error: "validation_failed", violations: out.violations });
    res.json({ agentId: out.agent.id, riskTier: out.agent.riskTier, computedRiskTier: out.agent.computedRiskTier, override: out.agent.riskOverride, lifecycleState: out.agent.lifecycleState });
  });

  app.post("/v1/agents/:id/recertify", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    const out = cp.registration.recertify(req.params.id, p.email, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations)).json({ error: "validation_failed", violations: out.violations });
    res.json({
      agentId: out.agent.id, lifecycleState: out.agent.lifecycleState, expiresAt: out.agent.expiresAt,
      // What the agent actually did over the last 90 days: the owner's evidence for this recertification.
      activity: cp.reconcile.activitySummary(out.agent.id, 90),
      credential: out.credential ? { token: out.credential.token, expiresAt: out.credential.expiresAt, note: "shown once - the agent was reactivated" } : undefined,
    });
  });

  // ---- discovery: the shadow-agent triage queue
  app.get("/v1/discovery", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin", "auditor", "agent_owner");
    if (!user) return;
    const status = DISCOVERY_STATUSES.includes(req.query.status as DiscoveryStatus) ? (req.query.status as DiscoveryStatus) : undefined;
    const items = cp.discovery.list({
      status, source: typeof req.query.source === "string" ? req.query.source : undefined,
      queue: req.query.queue === "triage" ? "triage" : undefined, limit: Number(req.query.limit) || 200,
    });
    res.json({ items });
  });

  app.post("/v1/discovery/import-egress", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin");
    if (!user) return;
    const csv = typeof req.body === "string" ? req.body : typeof req.body?.csv === "string" ? req.body.csv : undefined;
    if (!csv) return void res.status(400).json({ error: "bad_request", detail: "send text/csv, or JSON {\"csv\": \"...\"}" });
    const out = cp.discovery.importEgressCsv(csv, user.email, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations)).json({ error: "validation_failed", violations: out.violations });
    const { ok: _ok, ...summary } = out;
    res.json(summary);
  });

  app.get("/v1/discovery/connectors", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin", "auditor");
    if (!user) return;
    res.json({ jobs: cp.scheduler.status() });
  });

  app.post("/v1/discovery/connectors/:id/run", async (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin");
    if (!user) return;
    const jobId = cp.scheduler.jobIds().find((j) => j === req.params.id || j === `connector:${req.params.id}`);
    if (!jobId) return void res.status(404).json({ error: "not_found" });
    cp.audit.append({ stream: "user", actorType: "user", actorId: user.email, action: "discovery.run_requested", targetType: "job", targetId: jobId, outcome: "success", sourceIp: L(res).ip, requestId: L(res).requestId });
    res.json({ run: await cp.scheduler.runOnce(jobId) });
  });

  app.post("/v1/discovery/:id/claim", (req, res) => {
    const user = requireUser(res, req, "agent_owner");
    if (!user) return;
    const out = cp.discovery.claim(req.params.id, user.email, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations, out.notFound)).json({ error: "validation_failed", violations: out.violations });
    res.status(201).json({ discovery: out.item, agentId: out.agent.id, lifecycleState: out.agent.lifecycleState, owner: out.agent.ownerEmail });
  });

  app.post("/v1/discovery/:id/assign-owner", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin");
    if (!user) return;
    const out = cp.discovery.assignOwner(req.params.id, String(req.body?.ownerEmail ?? ""), user.email, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations, out.notFound)).json({ error: "validation_failed", violations: out.violations });
    res.json({ discovery: out.item, agentId: out.agent.id, lifecycleState: out.agent.lifecycleState, owner: out.agent.ownerEmail });
  });

  app.post("/v1/discovery/:id/ignore", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin");
    if (!user) return;
    const out = cp.discovery.ignore(req.params.id, user.email, req.body?.reason, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations, out.notFound)).json({ error: "validation_failed", violations: out.violations });
    res.json({ discovery: out.item });
  });

  app.post("/v1/discovery/:id/disable", (req, res) => {
    const user = requireUser(res, req, "security_reviewer", "admin");
    if (!user) return;
    const out = cp.discovery.disable(req.params.id, user.email, req.body?.reason, ctxOf(res));
    if (!out.ok) return void res.status(statusFor(out.violations, out.notFound)).json({ error: "validation_failed", violations: out.violations });
    res.json({ discovery: out.item, agentId: out.agent?.id, agentState: out.agent?.lifecycleState, manualActionRequired: out.manualActionRequired });
  });

  app.post("/v1/agents/:id/review", (req, res) => {
    const user = requireUser(res, req, "security_reviewer");
    if (!user) return;
    const { decision, checklist, notes } = req.body ?? {};
    if (decision !== "approve" && decision !== "reject") return void res.status(400).json({ error: "bad_request", detail: "decision must be approve or reject" });
    const out = cp.registration.review(req.params.id, user.email, decision, checklist ?? {}, notes, ctxOf(res));
    if (!out.ok) return void res.status(422).json({ error: "validation_failed", violations: out.violations });
    res.json({
      agentId: out.agent.id, lifecycleState: out.agent.lifecycleState,
      credential: out.credential ? { token: out.credential.token, expiresAt: out.credential.expiresAt, note: "shown once - hand to the owner securely" } : undefined,
    });
  });

  app.post("/v1/agents/:id/suspend", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    const out = cp.registration.suspend(req.params.id, p.email, String(req.body?.reason ?? "suspended via API"), ctxOf(res));
    if (!out.ok) return void res.status(403).json({ error: "forbidden", violations: out.violations });
    res.json({ agentId: out.agent.id, lifecycleState: out.agent.lifecycleState });
  });

  app.post("/v1/agents/:id/credentials/rotate", (req, res) => {
    const p = L(res).principal;
    if (p?.kind !== "user") return void res.status(403).json({ error: "forbidden" });
    const out = cp.registration.rotateCredential(req.params.id, p.email, ctxOf(res));
    if (!out.ok) return void res.status(403).json({ error: "forbidden", violations: out.violations });
    res.json({ credential: { token: out.credential.token, expiresAt: out.credential.expiresAt, note: "shown once; the previous credential is revoked" } });
  });

  // ---- policies: admin-managed, versioned, durable, every change in the user log
  app.put("/v1/policies", (req, res) => {
    const user = requireUser(res, req, "admin");
    if (!user) return;
    const parsed = parsePolicy(req.body);
    if (!parsed.ok) return void res.status(400).json({ error: "bad_request", violations: parsed.errors });
    const saved = cp.savePolicy(parsed.policy, user.email);
    cp.audit.append({
      stream: "user", actorType: "user", actorId: user.email, action: "policy.set", targetType: "policy", targetId: parsed.policy.toolName,
      outcome: saved.ok ? "success" : "denied", sourceIp: L(res).ip, requestId: L(res).requestId,
      details: { policyId: parsed.policy.id, version: parsed.policy.version, ...(saved.ok ? {} : { currentVersion: saved.currentVersion }) },
    });
    if (!saved.ok) return void res.status(409).json({ error: "version_conflict", currentVersion: saved.currentVersion });
    res.json({ toolName: parsed.policy.toolName, version: parsed.policy.version });
  });

  app.get("/v1/policies/:toolName", (req, res) => {
    const user = requireUser(res, req, "admin", "auditor");
    if (!user) return;
    const policy = cp.policyEngine.getPolicy(req.params.toolName);
    if (!policy) return void res.status(404).json({ error: "not_found" });
    res.json({ policy });
  });

  // ---- audit and security (read access is itself logged to the user stream)
  app.get("/v1/audit", (req, res) => {
    const user = requireUser(res, req, "auditor", "admin");
    if (!user) return;
    const q = req.query;
    const filter = {
      stream: q.stream === "audit" || q.stream === "user" ? q.stream : undefined,
      actorId: typeof q.actor === "string" ? q.actor : undefined,
      action: typeof q.action === "string" ? q.action : undefined,
      targetId: typeof q.target === "string" ? q.target : undefined,
      limit: Math.min(Number(q.limit) || 200, 1000),
    } as const;
    cp.audit.append({
      stream: "user", actorType: "user", actorId: user.email, action: "audit.query", outcome: "success",
      sourceIp: L(res).ip, requestId: L(res).requestId, details: { filter },
    });
    res.json({ events: cp.audit.query(filter) });
  });

  app.get("/v1/audit/verify", (req, res) => {
    const user = requireUser(res, req, "auditor", "admin");
    if (!user) return;
    const firstBroken = cp.audit.verifyChain();
    res.json({ intact: firstBroken === -1, firstBrokenSeq: firstBroken === -1 ? null : firstBroken });
  });

  app.get("/v1/security/alerts", (req, res) => {
    const user = requireUser(res, req, "auditor", "admin", "security_reviewer");
    if (!user) return;
    res.json({ alerts: cp.monitor.listAlerts() });
  });

  app.use((_req, res) => res.status(404).json({ error: "not_found" }));
  // Last resort: never send exception text, stack or SQL to the caller.
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    const requestId = L(res).requestId;
    console.error(`[${requestId}] ${req.method} ${req.path} failed:`, err);
    try {
      cp.audit.append({ stream: "audit", actorType: "system", actorId: "gateway", action: "request.error", outcome: "failure", sourceIp: L(res).ip, requestId, details: { path: req.path, method: req.method, errorName: (err as Error)?.name ?? "Error" } });
    } catch { /* the audit write itself may be what failed */ }
    if (!res.headersSent) res.status(500).json({ error: "internal_error", requestId });
  });
  return app;
}

// ---- process entry point: configuration from the environment ------------
// ZENAI4_DB_PATH, ZENAI4_SIEM_PATH, PORT, TRUST_PROXY=1, RATE_LIMIT_PER_MIN
// ZENAI4_SCHEDULER=1 starts discovery connectors (ZENAI4_DISCOVERY_CONNECTORS)
// and the expiry sweep in this process - run it in ONE replica only.
// Users and profiles are provisioned out of band (directory sync / admin tooling).
if (import.meta.url === `file://${process.argv[1]}`) {
  const { buildControlPlane } = await import("../control/control-plane.js");
  const { connectorsFromEnv } = await import("../discovery/connectors.js");
  const cp = buildControlPlane({
    dbPath: process.env.ZENAI4_DB_PATH ?? "./zenai4.db", siemPath: process.env.ZENAI4_SIEM_PATH,
    connectors: process.env.ZENAI4_SCHEDULER === "1" ? connectorsFromEnv() : [],
  });
  if (process.env.ZENAI4_SCHEDULER === "1") cp.scheduler.start();
  const app = createSecureGateway(cp, {
    trustProxy: process.env.TRUST_PROXY === "1",
    rateLimitPerMin: process.env.RATE_LIMIT_PER_MIN ? Number(process.env.RATE_LIMIT_PER_MIN) : undefined,
  });
  const port = Number(process.env.PORT ?? 8787);
  const server = app.listen(port, () => console.error(`ZenAi4 secure gateway listening on :${port}`));
  // Graceful shutdown so an autoscaler can drain replicas without dropping in-flight calls.
  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => server.close(() => { cp.close(); process.exit(0); }));
  }
}
