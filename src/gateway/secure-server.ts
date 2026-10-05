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

import express, { type NextFunction, type Request, type Response } from "express";
import { nanoid } from "nanoid";
import { hasRole, type DirectoryUser, type Role } from "../control/identity.js";
import type { ControlPlane } from "../control/control-plane.js";
import type { RegistrationRequest } from "../control/registration.js";

export interface SecureGatewayOptions {
  /** Max requests per minute per authenticated subject. */
  rateLimitPerMin?: number;
  /** Max requests per minute per source address, checked before authentication. */
  ipRateLimitPerMin?: number;
  maxBodyBytes?: number;
  /** Trust X-Forwarded-For (only behind a proxy/load balancer you control). */
  trustProxy?: boolean;
}

type Principal =
  | { kind: "agent"; agentId: string }
  | { kind: "user"; email: string; user: DirectoryUser };

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
  app.use(express.json({ limit: options.maxBodyBytes ?? 64 * 1024 }));
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
      res.status(401).json({ error: "unauthorized" }); // identical for every reason
    };

    if (!token) return fail("missing_credentials");
    const v = cp.credentials.verify(token);
    if (!v.ok) return fail(v.reason, v.subject);

    if (v.kind === "agent") {
      if (!cp.registry.isActive(v.subject)) return fail("agent_not_active", v.subject);
      ctx.principal = { kind: "agent", agentId: v.subject };
    } else {
      const user = cp.directory.lookup(v.subject);
      if (!user || !user.active) return fail("user_inactive", v.subject);
      ctx.principal = { kind: "user", email: user.email, user };
    }
    const subject = ctx.principal.kind === "agent" ? ctx.principal.agentId : ctx.principal.email;
    if (!subjectLimiter.allow(`sub:${subject}`)) {
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
      stream: "audit", actorType: p?.kind ?? "anonymous", actorId: p?.kind === "user" ? p.email : p?.kind === "agent" ? p.agentId : "unknown",
      action: "access.denied", outcome: "denied", sourceIp: L(res).ip, requestId: L(res).requestId,
      details: { path: req.path, method: req.method, requiredRoles: roles },
    });
    res.status(403).json({ error: "forbidden" });
    return undefined;
  };
  const ctxOf = (res: Response) => ({ sourceIp: L(res).ip, requestId: L(res).requestId });

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
    const out = cp.registration.submit(req.body as RegistrationRequest, user.email, ctxOf(res));
    if (!out.ok) return void res.status(422).json({ error: "validation_failed", violations: out.violations });
    res.status(201).json({
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
    res.json({ agents: agents.map((a) => ({ id: a.id, name: a.name, owner: a.ownerEmail, subOwner: a.subOwnerEmail, lifecycleState: a.lifecycleState, riskTier: a.riskTier, accessProfileId: a.accessProfileId })) });
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
  return app;
}

// ---- process entry point: configuration from the environment ------------
// GOVERNAI_DB_PATH, GOVERNAI_SIEM_PATH, PORT, TRUST_PROXY=1, RATE_LIMIT_PER_MIN
// Users and profiles are provisioned out of band (directory sync / admin tooling).
if (import.meta.url === `file://${process.argv[1]}`) {
  const { buildControlPlane } = await import("../control/control-plane.js");
  const cp = buildControlPlane({ dbPath: process.env.GOVERNAI_DB_PATH ?? "./governai.db", siemPath: process.env.GOVERNAI_SIEM_PATH });
  const app = createSecureGateway(cp, {
    trustProxy: process.env.TRUST_PROXY === "1",
    rateLimitPerMin: process.env.RATE_LIMIT_PER_MIN ? Number(process.env.RATE_LIMIT_PER_MIN) : undefined,
  });
  const port = Number(process.env.PORT ?? 8787);
  const server = app.listen(port, () => console.error(`governAI secure gateway listening on :${port}`));
  // Graceful shutdown so an autoscaler can drain replicas without dropping in-flight calls.
  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => server.close(() => { cp.close(); process.exit(0); }));
  }
}
