// Telemetry reconciliation (phase 1.1): compares what agents were OBSERVED
// doing with what they were REGISTERED to do, and writes every finding back
// through the Phase 1 services (discovery, registration, audit) so observed
// behaviour strengthens the registry instead of living in a side table.
//
// Runs as a scheduler job ("telemetry-reconcile", hourly by default) and on
// demand. Each run processes the steps stored since the previous run (a
// cursor on the append-only steps table), then the time-based checks:
//
//   unregistered   an agent key reported by an intake source that matches no
//                  registered agent -> discovered_agents row, source
//                  "telemetry", deduplicated per (source, key); tools, models
//                  and providers seen are merged into its attributes.
//   drift          an ACTIVE agent used a tool not in its grants or a model
//                  not in permittedModels -> "drift" alert. The risk tier is
//                  recomputed from registered + observed (an unknown tool is
//                  assumed irreversible, because nothing says otherwise). If
//                  the result is high/critical, or the access profile always
//                  requires review, the agent needs re-review:
//                    alert_only (default)  alert says so; registry unchanged
//                    enforce_review        system-recorded tier raise (if
//                                          higher), pending_approval and
//                                          credential revocation - the same
//                                          path as a widening Phase 1 update.
//   bypass         activity attributed to a suspended, retired or expired
//                  agent (state at arrival) -> high-severity "bypass" alert;
//                  draft / pending / rejected agents -> medium.
//   telemetry_gap  a session with numbered steps (steps API seq or
//                  zenai4.step.seq) has holes once it has been quiet for the
//                  grace period -> "telemetry_gap" alert listing the holes.
//   dormant        an active agent with no telemetry and no gateway call for
//                  N days (default 30) -> "dormant" alert, and the flag shows
//                  in the dormant listing and the recertification summary.
//   violations     deny decisions per agent over the window (30 days); at or
//                  above the threshold the effective tier is raised to the
//                  configured tier by a system-recorded "raise" override
//                  (owners cannot lower it; only security can, per Phase 1).
//
// Alerts are deduplicated by a key; a repeat bumps count/last_seen. Alert
// creation, the run summary, every registry change, discovery sighting and
// credential revocation is audited.

import type { AuditLog } from "../control/audit-log.js";
import type { AccessProfileStore } from "../control/access-profiles.js";
import type { RegistrationService } from "../control/registration.js";
import type { DiscoveryService } from "../discovery/discovery.js";
import type { Ledger } from "../ledger/ledger.js";
import { calculateRiskTier, effectiveRiskTier, maxTier, tierRank, type AgentRegistry } from "../registry/registry.js";
import type { Agent, RiskTier } from "../types.js";
import type { TelemetryConfig } from "./config.js";
import type { AlertKind, AlertSeverity, StepRecord, TelemetryAlert, TelemetryStore, Violation } from "./store.js";

const DAY_MS = 86_400_000;
const ACTOR = "system:telemetry-reconcile";
const CURSOR = "reconcile.cursor";
const BYPASS_HIGH = new Set(["suspended", "retired", "expired"]);
const BYPASS_MEDIUM = new Set(["draft", "pending_approval", "rejected"]);

export interface ReconcileSummary {
  stepsProcessed: number;
  discoveries: number;
  newDiscoveries: number;
  alertsRaised: number;
  alertsRepeated: number;
  reReviews: number;
  tierRaises: number;
  gapsFound: number;
  dormant: number;
}

export interface ActivitySummary {
  agentId: string;
  name: string;
  lifecycleState: string;
  windowDays: number;
  since: string;
  lastSeen?: string;
  lastTelemetryAt?: string;
  lastGatewayCallAt?: string;
  dormant: boolean;
  dormantDays: number;
  steps: number;
  sessions: number;
  errors: number;
  tokens: { input: number; output: number };
  tools: Array<{ name: string; calls: number; registered: boolean }>;
  models: Array<{ name: string; calls: number; permitted: boolean }>;
  providers: string[];
  gatewayCalls: Record<string, number>;
  violations: { total: number; denied: number; inWindow: number; recent: Array<Pick<Violation, "ts" | "policyId" | "policyVersion" | "rule" | "decision" | "source">> };
  openAlerts: Array<Pick<TelemetryAlert, "id" | "kind" | "severity" | "lastSeen" | "count">>;
  driftTools: string[];
  driftModels: string[];
}

/** A model is permitted if it is listed, or is a listed model plus a date or
 * version suffix (providers report "claude-sonnet-5-20261001" for "claude-sonnet-5"). */
export function modelPermitted(model: string, permitted: string[]): boolean {
  const m = model.toLowerCase();
  return permitted.some((p) => {
    const q = p.toLowerCase();
    return m === q || (m.startsWith(q) && /^[-@:]v?\d[\d.-]*$/.test(m.slice(q.length)));
  });
}

export class ReconcileService {
  constructor(
    private store: TelemetryStore,
    private registry: AgentRegistry,
    private registration: RegistrationService,
    private discovery: DiscoveryService,
    private profiles: AccessProfileStore,
    private ledger: Ledger,
    private audit: AuditLog,
    private cfg: TelemetryConfig,
    private now: () => Date = () => new Date(),
  ) {}

  private alert(kind: AlertKind, severity: AlertSeverity, dedupeKey: string, details: Record<string, unknown>, agentId: string | undefined, sum: ReconcileSummary, sessionId?: string) {
    const { alert, created } = this.store.raiseAlert({ kind, severity, agentId, sessionId, dedupeKey, details });
    if (created) {
      sum.alertsRaised++;
      this.audit.append({
        stream: "audit", actorType: "system", actorId: ACTOR, action: "telemetry.alert", targetType: agentId ? "agent" : "session",
        targetId: agentId ?? sessionId, outcome: "success", details: { alertId: alert.id, kind, severity, ...details },
      });
    } else sum.alertsRepeated++;
    return alert;
  }

  /** One full reconciliation pass. Never throws for a single bad agent. */
  run(): ReconcileSummary {
    const sum: ReconcileSummary = { stepsProcessed: 0, discoveries: 0, newDiscoveries: 0, alertsRaised: 0, alertsRepeated: 0, reReviews: 0, tierRaises: 0, gapsFound: 0, dormant: 0 };
    this.processNewSteps(sum);
    this.checkGaps(sum);
    this.checkDormant(sum);
    this.checkViolations(sum);
    this.audit.append({ stream: "audit", actorType: "system", actorId: ACTOR, action: "telemetry.reconcile", outcome: "success", details: { ...sum, driftMode: this.cfg.driftMode } });
    return sum;
  }

  // ------------------------------------------------------------------ step-driven checks

  private processNewSteps(sum: ReconcileSummary) {
    type Unreg = { sourceId: string; key: string; count: number; first: string; last: string; tools: Set<string>; models: Set<string>; providers: Set<string> };
    type Drift = { tools: Map<string, number>; models: Map<string, number>; last: string; sessions: Set<string> };
    type Bypass = { agentId: string; state: string; count: number; first: string; last: string; sessions: Set<string>; sources: Set<string> };
    const unreg = new Map<string, Unreg>();
    const drift = new Map<string, Drift>();
    const bypass = new Map<string, Bypass>();
    const grantCache = new Map<string, { agent?: Agent; tools: Set<string> }>();
    const agentInfo = (id: string) => {
      let g = grantCache.get(id);
      if (!g) {
        g = { agent: this.registry.get(id), tools: new Set(this.registry.grantsFor(id).map((t) => t.toolName.toLowerCase())) };
        grantCache.set(id, g);
      }
      return g;
    };

    let cursor = Number(this.store.getState(CURSOR) ?? 0);
    for (let page = 0; page < 100; page++) {
      const steps = this.store.stepsAfter(cursor, 5000);
      if (!steps.length) break;
      for (const s of steps) {
        cursor = s.rowid;
        sum.stepsProcessed++;
        if (!s.agentId) {
          if (!s.sourceId) continue;
          const k = `${s.sourceId}\u0000${s.observedAgentKey}`;
          const u = unreg.get(k) ?? { sourceId: s.sourceId, key: s.observedAgentKey, count: 0, first: s.ts, last: s.ts, tools: new Set(), models: new Set(), providers: new Set() };
          u.count++;
          if (s.ts < u.first) u.first = s.ts;
          if (s.ts > u.last) u.last = s.ts;
          if (s.toolName) u.tools.add(s.toolName);
          if (s.model) u.models.add(s.model);
          if (s.provider) u.providers.add(s.provider);
          unreg.set(k, u);
          continue;
        }
        const state = s.agentState ?? "unknown";
        if (BYPASS_HIGH.has(state) || BYPASS_MEDIUM.has(state)) {
          const k = `${s.agentId}\u0000${state}`;
          const b = bypass.get(k) ?? { agentId: s.agentId, state, count: 0, first: s.ts, last: s.ts, sessions: new Set(), sources: new Set() };
          b.count++;
          if (s.ts < b.first) b.first = s.ts;
          if (s.ts > b.last) b.last = s.ts;
          b.sessions.add(s.sessionId);
          if (s.sourceId) b.sources.add(s.sourceId);
          bypass.set(k, b);
          continue;
        }
        if (state !== "active") continue;
        const info = agentInfo(s.agentId);
        if (!info.agent) continue;
        const d = drift.get(s.agentId) ?? { tools: new Map(), models: new Map(), last: s.ts, sessions: new Set() };
        let drifted = false;
        if (s.toolName && !info.tools.has(s.toolName.toLowerCase())) { d.tools.set(s.toolName, (d.tools.get(s.toolName) ?? 0) + 1); drifted = true; }
        if (s.model && !modelPermitted(s.model, info.agent.permittedModels)) { d.models.set(s.model, (d.models.get(s.model) ?? 0) + 1); drifted = true; }
        if (drifted) {
          if (s.ts > d.last) d.last = s.ts;
          d.sessions.add(s.sessionId);
          drift.set(s.agentId, d);
        }
      }
    }
    this.store.setState(CURSOR, String(cursor));

    for (const u of unreg.values()) this.recordUnregistered(u, sum);
    for (const b of bypass.values()) {
      const agent = this.registry.get(b.agentId);
      this.alert("bypass", BYPASS_HIGH.has(b.state) ? "high" : "medium", `bypass:${b.agentId}:${b.state}`, {
        state: b.state, steps: b.count, firstSeen: b.first, lastSeen: b.last, sessions: [...b.sessions].slice(0, 20), sources: [...b.sources],
        agentName: agent?.name, owner: agent?.ownerEmail,
        note: `activity reported for an agent that is ${b.state}; it should not be acting`,
      }, b.agentId, sum);
    }
    for (const [agentId, d] of drift) this.handleDrift(agentId, d, sum);
  }

  private recordUnregistered(u: { sourceId: string; key: string; count: number; first: string; last: string; tools: Set<string>; models: Set<string>; providers: Set<string> }, sum: ReconcileSummary) {
    const identity = [u.sourceId, u.key];
    const prev = this.discovery.findByIdentity("telemetry", identity)?.attributes as Record<string, unknown> | undefined;
    const merge = (k: string, add: Set<string>) => [...new Set([...(Array.isArray(prev?.[k]) ? (prev![k] as string[]) : []), ...add])].slice(0, 50);
    const source = this.store.getSource(u.sourceId);
    const { created } = this.discovery.record({
      source: "telemetry", kind: "observed_agent", identity,
      displayName: u.key.startsWith("source:") ? `unidentified agent via ${source?.name ?? u.sourceId}` : `${u.key} (via ${source?.name ?? u.sourceId})`,
      count: u.count, firstSeen: u.first, lastSeen: u.last,
      attributes: {
        sourceId: u.sourceId, sourceName: source?.name, observedAgentKey: u.key,
        tools: merge("tools", u.tools), models: merge("models", u.models), providers: merge("providers", u.providers),
      },
    });
    sum.discoveries++;
    if (created) sum.newDiscoveries++;
  }

  /** Observed effective tier: grants plus observed unknown tools (assumed
   * irreversible), with the agent's override applied, never below current. */
  observedTier(agent: Agent, extraTools: string[]): RiskTier {
    const grants = this.registry.grantsFor(agent.id).map(({ agentId: _a, ...t }) => t);
    const observed = extraTools.map((toolName) => ({ toolName, reversible: false, dataClasses: [] as string[] }));
    const computed = calculateRiskTier([...grants, ...observed], agent.autonomyDefault);
    return maxTier(effectiveRiskTier(computed, agent.riskOverride), agent.riskTier);
  }

  private handleDrift(agentId: string, d: { tools: Map<string, number>; models: Map<string, number>; last: string; sessions: Set<string> }, sum: ReconcileSummary) {
    const agent = this.registry.get(agentId);
    if (!agent) return;
    const tools = [...d.tools.keys()].sort();
    const models = [...d.models.keys()].sort();
    const observedTier = this.observedTier(agent, tools);
    const profile = agent.accessProfileId ? this.profiles.get(agent.accessProfileId) : undefined;
    const needsReview = tierRank(observedTier) >= tierRank("high") || profile?.requiresSecurityReview === true;
    const widened = [...tools.map((t) => `observed tool "${t}" not in grants`), ...models.map((m) => `observed model "${m}" not permitted`)];
    let action = needsReview ? "re-review required (alert_only: registry unchanged)" : "alert only";

    if (needsReview && this.cfg.driftMode === "enforce_review" && (agent.lifecycleState === "active" || agent.lifecycleState === "suspended")) {
      if (tierRank(observedTier) > tierRank(agent.riskTier)) {
        if (this.registration.systemRaiseRiskTier(agentId, observedTier, ACTOR, `observed drift: ${widened.join("; ")}`)) sum.tierRaises++;
      }
      const moved = this.registration.sendToReReview(agentId, ACTOR, "observed tools/models outside the registration; security re-review required", widened, "observed_drift_pending_review");
      if (moved) { sum.reReviews++; action = "sent to pending_approval; credentials revoked"; }
    }
    // One alert per agent and drifted item set, so a new tool raises a new alert.
    this.alert("drift", needsReview ? "high" : "medium", `drift:${agentId}:${[...tools.map((t) => `t=${t}`), ...models.map((m) => `m=${m}`)].join(",")}`, {
      tools: Object.fromEntries(d.tools), models: Object.fromEntries(d.models), registeredTier: agent.riskTier, observedTier,
      profileRequiresReview: profile?.requiresSecurityReview === true, needsReview, driftMode: this.cfg.driftMode, action,
      lastSeen: d.last, sessions: [...d.sessions].slice(0, 20), agentName: agent.name, owner: agent.ownerEmail,
    }, agentId, sum);
  }

  // ------------------------------------------------------------------ time-based checks

  private checkGaps(sum: ReconcileSummary) {
    const quietBefore = new Date(this.now().getTime() - this.cfg.gapGraceMs).toISOString();
    for (const s of this.store.sessionsToGapCheck(quietBefore)) {
      const seqs = this.store.seqsForSession(s.id);
      const missing: number[] = [];
      let missingCount = 0;
      for (let i = 1; i < seqs.length; i++) {
        for (let m = seqs[i - 1] + 1; m < seqs[i]; m++) {
          missingCount++;
          if (missing.length < 50) missing.push(m);
        }
      }
      if (missingCount > 0) {
        sum.gapsFound++;
        this.alert("telemetry_gap", "medium", `gap:${s.id}`, {
          sessionKey: s.sessionKey, scope: s.scope, observedAgentKey: s.observedAgentKey, minSeq: seqs[0], maxSeq: seqs[seqs.length - 1],
          received: seqs.length, missingCount, missing, note: "steps are missing from this session: lost in transit, dropped by the sender, or suppressed",
        }, s.agentId, sum, s.id);
      }
      this.store.markGapChecked(s.id, s.maxSeq!);
    }
  }

  /** Last activity per agent: telemetry or a governed gateway call. */
  private lastActivity(): Map<string, { telemetry?: string; gateway?: string; last?: string }> {
    const out = new Map<string, { telemetry?: string; gateway?: string; last?: string }>();
    for (const [id, t] of this.store.lastSeenByAgent()) out.set(id, { telemetry: t, last: t });
    for (const [id, g] of this.ledger.lastActivityByAgent()) {
      const e = out.get(id) ?? {};
      e.gateway = g;
      if (!e.last || g > e.last) e.last = g;
      out.set(id, e);
    }
    return out;
  }

  /** Active, unexpired agents with no activity for dormantDays (since creation if never seen). */
  dormantAgents(): Array<{ agent: Agent; lastSeen?: string; idleDays: number }> {
    const now = this.now().getTime();
    const activity = this.lastActivity();
    const out: Array<{ agent: Agent; lastSeen?: string; idleDays: number }> = [];
    for (const a of this.registry.list()) {
      if (a.lifecycleState !== "active" || this.registry.isExpired(a)) continue;
      const last = activity.get(a.id)?.last;
      const since = Date.parse(last ?? a.createdAt);
      const idleDays = Math.floor((now - since) / DAY_MS);
      if (idleDays >= this.cfg.dormantDays) out.push({ agent: a, lastSeen: last, idleDays });
    }
    return out.sort((x, y) => y.idleDays - x.idleDays);
  }

  private checkDormant(sum: ReconcileSummary) {
    for (const d of this.dormantAgents()) {
      sum.dormant++;
      this.alert("dormant", "low", `dormant:${d.agent.id}:${d.lastSeen ?? "never"}`, {
        lastSeen: d.lastSeen ?? null, idleDays: d.idleDays, thresholdDays: this.cfg.dormantDays, agentName: d.agent.name, owner: d.agent.ownerEmail,
        expiresAt: d.agent.expiresAt, note: "no telemetry or gateway activity; confirm the agent is still needed before recertifying, or retire it",
      }, d.agent.id, sum);
    }
  }

  private checkViolations(sum: ReconcileSummary) {
    if (this.cfg.violationThreshold <= 0) return;
    const since = new Date(this.now().getTime() - this.cfg.violationWindowDays * DAY_MS).toISOString();
    const target = this.cfg.violationRaiseTier;
    for (const [agentId, n] of this.store.violationCountsSince(since)) {
      if (n < this.cfg.violationThreshold) continue;
      const agent = this.registry.get(agentId);
      if (!agent || agent.lifecycleState === "retired") continue;
      let action = "none (tier already at or above target)";
      if (tierRank(agent.riskTier) < tierRank(target)) {
        const raised = this.registration.systemRaiseRiskTier(agentId, target, ACTOR, `${n} policy violations in ${this.cfg.violationWindowDays} days (threshold ${this.cfg.violationThreshold})`);
        if (raised) {
          sum.tierRaises++;
          action = `effective tier raised ${agent.riskTier} -> ${raised.riskTier}`;
          // Phase 1 rule: raising a never-reviewed active agent into high/critical needs security approval.
          if (this.cfg.driftMode === "enforce_review" && tierRank(raised.riskTier) >= tierRank("high") && raised.lifecycleState === "active" && raised.securityReview?.status !== "approved") {
            if (this.registration.sendToReReview(agentId, ACTOR, `risk tier raised to ${raised.riskTier} by violations; security approval required`, [`${n} policy violations`], "risk_raised_pending_review")) {
              sum.reReviews++;
              action += "; sent to pending_approval, credentials revoked";
            }
          }
        }
      }
      this.alert("violation_threshold", "medium", `violations:${agentId}:${target}`, {
        violations: n, windowDays: this.cfg.violationWindowDays, threshold: this.cfg.violationThreshold, targetTier: target, action,
        agentName: agent.name, owner: agent.ownerEmail,
      }, agentId, sum);
    }
  }

  // ------------------------------------------------------------------ retention

  /** Nulls redacted payloads older than the retention period. Metadata rows,
   * violations, alerts and the audit log are never touched. */
  retentionSweep(): { purged: number; cutoff: string } {
    const cutoff = new Date(this.now().getTime() - this.cfg.payloadRetentionDays * DAY_MS).toISOString();
    const purged = this.store.purgePayloadsBefore(cutoff);
    this.audit.append({
      stream: "audit", actorType: "system", actorId: "system:telemetry-retention", action: "telemetry.retention", outcome: "success",
      details: { purged, cutoff, retentionDays: this.cfg.payloadRetentionDays },
    });
    return { purged, cutoff };
  }

  // ------------------------------------------------------------------ read side

  /** What the agent actually did: for owners before recertifying. */
  activitySummary(agentId: string, days = 90): ActivitySummary | undefined {
    const agent = this.registry.get(agentId);
    if (!agent) return undefined;
    const now = this.now().getTime();
    const since = new Date(now - days * DAY_MS).toISOString();
    const steps: StepRecord[] = this.store.stepsForAgentSince(agentId, since);
    const grants = new Set(this.registry.grantsFor(agentId).map((t) => t.toolName.toLowerCase()));
    const tools = new Map<string, number>();
    const models = new Map<string, number>();
    const providers = new Set<string>();
    const sessions = new Set<string>();
    let errors = 0, inTok = 0, outTok = 0;
    for (const s of steps) {
      sessions.add(s.sessionId);
      if (s.status === "error") errors++;
      if (s.toolName) tools.set(s.toolName, (tools.get(s.toolName) ?? 0) + 1);
      if (s.model) models.set(s.model, (models.get(s.model) ?? 0) + 1);
      if (s.provider) providers.add(s.provider);
      inTok += s.inputTokens ?? 0;
      outTok += s.outputTokens ?? 0;
    }
    const activity = this.lastActivity().get(agentId);
    const lastSeen = activity?.last;
    const idleDays = Math.floor((now - Date.parse(lastSeen ?? agent.createdAt)) / DAY_MS);
    const allViolations = this.store.listViolations({ agentId });
    const windowViolations = allViolations.filter((v) => v.ts >= since);
    const toolList = [...tools].map(([name, calls]) => ({ name, calls, registered: grants.has(name.toLowerCase()) })).sort((a, b) => b.calls - a.calls);
    const modelList = [...models].map(([name, calls]) => ({ name, calls, permitted: modelPermitted(name, agent.permittedModels) })).sort((a, b) => b.calls - a.calls);
    return {
      agentId, name: agent.name, lifecycleState: agent.lifecycleState, windowDays: days, since,
      lastSeen, lastTelemetryAt: activity?.telemetry, lastGatewayCallAt: activity?.gateway,
      dormant: agent.lifecycleState === "active" && idleDays >= this.cfg.dormantDays, dormantDays: this.cfg.dormantDays,
      steps: steps.length, sessions: sessions.size, errors, tokens: { input: inTok, output: outTok },
      tools: toolList, models: modelList, providers: [...providers].sort(),
      gatewayCalls: this.ledger.decisionCountsSince(agentId, since),
      violations: {
        total: allViolations.length, denied: allViolations.filter((v) => v.decision === "deny").length, inWindow: windowViolations.length,
        recent: windowViolations.slice(-10).reverse().map((v) => ({ ts: v.ts, policyId: v.policyId, policyVersion: v.policyVersion, rule: v.rule, decision: v.decision, source: v.source })),
      },
      openAlerts: this.store.listAlerts({ agentId, status: "open", limit: 50 }).map((a) => ({ id: a.id, kind: a.kind, severity: a.severity, lastSeen: a.lastSeen, count: a.count })),
      driftTools: toolList.filter((t) => !t.registered).map((t) => t.name),
      driftModels: modelList.filter((m) => !m.permitted).map((m) => m.name),
    };
  }

  /** Compact telemetry facts for the agent record. */
  agentTelemetry(agentId: string) {
    const since = new Date(this.now().getTime() - this.cfg.violationWindowDays * DAY_MS).toISOString();
    const violations = this.store.listViolations({ agentId, sinceIso: since });
    const s = this.activitySummary(agentId, this.cfg.violationWindowDays);
    return {
      violationsLast30d: violations.length, violationWindowDays: this.cfg.violationWindowDays, violationThreshold: this.cfg.violationThreshold,
      lastSeen: s?.lastSeen, dormant: s?.dormant ?? false, openAlerts: s?.openAlerts.length ?? 0,
    };
  }
}
