/**
 * @module modules
 * @description L3RS-1 core protocol modules — state machine, compliance,
 * identity, governance, fees, cross-chain, settlement, and transfer.
 */
import { constructTxId } from "../crypto/index.js";
import {
  AssetState, ComplianceDecision, ComplianceModule, ComplianceRule, EnforcementAction,
  FeeModule, IdentityLevel, IdentityRecord, IdentityStatus, RuleType, TransferEvent,
} from "../types/index.js";

// ── §2.5 State Transitions ────────────────────────────────────────────────────

/** All valid state transitions per §2.5 transition matrix. */
const TRANSITIONS: [AssetState, string, AssetState][] = [
  [AssetState.ISSUED,     "ACTIVATION",    AssetState.ACTIVE],
  [AssetState.ACTIVE,     "BREACH",        AssetState.RESTRICTED],
  [AssetState.ACTIVE,     "FREEZE",        AssetState.FROZEN],
  [AssetState.RESTRICTED, "CLEARED",       AssetState.ACTIVE],
  [AssetState.FROZEN,     "RELEASE",       AssetState.ACTIVE],
  [AssetState.ACTIVE,     "REDEMPTION",    AssetState.REDEEMED],
  [AssetState.REDEEMED,   "FINALIZATION",  AssetState.BURNED],
  [AssetState.ACTIVE,     "SUSPENSION",    AssetState.SUSPENDED],
  [AssetState.SUSPENDED,  "REINSTATEMENT", AssetState.ACTIVE],
];

/**
 * §2.5 — Apply a state transition. Enforces Invariant I₁.
 * @param current - Current asset state
 * @param trigger - Transition trigger string
 * @returns `{ success: true, newState }` or `{ success: false, error }`
 * @example
 * applyStateTransition(AssetState.ISSUED, "ACTIVATION")
 * // → { success: true, newState: AssetState.ACTIVE }
 */
export function applyStateTransition(
  current: AssetState,
  trigger: string,
): { success: boolean; newState?: AssetState; error?: string } {
  if (current === AssetState.BURNED) {
    return { success: false, error: "BURNED is a terminal state" };
  }
  const match = TRANSITIONS.find(([f, t]) => f === current && t === trigger);
  if (match) return { success: true, newState: match[2] };
  return { success: false, error: `No transition from ${current} via ${trigger}` };
}

// ── §4 Compliance ─────────────────────────────────────────────────────────────

const BLOCKING = new Set([EnforcementAction.REJECT, EnforcementAction.FREEZE, EnforcementAction.RESTRICT]);

/** Resolved, attested attributes of a transfer party (§3.6, §4.6 inputs). */
export interface PartyAttributes {
  identityStatus:  IdentityStatus;
  jurisdiction:    string;
  investorClass:   string;
  /** Unix seconds; basis for holding period. */
  acquisitionTime: number;
}

/**
 * §10.15 contract for external data sources (sanctions/AML/reserve). MUST be
 * hash-anchored, versioned and time-bounded. Unknown, stale, or mismatched
 * attestations evaluate as BLOCKING.
 */
export interface OracleAttestation {
  cleared:    boolean;
  version:    number;
  sourceHash: string;
  /** Unix seconds; stale at/after this time. */
  validUntil: number;
}

/** Everything the engine needs to evaluate every §4.4 category deterministically. */
export interface EvalContext {
  amount:       bigint;
  timestamp:    number;
  jurisdiction: string;
  sender:       PartyAttributes;
  receiver:     PartyAttributes;
  attestations: Partial<Record<RuleType, OracleAttestation>>;
}

/**
 * §4.3 — Compliance engine. `C: E → {0,1}` as the conjunction of all in-scope
 * rule predicates, evaluated in ascending priority order, first blocking rule
 * terminating (§4.5). Enforces Invariant I₂ (§10.6): any FALSE blocks.
 */
export function evaluateCompliance(
  module: ComplianceModule,
  state: AssetState,
  ctx: EvalContext,
): ComplianceDecision {
  if (state !== AssetState.ACTIVE) return { allowed: false };
  const sorted = [...module.rules].sort((a, b) => a.priority - b.priority);
  for (const rule of sorted) {
    if (rule.scope !== "*" && rule.scope !== ctx.jurisdiction) continue;
    if (!evalRule(rule, ctx) && BLOCKING.has(rule.action)) {
      return { allowed: false, blockedBy: rule, action: rule.action };
    }
  }
  return { allowed: true };
}

/**
 * Rule predicate rᵢ: E → {TRUE, FALSE} (§4.6). Every branch fails closed:
 * missing inputs, unknown rule types, and unverifiable oracle state all → FALSE.
 */
function evalRule(rule: ComplianceRule, ctx: EvalContext): boolean {
  switch (rule.ruleType) {
    case RuleType.TRANSFER_ELIGIBILITY:
      return ctx.sender.identityStatus === IdentityStatus.VALID
          && ctx.receiver.identityStatus === IdentityStatus.VALID;

    case RuleType.INVESTOR_CLASSIFICATION: {
      const allowed = listParam(rule.params, "allowedClasses");
      if (allowed.length === 0 || ctx.receiver.investorClass === "") return false;
      return allowed.includes(ctx.receiver.investorClass);
    }

    case RuleType.HOLDING_PERIOD: {
      const period = numParam(rule.params, "holdingPeriodSec");
      if (period === null || ctx.sender.acquisitionTime === 0) return false;
      return (ctx.timestamp - ctx.sender.acquisitionTime) >= period;
    }

    case RuleType.GEOGRAPHIC_RESTRICTION: {
      if (ctx.sender.jurisdiction === "" || ctx.receiver.jurisdiction === "") return false;
      const blocked = listParam(rule.params, "blockedJurisdictions");
      return !blocked.includes(ctx.sender.jurisdiction)
          && !blocked.includes(ctx.receiver.jurisdiction);
    }

    case RuleType.TRANSACTION_THRESHOLD: {
      const raw = rule.params["thresholdAmount"];
      if (typeof raw !== "number" && typeof raw !== "bigint" && typeof raw !== "string") return false;
      let t: bigint;
      try { t = BigInt(raw); } catch { return false; }
      return ctx.amount <= t;
    }

    case RuleType.MARKET_RESTRICTION: {
      const open = numParam(rule.params, "windowOpen");
      const close = numParam(rule.params, "windowClose");
      if (open !== null && close !== null) return ctx.timestamp >= open && ctx.timestamp < close;
      return attestationClears(rule, ctx);
    }

    case RuleType.SANCTIONS_SCREENING:
    case RuleType.AML_TRIGGER:
    case RuleType.REDEMPTION_ELIGIBILITY:
      return attestationClears(rule, ctx);

    default:
      // Unknown / future rule type cannot be evaluated deterministically → block.
      return false;
  }
}

/**
 * §10.15 oracle contract: the attestation must be present, anchored to the
 * operator-pinned source hash, at/above the pinned minimum version, and within
 * its freshness window. Anything else blocks.
 */
function attestationClears(rule: ComplianceRule, ctx: EvalContext): boolean {
  const att = ctx.attestations[rule.ruleType];
  if (!att) return false;                                   // unknown oracle state → block
  const pinned = strParam(rule.params, "sourceHash");
  if (pinned === "" || att.sourceHash !== pinned) return false;
  const minV = numParam(rule.params, "minVersion");
  if (minV !== null && att.version < minV) return false;    // stale version → block
  if (ctx.timestamp >= att.validUntil) return false;        // stale attestation → block
  return att.cleared;
}

function numParam(p: Record<string, unknown>, k: string): number | null {
  const v = p[k];
  if (typeof v === "number") return v;
  if (typeof v === "bigint") return Number(v);
  return null;
}

function strParam(p: Record<string, unknown>, k: string): string {
  const v = p[k];
  return typeof v === "string" ? v : "";
}

function listParam(p: Record<string, unknown>, k: string): string[] {
  const v = p[k];
  return Array.isArray(v) ? v.filter((e): e is string => typeof e === "string") : [];
}

// ── §6.12 Fee Validation ──────────────────────────────────────────────────────

/**
 * §6.12 — Validate fee module. Allocations must sum to exactly 10000 basis points.
 * @throws Error if constraint violated
 */
export function validateFeeModule(fee: FeeModule): void {
  const total = fee.allocations.reduce((s, a) => s + a.basisPoints, 0);
  if (total !== 10_000) throw new Error(`Fee allocations must sum to 10000; got ${total}`);
  if (fee.allocations.some(a => a.basisPoints < 0)) throw new Error("Negative allocation");
}

// ── §3.6 Identity Status ──────────────────────────────────────────────────────

/**
 * §3.6 — Compute identity record status.
 * `Status(IR) ∈ {VALID, EXPIRED, REVOKED, UNKNOWN}`
 */
export function identityStatus(record: IdentityRecord, nowUnix: number): IdentityStatus {
  if (record.revoked) return IdentityStatus.REVOKED;
  if (nowUnix >= record.expiry) return IdentityStatus.EXPIRED;
  return IdentityStatus.VALID;
}

// ── §9.6 Replay Protection ────────────────────────────────────────────────────

/**
 * §9.6 — Replay protection check.
 * Returns `true` if the event's TxID is already in ledger history.
 */
export function isReplay(event: TransferEvent, ledgerHistory: Set<string>): boolean {
  const txId = constructTxId(
    event.sender, event.receiver, event.amount, event.nonce, event.timestamp,
  );
  return ledgerHistory.has(txId);
}
