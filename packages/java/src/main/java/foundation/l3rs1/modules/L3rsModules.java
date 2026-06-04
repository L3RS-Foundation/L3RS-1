package foundation.l3rs1.modules;

import foundation.l3rs1.crypto.L3rsCrypto;
import java.math.BigInteger;
import java.util.*;

/** L3RS-1 Core Modules — asset · compliance · identity · fees · replay */
public final class L3rsModules {
    private L3rsModules() {}

    // ── Enums ──────────────────────────────────────────────────────────────────

    public enum AssetState {
        ISSUED, ACTIVE, RESTRICTED, FROZEN, SUSPENDED, REDEEMED, BURNED;
        public boolean isTerminal() { return this == BURNED; }
    }

    public enum IdentityStatus { VALID, EXPIRED, REVOKED, UNKNOWN }
    public enum EnforcementAction {
        REJECT, FREEZE, RESTRICT, FLAG, REQUIRE_DISCLOSURE;
        public boolean isBlocking() { return this==REJECT||this==FREEZE||this==RESTRICT; }
    }
    public enum GovernanceAction {
        FREEZE_BALANCE, UNFREEZE_BALANCE, RESTRICT_TRANSFER,
        SEIZE_ASSET, FORCE_REDEMPTION, EMERGENCY_ROLLBACK
    }
    public enum RuleType {
        TRANSFER_ELIGIBILITY, INVESTOR_CLASSIFICATION, HOLDING_PERIOD,
        GEOGRAPHIC_RESTRICTION, SANCTIONS_SCREENING, TRANSACTION_THRESHOLD,
        AML_TRIGGER, MARKET_RESTRICTION, REDEMPTION_ELIGIBILITY
    }

    // ── Records ────────────────────────────────────────────────────────────────

    public record ComplianceRule(String ruleId, RuleType ruleType, String scope,
        String trigger, int priority, EnforcementAction action, Map<String,Object> params) {}
    public record ComplianceModule(List<ComplianceRule> rules) {}
    public record FeeAllocation(String recipient, int basisPoints) {}
    public record FeeModule(int baseRateBasisPoints, List<FeeAllocation> allocations) {}
    public record IdentityRecord(String identityHash, String verificationAuthority,
        String jurisdictionIdentity, long expiry, boolean revoked) {}
    public record TransferEvent(String assetId, String sender, String receiver,
        BigInteger amount, String nonce, long timestamp) {}
    public record StateTransitionResult(boolean success, AssetState newState, String error) {}
    public record ComplianceDecision(boolean allowed, ComplianceRule blockedBy) {}

    /** Resolved, attested attributes of a transfer party (§3.6, §4.6 inputs). */
    public record PartyAttributes(IdentityStatus identityStatus, String jurisdiction,
        String investorClass, long acquisitionTime) {
        public static PartyAttributes empty() {
            return new PartyAttributes(IdentityStatus.UNKNOWN, "", "", 0L);
        }
    }
    /** §10.15 attested oracle datum. Unknown/stale/mismatched → block. */
    public record OracleAttestation(boolean cleared, long version, String sourceHash, long validUntil) {}
    /** Inputs for deterministic evaluation of every §4.4 category. */
    public record EvalContext(long amount, long timestamp, String jurisdiction,
        PartyAttributes sender, PartyAttributes receiver,
        Map<RuleType, OracleAttestation> attestations) {}

    // ── §2.5 State Machine ────────────────────────────────────────────────────

    private static final String[][] TRANSITIONS = {
        {"ISSUED","ACTIVATION","ACTIVE"}, {"ACTIVE","BREACH","RESTRICTED"},
        {"ACTIVE","FREEZE","FROZEN"}, {"RESTRICTED","CLEARED","ACTIVE"},
        {"FROZEN","RELEASE","ACTIVE"}, {"ACTIVE","REDEMPTION","REDEEMED"},
        {"REDEEMED","FINALIZATION","BURNED"}, {"ACTIVE","SUSPENSION","SUSPENDED"},
        {"SUSPENDED","REINSTATEMENT","ACTIVE"},
    };

    public static StateTransitionResult applyStateTransition(AssetState current, String trigger) {
        if (current.isTerminal())
            return new StateTransitionResult(false, null, "BURNED is terminal");
        for (var row : TRANSITIONS)
            if (current.name().equals(row[0]) && trigger.equals(row[1]))
                return new StateTransitionResult(true, AssetState.valueOf(row[2]), null);
        return new StateTransitionResult(false, null, "No transition from "+current+" via "+trigger);
    }

    // ── §6.12 Fee Validation ──────────────────────────────────────────────────

    public static void validateFeeModule(FeeModule fee) {
        int total = fee.allocations().stream().mapToInt(FeeAllocation::basisPoints).sum();
        if (total != 10_000)
            throw new IllegalArgumentException("Fee allocations must sum to 10000; got " + total);
        for (var a : fee.allocations())
            if (a.basisPoints() < 0) throw new IllegalArgumentException("Negative allocation");
    }

    // ── §3.6 Identity Status ──────────────────────────────────────────────────

    public static IdentityStatus identityStatus(IdentityRecord record, long nowUnix) {
        if (record.revoked()) return IdentityStatus.REVOKED;
        if (nowUnix >= record.expiry()) return IdentityStatus.EXPIRED;
        return IdentityStatus.VALID;
    }

    // ── §9.6 Replay Protection ────────────────────────────────────────────────

    public static boolean isReplay(TransferEvent event, Set<String> ledgerHistory) {
        var txId = L3rsCrypto.constructTxId(
            event.sender(), event.receiver(), event.amount(), event.nonce(), event.timestamp());
        return ledgerHistory.contains(txId);
    }

    // ── §4 Compliance Engine ───────────────────────────────────────────────────

    /**
     * §4.3 — {@code C: E → {0,1}} as the conjunction of all in-scope rule
     * predicates, evaluated in ascending priority order, first blocking rule
     * terminating (§4.5). Enforces Invariant I₂ (§10.6): any FALSE blocks.
     */
    public static ComplianceDecision evaluateCompliance(
            ComplianceModule module, AssetState state, EvalContext ctx) {
        if (state != AssetState.ACTIVE) return new ComplianceDecision(false, null);
        List<ComplianceRule> rules = new ArrayList<>(module.rules());
        rules.sort(Comparator.comparingInt(ComplianceRule::priority));
        for (ComplianceRule rule : rules) {
            if (!rule.scope().equals("*") && !rule.scope().equals(ctx.jurisdiction())) continue;
            if (!evalRule(rule, ctx) && rule.action().isBlocking()) {
                return new ComplianceDecision(false, rule);
            }
        }
        return new ComplianceDecision(true, null);
    }

    /**
     * Rule predicate rᵢ: E → {TRUE, FALSE} (§4.6). Every branch fails closed:
     * missing inputs, unknown rule types, and unverifiable oracle state → FALSE.
     */
    private static boolean evalRule(ComplianceRule rule, EvalContext ctx) {
        switch (rule.ruleType()) {
            case TRANSFER_ELIGIBILITY:
                return ctx.sender().identityStatus() == IdentityStatus.VALID
                    && ctx.receiver().identityStatus() == IdentityStatus.VALID;
            case INVESTOR_CLASSIFICATION: {
                List<String> allowed = listParam(rule.params(), "allowedClasses");
                if (allowed.isEmpty() || ctx.receiver().investorClass().isEmpty()) return false;
                return allowed.contains(ctx.receiver().investorClass());
            }
            case HOLDING_PERIOD: {
                Long period = numParam(rule.params(), "holdingPeriodSec");
                if (period == null || ctx.sender().acquisitionTime() == 0) return false;
                return (ctx.timestamp() - ctx.sender().acquisitionTime()) >= period;
            }
            case GEOGRAPHIC_RESTRICTION: {
                if (ctx.sender().jurisdiction().isEmpty() || ctx.receiver().jurisdiction().isEmpty())
                    return false;
                List<String> blocked = listParam(rule.params(), "blockedJurisdictions");
                return !blocked.contains(ctx.sender().jurisdiction())
                    && !blocked.contains(ctx.receiver().jurisdiction());
            }
            case TRANSACTION_THRESHOLD: {
                Long t = numParam(rule.params(), "thresholdAmount");
                if (t == null) return false;
                return ctx.amount() <= t;
            }
            case MARKET_RESTRICTION: {
                Long open = numParam(rule.params(), "windowOpen");
                Long close = numParam(rule.params(), "windowClose");
                if (open != null && close != null)
                    return ctx.timestamp() >= open && ctx.timestamp() < close;
                return attestationClears(rule, ctx);
            }
            case SANCTIONS_SCREENING:
            case AML_TRIGGER:
            case REDEMPTION_ELIGIBILITY:
                return attestationClears(rule, ctx);
            default:
                // Unknown / future rule type cannot be evaluated deterministically → block.
                return false;
        }
    }

    /**
     * §10.15 oracle contract: the attestation must be present, anchored to the
     * operator-pinned source hash, at/above the pinned minimum version, and
     * within its freshness window. Anything else blocks.
     */
    private static boolean attestationClears(ComplianceRule rule, EvalContext ctx) {
        OracleAttestation att = ctx.attestations().get(rule.ruleType());
        if (att == null) return false;                              // unknown oracle state → block
        String pinned = strParam(rule.params(), "sourceHash");
        if (pinned.isEmpty() || !att.sourceHash().equals(pinned)) return false;
        Long minV = numParam(rule.params(), "minVersion");
        if (minV != null && att.version() < minV) return false;     // stale version → block
        if (ctx.timestamp() >= att.validUntil()) return false;      // stale attestation → block
        return att.cleared();
    }

    private static Long numParam(Map<String, Object> params, String key) {
        Object v = params.get(key);
        return (v instanceof Number n) ? n.longValue() : null;      // Boolean is not a Number
    }

    private static String strParam(Map<String, Object> params, String key) {
        Object v = params.get(key);
        return (v instanceof String s) ? s : "";
    }

    private static List<String> listParam(Map<String, Object> params, String key) {
        Object v = params.get(key);
        List<String> out = new ArrayList<>();
        if (v instanceof List<?> list) {
            for (Object e : list) if (e instanceof String s) out.add(s);
        }
        return out;
    }
}
