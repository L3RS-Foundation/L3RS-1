// Package modules implements L3RS-1 core protocol modules.
package modules

import (
	"fmt"
	"math"
	"sort"

	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/crypto"
	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/types"
)

// ── §2.5 State Machine ───────────────────────────────────────────────────────

type transition struct {
	from    types.AssetState
	trigger string
	to      types.AssetState
}

var transitionMatrix = []transition{
	{types.AssetStateIssued, "ACTIVATION", types.AssetStateActive},
	{types.AssetStateActive, "BREACH", types.AssetStateRestricted},
	{types.AssetStateActive, "FREEZE", types.AssetStateFrozen},
	{types.AssetStateRestricted, "CLEARED", types.AssetStateActive},
	{types.AssetStateFrozen, "RELEASE", types.AssetStateActive},
	{types.AssetStateActive, "REDEMPTION", types.AssetStateRedeemed},
	{types.AssetStateRedeemed, "FINALIZATION", types.AssetStateBurned},
	{types.AssetStateActive, "SUSPENSION", types.AssetStateSuspended},
	{types.AssetStateSuspended, "REINSTATEMENT", types.AssetStateActive},
}

// StateTransitionResult holds the outcome of a state transition attempt.
type StateTransitionResult struct {
	Success  bool
	NewState types.AssetState
	Error    string
}

// ApplyStateTransition implements §2.5 deterministic state machine.
func ApplyStateTransition(current types.AssetState, trigger string) StateTransitionResult {
	if current.IsTerminal() {
		return StateTransitionResult{Error: "BURNED is a terminal state"}
	}
	for _, row := range transitionMatrix {
		if row.from == current && trigger == row.trigger {
			return StateTransitionResult{Success: true, NewState: row.to}
		}
	}
	return StateTransitionResult{Error: fmt.Sprintf("no transition from %s via %s", current, trigger)}
}

// ── §4 Compliance ────────────────────────────────────────────────────────────

// PartyAttributes holds the resolved, attested attributes of a transfer party.
// The host supplies them (resolved from IdentityRecords and verified data); the
// engine consumes them as deterministic, side-effect-free inputs per §4.6.
type PartyAttributes struct {
	IdentityStatus  types.IdentityStatus // §3.6 — must be VALID for identity-bearing rules
	Jurisdiction    string               // holder jurisdiction code
	InvestorClass   string               // e.g. ACCREDITED, QUALIFIED, RETAIL
	AcquisitionTime int64                // unix seconds; basis for holding period
}

// OracleAttestation is the §10.15 contract for external data sources
// (sanctions lists, AML scoring, reserve status). It MUST be hash-anchored,
// versioned and time-bounded. Unknown, stale, or mismatched attestations
// evaluate as BLOCKING ("Unknown oracle state SHALL evaluate as blocking").
type OracleAttestation struct {
	Cleared    bool   // determination result (true = passes)
	Version    uint64 // monotonic source-dataset version
	SourceHash string // hash anchor of the dataset actually used
	ValidUntil int64  // unix seconds; stale at/after this time
}

// EvalContext carries everything the engine needs to evaluate every §4.4
// category deterministically (§4.6, §4.13). Party-based categories read the
// resolved attributes; inherently external categories read attestations.
type EvalContext struct {
	Amount       uint64
	Timestamp    int64
	Jurisdiction string // asset jurisdiction (rule scope matching)
	Sender       PartyAttributes
	Receiver     PartyAttributes
	Attestations map[types.RuleType]OracleAttestation
}

// EvaluateCompliance implements C: E → {0,1} per §4.3 as the conjunction of all
// in-scope rule predicates, evaluated in ascending priority order with the first
// blocking rule terminating per §4.5. Enforces I₂ (§10.6): any FALSE blocks.
func EvaluateCompliance(module *types.ComplianceModule, state types.AssetState, ctx EvalContext) types.ComplianceDecision {
	if state != types.AssetStateActive {
		return types.ComplianceDecision{Allowed: false}
	}
	rules := make([]types.ComplianceRule, len(module.Rules))
	copy(rules, module.Rules)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })

	for i := range rules {
		rule := &rules[i]
		if rule.Scope != "*" && rule.Scope != ctx.Jurisdiction {
			continue
		}
		if !evalRule(rule, ctx) && rule.Action.IsBlocking() {
			return types.ComplianceDecision{Allowed: false, BlockedBy: rule, Action: rule.Action}
		}
	}
	return types.ComplianceDecision{Allowed: true}
}

// evalRule returns the rule predicate rᵢ: E → {TRUE, FALSE} (§4.6). Every branch
// fails closed: missing inputs, unknown rule types, and unverifiable oracle state
// all evaluate to FALSE (block).
func evalRule(rule *types.ComplianceRule, ctx EvalContext) bool {
	switch rule.RuleType {

	case types.RuleTypeTransferEligibility:
		return ctx.Sender.IdentityStatus == types.IdentityStatusValid &&
			ctx.Receiver.IdentityStatus == types.IdentityStatusValid

	case types.RuleTypeInvestorClassification:
		allowed := listParam(rule.Params, "allowedClasses")
		if len(allowed) == 0 || ctx.Receiver.InvestorClass == "" {
			return false
		}
		return contains(allowed, ctx.Receiver.InvestorClass)

	case types.RuleTypeHoldingPeriod:
		period, ok := numParam(rule.Params, "holdingPeriodSec")
		if !ok || ctx.Sender.AcquisitionTime == 0 {
			return false
		}
		return (ctx.Timestamp - ctx.Sender.AcquisitionTime) >= period

	case types.RuleTypeGeographicRestriction:
		if ctx.Sender.Jurisdiction == "" || ctx.Receiver.Jurisdiction == "" {
			return false
		}
		blocked := listParam(rule.Params, "blockedJurisdictions")
		return !contains(blocked, ctx.Sender.Jurisdiction) &&
			!contains(blocked, ctx.Receiver.Jurisdiction)

	case types.RuleTypeTransactionThreshold:
		t, ok := numParam(rule.Params, "thresholdAmount")
		if !ok {
			return false
		}
		return int64(ctx.Amount) <= t

	case types.RuleTypeMarketRestriction:
		// Deterministic trading-window check when configured; else attested oracle.
		open, ok1 := numParam(rule.Params, "windowOpen")
		closeT, ok2 := numParam(rule.Params, "windowClose")
		if ok1 && ok2 {
			return ctx.Timestamp >= open && ctx.Timestamp < closeT
		}
		return attestationClears(rule, ctx)

	case types.RuleTypeSanctionsScreening,
		types.RuleTypeAMLTrigger,
		types.RuleTypeRedemptionEligibility:
		// Inherently external determinations — §10.15 attested oracle, fail-closed.
		return attestationClears(rule, ctx)

	default:
		// Unknown / future rule type cannot be evaluated deterministically → block.
		return false
	}
}

// attestationClears applies the §10.15 oracle contract: the attestation must be
// present, anchored to the operator-pinned source hash, at/above the pinned
// minimum version, and within its freshness window. Anything else blocks.
func attestationClears(rule *types.ComplianceRule, ctx EvalContext) bool {
	att, ok := ctx.Attestations[rule.RuleType]
	if !ok {
		return false // unknown oracle state → block (§10.15)
	}
	pinned, _ := strParam(rule.Params, "sourceHash")
	if pinned == "" || att.SourceHash != pinned {
		return false // not anchored to the expected dataset → block
	}
	if minV, ok := numParam(rule.Params, "minVersion"); ok && int64(att.Version) < minV {
		return false // stale dataset version → block
	}
	if ctx.Timestamp >= att.ValidUntil {
		return false // stale attestation → block
	}
	return att.Cleared
}

func numParam(params map[string]any, key string) (int64, bool) {
	v, ok := params[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

func strParam(params map[string]any, key string) (string, bool) {
	v, ok := params[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func listParam(params map[string]any, key string) []string {
	v, ok := params[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, e := range xs {
		if e == x {
			return true
		}
	}
	return false
}

// ── §6.12 Fee Validation ─────────────────────────────────────────────────────

// ValidateFeeModule enforces §6.12 economic integrity constraint.
func ValidateFeeModule(fee *types.FeeModule) error {
	total := 0
	for _, a := range fee.Allocations {
		if a.BasisPoints < 0 {
			return fmt.Errorf("negative allocation not permitted")
		}
		total += a.BasisPoints
	}
	if total != 10_000 {
		return fmt.Errorf("fee allocations must sum to 10000; got %d", total)
	}
	return nil
}

// ── §3.6 Identity Status ─────────────────────────────────────────────────────

// IdentityStatus computes Status(IR) per §3.6.
func IdentityStatus(record *types.IdentityRecord, nowUnix int64) types.IdentityStatus {
	if record.Revoked {
		return types.IdentityStatusRevoked
	}
	if nowUnix >= record.Expiry {
		return types.IdentityStatusExpired
	}
	return types.IdentityStatusValid
}

// ── §5.5 Quorum Validation ───────────────────────────────────────────────────

// ValidateQuorum checks ⌈2/3 × N⌉ signatures are present.
func ValidateQuorum(authorities []string, signatures []string) (bool, int, int) {
	N := len(authorities)
	required := int(math.Ceil(float64(2*N) / 3.0))
	authSet := map[string]bool{}
	for _, a := range authorities {
		authSet[a] = true
	}
	signed := map[string]bool{}
	for _, s := range signatures {
		if authSet[s] {
			signed[s] = true
		}
	}
	return len(signed) >= required, len(signed), required
}

// ── §9.6 Replay Protection ───────────────────────────────────────────────────

// IsReplay returns true if the event's TxID is in ledger history.
func IsReplay(event *types.TransferEvent, ledgerHistory map[string]bool) (bool, error) {
	txID, err := crypto.ConstructTxID(
		event.Sender, event.Receiver, event.Amount, event.Nonce, event.Timestamp,
	)
	if err != nil {
		return false, err
	}
	return ledgerHistory[txID], nil
}
