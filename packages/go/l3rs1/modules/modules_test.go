package modules_test

import (
	"testing"

	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/crypto"
	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/modules"
	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/types"
)

const (
	testPubkey  = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	testTS      = int64(1740355200)
	testNonce   = "0000000000000001"
	expectedID  = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a"
)

func TestAssetIDVector(t *testing.T) {
	id, err := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
	if err != nil { t.Fatal(err) }
	if id != expectedID { t.Errorf("got %s want %s", id, expectedID) }
}

func TestAssetIDDeterministic(t *testing.T) {
	a, _ := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
	b, _ := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
	if a != b { t.Error("not deterministic") }
}

func TestCanonicalize(t *testing.T) {
	b, err := crypto.Canonicalize(map[string]any{"z": 3, "a": 1, "m": 2})
	if err != nil { t.Fatal(err) }
	if string(b) != `{"a":1,"m":2,"z":3}` { t.Errorf("got %s", b) }
}

func TestStateTransitions(t *testing.T) {
	cases := [][2]string{
		{"ISSUED", "ACTIVATION"}, {"ACTIVE", "BREACH"}, {"ACTIVE", "FREEZE"},
		{"RESTRICTED", "CLEARED"}, {"FROZEN", "RELEASE"}, {"ACTIVE", "REDEMPTION"},
		{"REDEEMED", "FINALIZATION"}, {"ACTIVE", "SUSPENSION"}, {"SUSPENDED", "REINSTATEMENT"},
	}
	expected := []string{
		"ACTIVE","RESTRICTED","FROZEN","ACTIVE","ACTIVE",
		"REDEEMED","BURNED","SUSPENDED","ACTIVE",
	}
	for i, c := range cases {
		r := modules.ApplyStateTransition(types.AssetState(c[0]), c[1])
		if !r.Success { t.Errorf("case %d failed: %s", i, r.Error) }
		if string(r.NewState) != expected[i] {
			t.Errorf("case %d: got %s want %s", i, r.NewState, expected[i])
		}
	}
}

func TestBurnedTerminal(t *testing.T) {
	r := modules.ApplyStateTransition(types.AssetStateBurned, "ACTIVATION")
	if r.Success { t.Error("BURNED should be terminal") }
}

func TestInvalidTransition(t *testing.T) {
	r := modules.ApplyStateTransition(types.AssetStateIssued, "FREEZE")
	if r.Success { t.Error("ISSUED->FREEZE should fail") }
}

func TestCIDDeterministic(t *testing.T) {
	fill := func(c string) string { return c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c }
	a, _ := crypto.ConstructCID(fill("a"), fill("b"), fill("c"), fill("d"), 1000)
	b, _ := crypto.ConstructCID(fill("a"), fill("b"), fill("c"), fill("d"), 1000)
	if a != b { t.Error("CID not deterministic") }
}

func TestCIDTimestampSensitive(t *testing.T) {
	fill := func(c string) string {
		s := ""
		for i := 0; i < 64; i++ { s += c }
		return s
	}
	a, _ := crypto.ConstructCID(fill("a"), fill("b"), fill("c"), fill("d"), 1000)
	b, _ := crypto.ConstructCID(fill("a"), fill("b"), fill("c"), fill("d"), 1001)
	if a == b { t.Error("CID should differ for different timestamps") }
}

func TestFeeValidation(t *testing.T) {
	valid := &types.FeeModule{
		BaseRateBasisPoints: 100,
		Allocations: []types.FeeAllocation{
			{Recipient: "a", BasisPoints: 2000},
			{Recipient: "b", BasisPoints: 3000},
			{Recipient: "c", BasisPoints: 2000},
			{Recipient: "d", BasisPoints: 2500},
			{Recipient: "e", BasisPoints: 500},
		},
	}
	if err := modules.ValidateFeeModule(valid); err != nil {
		t.Errorf("valid fee rejected: %v", err)
	}
	invalid := &types.FeeModule{
		Allocations: []types.FeeAllocation{{Recipient: "x", BasisPoints: 5000}},
	}
	if err := modules.ValidateFeeModule(invalid); err == nil {
		t.Error("partial allocation should be rejected")
	}
}

func TestIdentityStatus(t *testing.T) {
	now := int64(1740355200)
	valid   := &types.IdentityRecord{Expiry: 9999999999, Revoked: false}
	expired := &types.IdentityRecord{Expiry: 1000000000, Revoked: false}
	revoked := &types.IdentityRecord{Expiry: 9999999999, Revoked: true}
	if modules.IdentityStatus(valid, now)   != types.IdentityStatusValid   { t.Error("should be VALID") }
	if modules.IdentityStatus(expired, now) != types.IdentityStatusExpired { t.Error("should be EXPIRED") }
	if modules.IdentityStatus(revoked, now) != types.IdentityStatusRevoked { t.Error("should be REVOKED") }
}

func TestReplayProtection(t *testing.T) {
	ev := &types.TransferEvent{Sender: "alice", Receiver: "bob", Amount: 1000,
		Nonce: "0000000000000001", Timestamp: testTS}
	txID, _ := crypto.ConstructTxID(ev.Sender, ev.Receiver, ev.Amount, ev.Nonce, ev.Timestamp)
	history := map[string]bool{txID: true}

	replay, _ := modules.IsReplay(ev, history)
	if !replay { t.Error("should be replay") }

	ev2 := &types.TransferEvent{Sender: "alice", Receiver: "bob", Amount: 1000,
		Nonce: "0000000000000002", Timestamp: testTS}
	notReplay, _ := modules.IsReplay(ev2, history)
	if notReplay { t.Error("different nonce should not be replay") }
}

func TestComplianceFailsClosed(t *testing.T) {
	now := int64(1_740_355_200)
	mod := &types.ComplianceModule{Rules: []types.ComplianceRule{{
		RuleID: "r1", RuleType: types.RuleTypeSanctionsScreening, Scope: "*",
		Priority: 1, Action: types.EnforcementReject,
		Params:   map[string]any{"sourceHash": "OFAC-2026-06-04", "minVersion": int64(7)},
	}}}
	base := modules.EvalContext{
		Amount: 100, Timestamp: now, Jurisdiction: "GE",
		Sender:   modules.PartyAttributes{IdentityStatus: types.IdentityStatusValid, Jurisdiction: "GE"},
		Receiver: modules.PartyAttributes{IdentityStatus: types.IdentityStatusValid, Jurisdiction: "GE"},
	}
	att := func(a modules.OracleAttestation) modules.EvalContext {
		c := base
		c.Attestations = map[types.RuleType]modules.OracleAttestation{types.RuleTypeSanctionsScreening: a}
		return c
	}
	check := func(name string, c modules.EvalContext, wantAllow bool) {
		got := modules.EvaluateCompliance(mod, types.AssetStateActive, c).Allowed
		if got != wantAllow {
			t.Errorf("%s: allowed=%v want %v", name, got, wantAllow)
		}
	}
	check("no attestation (unknown oracle)", base, false)
	check("wrong source hash", att(modules.OracleAttestation{Cleared: true, Version: 9, SourceHash: "WRONG", ValidUntil: now + 3600}), false)
	check("stale version", att(modules.OracleAttestation{Cleared: true, Version: 3, SourceHash: "OFAC-2026-06-04", ValidUntil: now + 3600}), false)
	check("expired attestation", att(modules.OracleAttestation{Cleared: true, Version: 9, SourceHash: "OFAC-2026-06-04", ValidUntil: now - 1}), false)
	check("sanctions hit", att(modules.OracleAttestation{Cleared: false, Version: 9, SourceHash: "OFAC-2026-06-04", ValidUntil: now + 3600}), false)
	check("valid+fresh+cleared", att(modules.OracleAttestation{Cleared: true, Version: 9, SourceHash: "OFAC-2026-06-04", ValidUntil: now + 3600}), true)
}

func TestComplianceNativeCategories(t *testing.T) {
	now := int64(1_740_355_200)
	ctx := modules.EvalContext{
		Amount: 500, Timestamp: now, Jurisdiction: "GE",
		Sender:   modules.PartyAttributes{IdentityStatus: types.IdentityStatusValid, Jurisdiction: "GE", InvestorClass: "ACCREDITED", AcquisitionTime: now - 100000},
		Receiver: modules.PartyAttributes{IdentityStatus: types.IdentityStatusValid, Jurisdiction: "GE", InvestorClass: "ACCREDITED"},
	}
	geo := &types.ComplianceModule{Rules: []types.ComplianceRule{{
		RuleID: "g", RuleType: types.RuleTypeGeographicRestriction, Scope: "*", Priority: 1,
		Action: types.EnforcementReject, Params: map[string]any{"blockedJurisdictions": []string{"GE"}},
	}}}
	if modules.EvaluateCompliance(geo, types.AssetStateActive, ctx).Allowed {
		t.Error("blocked jurisdiction must reject")
	}
	teCtx := ctx
	teCtx.Receiver.IdentityStatus = types.IdentityStatusExpired
	te := &types.ComplianceModule{Rules: []types.ComplianceRule{{
		RuleID: "t", RuleType: types.RuleTypeTransferEligibility, Scope: "*", Priority: 1, Action: types.EnforcementReject,
	}}}
	if modules.EvaluateCompliance(te, types.AssetStateActive, teCtx).Allowed {
		t.Error("expired receiver identity must block transfer eligibility")
	}
}
