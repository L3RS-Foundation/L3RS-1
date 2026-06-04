// Package conformance runs the shared cross-language compliance corpus
// (test-vectors/compliance_vectors.json) through the Go reference engine and
// verifies each decision matches the golden expectation. §11.5.
package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/modules"
	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/types"
)

type party struct {
	IdentityStatus  string `json:"identityStatus"`
	Jurisdiction    string `json:"jurisdiction"`
	InvestorClass   string `json:"investorClass"`
	AcquisitionTime int64  `json:"acquisitionTime"`
}
type attest struct {
	Cleared    bool   `json:"cleared"`
	Version    uint64 `json:"version"`
	SourceHash string `json:"sourceHash"`
	ValidUntil int64  `json:"validUntil"`
}
type vcase struct {
	Name         string                 `json:"name"`
	State        string                 `json:"state"`
	Jurisdiction string                 `json:"jurisdiction"`
	Amount       uint64                 `json:"amount"`
	Timestamp    int64                  `json:"timestamp"`
	Sender       party                  `json:"sender"`
	Receiver     party                  `json:"receiver"`
	Attestations map[string]attest      `json:"attestations"`
	Module       types.ComplianceModule `json:"module"`
	Expected     struct {
		Allowed   bool    `json:"allowed"`
		BlockedBy *string `json:"blockedBy"`
	} `json:"expected"`
}

func toParty(p party) modules.PartyAttributes {
	return modules.PartyAttributes{
		IdentityStatus:  types.IdentityStatus(p.IdentityStatus),
		Jurisdiction:    p.Jurisdiction,
		InvestorClass:   p.InvestorClass,
		AcquisitionTime: p.AcquisitionTime,
	}
}

func corpusPath(t *testing.T) string {
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), "..", "..", "..", "..", "test-vectors", "compliance_vectors.json")
}

func TestComplianceCorpusMatchesGolden(t *testing.T) {
	raw, err := os.ReadFile(corpusPath(t))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c struct {
		Cases []vcase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}

	for _, tc := range c.Cases {
		att := make(map[types.RuleType]modules.OracleAttestation, len(tc.Attestations))
		for k, v := range tc.Attestations {
			att[types.RuleType(k)] = modules.OracleAttestation{
				Cleared: v.Cleared, Version: v.Version, SourceHash: v.SourceHash, ValidUntil: v.ValidUntil,
			}
		}
		ctx := modules.EvalContext{
			Amount: tc.Amount, Timestamp: tc.Timestamp, Jurisdiction: tc.Jurisdiction,
			Sender: toParty(tc.Sender), Receiver: toParty(tc.Receiver), Attestations: att,
		}
		dec := modules.EvaluateCompliance(&tc.Module, types.AssetState(tc.State), ctx)

		var got *string
		if dec.BlockedBy != nil {
			id := dec.BlockedBy.RuleID
			got = &id
		}
		if dec.Allowed != tc.Expected.Allowed {
			t.Errorf("%s: allowed=%v, want %v", tc.Name, dec.Allowed, tc.Expected.Allowed)
		}
		switch {
		case got == nil && tc.Expected.BlockedBy == nil:
		case got != nil && tc.Expected.BlockedBy != nil && *got == *tc.Expected.BlockedBy:
		default:
			ge, ee := "nil", "nil"
			if got != nil {
				ge = *got
			}
			if tc.Expected.BlockedBy != nil {
				ee = *tc.Expected.BlockedBy
			}
			t.Errorf("%s: blockedBy=%s, want %s", tc.Name, ge, ee)
		}
	}
	t.Logf("Go compliance vectors: %d cases", len(c.Cases))
}
