#!/usr/bin/env python3
"""
L3RS-1 Canonical Test Vector Runner — §11.5
Run: PYTHONPATH=packages/python python test-vectors/run_vectors.py
"""
import json
import sys
from pathlib import Path

# Support both repo-root invocation and direct invocation
_repo_root = Path(__file__).parent.parent
_py_pkg    = _repo_root / "packages" / "python"
if str(_py_pkg) not in sys.path:
    sys.path.insert(0, str(_py_pkg))

from l3rs1.crypto import (
    canonicalize, construct_asset_id, construct_cid,
    construct_tx_id, construct_identity_hash,
)
from l3rs1.types import (
    AssetState, AssetType, IdentityLevel, IdentityStatus,
    RuleType, EnforcementAction, GovernanceAction, BackingType,
    AttestationFrequency, ReserveStatus, InsolvencyPriority,
    FeeModule, FeeAllocation, IdentityRecord, TransferEvent,
    ComplianceRule, ComplianceModule,
)
from l3rs1.modules import (
    apply_state_transition, validate_fee_module,
    is_replay, identity_status,
    evaluate_compliance, ComplianceContext, PartyAttributes, OracleAttestation,
)

vectors_path = Path(__file__).parent / "canonical.json"
with open(vectors_path) as f:
    TV = json.load(f)

passed = failed = 0


def check(name: str, actual: object, expected: object) -> None:
    global passed, failed
    if actual == expected:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")
        print(f"        expected: {expected}")
        print(f"        actual:   {actual}")


def check_true(name: str, condition: bool) -> None:
    check(name, condition, True)


print("=== L3RS-1 Canonical Test Vector Suite ===")
print()

# ── §2.2 Asset_ID ────────────────────────────────────────────────────────────
v = TV["vectors"]["asset_id_construction"]
check("§2.2 Asset_ID canonical vector",
      construct_asset_id(v["inputs"]["issuer_pubkey_hex"],
                         v["inputs"]["timestamp_unix"],
                         v["inputs"]["nonce_hex"]),
      v["expected"])

# ── §9.6 TxID ────────────────────────────────────────────────────────────────
v = TV["vectors"]["txid_construction"]
check("§9.6 TxID canonical vector",
      construct_tx_id(v["inputs"]["sender"], v["inputs"]["receiver"],
                      v["inputs"]["amount"], v["inputs"]["nonce_hex"],
                      v["inputs"]["timestamp_unix"]),
      v["expected"])

# ── §8.3 CID ─────────────────────────────────────────────────────────────────
v = TV["vectors"]["crosschain_cid"]
check("§8.3 CID canonical vector",
      construct_cid(v["inputs"]["asset_id"], v["inputs"]["state_hash"],
                    v["inputs"]["compliance_hash"], v["inputs"]["governance_hash"],
                    v["inputs"]["timestamp_unix"]),
      v["expected"])

# ── §2.3 Asset types ─────────────────────────────────────────────────────────
for val in TV["vectors"]["asset_types"]["valid_values"]:
    check_true(f"§2.3 AssetType.{val}", val in [e.value for e in AssetType])

# ── §2.4 Asset states ────────────────────────────────────────────────────────
for val in TV["vectors"]["asset_states"]["valid_values"]:
    check_true(f"§2.4 AssetState.{val}", val in [e.value for e in AssetState])

# ── §2.5 State transitions ───────────────────────────────────────────────────
for t in TV["vectors"]["state_transitions"]["valid_transitions"]:
    r = apply_state_transition(AssetState(t["from"]), t["trigger"])
    check(f"§2.5 {t['from']}--{t['trigger']}-->{t['to']}",
          r.new_state.value if r.new_state else None, t["to"])

for t in TV["vectors"]["state_transitions"]["invalid_transitions"]:
    r = apply_state_transition(AssetState(t["from"]), t["trigger"])
    check_true(f"§2.5 invalid: {t['from']}--{t['trigger']} blocked", not r.success)

# ── §3.2 Identity levels ─────────────────────────────────────────────────────
for val in TV["vectors"]["identity_requirement_levels"]["valid_values"]:
    check_true(f"§3.2 IdentityLevel {val}", val in [e.value for e in IdentityLevel])

# ── §3.6 Identity status ─────────────────────────────────────────────────────
NOW = 1_740_355_200
h   = "a" * 64
check("§3.6 VALID status",
      identity_status(IdentityRecord(h, "va", "US", 9_999_999_999, False), NOW),
      IdentityStatus.VALID)
check("§3.6 EXPIRED status",
      identity_status(IdentityRecord(h, "va", "US", 1_000_000_000, False), NOW),
      IdentityStatus.EXPIRED)
check("§3.6 REVOKED status",
      identity_status(IdentityRecord(h, "va", "US", 9_999_999_999, True), NOW),
      IdentityStatus.REVOKED)

# ── §4.4 Rule types ──────────────────────────────────────────────────────────
for val in TV["vectors"]["compliance_rule_types"]["valid_values"]:
    check_true(f"§4.4 RuleType.{val}", val in [e.value for e in RuleType])

# ── §4.7 Enforcement actions ─────────────────────────────────────────────────
for val in TV["vectors"]["enforcement_actions"]["valid_values"]:
    check_true(f"§4.7 EnforcementAction.{val}", val in [e.value for e in EnforcementAction])

# ── §5.3 Governance actions ──────────────────────────────────────────────────
for val in TV["vectors"]["governance_actions"]["valid_values"]:
    check_true(f"§5.3 GovernanceAction.{val}", val in [e.value for e in GovernanceAction])

# ── §6.4 Fee validation ──────────────────────────────────────────────────────
ex = TV["vectors"]["fee_allocation"]["valid_example"]
fm = FeeModule(100, tuple(FeeAllocation(k, v) for k, v in ex.items()))
try:
    validate_fee_module(fm)
    check_true("§6.4 valid fee allocation accepted", True)
except ValueError:
    check_true("§6.4 valid fee allocation accepted", False)

try:
    validate_fee_module(FeeModule(100, (FeeAllocation("only", 5000),)))
    check_true("§6.4 invalid fee allocation rejected", False)
except ValueError:
    check_true("§6.4 invalid fee allocation rejected", True)

# ── §7 Reserve types ─────────────────────────────────────────────────────────
for val in TV["vectors"]["reserve_backing_types"]["valid_values"]:
    check_true(f"§7.5 BackingType.{val}", val in [e.value for e in BackingType])
for val in TV["vectors"]["attestation_frequencies"]["valid_values"]:
    check_true(f"§7.7 AttestationFrequency.{val}", val in [e.value for e in AttestationFrequency])
for val in TV["vectors"]["reserve_status_values"]["valid_values"]:
    check_true(f"§7.8 ReserveStatus.{val}", val in [e.value for e in ReserveStatus])

# ── §8.3 CID properties ──────────────────────────────────────────────────────
A, B, C, D = "a"*64, "b"*64, "c"*64, "d"*64
cid1 = construct_cid(A, B, C, D, 1000)
cid2 = construct_cid(A, B, C, D, 1000)
cid3 = construct_cid(A, B, C, D, 1001)
check_true("§8.3 CID determinism",        cid1 == cid2)
check_true("§8.3 CID timestamp-sensitive", cid1 != cid3)
check_true("§8.3 CID length 64",          len(cid1) == 64)

# ── §9.6 Replay protection ───────────────────────────────────────────────────
ev1 = TransferEvent("a", "alice", "bob", 1000, "00"*8, 1_740_355_200)
ev2 = TransferEvent("a", "alice", "bob", 1000, "01"*8, 1_740_355_200)
txid = construct_tx_id(ev1.sender, ev1.receiver, ev1.amount, ev1.nonce, ev1.timestamp)
check_true("§9.6 identical event is replay",    is_replay(ev1, {txid}))
check_true("§9.6 different nonce not replay",   not is_replay(ev2, {txid}))

# ── §13.11 Canonical serialization ───────────────────────────────────────────
check("§13.11 keys sorted",
      canonicalize({"z": 3, "a": 1, "m": 2}), '{"a":1,"m":2,"z":3}')
check("§13.11 nested sorted",
      canonicalize({"b": {"d": 4, "c": 3}, "a": 1}), '{"a":1,"b":{"c":3,"d":4}}')
check_true("§13.11 no whitespace", " " not in canonicalize({"k": "v"}))
check_true("§13.11 deterministic",
           canonicalize({"b": 2, "a": 1}) == canonicalize({"a": 1, "b": 2}))

# ── §10 Invariants present ───────────────────────────────────────────────────
for key in [f"I{i}" for i in range(1, 12)]:
    check_true(f"§10 Invariant {key} defined", key in TV["vectors"]["invariants"])

# ── §4 Compliance evaluation (cross-language corpus) ──────────────────
from types import SimpleNamespace
_cv_path = Path(__file__).parent / "compliance_vectors.json"
with open(_cv_path) as _f:
    CV = json.load(_f)

def _pa(p):
    return PartyAttributes(IdentityStatus(p["identityStatus"]), p["jurisdiction"],
                           p["investorClass"], p["acquisitionTime"])

def _att(d):
    return {RuleType(k): OracleAttestation(v["cleared"], v["version"], v["sourceHash"], v["validUntil"])
            for k, v in d.items()}

def _rule(r):
    return ComplianceRule(r["ruleId"], RuleType(r["ruleType"]), r["scope"], r["trigger"],
                          r["priority"], EnforcementAction(r["action"]), r.get("params", {}))

for tc in CV["cases"]:
    mod = ComplianceModule(tuple(_rule(r) for r in tc["module"]["rules"]))
    ctx = ComplianceContext(
        asset=SimpleNamespace(state=AssetState(tc["state"]), jurisdiction=tc["jurisdiction"]),
        sender=tc["sender"], receiver=tc["receiver"], amount=tc["amount"], timestamp=tc["timestamp"],
        sender_attrs=_pa(tc["sender"]), receiver_attrs=_pa(tc["receiver"]),
        attestations=_att(tc["attestations"]))
    dec = evaluate_compliance(mod, ctx)
    got = dec.blocked_by.rule_id if dec.blocked_by else None
    check_true(f"§4 vector {tc['name']} allowed",   dec.allowed == tc["expected"]["allowed"])
    check_true(f"§4 vector {tc['name']} blockedBy", got == tc["expected"]["blockedBy"])


# ── Summary ──────────────────────────────────────────────────────────────────
print()
print(f"Results: {passed} passed, {failed} failed")
print(f"SDK version: {TV['version']} | Conformance: {TV['conformance_class']}")

if failed:
    print(f"\nCONFORMANCE FAILURE: {failed} vector(s) did not match.")
    sys.exit(1)
else:
    print("\nALL VECTORS PASS — implementation is conformant.")
    sys.exit(0)
