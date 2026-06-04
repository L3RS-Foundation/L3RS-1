"""
L3RS-1 Core Modules — Python
asset · compliance · identity · governance · settlement · transfer
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Optional, Protocol

from l3rs1.types import (
    Asset, AssetState, ComplianceDecision, ComplianceModule, ComplianceRule,
    EnforcementAction, GovernanceAction, GovernanceModule, IdentityLevel,
    IdentityRecord, IdentityStatus, OverrideObject, FeeModule,
    RuleType, SettlementProof, TransferEvent,
)
from l3rs1.crypto import (
    construct_override_hash, construct_tx_id, hash_object,
    sha256_concat, canonicalize, construct_cid, SignatureVerifier,
)


# ══════════════════════════════════════════════════════════════════════════════
# §2 Asset State Machine
# ══════════════════════════════════════════════════════════════════════════════

_TRANSITIONS: list[tuple[AssetState, str, AssetState]] = [
    (AssetState.ISSUED,     "ACTIVATION",    AssetState.ACTIVE),
    (AssetState.ACTIVE,     "BREACH",        AssetState.RESTRICTED),
    (AssetState.ACTIVE,     "FREEZE",        AssetState.FROZEN),
    (AssetState.RESTRICTED, "CLEARED",       AssetState.ACTIVE),
    (AssetState.FROZEN,     "RELEASE",       AssetState.ACTIVE),
    (AssetState.ACTIVE,     "REDEMPTION",    AssetState.REDEEMED),
    (AssetState.REDEEMED,   "FINALIZATION",  AssetState.BURNED),
    (AssetState.ACTIVE,     "SUSPENSION",    AssetState.SUSPENDED),
    (AssetState.SUSPENDED,  "REINSTATEMENT", AssetState.ACTIVE),
]


@dataclass(frozen=True)
class StateTransitionResult:
    success:   bool
    new_state: Optional[AssetState] = None
    error:     Optional[str] = None


def apply_state_transition(current: AssetState, trigger: str) -> StateTransitionResult:
    """§2.5 Deterministic state transition. Invariant I₁."""
    if current.is_terminal():
        return StateTransitionResult(False, error="BURNED is a terminal state")
    for from_s, t, to_s in _TRANSITIONS:
        if from_s == current and t == trigger:
            return StateTransitionResult(True, new_state=to_s)
    return StateTransitionResult(False, error=f"No transition from {current.value} via {trigger}")


def validate_asset(asset: Asset) -> None:
    """§13.14 Strict asset validation."""
    if not isinstance(asset.jurisdiction, str) or len(asset.jurisdiction) != 2:
        raise ValueError("jurisdiction must be ISO 3166-1 alpha-2")
    if not asset.standard_version.startswith("L3RS-"):
        raise ValueError('standard_version must start with "L3RS-"')


# ══════════════════════════════════════════════════════════════════════════════
# §4 Compliance Engine
# ══════════════════════════════════════════════════════════════════════════════

class SanctionsRegistry(Protocol):
    registry_hash: str
    def is_listed(self, address: str) -> bool: ...


@dataclass(frozen=True)
class PartyAttributes:
    """Resolved, attested attributes of a transfer party (§3.6, §4.6 inputs)."""
    identity_status:  IdentityStatus = IdentityStatus.UNKNOWN
    jurisdiction:     str = ""
    investor_class:   str = ""
    acquisition_time: int = 0   # unix seconds; basis for holding period


@dataclass(frozen=True)
class OracleAttestation:
    """§10.15 contract for external data sources (sanctions/AML/reserve).

    MUST be hash-anchored, versioned and time-bounded. Unknown, stale, or
    mismatched attestations evaluate as BLOCKING.
    """
    cleared:     bool
    version:     int
    source_hash: str
    valid_until: int   # unix seconds; stale at/after this time


@dataclass(frozen=True)
class ComplianceContext:
    asset:          Asset
    sender:         str
    receiver:       str
    amount:         int
    timestamp:      int
    sanctions:      Optional[SanctionsRegistry] = None  # deprecated; superseded by attestations
    sender_attrs:   PartyAttributes = field(default_factory=PartyAttributes)
    receiver_attrs: PartyAttributes = field(default_factory=PartyAttributes)
    attestations:   dict[RuleType, OracleAttestation] = field(default_factory=dict)


_BLOCKING = {EnforcementAction.REJECT, EnforcementAction.FREEZE, EnforcementAction.RESTRICT}


def evaluate_compliance(module: ComplianceModule, ctx: ComplianceContext) -> ComplianceDecision:
    """C: E → {0,1} — §4.3. O(n) per §14.3. Invariant I₂."""
    if ctx.asset.state != AssetState.ACTIVE:
        # State gate is a precondition, not a compliance rule → no blockedBy.
        return ComplianceDecision(False)
    for rule in sorted(module.rules, key=lambda r: r.priority):
        if not _scope_applies(rule, ctx):
            continue
        if not _eval_rule(rule, ctx) and rule.action in _BLOCKING:
            return ComplianceDecision(False, rule, rule.action)
    return ComplianceDecision(True)


def _scope_applies(rule: ComplianceRule, ctx: ComplianceContext) -> bool:
    return rule.scope in ("*", ctx.asset.jurisdiction)


def _eval_rule(rule: ComplianceRule, ctx: ComplianceContext) -> bool:
    """Rule predicate rᵢ: E → {TRUE, FALSE} (§4.6). Every branch fails closed:
    missing inputs, unknown rule types, and unverifiable oracle state all → False."""
    rt = rule.rule_type

    if rt == RuleType.TRANSFER_ELIGIBILITY:
        return (ctx.sender_attrs.identity_status == IdentityStatus.VALID and
                ctx.receiver_attrs.identity_status == IdentityStatus.VALID)

    if rt == RuleType.INVESTOR_CLASSIFICATION:
        allowed = _list_param(rule.params, "allowedClasses")
        if not allowed or not ctx.receiver_attrs.investor_class:
            return False
        return ctx.receiver_attrs.investor_class in allowed

    if rt == RuleType.HOLDING_PERIOD:
        period = _num_param(rule.params, "holdingPeriodSec")
        if period is None or ctx.sender_attrs.acquisition_time == 0:
            return False
        return (ctx.timestamp - ctx.sender_attrs.acquisition_time) >= period

    if rt == RuleType.GEOGRAPHIC_RESTRICTION:
        if not ctx.sender_attrs.jurisdiction or not ctx.receiver_attrs.jurisdiction:
            return False
        blocked = _list_param(rule.params, "blockedJurisdictions")
        return (ctx.sender_attrs.jurisdiction not in blocked and
                ctx.receiver_attrs.jurisdiction not in blocked)

    if rt == RuleType.TRANSACTION_THRESHOLD:
        threshold = _num_param(rule.params, "thresholdAmount")
        if threshold is None:
            return False
        return ctx.amount <= threshold

    if rt == RuleType.MARKET_RESTRICTION:
        open_ = _num_param(rule.params, "windowOpen")
        close = _num_param(rule.params, "windowClose")
        if open_ is not None and close is not None:
            return open_ <= ctx.timestamp < close
        return _attestation_clears(rule, ctx)

    if rt in (RuleType.SANCTIONS_SCREENING,
              RuleType.AML_TRIGGER,
              RuleType.REDEMPTION_ELIGIBILITY):
        return _attestation_clears(rule, ctx)

    return False  # unknown / future rule type → block


def _attestation_clears(rule: ComplianceRule, ctx: ComplianceContext) -> bool:
    """§10.15 oracle contract: present, anchored to the operator-pinned source
    hash, at/above the pinned minimum version, and within its freshness window."""
    att = ctx.attestations.get(rule.rule_type)
    if att is None:
        return False  # unknown oracle state → block
    pinned = _str_param(rule.params, "sourceHash")
    if not pinned or att.source_hash != pinned:
        return False
    min_v = _num_param(rule.params, "minVersion")
    if min_v is not None and att.version < min_v:
        return False
    if ctx.timestamp >= att.valid_until:
        return False
    return att.cleared


def _num_param(params: dict, key: str) -> Optional[int]:
    v = params.get(key)
    if isinstance(v, bool):       # bool is an int subclass — exclude it
        return None
    if isinstance(v, (int, float)):
        return int(v)
    return None


def _str_param(params: dict, key: str) -> str:
    v = params.get(key)
    return v if isinstance(v, str) else ""


def _list_param(params: dict, key: str) -> list[str]:
    v = params.get(key)
    return [e for e in v if isinstance(e, str)] if isinstance(v, list) else []


# ══════════════════════════════════════════════════════════════════════════════
# §3 Identity Binding
# ══════════════════════════════════════════════════════════════════════════════

def identity_status(record: IdentityRecord, now_unix: int) -> IdentityStatus:
    """Status(IR) — §3.6."""
    if record.revoked:
        return IdentityStatus.REVOKED
    if now_unix >= record.expiry:
        return IdentityStatus.EXPIRED
    return IdentityStatus.VALID


def validate_identity(record: IdentityRecord, now_unix: int) -> tuple[bool, str]:
    """validate_identity(party) — §3.11."""
    status = identity_status(record, now_unix)
    if status != IdentityStatus.VALID:
        return False, f"Identity status: {status.value}"
    if record.proof is not None:
        return False, "ZKP verification not implemented — supply real verifier"
    return True, ""


def enforce_identity_level(
    level: IdentityLevel,
    sender_records: list[IdentityRecord],
    receiver_records: list[IdentityRecord],
    now_unix: int,
    required_jurisdictions: Optional[list[str]] = None,
) -> tuple[bool, str]:
    if level == IdentityLevel.UNBOUND:
        return True, ""
    if not sender_records:
        return False, "Sender has no identity record"
    ok, err = validate_identity(sender_records[0], now_unix)
    if not ok:
        return False, f"Sender: {err}"
    if not receiver_records:
        return False, "Receiver has no identity record"
    ok, err = validate_identity(receiver_records[0], now_unix)
    if not ok:
        return False, f"Receiver: {err}"
    if level == IdentityLevel.MULTI_JURISDICTION and required_jurisdictions:
        for name, records in [("Sender", sender_records), ("Receiver", receiver_records)]:
            valid = {r.jurisdiction_identity for r in records
                     if identity_status(r, now_unix) == IdentityStatus.VALID}
            missing = set(required_jurisdictions) - valid
            if missing:
                return False, f"{name} missing jurisdictions: {missing}"
    return True, ""


# ══════════════════════════════════════════════════════════════════════════════
# §5 Governance Override
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class OverrideRecord:
    record_hash: str
    override_id: str
    authority:   str
    action:      GovernanceAction
    timestamp:   int


def validate_override(
    override: OverrideObject,
    governance: GovernanceModule,
    verifier: SignatureVerifier,
    all_signatures: Optional[list[dict[str, str]]] = None,
) -> tuple[bool, str]:
    """validate_override(O) — §5.6. Invariant I₄."""
    if override.authority not in governance.authorities:
        return False, "Authority not registered"
    if override.action not in governance.override_types:
        return False, f"Action {override.action.value} not permitted"
    if not override.legal_basis or len(override.legal_basis) < 64:
        return False, "Legal basis hash missing"
    msg = bytes.fromhex(override.legal_basis)
    if not verifier.verify(msg, override.signature, override.authority):
        return False, "Signature verification failed"
    if override.action == GovernanceAction.EMERGENCY_ROLLBACK:
        met, count, required = validate_quorum(governance, all_signatures or [])
        if not met:
            return False, f"Quorum not met: {count}/{required}"
    return True, ""


def validate_quorum(
    governance: GovernanceModule,
    signatures: list[dict[str, str]],
) -> tuple[bool, int, int]:
    """Quorum = ⌈(2/3) × N⌉ — §5.5"""
    N = len(governance.authorities)
    required = math.ceil(2 / 3 * N)
    signed = {s["authority"] for s in signatures
              if s.get("authority") in governance.authorities}
    return len(signed) >= required, len(signed), required


def create_override_record(override: OverrideObject) -> OverrideRecord:
    return OverrideRecord(
        record_hash=construct_override_hash(
            override.override_id, override.authority,
            override.action.value, override.timestamp,
        ),
        override_id=override.override_id,
        authority=override.authority,
        action=override.action,
        timestamp=override.timestamp,
    )


# ══════════════════════════════════════════════════════════════════════════════
# §6 Fee Routing
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FeeDistribution:
    total_fee:       int
    allocations:     list[dict[str, object]]
    fee_record_hash: str


def validate_fee_module(fee: FeeModule) -> None:
    """§6.12 Economic Integrity Constraint."""
    total = sum(a.basis_points for a in fee.allocations)
    if total != 10_000:
        raise ValueError(f"Fee allocations must sum to 10000 basis points; got {total}")
    for a in fee.allocations:
        if a.basis_points < 0:
            raise ValueError("Negative fee allocation not permitted")


def distribute_fees(fee: FeeModule, amount: int, tx_id: str, timestamp: int) -> FeeDistribution:
    """distribute_fees(A, amount) — §6.5."""
    validate_fee_module(fee)
    total_fee = (amount * fee.base_rate_basis_points) // 10_000
    allocations = [
        {"recipient": a.recipient, "amount": (total_fee * a.basis_points) // 10_000}
        for a in fee.allocations
    ]
    fee_record_hash = sha256_concat(
        bytes.fromhex(tx_id),
        total_fee.to_bytes(32, "big"),
        struct.pack(">Q", timestamp),
    )
    return FeeDistribution(total_fee, allocations, fee_record_hash)


# ══════════════════════════════════════════════════════════════════════════════
# §8 Cross-Chain
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CrossChainCertificate:
    cid:             str
    asset_id:        str
    state_hash:      str
    compliance_hash: str
    governance_hash: str
    timestamp:       int


def build_cross_chain_certificate(asset: Asset, timestamp: int) -> CrossChainCertificate:
    """§8.3 — CID = H(I || SH || CH || GH || t)"""
    state_hash      = hash_object(asset.state.value)
    compliance_hash = hash_object(canonicalize({"rules": [
        {"rule_id": r.rule_id, "rule_type": r.rule_type.value, "priority": r.priority}
        for r in asset.compliance_module.rules
    ]}))
    governance_hash = hash_object(canonicalize({
        "authorities": list(asset.governance_module.authorities),
        "quorum_threshold": asset.governance_module.quorum_threshold,
    }))
    cid = construct_cid(asset.asset_id, state_hash, compliance_hash, governance_hash, timestamp)
    return CrossChainCertificate(cid, asset.asset_id, state_hash, compliance_hash, governance_hash, timestamp)


def verify_cross_chain(
    cert: CrossChainCertificate,
    dest_asset_id: str,
    dest_compliance_hash: str,
    dest_governance_hash: str,
) -> tuple[bool, str]:
    """§8.9 verify_crosschain"""
    if dest_asset_id != cert.asset_id:
        return False, "Asset_ID changed — invariant violated"
    recomputed = construct_cid(
        cert.asset_id, cert.state_hash, cert.compliance_hash,
        cert.governance_hash, cert.timestamp,
    )
    if recomputed != cert.cid:
        return False, "CID recomputation mismatch"
    if dest_compliance_hash != cert.compliance_hash:
        return False, "Compliance downgrade detected"
    if dest_governance_hash != cert.governance_hash:
        return False, "Governance hash changed"
    return True, ""


# ══════════════════════════════════════════════════════════════════════════════
# §9 Settlement
# ══════════════════════════════════════════════════════════════════════════════

def is_replay(event: TransferEvent, ledger_history: set[str]) -> bool:
    """§9.6 Replay protection."""
    tx_id = construct_tx_id(
        event.sender, event.receiver, event.amount, event.nonce, event.timestamp,
    )
    return tx_id in ledger_history


def build_settlement_proof(
    event: TransferEvent, block_height: int, state_hash: str,
) -> SettlementProof:
    tx_id = construct_tx_id(
        event.sender, event.receiver, event.amount, event.nonce, event.timestamp,
    )
    return SettlementProof(tx_id, block_height, state_hash, event.timestamp)


# ══════════════════════════════════════════════════════════════════════════════
# §2.7 Transfer Executor
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class TransferOutput:
    success:     bool
    tx_id:       Optional[str] = None
    proof:       Optional[SettlementProof] = None
    fee_record:  Optional[str] = None
    error:       Optional[str] = None
    failed_step: Optional[str] = None


def execute_transfer(
    asset: Asset,
    event: TransferEvent,
    sender_records: list[IdentityRecord],
    receiver_records: list[IdentityRecord],
    ledger_history: set[str],
    block_height: int,
    sanctions: Optional[SanctionsRegistry] = None,
    required_jurisdictions: Optional[list[str]] = None,
) -> TransferOutput:
    """§2.6 Deterministic 7-step transfer execution."""

    def fail(step: str, msg: str) -> TransferOutput:
        return TransferOutput(False, failed_step=step, error=msg)

    if is_replay(event, ledger_history):
        return fail("REPLAY_CHECK", "Duplicate TxID — replay rejected")

    tx_id = construct_tx_id(
        event.sender, event.receiver, event.amount, event.nonce, event.timestamp,
    )

    if asset.state != AssetState.ACTIVE:
        return fail("STATE_CHECK", f"Asset state {asset.state.value} is not ACTIVE")

    if asset.identity_level >= IdentityLevel.VERIFIED:
        ok, err = enforce_identity_level(
            asset.identity_level, sender_records, receiver_records,
            event.timestamp, required_jurisdictions,
        )
        if not ok:
            return fail("IDENTITY", err)

    ctx = ComplianceContext(asset, event.sender, event.receiver,
                            event.amount, event.timestamp, sanctions)
    decision = evaluate_compliance(asset.compliance_module, ctx)
    if not decision.allowed:
        rule_id = decision.blocked_by.rule_id if decision.blocked_by else "unknown"
        return fail("COMPLIANCE", f"Blocked by rule: {rule_id}")

    try:
        fee_result = distribute_fees(asset.fee_module, event.amount, tx_id, event.timestamp)
    except ValueError as e:
        return fail("FEE_ROUTING", str(e))

    proof = SettlementProof(tx_id, block_height, "", event.timestamp)
    return TransferOutput(
        success=True,
        tx_id=tx_id,
        proof=proof,
        fee_record=fee_result.fee_record_hash,
    )
