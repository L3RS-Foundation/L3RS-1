//! L3RS-1 Core Modules — Rust
use crate::{crypto::construct_tx_id, types::*, L3rsError};
use std::collections::HashSet;

// ── §2.5 State Transitions ────────────────────────────────────────────────────

static TRANSITIONS: &[(&str, &str, &str)] = &[
    ("ISSUED", "ACTIVATION", "ACTIVE"),
    ("ACTIVE", "BREACH", "RESTRICTED"),
    ("ACTIVE", "FREEZE", "FROZEN"),
    ("RESTRICTED", "CLEARED", "ACTIVE"),
    ("FROZEN", "RELEASE", "ACTIVE"),
    ("ACTIVE", "REDEMPTION", "REDEEMED"),
    ("REDEEMED", "FINALIZATION", "BURNED"),
    ("ACTIVE", "SUSPENSION", "SUSPENDED"),
    ("SUSPENDED", "REINSTATEMENT", "ACTIVE"),
];

pub fn apply_state_transition(
    current: &AssetState,
    trigger: &str,
) -> Result<AssetState, L3rsError> {
    if current.is_terminal() {
        return Err(L3rsError::InvalidStateTransition(
            "BURNED is terminal".into(),
        ));
    }
    let cur = serde_json::to_value(current)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    for (from, t, to) in TRANSITIONS {
        if *from == cur && *t == trigger {
            return serde_json::from_value(serde_json::Value::String(to.to_string()))
                .map_err(|e| L3rsError::Serialization(e.to_string()));
        }
    }
    Err(L3rsError::InvalidStateTransition(format!(
        "No transition from {} via {}",
        cur, trigger
    )))
}

// ── §6.12 Fee Validation ─────────────────────────────────────────────────────

pub fn validate_fee_module(fee: &FeeModule) -> Result<(), L3rsError> {
    let total: u32 = fee.allocations.iter().map(|a| a.basis_points).sum();
    if total != 10_000 {
        return Err(L3rsError::Validation(format!(
            "Fee allocations must sum to 10000; got {}",
            total
        )));
    }
    Ok(())
}

// ── §3.6 Identity Status ─────────────────────────────────────────────────────

pub fn identity_status(record: &IdentityRecord, now: i64) -> IdentityStatus {
    if record.revoked {
        return IdentityStatus::Revoked;
    }
    if now >= record.expiry {
        return IdentityStatus::Expired;
    }
    IdentityStatus::Valid
}

// ── §9.6 Replay Protection ────────────────────────────────────────────────────

pub fn is_replay(event: &TransferEvent, history: &HashSet<String>) -> Result<bool, L3rsError> {
    let tx_id = construct_tx_id(
        &event.sender,
        &event.receiver,
        event.amount,
        &event.nonce,
        event.timestamp,
    )?;
    Ok(history.contains(&tx_id))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::crypto::*;
    use crate::modules::*;
    use crate::types::*;
    use std::collections::HashSet;

    const PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const TS: i64 = 1740355200;
    const NONCE: &str = "0000000000000001";
    const EXPECTED: &str = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a";

    #[test]
    fn asset_id_canonical_vector() {
        assert_eq!(construct_asset_id(PUBKEY, TS, NONCE).unwrap(), EXPECTED);
    }

    #[test]
    fn asset_id_deterministic() {
        let a = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        let b = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn asset_id_nonce_sensitive() {
        let a = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        let b = construct_asset_id(PUBKEY, TS, "0000000000000002").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_key_sort() {
        let obj = serde_json::json!({"z": 3, "a": 1, "m": 2});
        let out = canonicalize(&obj).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":1,"m":2,"z":3}"#);
    }

    #[test]
    fn state_transitions_valid() {
        let cases = [
            (AssetState::Issued, "ACTIVATION", AssetState::Active),
            (AssetState::Active, "BREACH", AssetState::Restricted),
            (AssetState::Active, "FREEZE", AssetState::Frozen),
            (AssetState::Restricted, "CLEARED", AssetState::Active),
            (AssetState::Frozen, "RELEASE", AssetState::Active),
            (AssetState::Active, "REDEMPTION", AssetState::Redeemed),
            (AssetState::Redeemed, "FINALIZATION", AssetState::Burned),
            (AssetState::Active, "SUSPENSION", AssetState::Suspended),
            (AssetState::Suspended, "REINSTATEMENT", AssetState::Active),
        ];
        for (from, trigger, expected) in cases {
            let result = apply_state_transition(&from, trigger).unwrap();
            assert_eq!(result, expected, "failed: {:?} --{}-->", from, trigger);
        }
    }

    #[test]
    fn burned_is_terminal() {
        assert!(apply_state_transition(&AssetState::Burned, "ACTIVATION").is_err());
    }

    #[test]
    fn invalid_transition_rejected() {
        assert!(apply_state_transition(&AssetState::Issued, "FREEZE").is_err());
    }

    #[test]
    fn cid_deterministic() {
        let fill = |c: &str| c.repeat(64);
        let a = construct_cid(&fill("a"), &fill("b"), &fill("c"), &fill("d"), 1000).unwrap();
        let b = construct_cid(&fill("a"), &fill("b"), &fill("c"), &fill("d"), 1000).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn cid_timestamp_sensitive() {
        let fill = |c: &str| c.repeat(64);
        let a = construct_cid(&fill("a"), &fill("b"), &fill("c"), &fill("d"), 1000).unwrap();
        let b = construct_cid(&fill("a"), &fill("b"), &fill("c"), &fill("d"), 1001).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fee_validation() {
        let valid = FeeModule {
            base_rate_basis_points: 100,
            allocations: vec![
                FeeAllocation {
                    recipient: "a".into(),
                    basis_points: 2000,
                },
                FeeAllocation {
                    recipient: "b".into(),
                    basis_points: 3000,
                },
                FeeAllocation {
                    recipient: "c".into(),
                    basis_points: 2000,
                },
                FeeAllocation {
                    recipient: "d".into(),
                    basis_points: 2500,
                },
                FeeAllocation {
                    recipient: "e".into(),
                    basis_points: 500,
                },
            ],
        };
        assert!(validate_fee_module(&valid).is_ok());

        let invalid = FeeModule {
            base_rate_basis_points: 100,
            allocations: vec![FeeAllocation {
                recipient: "x".into(),
                basis_points: 5000,
            }],
        };
        assert!(validate_fee_module(&invalid).is_err());
    }

    #[test]
    fn identity_status_cases() {
        let now = 1_740_355_200i64;
        let valid = IdentityRecord {
            identity_hash: "".into(),
            verification_authority: "".into(),
            jurisdiction_identity: "US".into(),
            expiry: 9_999_999_999,
            revoked: false,
        };
        let expired = IdentityRecord {
            expiry: 1_000_000_000,
            ..valid.clone()
        };
        let revoked = IdentityRecord {
            revoked: true,
            ..valid.clone()
        };
        assert_eq!(identity_status(&valid, now), IdentityStatus::Valid);
        assert_eq!(identity_status(&expired, now), IdentityStatus::Expired);
        assert_eq!(identity_status(&revoked, now), IdentityStatus::Revoked);
    }

    #[test]
    fn replay_protection() {
        let ev = TransferEvent {
            asset_id: "a".into(),
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 1000,
            nonce: NONCE.into(),
            timestamp: TS,
        };
        let tx_id =
            construct_tx_id(&ev.sender, &ev.receiver, ev.amount, &ev.nonce, ev.timestamp).unwrap();
        let history: HashSet<String> = [tx_id].into();
        assert!(is_replay(&ev, &history).unwrap());

        let ev2 = TransferEvent {
            nonce: "0000000000000002".into(),
            ..ev
        };
        assert!(!is_replay(&ev2, &history).unwrap());
    }
}

// ── §4 Compliance Engine ──────────────────────────────────────────────────────

/// Resolved, attested attributes of a transfer party (§3.6, §4.6 inputs).
#[derive(Debug, Clone)]
pub struct PartyAttributes {
    pub identity_status: IdentityStatus,
    pub jurisdiction: String,
    pub investor_class: String,
    pub acquisition_time: i64, // unix seconds; basis for holding period
}

impl Default for PartyAttributes {
    fn default() -> Self {
        Self {
            identity_status: IdentityStatus::Unknown,
            jurisdiction: String::new(),
            investor_class: String::new(),
            acquisition_time: 0,
        }
    }
}

/// §10.15 contract for external data sources (sanctions/AML/reserve). MUST be
/// hash-anchored, versioned and time-bounded. Unknown, stale, or mismatched
/// attestations evaluate as BLOCKING.
#[derive(Debug, Clone)]
pub struct OracleAttestation {
    pub cleared: bool,
    pub version: u64,
    pub source_hash: String,
    pub valid_until: i64, // unix seconds; stale at/after this time
}

/// Everything the engine needs to evaluate every §4.4 category deterministically.
#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    pub amount: u64,
    pub timestamp: i64,
    pub jurisdiction: String,
    pub sender: PartyAttributes,
    pub receiver: PartyAttributes,
    pub attestations: std::collections::HashMap<RuleType, OracleAttestation>,
}

/// §4.3 — `C: E → {0,1}` as the conjunction of all in-scope rule predicates,
/// evaluated in ascending priority order, first blocking rule terminating
/// (§4.5). Enforces Invariant I₂ (§10.6): any FALSE blocks.
pub fn evaluate_compliance(
    module: &ComplianceModule,
    state: AssetState,
    ctx: &EvalContext,
) -> ComplianceDecision {
    if !matches!(state, AssetState::Active) {
        return ComplianceDecision { allowed: false, blocked_by: None };
    }
    let mut rules = module.rules.clone();
    rules.sort_by_key(|r| r.priority);
    for rule in &rules {
        if rule.scope != "*" && rule.scope != ctx.jurisdiction {
            continue;
        }
        if !eval_rule(rule, ctx) && rule.action.is_blocking() {
            return ComplianceDecision { allowed: false, blocked_by: Some(rule.clone()) };
        }
    }
    ComplianceDecision { allowed: true, blocked_by: None }
}

/// Rule predicate rᵢ: E → {TRUE, FALSE} (§4.6). Every branch fails closed:
/// missing inputs and unverifiable oracle state all evaluate to FALSE (block).
/// The match is exhaustive over all nine §4.4 categories — no silent fallthrough.
fn eval_rule(rule: &ComplianceRule, ctx: &EvalContext) -> bool {
    match rule.rule_type {
        RuleType::TransferEligibility => {
            ctx.sender.identity_status == IdentityStatus::Valid
                && ctx.receiver.identity_status == IdentityStatus::Valid
        }
        RuleType::InvestorClassification => {
            let allowed = list_param(&rule.params, "allowedClasses");
            if allowed.is_empty() || ctx.receiver.investor_class.is_empty() {
                return false;
            }
            allowed.iter().any(|c| c == &ctx.receiver.investor_class)
        }
        RuleType::HoldingPeriod => match num_param(&rule.params, "holdingPeriodSec") {
            Some(period) if ctx.sender.acquisition_time != 0 => {
                (ctx.timestamp - ctx.sender.acquisition_time) >= period
            }
            _ => false,
        },
        RuleType::GeographicRestriction => {
            if ctx.sender.jurisdiction.is_empty() || ctx.receiver.jurisdiction.is_empty() {
                return false;
            }
            let blocked = list_param(&rule.params, "blockedJurisdictions");
            !blocked.contains(&ctx.sender.jurisdiction)
                && !blocked.contains(&ctx.receiver.jurisdiction)
        }
        RuleType::TransactionThreshold => match num_param(&rule.params, "thresholdAmount") {
            Some(t) => (ctx.amount as i64) <= t,
            None => false,
        },
        RuleType::MarketRestriction => {
            match (
                num_param(&rule.params, "windowOpen"),
                num_param(&rule.params, "windowClose"),
            ) {
                (Some(open), Some(close)) => ctx.timestamp >= open && ctx.timestamp < close,
                _ => attestation_clears(rule, ctx),
            }
        }
        RuleType::SanctionsScreening
        | RuleType::AmlTrigger
        | RuleType::RedemptionEligibility => attestation_clears(rule, ctx),
    }
}

/// §10.15 oracle contract: present, anchored to the operator-pinned source hash,
/// at/above the pinned minimum version, and within its freshness window.
fn attestation_clears(rule: &ComplianceRule, ctx: &EvalContext) -> bool {
    let att = match ctx.attestations.get(&rule.rule_type) {
        Some(a) => a,
        None => return false, // unknown oracle state → block
    };
    let pinned = str_param(&rule.params, "sourceHash");
    if pinned.is_empty() || att.source_hash != pinned {
        return false;
    }
    if let Some(min_v) = num_param(&rule.params, "minVersion") {
        if (att.version as i64) < min_v {
            return false;
        }
    }
    if ctx.timestamp >= att.valid_until {
        return false;
    }
    att.cleared
}

fn num_param(params: &std::collections::HashMap<String, serde_json::Value>, key: &str) -> Option<i64> {
    params
        .get(key)
        .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
}

fn str_param(params: &std::collections::HashMap<String, serde_json::Value>, key: &str) -> String {
    params.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn list_param(params: &std::collections::HashMap<String, serde_json::Value>, key: &str) -> Vec<String> {
    params
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod compliance_tests {
    use super::*;
    use crate::types::*;

    fn params(v: serde_json::Value) -> std::collections::HashMap<String, serde_json::Value> {
        serde_json::from_value(v).unwrap()
    }

    fn sanctions_module() -> ComplianceModule {
        ComplianceModule {
            rules: vec![ComplianceRule {
                rule_id: "r1".into(),
                rule_type: RuleType::SanctionsScreening,
                scope: "*".into(),
                trigger: "TRANSFER".into(),
                priority: 1,
                action: EnforcementAction::Reject,
                params: params(serde_json::json!({"sourceHash":"OFAC-2026-06-04","minVersion":7})),
            }],
        }
    }

    fn ctx(att: Option<OracleAttestation>) -> EvalContext {
        let mut attestations = std::collections::HashMap::new();
        if let Some(a) = att {
            attestations.insert(RuleType::SanctionsScreening, a);
        }
        EvalContext {
            amount: 100,
            timestamp: 1_740_355_200,
            jurisdiction: "GE".into(),
            sender: PartyAttributes { identity_status: IdentityStatus::Valid, jurisdiction: "GE".into(), ..Default::default() },
            receiver: PartyAttributes { identity_status: IdentityStatus::Valid, jurisdiction: "GE".into(), ..Default::default() },
            attestations,
        }
    }

    #[test]
    fn fails_closed_without_attestation() {
        assert!(!evaluate_compliance(&sanctions_module(), AssetState::Active, &ctx(None)).allowed);
    }

    #[test]
    fn blocks_wrong_hash() {
        let a = OracleAttestation { cleared: true, version: 9, source_hash: "WRONG".into(), valid_until: 1_740_358_800 };
        assert!(!evaluate_compliance(&sanctions_module(), AssetState::Active, &ctx(Some(a))).allowed);
    }

    #[test]
    fn blocks_stale_version() {
        let a = OracleAttestation { cleared: true, version: 3, source_hash: "OFAC-2026-06-04".into(), valid_until: 1_740_358_800 };
        assert!(!evaluate_compliance(&sanctions_module(), AssetState::Active, &ctx(Some(a))).allowed);
    }

    #[test]
    fn blocks_expired() {
        let a = OracleAttestation { cleared: true, version: 9, source_hash: "OFAC-2026-06-04".into(), valid_until: 1_740_355_199 };
        assert!(!evaluate_compliance(&sanctions_module(), AssetState::Active, &ctx(Some(a))).allowed);
    }

    #[test]
    fn blocks_sanctions_hit() {
        let a = OracleAttestation { cleared: false, version: 9, source_hash: "OFAC-2026-06-04".into(), valid_until: 1_740_358_800 };
        assert!(!evaluate_compliance(&sanctions_module(), AssetState::Active, &ctx(Some(a))).allowed);
    }

    #[test]
    fn allows_valid() {
        let a = OracleAttestation { cleared: true, version: 9, source_hash: "OFAC-2026-06-04".into(), valid_until: 1_740_358_800 };
        assert!(evaluate_compliance(&sanctions_module(), AssetState::Active, &ctx(Some(a))).allowed);
    }

    #[test]
    fn geographic_blocks() {
        let module = ComplianceModule {
            rules: vec![ComplianceRule {
                rule_id: "g".into(), rule_type: RuleType::GeographicRestriction, scope: "*".into(),
                trigger: "TRANSFER".into(), priority: 1, action: EnforcementAction::Reject,
                params: params(serde_json::json!({"blockedJurisdictions":["GE"]})),
            }],
        };
        assert!(!evaluate_compliance(&module, AssetState::Active, &ctx(None)).allowed);
    }

    #[test]
    fn transfer_eligibility_blocks_bad_identity() {
        let mut c = ctx(None);
        c.receiver.identity_status = IdentityStatus::Expired;
        let module = ComplianceModule {
            rules: vec![ComplianceRule {
                rule_id: "t".into(), rule_type: RuleType::TransferEligibility, scope: "*".into(),
                trigger: "TRANSFER".into(), priority: 1, action: EnforcementAction::Reject,
                params: std::collections::HashMap::new(),
            }],
        };
        assert!(!evaluate_compliance(&module, AssetState::Active, &c).allowed);
    }
}
