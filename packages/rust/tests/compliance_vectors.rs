//! Cross-language compliance conformance: runs the shared corpus
//! (test-vectors/compliance_vectors.json) through the Rust engine and asserts
//! each decision matches the golden expectation. §11.5.
use l3rs1::modules::*;
use l3rs1::types::*;
use serde_json::Value;
use std::collections::HashMap;

fn ident(s: &str) -> IdentityStatus {
    match s {
        "VALID" => IdentityStatus::Valid,
        "EXPIRED" => IdentityStatus::Expired,
        "REVOKED" => IdentityStatus::Revoked,
        _ => IdentityStatus::Unknown,
    }
}
fn rtype(s: &str) -> RuleType {
    match s {
        "TRANSFER_ELIGIBILITY" => RuleType::TransferEligibility,
        "INVESTOR_CLASSIFICATION" => RuleType::InvestorClassification,
        "HOLDING_PERIOD" => RuleType::HoldingPeriod,
        "GEOGRAPHIC_RESTRICTION" => RuleType::GeographicRestriction,
        "SANCTIONS_SCREENING" => RuleType::SanctionsScreening,
        "TRANSACTION_THRESHOLD" => RuleType::TransactionThreshold,
        "AML_TRIGGER" => RuleType::AmlTrigger,
        "MARKET_RESTRICTION" => RuleType::MarketRestriction,
        "REDEMPTION_ELIGIBILITY" => RuleType::RedemptionEligibility,
        other => panic!("unknown rule type {other}"),
    }
}
fn action(s: &str) -> EnforcementAction {
    match s {
        "REJECT" => EnforcementAction::Reject,
        "FREEZE" => EnforcementAction::Freeze,
        "RESTRICT" => EnforcementAction::Restrict,
        "FLAG" => EnforcementAction::Flag,
        _ => EnforcementAction::RequireDisclosure,
    }
}
fn astate(s: &str) -> AssetState {
    match s {
        "ISSUED" => AssetState::Issued,
        "ACTIVE" => AssetState::Active,
        "RESTRICTED" => AssetState::Restricted,
        "FROZEN" => AssetState::Frozen,
        "SUSPENDED" => AssetState::Suspended,
        "REDEEMED" => AssetState::Redeemed,
        _ => AssetState::Burned,
    }
}
fn party(v: &Value) -> PartyAttributes {
    PartyAttributes {
        identity_status: ident(v["identityStatus"].as_str().unwrap()),
        jurisdiction: v["jurisdiction"].as_str().unwrap_or("").to_string(),
        investor_class: v["investorClass"].as_str().unwrap_or("").to_string(),
        acquisition_time: v["acquisitionTime"].as_i64().unwrap_or(0),
    }
}

#[test]
fn compliance_corpus_matches_golden() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/compliance_vectors.json"
    );
    let raw = std::fs::read_to_string(path).expect("read corpus");
    let corpus: Value = serde_json::from_str(&raw).expect("parse corpus");
    let cases = corpus["cases"].as_array().expect("cases array");

    let mut failures = Vec::new();
    for tc in cases {
        let name = tc["name"].as_str().unwrap();

        let mut attestations = HashMap::new();
        if let Some(obj) = tc["attestations"].as_object() {
            for (k, v) in obj {
                attestations.insert(
                    rtype(k),
                    OracleAttestation {
                        cleared: v["cleared"].as_bool().unwrap(),
                        version: v["version"].as_u64().unwrap(),
                        source_hash: v["sourceHash"].as_str().unwrap().to_string(),
                        valid_until: v["validUntil"].as_i64().unwrap(),
                    },
                );
            }
        }

        let rules = tc["module"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| ComplianceRule {
                rule_id: r["ruleId"].as_str().unwrap().to_string(),
                rule_type: rtype(r["ruleType"].as_str().unwrap()),
                scope: r["scope"].as_str().unwrap().to_string(),
                trigger: r["trigger"].as_str().unwrap_or("").to_string(),
                priority: r["priority"].as_i64().unwrap() as i32,
                action: action(r["action"].as_str().unwrap()),
                params: serde_json::from_value(r["params"].clone()).unwrap_or_default(),
            })
            .collect();
        let module = ComplianceModule { rules };

        let ctx = EvalContext {
            amount: tc["amount"].as_u64().unwrap(),
            timestamp: tc["timestamp"].as_i64().unwrap(),
            jurisdiction: tc["jurisdiction"].as_str().unwrap().to_string(),
            sender: party(&tc["sender"]),
            receiver: party(&tc["receiver"]),
            attestations,
        };

        let dec = evaluate_compliance(&module, astate(tc["state"].as_str().unwrap()), &ctx);
        let got_blocked = dec.blocked_by.as_ref().map(|r| r.rule_id.clone());
        let exp_allowed = tc["expected"]["allowed"].as_bool().unwrap();
        let exp_blocked = tc["expected"]["blockedBy"].as_str().map(|s| s.to_string());

        if dec.allowed != exp_allowed || got_blocked != exp_blocked {
            failures.push(format!(
                "{name}: got allowed={} blockedBy={:?}, expected allowed={} blockedBy={:?}",
                dec.allowed, got_blocked, exp_allowed, exp_blocked
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "Rust compliance vector mismatches:\n{}",
        failures.join("\n")
    );
    println!("Rust compliance vectors: {} passed", cases.len());
}
