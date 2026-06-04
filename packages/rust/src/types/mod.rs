//! L3RS-1 Type Definitions — §13 Canonical Data Schema
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssetType {
    Cbdc,
    IndustryStable,
    RegulatedSecurity,
    Utility,
    Governance,
    StorageBacked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssetState {
    Issued,
    Active,
    Restricted,
    Frozen,
    Suspended,
    Redeemed,
    Burned,
}

impl AssetState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Burned)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdentityLevel {
    Unbound = 0,
    Verified = 1,
    SovereignValidated = 2,
    MultiJurisdiction = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityStatus {
    Valid,
    Expired,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleType {
    TransferEligibility,
    InvestorClassification,
    HoldingPeriod,
    GeographicRestriction,
    SanctionsScreening,
    TransactionThreshold,
    AmlTrigger,
    MarketRestriction,
    RedemptionEligibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementAction {
    Reject,
    Freeze,
    Restrict,
    Flag,
    RequireDisclosure,
}

impl EnforcementAction {
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Reject | Self::Freeze | Self::Restrict)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceAction {
    FreezeBalance,
    UnfreezeBalance,
    RestrictTransfer,
    SeizeAsset,
    ForceRedemption,
    EmergencyRollback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceRule {
    pub rule_id: String,
    pub rule_type: RuleType,
    pub scope: String,
    pub trigger: String,
    pub priority: i32,
    pub action: EnforcementAction,
    #[serde(default)]
    pub params: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceModule {
    pub rules: Vec<ComplianceRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceModule {
    pub authorities: Vec<String>,
    pub quorum_threshold: u32,
    pub override_types: Vec<GovernanceAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeAllocation {
    pub recipient: String,
    pub basis_points: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeModule {
    pub base_rate_basis_points: u32,
    pub allocations: Vec<FeeAllocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRecord {
    pub identity_hash: String,
    pub verification_authority: String,
    pub jurisdiction_identity: String,
    pub expiry: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferEvent {
    pub asset_id: String,
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub nonce: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementProof {
    pub tx_id: String,
    pub block_height: u64,
    pub state_hash: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
pub struct ComplianceDecision {
    pub allowed: bool,
    pub blocked_by: Option<ComplianceRule>,
}
