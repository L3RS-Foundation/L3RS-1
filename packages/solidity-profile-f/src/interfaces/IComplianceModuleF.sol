// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: L3RS-1 v1.0.0 §4 (Compliance Engine), §2.1 (Asset Object), §13.12 (Canonical Hashing),
//         07-profile-f.md (ComplianceModule Solidity interface).
// Profile F implements Hybrid Public-Private Architecture per L3RS-1 §17.7.

/// @title IComplianceModuleF
/// @notice The Profile F ComplianceModule interface.
/// @dev The module realizes the total decision function C : E → {0, 1} per L3RS-1 §4.3.
///      It is total. It never reverts. It always returns (allow, reasonCode).
///      Its canonical hash is the input to Phase Two's PG[Σ] signing prelude as C_hash,
///      and to L3RS-1 §13.12 ComplianceHash used in the CrossChainMetadata object X
///      per §13.9.
interface IComplianceModuleF {
    // L3RS-1 §4.2: a rule is a tuple (RID, TYPE, SCOPE, TRIGGER, CONDITION, ACTION, PRIORITY).
    struct Rule {
        bytes32 rid;
        RuleType ruleType;
        bytes32 scope;
        bytes32 trigger;
        bytes condition;
        EnforcementAction action;
        uint16 priority;
    }

    // L3RS-1 §4.4: the nine mandatory rule types for Profile F conformance.
    enum RuleType {
        TRANSFER_ELIGIBILITY,
        INVESTOR_CLASSIFICATION,
        HOLDING_PERIOD,
        GEOGRAPHIC_RESTRICTION,
        SANCTIONS_SCREENING,
        TRANSACTION_THRESHOLD,
        AML_TRIGGER,
        MARKET_RESTRICTION,
        REDEMPTION_ELIGIBILITY
    }

    // L3RS-1 §4.7: the five enforcement actions.
    enum EnforcementAction {
        REJECT,
        FREEZE,
        RESTRICT,
        FLAG,
        REQUIRE_DISCLOSURE
    }

    /// @notice Evaluate whether an event is permitted under the current policy.
    /// @dev Implements the total decision function C : E → {0, 1} per L3RS-1 §4.3.
    ///      This function is total. It MUST NOT revert. It MUST return on every input.
    ///      The first blocking rule in priority order terminates evaluation per §4.5.
    /// @param assetRef The asset this evaluation applies to.
    /// @param sender The originator address.
    /// @param receiver The beneficiary address.
    /// @param amount The transfer amount.
    /// @param context Additional context (jurisdictions, timestamps, travel rule payload).
    /// @return allow True if C(e) = ALLOW, false otherwise.
    /// @return reasonCode On block, a structured reason code; zero on allow.
    function evaluate(
        address assetRef,
        address sender,
        address receiver,
        uint256 amount,
        bytes calldata context
    ) external view returns (bool allow, bytes32 reasonCode);

    /// @notice Return the canonical ComplianceModule hash.
    /// @dev ComplianceHash = H(serialize(ComplianceModule)) per L3RS-1 §13.12.
    ///      H is SHA-3-256 with domain string "T3RRA-POLICY-HASH-v1" per Cryptographic
    ///      Specification §1.2 and §14. The serialized form follows the canonical rules
    ///      of L3RS-1 §13.11. This hash is what Phase Two's PG[Σ] prelude binds as C_hash.
    function complianceHash() external view returns (bytes32);

    /// @notice Return the rule set in priority order.
    /// @dev L3RS-1 §4.2 rule structure. Rules are evaluated in ascending PRIORITY.
    function getRules() external view returns (Rule[] memory);

    /// @notice Return the amendment version of this module.
    /// @dev Versioned amendment is governed per Whitepaper v3.3 and L3RS-1 §4.6.
    function version() external view returns (uint256);
}
