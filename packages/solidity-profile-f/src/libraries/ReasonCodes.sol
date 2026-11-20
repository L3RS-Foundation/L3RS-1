// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: L3RS-1 v1.0.0 §4.7 (enforcement actions), §4.8 (sanctions screening),
//         §4.9 (holding period), §4.10 (transaction threshold), §14.10 (oracle timeout),
//         07-profile-f.md (reason code table).

/// @title ReasonCodes
/// @notice Canonical reason codes returned by ComplianceModule.evaluate on block.
/// @dev Every code is a bytes32 constant. Zero means ALLOW. A non-zero code identifies
///      the rule type that blocked the transfer. All L3RS-1 implementations on the same
///      profile must use identical reason codes so external reviewers can compare
///      compliance events across deployments.
library ReasonCodes {
    bytes32 internal constant NONE                     = bytes32(0);

    // Mandatory L3RS-1 §4.4 rule types mapped to reason codes.
    bytes32 internal constant TRANSFER_INELIGIBLE      = keccak256("L3RS-1/REASON/TRANSFER_INELIGIBLE");
    bytes32 internal constant INVESTOR_CLASS           = keccak256("L3RS-1/REASON/INVESTOR_CLASS");
    bytes32 internal constant HOLDING_PERIOD           = keccak256("L3RS-1/REASON/HOLDING_PERIOD");
    bytes32 internal constant GEOGRAPHIC               = keccak256("L3RS-1/REASON/GEOGRAPHIC");
    bytes32 internal constant SANCTIONS                = keccak256("L3RS-1/REASON/SANCTIONS");
    bytes32 internal constant THRESHOLD                = keccak256("L3RS-1/REASON/THRESHOLD");
    bytes32 internal constant AML                      = keccak256("L3RS-1/REASON/AML");
    bytes32 internal constant MARKET                   = keccak256("L3RS-1/REASON/MARKET");
    bytes32 internal constant REDEMPTION               = keccak256("L3RS-1/REASON/REDEMPTION");

    // Oracle unavailability per L3RS-1 §4.8 (sanctions feed) and §14.10 (generic timeout).
    bytes32 internal constant ORACLE_UNAVAILABLE       = keccak256("L3RS-1/REASON/ORACLE_UNAVAILABLE");

    // Identity-binding failures per L3RS-1 §3.6. Exposed here for cross-contract use.
    bytes32 internal constant IDENTITY_INVALID         = keccak256("L3RS-1/REASON/IDENTITY_INVALID");
    bytes32 internal constant IDENTITY_EXPIRED         = keccak256("L3RS-1/REASON/IDENTITY_EXPIRED");
    bytes32 internal constant IDENTITY_REVOKED         = keccak256("L3RS-1/REASON/IDENTITY_REVOKED");

    // Governance and lifecycle failures surfaced during transfer per L3RS-1 §2.6 step 3.
    bytes32 internal constant GOVERNANCE_BLOCK         = keccak256("L3RS-1/REASON/GOVERNANCE_BLOCK");
    bytes32 internal constant STATE_DISALLOWS          = keccak256("L3RS-1/REASON/STATE_DISALLOWS");

    // Post-redemption rejection per L3RS-1 §2.5. Distinct from STATE_DISALLOWS so
    // external consumers can distinguish a mandate-level redemption event from a
    // governance-driven FROZEN / RESTRICTED state.
    bytes32 internal constant ASSET_REDEEMED           = keccak256("L3RS-1/REASON/ASSET_REDEEMED");

    // Transfer-rule and fee-routing failures per L3RS-1 §2.6 steps 4 and 5.
    bytes32 internal constant INSUFFICIENT_BALANCE     = keccak256("L3RS-1/REASON/INSUFFICIENT_BALANCE");
    bytes32 internal constant FEE_TRANSFER_FAILED      = keccak256("L3RS-1/REASON/FEE_TRANSFER_FAILED");

    // Replay-resistance failure per L3RS-1 §15.4 Theorem 15.2.
    bytes32 internal constant REPLAY_DETECTED          = keccak256("L3RS-1/REASON/REPLAY_DETECTED");
}
