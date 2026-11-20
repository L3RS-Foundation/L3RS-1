// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Theorem 15.5 — Governance Safety, Handler-based.
// Source: L3RS-1 v1.0.0 §15.7. Mapped in 06-theorems.md Part A.
// DESIGN.md §9 TODO 10 (done in 6C).
//
// Under the Handler-driven campaign the fuzzer triggers governance overrides
// via the Handler's governanceFreezeAction, emergencyRollbackAction, and
// bumpVersionAction. Every successful override must have been reached with at
// least the quorum number of distinct signers (⌈2/3 × N⌉ = 2 for N = 3).

import {Test} from "forge-std/Test.sol";
import {L3RS1Handler} from "../handlers/L3RS1Handler.sol";

contract T5_Handler_GovernanceSafety is Test {
    L3RS1Handler internal handler;

    function setUp() public {
        handler = new L3RS1Handler();
        targetContract(address(handler));

        bytes4[] memory s = new bytes4[](21);
        for (uint256 i = 0; i < 8; i++) s[i] = L3RS1Handler.transferAction.selector;
        for (uint256 i = 8; i < 12; i++) s[i] = L3RS1Handler.authenticatedTransferAction.selector;
        s[12] = L3RS1Handler.issueAction.selector;
        s[13] = L3RS1Handler.issueAction.selector;
        s[14] = L3RS1Handler.redeemAction.selector;
        s[15] = L3RS1Handler.redeemAction.selector;
        s[16] = L3RS1Handler.addSanctionedAction.selector;
        s[17] = L3RS1Handler.governanceFreezeAction.selector;
        s[18] = L3RS1Handler.emergencyRollbackAction.selector;
        s[19] = L3RS1Handler.setFeeRecipientAction.selector;
        s[20] = L3RS1Handler.bumpVersionAction.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: s}));
    }

    /// @notice Minority never overrides: `minSigners` across every successful
    ///         override is at least the quorum threshold of 2.
    function invariant_T5_minoritySignerCountNeverBelowThreshold() public view {
        if (handler.ghost_overrideSuccessCount() == 0) return;
        assertGe(
            handler.ghost_minSignersOnSuccessfulOverride(),
            2,
            "T5: Handler observed a successful override with < 2 distinct signers"
        );
    }

    /// @notice Contract-side cross-check: L3RS1Asset's own
    ///         `minSignersForAnySuccessfulOverride` tracks the same property
    ///         for asset-scoped overrides. Handler's counter includes
    ///         ComplianceModule.bumpVersion as well, which is not in the
    ///         asset's overrideCount — so the asset counter may be lower than
    ///         the Handler's (more conservative) count. Still must be ≥ 2 on
    ///         every successful asset override.
    function invariant_T5_assetOverrideCounterAgrees() public view {
        if (handler.asset().overrideCount() == 0) return;
        assertGe(
            handler.asset().minSignersForAnySuccessfulOverride(),
            2,
            "T5: asset-side minSigners below quorum"
        );
    }
}
