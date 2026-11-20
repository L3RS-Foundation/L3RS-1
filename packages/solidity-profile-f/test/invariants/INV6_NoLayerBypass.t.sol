// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// INV-6 — No Layer Bypass, Handler-based (6C).
// Source: Architecture v1.1 §7 INV-6. Mapped in 06-theorems.md Part E.
// DESIGN.md §9 TODO 10 (done in 6C).
//
// Statement: every state-changing operation on L3RS1Asset calls ComplianceModule
// as its first non-view operation. No code path mutates persistent state
// without first passing through `compliance.evaluate`.
//
// Rewired per step 6C: the campaign targets the Handler's action surface, which
// exercises the pipeline under realistic action distribution. The invariant
// asserts two things:
//   1. asset.stateMutationCount() == handler.ghost_successfulMutations()
//      — the Handler's Solidity-level view of successful mutations matches the
//      contract's own counter.
//   2. asset.stateMutationCount() <= asset.complianceCallCount()
//      — every mutation was preceded by a compliance call, but the reverse is
//      not required (compliance rejections bump complianceCallCount without
//      mutating state). This is the correct statement of INV-6; the prior
//      equality was too strict and would fail under realistic exploration.

import {Test} from "forge-std/Test.sol";
import {L3RS1Handler} from "../handlers/L3RS1Handler.sol";

contract INV6_NoLayerBypass is Test {
    L3RS1Handler internal handler;

    function setUp() public {
        handler = new L3RS1Handler();
        targetContract(address(handler));

        // Weighted selector pool. Transfers most common, governance rare.
        bytes4[] memory s = new bytes4[](21);
        // transferAction × 8
        for (uint256 i = 0; i < 8; i++) s[i] = L3RS1Handler.transferAction.selector;
        // authenticatedTransferAction × 4
        for (uint256 i = 8; i < 12; i++) s[i] = L3RS1Handler.authenticatedTransferAction.selector;
        // issueAction × 2
        s[12] = L3RS1Handler.issueAction.selector;
        s[13] = L3RS1Handler.issueAction.selector;
        // redeemAction × 2
        s[14] = L3RS1Handler.redeemAction.selector;
        s[15] = L3RS1Handler.redeemAction.selector;
        // rare governance / admin
        s[16] = L3RS1Handler.addSanctionedAction.selector;
        s[17] = L3RS1Handler.governanceFreezeAction.selector;
        s[18] = L3RS1Handler.emergencyRollbackAction.selector;
        s[19] = L3RS1Handler.setFeeRecipientAction.selector;
        s[20] = L3RS1Handler.bumpVersionAction.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: s}));
    }

    /// @notice INV-6 part A: every successful mutation observed by the Handler
    ///         matches the contract's `stateMutationCount`.
    function invariant_INV6_handlerGhostMatchesContract() public view {
        assertEq(
            handler.asset().stateMutationCount(),
            handler.ghost_successfulMutations(),
            "INV-6: Handler ghost diverged from asset.stateMutationCount"
        );
    }

    /// @notice INV-6 part B: every state mutation was preceded by a compliance
    ///         call. The inequality is strict: compliance rejections raise
    ///         complianceCallCount without advancing stateMutationCount.
    function invariant_INV6_mutationsAreComplianceGated() public view {
        assertLe(
            handler.asset().stateMutationCount(),
            handler.asset().complianceCallCount(),
            "INV-6: a state mutation occurred without a prior compliance call"
        );
    }

    /// @notice INV-6 part C: every mutable selector on L3RS1Asset that is
    ///         enumerated in `mutableSelectors()` has the
    ///         `selectorCallsCompliance` flag set.
    function invariant_INV6_structuralFlagsIntact() public view {
        bytes4[] memory sels = handler.asset().mutableSelectors();
        for (uint256 i = 0; i < sels.length; i++) {
            assertTrue(
                handler.asset().selectorCallsCompliance(sels[i]),
                "INV-6: a mutable selector is missing the compliance flag"
            );
        }
    }
}
