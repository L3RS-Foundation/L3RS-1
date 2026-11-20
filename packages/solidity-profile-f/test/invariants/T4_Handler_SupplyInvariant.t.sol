// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Theorem 15.4 — Double Issuance Prevention (supply accounting), Handler-based.
// Source: L3RS-1 v1.0.0 §15.6. Mapped in 06-theorems.md Part A.
// DESIGN.md §9 TODO 10 (done in 6C).
//
// Under the Handler-driven campaign the fuzzer performs a weighted mix of
// transfers, mints, burns, and admin actions. The contract's supply
// accounting (mintedTotal, burnedTotal, totalSupply) must remain consistent
// with the Handler's own ghost totals across the entire campaign.

import {Test} from "forge-std/Test.sol";
import {L3RS1Handler} from "../handlers/L3RS1Handler.sol";

contract T4_Handler_SupplyInvariant is Test {
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

    /// @notice totalSupply = mintedTotal − burnedTotal, at all times, by
    ///         construction. This holds on-chain regardless of the Handler.
    function invariant_T4_contractSupplyIdentity() public view {
        assertEq(
            handler.asset().totalSupply(),
            handler.asset().mintedTotal() - handler.asset().burnedTotal(),
            "T4: totalSupply desynchronized from mint/burn accounting"
        );
    }

    /// @notice Handler ghost cross-check. Handler accumulates ghost_totalMinted
    ///         and ghost_totalBurned independently. totalSupply must equal
    ///         their difference — if it doesn't, either the Handler has not
    ///         observed every mint/burn, or the contract is mutating supply
    ///         through a path the Handler cannot see.
    function invariant_T4_handlerGhostMatchesContract() public view {
        assertEq(
            handler.asset().totalSupply(),
            handler.ghost_totalMinted() - handler.ghost_totalBurned(),
            "T4: Handler ghost totals diverge from on-chain supply"
        );
    }

    /// @notice mintedTotal and burnedTotal monotonically increase — transfers
    ///         must not mutate either counter.
    function invariant_T4_mintedBurnedMonotonic() public view {
        // Contract-side mintedTotal equals Handler ghost (all mints routed through
        // issueAction which increments both); burnedTotal equals Handler ghost.
        assertEq(
            handler.asset().mintedTotal(),
            handler.ghost_totalMinted(),
            "T4: asset.mintedTotal diverged from handler ghost"
        );
        assertEq(
            handler.asset().burnedTotal(),
            handler.ghost_totalBurned(),
            "T4: asset.burnedTotal diverged from handler ghost"
        );
    }
}
