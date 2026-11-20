// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Theorem 15.2 — Replay Resistance.
// Source: L3RS-1 v1.0.0 §15.4. Mapped in 06-theorems.md Part A.
//
// Formal statement: "A previously executed transaction cannot be replayed to produce
// duplicate state mutation."
//
// Proof sketch: Each transaction includes TxID = H(sender ‖ receiver ‖ amount ‖
// nonce ‖ timestamp). Nonce uniqueness ensures nonce_new ≠ nonce_previous. Ledger
// history maintains a record of TxID. Replay requires a collision in H or reuse
// of a nonce. Under collision resistance, replay is infeasible.
//
// Phase One obligation: every transfer commits a TxID to an on-contract registry.
// A submitted transfer with a previously-seen TxID is rejected. Two transfers
// with identical (sender, receiver, amount) but distinct nonces are accepted.

import {BaseTest} from "../BaseTest.t.sol";

contract Theorem02_ReplayResistance is BaseTest {
    function test_T2_distinctNoncesProduceDistinctTxIds() public view {
        bytes32 tx1 = asset.computeTxId(holderA, holderB, 100, 1, uint64(block.timestamp));
        bytes32 tx2 = asset.computeTxId(holderA, holderB, 100, 2, uint64(block.timestamp));
        assertTrue(tx1 != tx2, "T2: distinct nonces must yield distinct TxIDs");
    }

    function test_T2_submittedTxIdCannotBeResubmitted() public {
        uint256 nonce = 42;
        uint64 ts = uint64(block.timestamp);

        _whitelistAndGrantId(holderA, holderB);
        vm.prank(issuer);
        asset.issue(holderA, 1_000);

        vm.prank(holderA);
        asset.authenticatedTransfer(holderB, 100, nonce, ts);

        // Replay with the same (sender, receiver, amount, nonce, timestamp) must fail.
        vm.prank(holderA);
        vm.expectRevert();
        asset.authenticatedTransfer(holderB, 100, nonce, ts);
    }

    function test_T2_replayAfterStateChangeStillFails() public {
        uint256 nonce = 7;
        uint64 ts = uint64(block.timestamp);

        _whitelistAndGrantId(holderA, holderB);
        vm.prank(issuer);
        asset.issue(holderA, 1_000);

        vm.prank(holderA);
        asset.authenticatedTransfer(holderB, 100, nonce, ts);

        // Unrelated transfer in between.
        vm.prank(holderA);
        asset.authenticatedTransfer(holderB, 50, nonce + 1, ts);

        // Replay of the first TxID still fails.
        vm.prank(holderA);
        vm.expectRevert();
        asset.authenticatedTransfer(holderB, 100, nonce, ts);
    }

    function test_T2_forgedTxIdRejected() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        bytes32 forged = bytes32(uint256(1));
        assertFalse(asset.isSeenTxId(forged), "T2: forged TxID should not be seen before use");
    }

    // ---------- invariant ----------------------------------------------------------

    /// @notice Invariant: at any point in the fuzzer's sequence, the set of seen
    ///         TxIDs has no duplicates and each entry is the canonical H of its
    ///         five-tuple per §15.4.
    function invariant_T2_noDuplicateTxIds() public view {
        require(asset.isImplemented(), "skeleton-revert; invariant cannot be trusted until L3RS1Asset is implemented");
        assertEq(
            asset.seenTxIdCount(),
            asset.distinctTxIdCount(),
            "T2: duplicate TxID accepted into the registry"
        );
    }

    // ---------- helpers ------------------------------------------------------------

    function _whitelistAndGrantId(address from, address to) internal {
        _grantAttestationVA(from, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantAttestationVA(to, JURISDICTION_US, 2, block.timestamp + 365 days);
        vm.prank(issuer);
        compliance.allowJurisdictionPair(JURISDICTION_GB, JURISDICTION_US);
    }
}
