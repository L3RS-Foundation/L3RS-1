// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Theorem 15.5 — Governance Safety.
// Source: L3RS-1 v1.0.0 §15.7. Mapped in 06-theorems.md Part A.
//
// Formal statement: "No minority subset of governance authorities can execute
// restricted override actions."
//
// Proof sketch: override requires k ≥ (2/3) N. If adversary controls k < threshold,
// override validation fails. Thus governance safety reduces to signature
// unforgeability and key security.
//
// Phase One obligation: every override action — FREEZE_BALANCE, UNFREEZE_BALANCE,
// RESTRICT_TRANSFER, SEIZE_ASSET, FORCE_REDEMPTION, EMERGENCY_ROLLBACK per
// L3RS-1 §5.3 — requires at least ⌈(2/3) × N⌉ distinct valid authority
// signatures verified by real ECDSA recovery. EMERGENCY_ROLLBACK specifically
// requires quorum per §5.5 and is not possible without it.

import {BaseTest} from "../BaseTest.t.sol";
import {ILifecycle} from "../../src/interfaces/ILifecycle.sol";

contract Theorem05_GovernanceSafety is BaseTest {
    function test_T5_singleSignerCannotFreeze() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _oneSig(gov1Key, _freezeDigest(nonce, deadline));

        vm.expectRevert();
        asset.governanceFreeze(nonce, deadline, sigs);
    }

    function test_T5_quorumCanFreeze() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _freezeDigest(nonce, deadline));

        asset.governanceFreeze(nonce, deadline, sigs);

        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.FROZEN), "T5: quorum freeze did not take effect");
    }

    function test_T5_emergencyRollbackRequiresQuorum() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");

        // First, move the asset out of ACTIVE so rollback has somewhere to return to.
        {
            uint256 freezeNonce = asset.governanceNonce();
            uint256 freezeDeadline = block.timestamp + 1 hours;
            bytes[] memory freezeSigs = _twoSigs(gov1Key, gov2Key, _freezeDigest(freezeNonce, freezeDeadline));
            asset.governanceFreeze(freezeNonce, freezeDeadline, freezeSigs);
        }

        // Single signer rollback: must fail.
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory solo = _oneSig(gov1Key, _rollbackDigest(nonce, deadline));
        vm.expectRevert();
        asset.emergencyRollback(nonce, deadline, solo);

        // Quorum rollback: must succeed.
        bytes[] memory quorum = _twoSigs(gov1Key, gov2Key, _rollbackDigest(nonce, deadline));
        asset.emergencyRollback(nonce, deadline, quorum);
    }

    function test_T5_duplicateSignerDoesNotCountTwice() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signDigest(gov1Key, _freezeDigest(nonce, deadline));
        bytes[] memory duplicated = new bytes[](2);
        duplicated[0] = sig;
        duplicated[1] = sig; // same recovered address; must dedup by address per §8.2

        vm.expectRevert();
        asset.governanceFreeze(nonce, deadline, duplicated);
    }

    // Theorem 15.5 invariant moved to test/invariants/T5_Handler_GovernanceSafety.t.sol
    // as of step 6C (Handler-based campaign per DESIGN.md §9 TODO 10). The
    // contract-state minSignersForAnySuccessfulOverride is still checked there
    // via the Handler's ghost cross-check. This file retains the unit tests
    // for single-signer rejection, quorum success, duplicate-signer handling,
    // and emergency-rollback-requires-quorum.
}
