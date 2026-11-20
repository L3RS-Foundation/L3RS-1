// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Theorem 15.6 — Atomic Settlement.
// Source: L3RS-1 v1.0.0 §15.8. Mapped in 06-theorems.md Part A.
//
// Formal statement: "No partial state mutation occurs under settlement failure."
//
// Proof sketch: SettlementSuccess ⇐⇒ Compliance ∧ Identity ∧ Governance ∧ Fee ∧
// StateCommit. If any component fails, SettlementSuccess = FALSE. State commit
// executes only after all validations. No partial state persists.
//
// Phase One obligation: L3RS1Asset.transfer runs the seven-step L3RS-1 §2.6
// sequence. Every failure mode leaves the pre-state untouched AND surfaces a
// structured reason identifying the exact step that rejected. The T6 tests
// assert on the TransferStepRejected(step, reasonCode) error directly so a
// revert at one step cannot pass as a revert at another.

import {BaseTest} from "../BaseTest.t.sol";
import {ReasonCodes} from "../../src/libraries/ReasonCodes.sol";
import {L3RS1Asset} from "../../src/L3RS1Asset.sol";

contract Theorem06_AtomicSettlement is BaseTest {
    struct Snapshot {
        uint256 senderBalance;
        uint256 receiverBalance;
        uint256 totalSupply;
        uint256 lastNonce;
        bytes32 lastTxId;
    }

    function _snapshot() internal view returns (Snapshot memory s) {
        s.senderBalance = asset.balanceOf(holderA);
        s.receiverBalance = asset.balanceOf(holderB);
        s.totalSupply = asset.totalSupply();
        s.lastNonce = asset.lastNonceFor(holderA);
        s.lastTxId = asset.lastCommittedTxId();
    }

    function _assertUnchanged(Snapshot memory before, string memory label) internal view {
        Snapshot memory afterSnap = _snapshot();
        assertEq(before.senderBalance, afterSnap.senderBalance, string.concat(label, ": sender balance mutated"));
        assertEq(before.receiverBalance, afterSnap.receiverBalance, string.concat(label, ": receiver balance mutated"));
        assertEq(before.totalSupply, afterSnap.totalSupply, string.concat(label, ": totalSupply mutated"));
        assertEq(before.lastNonce, afterSnap.lastNonce, string.concat(label, ": nonce recorded on failed tx"));
        assertEq(before.lastTxId, afterSnap.lastTxId, string.concat(label, ": TxID registered on failed tx"));
    }

    /// @dev Bring both counterparties to valid Sovereign-Validated identity and mint
    ///      starting balance to holderA. Each atomic-failure test then disables exactly
    ///      one of the seven pipeline steps to verify the step-specific reason.
    function _setupValidBaseline() internal {
        _grantAttestationVA(holderA, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantAttestationVA(holderB, JURISDICTION_US, 2, block.timestamp + 365 days);
        vm.startPrank(issuer);
        compliance.allowJurisdictionPair(JURISDICTION_GB, JURISDICTION_US);
        asset.issue(holderA, 1_000_000);
        vm.stopPrank();
    }

    // ---- step 2: compliance ---------------------------------------------------

    function test_T6_complianceFailureIsAtomic() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        _setupValidBaseline();

        vm.prank(issuer);
        compliance.addSanctionedAddress(holderB);

        Snapshot memory before = _snapshot();
        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(L3RS1Asset.TransferStepRejected.selector, uint8(2), ReasonCodes.SANCTIONS)
        );
        asset.transfer(holderB, 100);
        _assertUnchanged(before, "T6-compliance");
    }

    // ---- step 1: identity -----------------------------------------------------

    function test_T6_identityFailureIsAtomic() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        _setupValidBaseline();

        // Revoke holderA's GB attestation so step 1 rejects with IDENTITY_REVOKED
        // per L3RS-1 §3.6. holderA has only the GB record in this test baseline,
        // so revoking it causes getStatus(holderA) to return REVOKED.
        _revokeAttestationGov(holderA, JURISDICTION_GB);

        Snapshot memory before = _snapshot();
        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(L3RS1Asset.TransferStepRejected.selector, uint8(1), ReasonCodes.IDENTITY_REVOKED)
        );
        asset.transfer(holderB, 100);
        _assertUnchanged(before, "T6-identity");
    }

    // ---- step 3: governance ---------------------------------------------------

    function test_T6_governanceFailureIsAtomic() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        _setupValidBaseline();

        // FROZEN state disallows transfer per L3RS-1 §2.5 matrix.
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _freezeDigest(nonce, deadline));
        asset.governanceFreeze(nonce, deadline, sigs);

        Snapshot memory before = _snapshot();
        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(L3RS1Asset.TransferStepRejected.selector, uint8(3), ReasonCodes.STATE_DISALLOWS)
        );
        asset.transfer(holderB, 100);
        _assertUnchanged(before, "T6-governance");
    }

    // ---- step 5: fee routing --------------------------------------------------

    function test_T6_feeFailureIsAtomic() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        _setupValidBaseline();

        // A fee recipient contract that reverts on its onFeeReceived hook triggers a
        // failure at step 5 per L3RS-1 §2.6.
        address revertingRecipient = address(new RevertOnReceipt());
        vm.prank(issuer);
        asset.setFeeRecipient(revertingRecipient);

        Snapshot memory before = _snapshot();
        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(L3RS1Asset.TransferStepRejected.selector, uint8(5), ReasonCodes.FEE_TRANSFER_FAILED)
        );
        asset.transfer(holderB, 100_000);
        _assertUnchanged(before, "T6-fee");
    }

    // ---- reentrancy probe -----------------------------------------------------

    function test_T6_reentrancyGuardIsPresent() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        assertTrue(asset.reentrancyGuardIsActive(), "T6: no reentrancy guard active on transfers");
    }
}

/// @notice Helper for the step-5 fee-failure test. Any call to its fallback reverts,
///         which makes the fee-recipient hook fail within the transfer pipeline.
contract RevertOnReceipt {
    fallback() external payable {
        revert("fee recipient rejects");
    }
    receive() external payable {
        revert("fee recipient rejects");
    }
}
