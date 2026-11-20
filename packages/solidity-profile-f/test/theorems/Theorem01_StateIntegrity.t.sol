// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Theorem 15.1 — State Integrity.
// Source: L3RS-1 v1.0.0 §15.3. Mapped in 06-theorems.md Part A.
//
// Formal statement: "No unauthorized state transition can occur."
//
// Proof sketch (from the standard): State transitions are S_new = f(S_old, event).
// The event must pass ComplianceSuccess ∧ IdentitySuccess ∧ GovernanceSuccess.
// Compliance is deterministic and blocking; identity validation rejects invalid
// identity; governance override requires valid signatures at quorum. An adversary
// must break signature unforgeability or bypass compliance evaluation to alter
// state. Under assumptions, this is computationally infeasible.
//
// Phase One obligation: every state-changing operation on L3RS1Asset must invoke
// ComplianceModule, IdentityAttestation, and (where applicable) the governance
// quorum before mutating state. Any path that mutates state without all three is
// a fail.

import {BaseTest} from "../BaseTest.t.sol";
import {ILifecycle} from "../../src/interfaces/ILifecycle.sol";
import {ReasonCodes} from "../../src/libraries/ReasonCodes.sol";

contract Theorem01_StateIntegrity is BaseTest {
    // ---------- direct negative tests ----------------------------------------------

    /// @notice A transfer with failing compliance must not mutate state.
    /// @dev Derives from L3RS-1 §15.3 ComplianceSuccess clause.
    function test_T1_complianceRejectBlocksTransfer() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        // Configure the policy so every transfer blocks on SANCTIONS.
        vm.prank(issuer);
        compliance.addSanctionedAddress(holderB);

        uint256 amountBefore = asset.balanceOf(holderA);
        uint256 receiverBefore = asset.balanceOf(holderB);

        vm.prank(holderA);
        vm.expectRevert(); // state-change attempts revert when compliance blocks per §2.6.
        asset.transfer(holderB, 100);

        assertEq(asset.balanceOf(holderA), amountBefore, "T1: sender balance changed despite compliance reject");
        assertEq(asset.balanceOf(holderB), receiverBefore, "T1: receiver balance changed despite compliance reject");
    }

    /// @notice A transfer with missing identity attestation must not mutate state
    ///         when ID >= 1 per L3RS-1 §3.2.
    function test_T1_identityMissingBlocksTransfer() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        // Asset is deployed with ID tier 2. holderA has no Sovereign-Validated attestation.
        uint256 senderBefore = asset.balanceOf(holderA);
        uint256 receiverBefore = asset.balanceOf(holderB);

        vm.prank(holderA);
        vm.expectRevert();
        asset.transfer(holderB, 100);

        assertEq(asset.balanceOf(holderA), senderBefore, "T1: sender balance changed despite identity missing");
        assertEq(asset.balanceOf(holderB), receiverBefore, "T1: receiver balance changed despite identity missing");
    }

    /// @notice A governance override without quorum must not mutate state.
    /// @dev Quorum per L3RS-1 §5.4 and Theorem 15.5.
    function test_T1_unauthorizedOverrideBlocksStateChange() public {
        assertTrue(asset.isImplemented(), "skeleton-revert; test cannot be trusted until L3RS1Asset is implemented");
        ILifecycle.State stateBefore = asset.currentState();

        // Single authority signature is below the ceil(2/3 * 3) = 2 threshold.
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _oneSig(gov1Key, _freezeDigest(nonce, deadline));

        vm.expectRevert();
        asset.governanceFreeze(nonce, deadline, sigs);

        assertEq(uint8(asset.currentState()), uint8(stateBefore), "T1: state mutated without governance quorum");
    }

    // ---------- invariant (property-based) -----------------------------------------

    /// @notice Invariant: L3RS1Asset.currentState() only changes through a path that
    ///         called ComplianceModule, IdentityAttestation, and (if applicable) the
    ///         governance quorum verifier. The target contract exposes a ghost
    ///         variable transitionEvidence() that records the last checks that passed.
    function invariant_T1_everyStateChangeHasEvidence() public view {
        require(asset.isImplemented(), "skeleton-revert; invariant cannot be trusted until L3RS1Asset is implemented");
        // transitionEvidence is a ghost value set inside L3RS1Asset at every state
        // mutation. It is a bitmask of the three guards. All three must be set at
        // every transition per L3RS-1 §15.3.
        uint256 evidence = asset.lastTransitionEvidence();
        if (asset.transitionCount() == 0) return; // nothing to check before the first transition
        assertTrue(evidence & 0x01 != 0, "T1: compliance success bit missing");
        assertTrue(evidence & 0x02 != 0, "T1: identity success bit missing");
        // Governance bit is only required for governance-initiated transitions.
        if (asset.lastTransitionWasGovernance()) {
            assertTrue(evidence & 0x04 != 0, "T1: governance success bit missing for governance transition");
        }
    }
}
