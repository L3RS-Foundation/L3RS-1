// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Theorem 15.3 — Cross-Chain Downgrade Resistance.
// Source: L3RS-1 v1.0.0 §15.5. Mapped in 06-theorems.md Part A.
//
// Formal statement: "Compliance and governance configuration cannot be downgraded
// during cross-chain transfer."
//
// Proof sketch: CID = H(I ‖ StateHash ‖ ComplianceHash ‖ GovHash ‖ Timestamp).
// Destination verifies ComplianceHash_dest = ComplianceHash_origin. Under collision
// resistance, an adversary cannot forge an equivalent hash for a weakened policy.
//
// Phase One applicability: partial. The bridge is Phase Five. Phase One owns the
// origin-side construction — the CrossChainMetadata object X per L3RS-1 §13.9, the
// ComplianceHash and GovHash computations per §13.12, and the CID construction per
// §2.12. The destination-side verification is left to Phase Five.

import {BaseTest} from "../BaseTest.t.sol";

contract Theorem03_CrossChainDowngrade is BaseTest {
    /// @notice Mutating the ComplianceModule's serialized form changes ComplianceHash
    ///         and therefore changes the derived CID per §2.12 and §13.12.
    function test_T3_complianceMutationChangesHash() public {
        bytes32 complianceHashBefore = compliance.complianceHash();
        bytes32 cidBefore = asset.computeCID();

        // Any non-trivial change to the compliance rule set must rehash.
        vm.prank(issuer);
        compliance.addSanctionedAddress(holderB);

        bytes32 complianceHashAfter = compliance.complianceHash();
        bytes32 cidAfter = asset.computeCID();

        assertTrue(complianceHashBefore != complianceHashAfter, "T3: ComplianceHash unchanged under rule mutation");
        assertTrue(cidBefore != cidAfter, "T3: CID unchanged despite ComplianceHash change");
    }

    /// @notice Mutating the governance authority set changes GovHash and therefore CID.
    function test_T3_governanceMutationChangesHash() public {
        bytes32 govHashBefore = asset.governanceHash();
        bytes32 cidBefore = asset.computeCID();

        address newAuth = makeAddr("gov4");
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _rotateDigest(gov3, newAuth, nonce, deadline);
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, digest);

        asset.rotateAuthority(gov3, newAuth, nonce, deadline, sigs);

        bytes32 govHashAfter = asset.governanceHash();
        bytes32 cidAfter = asset.computeCID();

        assertTrue(govHashBefore != govHashAfter, "T3: GovHash unchanged after authority rotation");
        assertTrue(cidBefore != cidAfter, "T3: CID unchanged after governance change");
    }

    /// @notice The CID is H(I ‖ S ‖ ComplianceHash ‖ GovHash ‖ ts) per L3RS-1 §2.12.
    ///         Changing any input must change the output.
    function test_T3_cidCoversEveryInput(
        uint8 stateMutation,
        uint64 ts
    ) public {
        vm.assume(ts != 0);
        vm.assume(ts < type(uint64).max); // ts + 1 below must not overflow uint64
        bytes32 baseline = asset.computeCIDWith(
            asset.assetId(),
            asset.currentState(),
            compliance.complianceHash(),
            asset.governanceHash(),
            ts
        );

        // Flip the state enum to any other valid state.
        uint8 newState = stateMutation % 7;
        vm.assume(newState != uint8(asset.currentState()));
        bytes32 mutatedState = asset.computeCIDWith(
            asset.assetId(),
            asset.stateFromIndex(newState),
            compliance.complianceHash(),
            asset.governanceHash(),
            ts
        );
        assertTrue(baseline != mutatedState, "T3: CID invariant to state change");

        // Mutate the timestamp by one.
        bytes32 mutatedTs = asset.computeCIDWith(
            asset.assetId(),
            asset.currentState(),
            compliance.complianceHash(),
            asset.governanceHash(),
            ts + 1
        );
        assertTrue(baseline != mutatedTs, "T3: CID invariant to timestamp change");
    }

    /// @notice Canonical serialization is deterministic per L3RS-1 §13.11. Two calls
    ///         on identical inputs must produce identical bytes.
    function test_T3_canonicalSerializationIsDeterministic() public view {
        bytes memory s1 = compliance.canonicalSerialization();
        bytes memory s2 = compliance.canonicalSerialization();
        assertEq(keccak256(s1), keccak256(s2), "T3: canonical serialization non-deterministic");
    }
}
