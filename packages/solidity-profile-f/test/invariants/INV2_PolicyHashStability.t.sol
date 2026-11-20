// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// INV-2 — Signing-Compliance Binding (partial in Phase One — the C_hash precondition
// for Layer 2 PG[Σ] is exposed correctly).
// Source: Architecture v1.1 §7. Mapped in 06-theorems.md Part E.
//
// Statement: ComplianceModule exposes a canonical hash whose value changes only
// when the module's canonical serialization changes, and whose value is computable
// by any verifier who observes the serialized module bytes. Phase One names this
// function complianceHash(), following L3RS-1 §13.12 naming. The canonical hash
// uses H = SHA-3-256 with domain string "T3RRA-POLICY-HASH-v1" per Cryptographic
// Specification §1.2 and §14.
//
// Note on deviation from 06-theorems.md Part E text. The invariant text in
// 06-theorems.md reads: "ComplianceModule exposes policyHash() returning keccak256
// of bytecode; hash changes only when bytecode changes." Phase One implements the
// L3RS-1 §13.12 normative construction — SHA-3-256 over canonical object
// serialization, not keccak256 over raw runtime bytecode — per the conflict
// resolution recorded in DESIGN.md §2 and the user's accepted restatement reply.
// The function is named complianceHash(). DESIGN.md records this deviation.

import {Test} from "forge-std/Test.sol";
import {ComplianceModule} from "../../src/ComplianceModule.sol";

contract INV2_PolicyHashStability is Test {
    ComplianceModule internal compliance;
    address internal issuer;
    uint256 internal issuerKey;
    address internal gov1;
    uint256 internal gov1Key;
    address internal gov2;
    uint256 internal gov2Key;
    address internal gov3;
    uint256 internal gov3Key;

    function setUp() public {
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        (gov1, gov1Key) = makeAddrAndKey("gov1");
        (gov2, gov2Key) = makeAddrAndKey("gov2");
        (gov3, gov3Key) = makeAddrAndKey("gov3");

        address[] memory authorities = new address[](3);
        authorities[0] = gov1;
        authorities[1] = gov2;
        authorities[2] = gov3;

        // Deploy as the issuer so the module records issuer as its owner; owner-gated
        // methods (addSanctionedAddress, allowJurisdictionPair) must succeed below.
        vm.prank(issuer);
        compliance = new ComplianceModule(authorities);

        targetContract(address(compliance));
    }

    function _signDigest(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _bumpVersionSigs(uint256 nonce, uint256 deadline) internal view returns (bytes[] memory sigs) {
        bytes32 structHash = keccak256(abi.encode(
            compliance.BUMP_VERSION_TYPEHASH(), address(compliance), nonce, deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", compliance.DOMAIN_SEPARATOR(), structHash));
        sigs = new bytes[](2);
        sigs[0] = _signDigest(gov1Key, digest);
        sigs[1] = _signDigest(gov2Key, digest);
    }

    /// @notice Two reads of complianceHash() without intervening mutation are equal.
    function test_INV2_readIsStable() public view {
        bytes32 a = compliance.complianceHash();
        bytes32 b = compliance.complianceHash();
        assertEq(a, b, "INV-2: complianceHash returned different values on consecutive reads");
    }

    /// @notice Adding a rule changes the hash.
    function test_INV2_rulesetMutationChangesHash() public {
        bytes32 before = compliance.complianceHash();

        vm.prank(issuer);
        compliance.addSanctionedAddress(address(0xBEEF));

        bytes32 afterHash = compliance.complianceHash();
        assertTrue(before != afterHash, "INV-2: complianceHash unchanged after rule addition");
    }

    /// @notice An amendment that changes the version but not the rule set still
    ///         changes the hash, because the amendment version is part of the
    ///         canonical serialization per §13.12.
    function test_INV2_versionBumpChangesHash() public {
        bytes32 before = compliance.complianceHash();

        uint256 nonce = compliance.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _bumpVersionSigs(nonce, deadline);
        compliance.bumpVersion(nonce, deadline, sigs);

        bytes32 afterHash = compliance.complianceHash();
        assertTrue(before != afterHash, "INV-2: version bump did not change complianceHash");
    }

    /// @notice The domain string used inside the canonical hash is exactly the
    ///         spec-prescribed string. The contract exposes the domain string for
    ///         third-party re-derivation.
    function test_INV2_domainStringMatchesSpec() public view {
        assertEq(
            compliance.canonicalHashDomain(),
            bytes("T3RRA-POLICY-HASH-v1"),
            unicode"INV-2: canonical hash domain string does not match Cryptographic Specification §1.2"
        );
    }

    /// @notice Third-party verifier can re-derive the hash from the exposed
    ///         serialization and get the same value as complianceHash() returns.
    function test_INV2_thirdPartyRederivationAgrees() public view {
        bytes memory serialized = compliance.canonicalSerialization();
        bytes32 derived = compliance.hashOf(serialized);
        assertEq(derived, compliance.complianceHash(), "INV-2: third-party hash does not match complianceHash");
    }

    /// @notice Invariant campaign: the hash changes if and only if the serialization
    ///         changes. The contract exposes paired ghosts tracking hash changes and
    ///         serialization-byte changes.
    function invariant_INV2_hashChangesIffSerializationChanges() public view {
        assertEq(
            compliance.serializationChangeCount(),
            compliance.hashChangeCount(),
            "INV-2: hash and serialization change counts diverged"
        );
    }
}
