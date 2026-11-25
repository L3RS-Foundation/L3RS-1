// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// IdentityAttestation unit tests.
// Source: L3RS-1 v1.0.0 §3 (Identity Binding), §3.2 (ID tier), §3.3 (Identity
//         Record), §3.5 (Verification Authority registry), §3.6 (Identity
//         status). DESIGN.md §5a (placeholder HID), §8.2 (shared sig library,
//         two signing surfaces on this contract).
//
// Stage 2 tests. Identity grant is now VA-signed over DOMAIN_SEPARATOR_VA.
// Governance actions (registerVA, deregisterVA, revokeAttestation) are
// quorum-gated over DOMAIN_SEPARATOR_GOVERNANCE.

import {Test} from "forge-std/Test.sol";
import {IdentityAttestation} from "../../src/IdentityAttestation.sol";
import {MockZKVerifier} from "../../src/MockZKVerifier.sol";
import {IZKVerifier} from "../../src/interfaces/IZKVerifier.sol";

/// @dev Test-only verifier that rejects every proof. Used to verify that
///      IdentityAttestation surfaces proof failures correctly.
contract RejectingZKVerifier is IZKVerifier {
    function verify(bytes calldata, bytes calldata) external pure returns (bool) {
        return false;
    }
    function verifierId() external pure returns (string memory) {
        return "reject-all";
    }
}

contract IdentityAttestationTest is Test {
    IdentityAttestation internal identity;

    address internal issuer;
    uint256 internal issuerKey;
    address internal holder;
    uint256 internal holderKey;
    address internal outsider;
    uint256 internal outsiderKey;
    address internal gov1;
    uint256 internal gov1Key;
    address internal gov2;
    uint256 internal gov2Key;
    address internal gov3;
    uint256 internal gov3Key;
    address internal va1;
    uint256 internal va1Key;
    address internal va2;
    uint256 internal va2Key;

    bytes2 internal constant JURISDICTION_GB = bytes2("GB");

    uint256 internal _vaNonceCursor;

    function setUp() public {
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        (holder, holderKey) = makeAddrAndKey("holder");
        (outsider, outsiderKey) = makeAddrAndKey("outsider");
        (gov1, gov1Key) = makeAddrAndKey("gov1");
        (gov2, gov2Key) = makeAddrAndKey("gov2");
        (gov3, gov3Key) = makeAddrAndKey("gov3");
        (va1, va1Key) = makeAddrAndKey("va1");
        (va2, va2Key) = makeAddrAndKey("va2");

        address[] memory authorities = new address[](3);
        authorities[0] = gov1;
        authorities[1] = gov2;
        authorities[2] = gov3;

        address[] memory initialVAs = new address[](1);
        initialVAs[0] = va1;

        vm.startPrank(issuer);
        MockZKVerifier mockVerifier = new MockZKVerifier();
        identity = new IdentityAttestation(authorities, initialVAs, mockVerifier);
        vm.stopPrank();
    }

    // ----- signature helpers ---------------------------------------------------

    function _signDigest(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _eip712VA(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", identity.DOMAIN_SEPARATOR_VA(), structHash));
    }

    function _eip712Gov(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", identity.DOMAIN_SEPARATOR_GOVERNANCE(), structHash));
    }

    function _attestationStructHash(IdentityAttestation.Attestation memory a) internal view returns (bytes32) {
        return keccak256(abi.encode(
            identity.ATTESTATION_TYPEHASH(),
            a.holder, a.hid, a.jurisdiction, a.tier, a.expiry, a.nonce, a.epoch,
            a.attributeCommitmentsRoot,
            keccak256(a.zkProof)
        ));
    }

    function _makeAttestation(address who, bytes2 j, uint8 tier, uint256 expiry)
        internal
        returns (IdentityAttestation.Attestation memory)
    {
        _vaNonceCursor += 1;
        return IdentityAttestation.Attestation({
            holder: who,
            hid: keccak256(abi.encodePacked(who, j, uint256(tier))),
            jurisdiction: j,
            tier: tier,
            expiry: expiry,
            nonce: _vaNonceCursor,
            epoch: identity.attestationEpoch(who, j),
            attributeCommitmentsRoot: bytes32(0),
            zkProof: ""
        });
    }

    function _grantByVA(uint256 vaKey, IdentityAttestation.Attestation memory a) internal {
        bytes32 digest = _eip712VA(_attestationStructHash(a));
        bytes memory sig = _signDigest(vaKey, digest);
        identity.grantAttestation(a, sig);
    }

    function _twoGovSigs(bytes32 digest) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](2);
        sigs[0] = _signDigest(gov1Key, digest);
        sigs[1] = _signDigest(gov2Key, digest);
    }

    function _oneGovSig(bytes32 digest) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](1);
        sigs[0] = _signDigest(gov1Key, digest);
    }

    function _revokeByGovQuorum(address who, bytes2 j) internal {
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            identity.REVOKE_ATTESTATION_TYPEHASH(), address(identity), who, j, nonce, deadline
        ));
        bytes32 digest = _eip712Gov(structHash);
        identity.revokeAttestation(who, j, nonce, deadline, _twoGovSigs(digest));
    }

    // ----- §3.3 Record field coverage ----------------------------------------

    function test_record_populatesAllSevenFields() public {
        uint256 expiry = block.timestamp + 365 days;
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, expiry);
        _grantByVA(va1Key, a);

        IdentityAttestation.Record memory r = identity.recordOf(holder);
        assertEq(r.hid, a.hid, "IR.HID not set from VA payload");
        assertEq(r.verificationAuthority, va1, "IR.VA not recovered signer");
        assertEq(r.jurisdiction, JURISDICTION_GB, "IR.JI mismatch");
        assertEq(r.tier, 2, "IR.tier mismatch");
        assertEq(r.expiry, expiry, "IR.EXP mismatch");
        assertEq(r.revoked, false, "IR.REV defaulted wrong");
        assertEq(r.attributeCommitmentsRoot, bytes32(0), "IR.ATTR root should be zero when no commitment");
        assertEq(r.zkProof.length, 0, "IR.PROOF should be empty in stage 2");
    }

    function test_grant_recordsRecoveredVA() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantByVA(va1Key, a);
        assertEq(identity.verificationAuthorityOf(holder), va1);
    }

    function test_grant_revertsForUnknownVA() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        // va2 is NOT registered at construction. Signing with va2Key → recovery
        // returns va2 → not in _isVA → revert.
        bytes32 digest = _eip712VA(_attestationStructHash(a));
        bytes memory sig = _signDigest(va2Key, digest);
        vm.expectRevert();
        identity.grantAttestation(a, sig);
    }

    function test_grant_revertsOnNonceReuse() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantByVA(va1Key, a);

        // Reusing the same (va, nonce) tuple reverts even with different holder.
        IdentityAttestation.Attestation memory replayed = a;
        replayed.holder = outsider; // new holder
        bytes32 digest = _eip712VA(_attestationStructHash(replayed));
        bytes memory sig = _signDigest(va1Key, digest);
        vm.expectRevert();
        identity.grantAttestation(replayed, sig);
    }

    function test_grant_distinctNoncesIssueSuccessfully() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantByVA(va1Key, a);

        IdentityAttestation.Attestation memory b = _makeAttestation(outsider, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantByVA(va1Key, b);

        assertEq(identity.verificationAuthorityOf(holder), va1);
        assertEq(identity.verificationAuthorityOf(outsider), va1);
    }

    // ----- VA registry --------------------------------------------------------

    function test_initialVA_listedAndRegistered() public view {
        address[] memory list = identity.vaList();
        assertEq(list.length, 1);
        assertEq(list[0], va1);
        assertTrue(identity.isVA(va1));
        assertFalse(identity.isVA(va2));
    }

    function test_registerVA_addsNewVA() public {
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va2, nonce, deadline
        ));
        bytes32 digest = _eip712Gov(structHash);
        identity.registerVA(va2, nonce, deadline, _twoGovSigs(digest));

        assertTrue(identity.isVA(va2));
        address[] memory list = identity.vaList();
        assertEq(list.length, 2);
    }

    function test_registerVA_revertsWithoutQuorum() public {
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va2, nonce, deadline
        ));
        bytes32 digest = _eip712Gov(structHash);
        bytes[] memory sigs = _oneGovSig(digest);
        vm.expectRevert();
        identity.registerVA(va2, nonce, deadline, sigs);
    }

    function test_deregisterVA_removesVA() public {
        // First add va2 then remove va1.
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 reg = _eip712Gov(keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va2, nonce, deadline
        )));
        identity.registerVA(va2, nonce, deadline, _twoGovSigs(reg));

        nonce = identity.governanceNonce();
        bytes32 dereg = _eip712Gov(keccak256(abi.encode(
            identity.DEREGISTER_VA_TYPEHASH(), address(identity), va1, nonce, deadline
        )));
        identity.deregisterVA(va1, nonce, deadline, _twoGovSigs(dereg));

        assertFalse(identity.isVA(va1));
        assertTrue(identity.isVA(va2));
    }

    function test_deregisteredVA_cannotGrant() public {
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 dereg = _eip712Gov(keccak256(abi.encode(
            identity.DEREGISTER_VA_TYPEHASH(), address(identity), va1, nonce, deadline
        )));
        identity.deregisterVA(va1, nonce, deadline, _twoGovSigs(dereg));

        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        bytes32 attestDigest = _eip712VA(_attestationStructHash(a));
        bytes memory sig = _signDigest(va1Key, attestDigest);
        vm.expectRevert();
        identity.grantAttestation(a, sig);
    }

    // ----- governance-gated revocation ----------------------------------------

    function test_revokeAttestation_flipsRev() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantByVA(va1Key, a);
        _revokeByGovQuorum(holder, JURISDICTION_GB);

        IdentityAttestation.Record memory r = identity.recordOf(holder);
        assertTrue(r.revoked);
        assertEq(uint8(identity.getStatus(holder)), uint8(IdentityAttestation.Status.REVOKED));
    }

    function test_revoke_revertsWithoutQuorum() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantByVA(va1Key, a);

        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _eip712Gov(keccak256(abi.encode(
            identity.REVOKE_ATTESTATION_TYPEHASH(), address(identity), holder, JURISDICTION_GB, nonce, deadline
        )));
        bytes[] memory sigs = _oneGovSig(digest);
        vm.expectRevert();
        identity.revokeAttestation(holder, JURISDICTION_GB, nonce, deadline, sigs);
    }

    // ----- status surface reads correctly after grant + lifecycle -------------

    function test_getStatus_unknownBeforeGrant() public view {
        assertEq(uint8(identity.getStatus(holder)), uint8(IdentityAttestation.Status.UNKNOWN));
    }

    function test_getStatus_validAfterGrant() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantByVA(va1Key, a);
        assertEq(uint8(identity.getStatus(holder)), uint8(IdentityAttestation.Status.VALID));
    }

    function test_getStatus_expiredAfterDeadline() public {
        uint256 expiry = block.timestamp + 10;
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, expiry);
        _grantByVA(va1Key, a);
        vm.warp(expiry + 1);
        assertEq(uint8(identity.getStatus(holder)), uint8(IdentityAttestation.Status.EXPIRED));
    }

    // ----- stage 2 / 3 checkpoint verification --------------------------------
    //
    // These tests are the checkpoint-pause evidence that the two new EIP-712
    // domains are registered against the correct contract address and that VA
    // storage is isolated from governance authority storage.

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    function _expectedDomainSep(string memory name) internal view returns (bytes32) {
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes(name)),
            keccak256(bytes("1")),
            block.chainid,
            address(identity)
        ));
    }

    /// @notice Checkpoint evidence: DOMAIN_SEPARATOR_GOVERNANCE is the EIP-712
    ///         domain separator for ("T3RRA-IdentityAttestation-Governance", "1",
    ///         chainId, identity-contract-address).
    function test_checkpoint_governanceDomainSeparator() public view {
        bytes32 expected = _expectedDomainSep("T3RRA-IdentityAttestation-Governance");
        assertEq(
            identity.DOMAIN_SEPARATOR_GOVERNANCE(),
            expected,
            "checkpoint: governance domain separator does not match expected value"
        );
    }

    /// @notice Checkpoint evidence: DOMAIN_SEPARATOR_VA is the EIP-712 domain
    ///         separator for ("T3RRA-IdentityAttestation-VA", "1", chainId,
    ///         identity-contract-address).
    function test_checkpoint_vaDomainSeparator() public view {
        bytes32 expected = _expectedDomainSep("T3RRA-IdentityAttestation-VA");
        assertEq(
            identity.DOMAIN_SEPARATOR_VA(),
            expected,
            "checkpoint: VA domain separator does not match expected value"
        );
    }

    /// @notice Checkpoint evidence: the two domain separators are distinct.
    ///         A signature valid under one cannot verify under the other.
    function test_checkpoint_domainsAreDistinct() public view {
        assertTrue(
            identity.DOMAIN_SEPARATOR_GOVERNANCE() != identity.DOMAIN_SEPARATOR_VA(),
            "checkpoint: governance and VA domain separators collide"
        );
    }

    /// @notice Checkpoint evidence: a signature under the VA domain does not
    ///         verify under the governance domain. Without domain separation
    ///         a VA signature could be replayed as a governance action.
    function test_checkpoint_vaSignatureRejectedByGovernancePath() public {
        // Sign a "RegisterVA" struct-hash payload under the VA domain. This is
        // a mis-used signature — the governance path expects the governance
        // domain separator. verifyQuorum recovers a different address and the
        // quorum fails.
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va2, nonce, deadline
        ));
        // Sign under the WRONG domain (VA instead of governance).
        bytes32 wrongDigest = _eip712VA(structHash);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signDigest(gov1Key, wrongDigest);
        sigs[1] = _signDigest(gov2Key, wrongDigest);
        vm.expectRevert();
        identity.registerVA(va2, nonce, deadline, sigs);
    }

    /// @notice Checkpoint evidence: VA registry storage and governance authority
    ///         storage are independent. Adding or removing a VA does not change
    ///         the authority set; rotating an authority does not change the VA
    ///         set. No entry appears in both sets by accident.
    function test_checkpoint_vaAndGovernanceStorageIndependent() public {
        // Precondition: gov1, gov2, gov3 are authorities; va1 is the only VA.
        assertTrue(identity.isVA(va1), "precondition: va1 should be VA");
        assertFalse(identity.isVA(gov1), "precondition: gov1 must not be VA");

        // Register va2 via governance quorum.
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _eip712Gov(keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va2, nonce, deadline
        )));
        identity.registerVA(va2, nonce, deadline, _twoGovSigs(digest));

        // Postcondition: va2 is in VA registry. Authorities are unchanged.
        assertTrue(identity.isVA(va2), "va2 should now be a VA");

        address[] memory auths = identity.authorities();
        assertEq(auths.length, 3, "authority count changed after VA registration");
        assertEq(auths[0], gov1);
        assertEq(auths[1], gov2);
        assertEq(auths[2], gov3);

        // An authority is not automatically a VA.
        assertFalse(identity.isVA(gov1), "gov1 must not be VA after unrelated registerVA");
        assertFalse(identity.isVA(gov2), "gov2 must not be VA");
        assertFalse(identity.isVA(gov3), "gov3 must not be VA");

        // Deregister va1; va2 remains, authorities remain.
        nonce = identity.governanceNonce();
        bytes32 deregDigest = _eip712Gov(keccak256(abi.encode(
            identity.DEREGISTER_VA_TYPEHASH(), address(identity), va1, nonce, deadline
        )));
        identity.deregisterVA(va1, nonce, deadline, _twoGovSigs(deregDigest));

        assertFalse(identity.isVA(va1), "va1 should be deregistered");
        assertTrue(identity.isVA(va2), "va2 should still be VA");

        auths = identity.authorities();
        assertEq(auths.length, 3, "authority count changed after deregisterVA");
        assertEq(auths[0], gov1, "authority set mutated by deregisterVA");
    }

    // ----- stage 3 multi-jurisdiction stacking per §3.9 ------------------------

    bytes2 internal constant JURISDICTION_US = bytes2("US");
    bytes2 internal constant JURISDICTION_GE = bytes2("GE");

    function test_stacking_holderCarriesMultipleJurisdictions() public {
        uint256 expiry = block.timestamp + 365 days;
        IdentityAttestation.Attestation memory aGB = _makeAttestation(holder, JURISDICTION_GB, 2, expiry);
        _grantByVA(va1Key, aGB);
        IdentityAttestation.Attestation memory aUS = _makeAttestation(holder, JURISDICTION_US, 2, expiry);
        _grantByVA(va1Key, aUS);

        bytes2[] memory js = identity.jurisdictionsOf(holder);
        assertEq(js.length, 2, "holder should have two jurisdictions");
        assertEq(js[0], JURISDICTION_GB);
        assertEq(js[1], JURISDICTION_US);

        assertTrue(identity.hasAttestationIn(holder, JURISDICTION_GB));
        assertTrue(identity.hasAttestationIn(holder, JURISDICTION_US));
        assertFalse(identity.hasAttestationIn(holder, JURISDICTION_GE));
    }

    function test_stacking_getStatusInSpecificJurisdiction() public {
        uint256 expiry = block.timestamp + 365 days;
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 2, expiry));
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_US, 2, expiry));

        assertEq(uint8(identity.getStatusIn(holder, JURISDICTION_GB)), uint8(IdentityAttestation.Status.VALID));
        assertEq(uint8(identity.getStatusIn(holder, JURISDICTION_US)), uint8(IdentityAttestation.Status.VALID));
        assertEq(uint8(identity.getStatusIn(holder, JURISDICTION_GE)), uint8(IdentityAttestation.Status.UNKNOWN));
    }

    function test_stacking_revokeAffectsOnlyThatJurisdiction() public {
        uint256 expiry = block.timestamp + 365 days;
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 2, expiry));
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_US, 2, expiry));

        _revokeByGovQuorum(holder, JURISDICTION_GB);

        assertEq(uint8(identity.getStatusIn(holder, JURISDICTION_GB)), uint8(IdentityAttestation.Status.REVOKED));
        assertEq(uint8(identity.getStatusIn(holder, JURISDICTION_US)), uint8(IdentityAttestation.Status.VALID));
        // Holder-level "any VALID" is still VALID because the US record remains.
        assertEq(uint8(identity.getStatus(holder)), uint8(IdentityAttestation.Status.VALID));
    }

    function test_stacking_validJurisdictionCountTracksRevocations() public {
        uint256 expiry = block.timestamp + 365 days;
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 2, expiry));
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_US, 2, expiry));
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GE, 2, expiry));

        assertEq(identity.validJurisdictionCount(holder), 3);

        _revokeByGovQuorum(holder, JURISDICTION_GB);
        assertEq(identity.validJurisdictionCount(holder), 2);
    }

    function test_stacking_tier3ExistentialCheck() public {
        uint256 expiry = block.timestamp + 365 days;
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 3, expiry));
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_US, 3, expiry));

        bytes2[] memory req = new bytes2[](2);
        req[0] = JURISDICTION_GB;
        req[1] = JURISDICTION_US;

        assertTrue(
            identity.satisfiesRequiredJurisdictions(holder, req),
            "tier-3 existential check should pass when all ReqJ have VALID records"
        );

        // Missing a required jurisdiction → false.
        bytes2[] memory reqWithGE = new bytes2[](3);
        reqWithGE[0] = JURISDICTION_GB;
        reqWithGE[1] = JURISDICTION_US;
        reqWithGE[2] = JURISDICTION_GE;
        assertFalse(
            identity.satisfiesRequiredJurisdictions(holder, reqWithGE),
            "tier-3 check should fail when a required jurisdiction is absent"
        );

        // Revoking one of the ReqJ records fails the check.
        _revokeByGovQuorum(holder, JURISDICTION_GB);
        assertFalse(
            identity.satisfiesRequiredJurisdictions(holder, req),
            "tier-3 check should fail when a required-jurisdiction record is revoked"
        );
    }

    // ----- stage 5 ZKP verifier surface per DESIGN.md §5b ---------------------

    function test_zkVerifier_defaultIsMock() public view {
        assertEq(identity.zkVerifier().verifierId(), "mock");
    }

    function test_zkVerifier_acceptsEmptyProofWithoutVerifierCall() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        // a.zkProof defaults to "" — IdentityAttestation should not call verifier.
        _grantByVA(va1Key, a);
        assertEq(identity.getStatusIn(holder, JURISDICTION_GB) == IdentityAttestation.Status.VALID, true);
    }

    function test_zkVerifier_callsVerifierOnNonEmptyProof() public {
        IdentityAttestation.Attestation memory a = IdentityAttestation.Attestation({
            holder: holder,
            hid: keccak256(abi.encodePacked(holder, JURISDICTION_GB, uint256(2))),
            jurisdiction: JURISDICTION_GB,
            tier: 2,
            expiry: block.timestamp + 365 days,
            nonce: 1001,
            epoch: identity.attestationEpoch(holder, JURISDICTION_GB),
            attributeCommitmentsRoot: bytes32(0),
            zkProof: hex"deadbeef" // arbitrary bytes; mock accepts
        });
        _grantByVA(va1Key, a);
        IdentityAttestation.Record memory r = identity.recordOf(holder, JURISDICTION_GB);
        assertEq(r.zkProof.length, 4);
        assertEq(uint8(r.zkProof[0]), 0xde);
    }

    function test_zkVerifier_rejectsFailingVerifier() public {
        RejectingZKVerifier rejecting = new RejectingZKVerifier();

        // Swap the verifier via governance quorum.
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            identity.SET_ZK_VERIFIER_TYPEHASH(), address(identity), address(rejecting), nonce, deadline
        ));
        bytes32 digest = _eip712Gov(structHash);
        identity.setZKVerifier(rejecting, nonce, deadline, _twoGovSigs(digest));
        assertEq(identity.zkVerifier().verifierId(), "reject-all");

        // Now a non-empty-proof attestation must fail.
        IdentityAttestation.Attestation memory a = IdentityAttestation.Attestation({
            holder: holder,
            hid: keccak256(abi.encodePacked(holder, JURISDICTION_GB, uint256(2))),
            jurisdiction: JURISDICTION_GB,
            tier: 2,
            expiry: block.timestamp + 365 days,
            nonce: 1002,
            epoch: identity.attestationEpoch(holder, JURISDICTION_GB),
            attributeCommitmentsRoot: bytes32(0),
            zkProof: hex"00"
        });
        bytes32 attDigest = _eip712VA(_attestationStructHash(a));
        bytes memory sig = _signDigest(va1Key, attDigest);
        vm.expectRevert();
        identity.grantAttestation(a, sig);
    }

    function test_setZKVerifier_requiresQuorum() public {
        RejectingZKVerifier rejecting = new RejectingZKVerifier();
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            identity.SET_ZK_VERIFIER_TYPEHASH(), address(identity), address(rejecting), nonce, deadline
        ));
        bytes32 digest = _eip712Gov(structHash);
        bytes[] memory sigs = _oneGovSig(digest);
        vm.expectRevert();
        identity.setZKVerifier(rejecting, nonce, deadline, sigs);
    }

    function test_stacking_overwriteSameJurisdictionDoesNotDoubleCount() public {
        uint256 expiry = block.timestamp + 365 days;
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 2, expiry));
        // Re-grant to same jurisdiction — must overwrite in place, not duplicate.
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 2, expiry));

        bytes2[] memory js = identity.jurisdictionsOf(holder);
        assertEq(js.length, 1, "duplicate jurisdiction entry");
    }

    // ----- stage 6 revocation event for Phase Five bridge consumption ---------

    event AttestationRevoked(
        bytes32 indexed hid,
        address indexed issuingVA,
        address holder,
        address revokingAuthority,
        uint256 blockNumber,
        uint256 revocationIndex
    );

    function test_revocation_eventCarriesAllSixFields() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantByVA(va1Key, a);

        uint256 preIndex = identity.revocationIndex();

        // vm.expectEmit checks the indexed and non-indexed field values.
        vm.expectEmit(true, true, false, true);
        emit AttestationRevoked(
            a.hid,
            va1,           // issuing VA
            holder,
            gov1,          // msg.sender of the revoke call (we prank as gov1)
            block.number,
            preIndex + 1
        );

        // Build and submit the revocation signed by the two-of-three quorum.
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            identity.REVOKE_ATTESTATION_TYPEHASH(), address(identity), holder, JURISDICTION_GB, nonce, deadline
        ));
        bytes32 digest = _eip712Gov(structHash);
        bytes[] memory sigs = _twoGovSigs(digest);

        vm.prank(gov1);
        identity.revokeAttestation(holder, JURISDICTION_GB, nonce, deadline, sigs);

        assertEq(identity.revocationIndex(), preIndex + 1, "revocationIndex not incremented");
    }

    function test_revocation_indexIsMonotonicAcrossMultipleRevokes() public {
        uint256 expiry = block.timestamp + 365 days;
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 2, expiry));
        _grantByVA(va1Key, _makeAttestation(holder, bytes2("US"), 2, expiry));
        _grantByVA(va1Key, _makeAttestation(outsider, JURISDICTION_GB, 2, expiry));

        assertEq(identity.revocationIndex(), 0, "revocationIndex should start at 0");

        _revokeByGovQuorum(holder, JURISDICTION_GB);
        assertEq(identity.revocationIndex(), 1);

        _revokeByGovQuorum(holder, bytes2("US"));
        assertEq(identity.revocationIndex(), 2);

        _revokeByGovQuorum(outsider, JURISDICTION_GB);
        assertEq(identity.revocationIndex(), 3);
    }

    function test_revocation_indexDistinctFromGovernanceNonce() public {
        // Perform one governance action that is not a revocation — registerVA.
        uint256 gn = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 regDigest = _eip712Gov(keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va2, gn, deadline
        )));
        identity.registerVA(va2, gn, deadline, _twoGovSigs(regDigest));

        // governanceNonce advanced, revocationIndex did not.
        assertEq(identity.governanceNonce(), gn + 1);
        assertEq(identity.revocationIndex(), 0);

        // Now revoke.
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 2, block.timestamp + 365 days));
        _revokeByGovQuorum(holder, JURISDICTION_GB);

        // governanceNonce advances again (revocation is a governance action too).
        // revocationIndex advances separately.
        // governanceNonce counts governance actions only; grantAttestation is
        // a VA action and does not bump it. Two gov actions after gn were read:
        // registerVA and revokeAttestation.
        assertEq(identity.governanceNonce(), gn + 2);
        assertEq(identity.revocationIndex(), 1);
    }

    // ----- stage 2 / 3 checkpoint: keyed per-VA nonce registry ----------------

    /// @notice Checkpoint evidence: the used-VA-nonce registry is keyed per VA.
    ///         A nonce consumed by va1 is still available for va2.
    function test_checkpoint_vaNonceRegistryIsPerVA() public {
        // Register va2.
        uint256 gnonce = identity.governanceNonce();
        uint256 gdeadline = block.timestamp + 1 hours;
        bytes32 registerDigest = _eip712Gov(keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va2, gnonce, gdeadline
        )));
        identity.registerVA(va2, gnonce, gdeadline, _twoGovSigs(registerDigest));

        // va1 uses nonce 42.
        IdentityAttestation.Attestation memory a1 = IdentityAttestation.Attestation({
            holder: holder,
            hid: keccak256(abi.encodePacked(holder, JURISDICTION_GB, uint256(2))),
            jurisdiction: JURISDICTION_GB,
            tier: 2,
            expiry: block.timestamp + 365 days,
            nonce: 42,
            epoch: identity.attestationEpoch(holder, JURISDICTION_GB),
            attributeCommitmentsRoot: bytes32(0),
            zkProof: ""
        });
        bytes memory sig1 = _signDigest(va1Key, _eip712VA(_attestationStructHash(a1)));
        identity.grantAttestation(a1, sig1);

        // va2 can still use nonce 42 because the registry is keyed per VA.
        IdentityAttestation.Attestation memory a2 = IdentityAttestation.Attestation({
            holder: outsider,
            hid: keccak256(abi.encodePacked(outsider, JURISDICTION_GB, uint256(2))),
            jurisdiction: JURISDICTION_GB,
            tier: 2,
            expiry: block.timestamp + 365 days,
            nonce: 42,
            epoch: identity.attestationEpoch(outsider, JURISDICTION_GB),
            attributeCommitmentsRoot: bytes32(0),
            zkProof: ""
        });
        bytes memory sig2 = _signDigest(va2Key, _eip712VA(_attestationStructHash(a2)));
        identity.grantAttestation(a2, sig2);

        assertTrue(identity.hasVANonceBeenUsed(va1, 42));
        assertTrue(identity.hasVANonceBeenUsed(va2, 42));
    }

    // ----- 6B: per-jurisdiction accessor coverage -----------------------------

    function test_6B_perJurisdictionAccessors() public {
        uint256 expiry = block.timestamp + 365 days;
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 2, expiry));

        // Per-jurisdiction overloads (priority 3).
        IdentityAttestation.Record memory r = identity.recordOf(holder, JURISDICTION_GB);
        assertEq(r.tier, 2);
        assertEq(identity.tierOf(holder, JURISDICTION_GB), 2);
        assertEq(identity.verificationAuthorityOf(holder, JURISDICTION_GB), va1);
        assertEq(identity.attributeCommitmentsRootOf(holder, JURISDICTION_GB), bytes32(0));
        assertEq(identity.proofOf(holder, JURISDICTION_GB).length, 0);

        // Holder-only legacy overloads (first-jurisdiction fallback).
        assertEq(identity.tierOf(holder), 2);
        assertEq(identity.verificationAuthorityOf(holder), va1);
        assertEq(identity.attributeCommitmentsRootOf(holder), bytes32(0));
        assertEq(identity.proofOf(holder).length, 0);
        assertEq(identity.jurisdictionOf(holder), JURISDICTION_GB);
    }

    // ----- 6B: constructor and grant branch coverage --------------------------

    function test_6B_constructor_rejectsZeroVA() public {
        address[] memory auths = new address[](3);
        auths[0] = gov1; auths[1] = gov2; auths[2] = gov3;
        address[] memory badVAs = new address[](1);
        badVAs[0] = address(0);
        MockZKVerifier v = new MockZKVerifier();
        vm.expectRevert();
        new IdentityAttestation(auths, badVAs, v);
    }

    function test_6B_constructor_rejectsDuplicateVA() public {
        address[] memory auths = new address[](3);
        auths[0] = gov1; auths[1] = gov2; auths[2] = gov3;
        address[] memory dupVAs = new address[](2);
        dupVAs[0] = va1;
        dupVAs[1] = va1;
        MockZKVerifier v = new MockZKVerifier();
        vm.expectRevert();
        new IdentityAttestation(auths, dupVAs, v);
    }

    function test_6B_constructor_rejectsZeroZKVerifier() public {
        address[] memory auths = new address[](3);
        auths[0] = gov1; auths[1] = gov2; auths[2] = gov3;
        address[] memory vas = new address[](1);
        vas[0] = va1;
        vm.expectRevert();
        new IdentityAttestation(auths, vas, MockZKVerifier(address(0)));
    }

    function test_6B_constructor_rejectsDuplicateAuthority() public {
        address[] memory dup = new address[](3);
        dup[0] = gov1; dup[1] = gov2; dup[2] = gov1; // duplicate
        address[] memory vas = new address[](1);
        vas[0] = va1;
        MockZKVerifier v = new MockZKVerifier();
        vm.expectRevert();
        new IdentityAttestation(dup, vas, v);
    }

    function test_6B_grantAttestation_rejectsZeroHolder() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(address(0), JURISDICTION_GB, 2, block.timestamp + 365 days);
        bytes memory sig = _signDigest(va1Key, _eip712VA(_attestationStructHash(a)));
        vm.expectRevert();
        identity.grantAttestation(a, sig);
    }

    function test_6B_grantAttestation_rejectsTierZero() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 0, block.timestamp + 365 days);
        bytes memory sig = _signDigest(va1Key, _eip712VA(_attestationStructHash(a)));
        vm.expectRevert();
        identity.grantAttestation(a, sig);
    }

    function test_6B_grantAttestation_rejectsTierFour() public {
        IdentityAttestation.Attestation memory a = _makeAttestation(holder, JURISDICTION_GB, 4, block.timestamp + 365 days);
        bytes memory sig = _signDigest(va1Key, _eip712VA(_attestationStructHash(a)));
        vm.expectRevert();
        identity.grantAttestation(a, sig);
    }

    function test_6B_deregisterVA_rejectsUnknownVA() public {
        address stranger = makeAddr("stranger");
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _eip712Gov(keccak256(abi.encode(
            identity.DEREGISTER_VA_TYPEHASH(), address(identity), stranger, nonce, deadline
        )));
        vm.expectRevert();
        identity.deregisterVA(stranger, nonce, deadline, _twoGovSigs(digest));
    }

    function test_6B_registerVA_rejectsDuplicate() public {
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        // va1 is already registered at construction.
        bytes32 digest = _eip712Gov(keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va1, nonce, deadline
        )));
        vm.expectRevert();
        identity.registerVA(va1, nonce, deadline, _twoGovSigs(digest));
    }

    function test_6B_registerVA_rejectsZeroAddress() public {
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _eip712Gov(keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), address(0), nonce, deadline
        )));
        vm.expectRevert();
        identity.registerVA(address(0), nonce, deadline, _twoGovSigs(digest));
    }

    function test_6B_revokeAttestation_revertsOnUnknownHolder() public {
        address stranger = makeAddr("stranger");
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _eip712Gov(keccak256(abi.encode(
            identity.REVOKE_ATTESTATION_TYPEHASH(), address(identity), stranger, JURISDICTION_GB, nonce, deadline
        )));
        vm.expectRevert();
        identity.revokeAttestation(stranger, JURISDICTION_GB, nonce, deadline, _twoGovSigs(digest));
    }

    function test_6B_governance_rejectsExpiredDeadline() public {
        // Any gov action with block.timestamp > deadline should revert.
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp - 1;
        bytes32 digest = _eip712Gov(keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va2, nonce, deadline
        )));
        vm.expectRevert(IdentityAttestation.Expired.selector);
        identity.registerVA(va2, nonce, deadline, _twoGovSigs(digest));
    }

    function test_6B_governance_rejectsInvalidNonce() public {
        uint256 badNonce = identity.governanceNonce() + 5;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _eip712Gov(keccak256(abi.encode(
            identity.REGISTER_VA_TYPEHASH(), address(identity), va2, badNonce, deadline
        )));
        vm.expectRevert(IdentityAttestation.InvalidNonce.selector);
        identity.registerVA(va2, badNonce, deadline, _twoGovSigs(digest));
    }

    function test_6B_getStatus_unknownJurisdictionReturnsUnknown() public view {
        assertEq(uint8(identity.getStatusIn(holder, bytes2("XX"))), uint8(IdentityAttestation.Status.UNKNOWN));
    }

    function test_6B_getStatus_holderWithoutRecordReturnsUnknown() public view {
        assertEq(uint8(identity.getStatus(outsider)), uint8(IdentityAttestation.Status.UNKNOWN));
    }

    /// @notice 6B: cover the `sawExpired` path at the end of getStatus(holder).
    ///         Holder has one record, it is expired (not revoked). Holder-level
    ///         status aggregates to EXPIRED because no VALID and no REVOKED are
    ///         present.
    function test_6B_getStatus_allExpiredAggregatesToExpired() public {
        uint256 shortExpiry = block.timestamp + 10;
        _grantByVA(va1Key, _makeAttestation(holder, JURISDICTION_GB, 2, shortExpiry));
        vm.warp(shortExpiry + 1);
        assertEq(uint8(identity.getStatus(holder)), uint8(IdentityAttestation.Status.EXPIRED));
    }
}
