// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// SelectiveDisclosure library unit tests.
// Source: L3RS-1 v1.0.0 §3.7 (Selective Disclosure), DESIGN.md §8.3 (design),
//         DESIGN.md §8.2 (EIP-712 domains and shared signature library).
//
// Coverage:
// - Valid presentation accepted, nonce consumed.
// - Replay fails with NonceAlreadyUsed.
// - Wrong-verifier call fails with WrongVerifier.
// - Expired presentation fails with PresentationExpired.
// - Tampered leaf fails with InvalidMerkleProof.
// - Forged holder signature fails with HolderSignatureInvalid.
// - Commitment-root mismatch fails at the IdentityAttestation.verifyPresentation
//   wrapper (storage-side check before the library is invoked).

import {Test} from "forge-std/Test.sol";
import {IdentityAttestation} from "../../src/IdentityAttestation.sol";
import {MockZKVerifier} from "../../src/MockZKVerifier.sol";
import {SelectiveDisclosure} from "../../src/libraries/SelectiveDisclosure.sol";

contract SelectiveDisclosureTest is Test {
    IdentityAttestation internal identity;
    MockZKVerifier internal mockVerifier;

    address internal issuer;
    uint256 internal issuerKey;
    address internal holder;
    uint256 internal holderKey;
    address internal gov1;
    uint256 internal gov1Key;
    address internal gov2;
    uint256 internal gov2Key;
    address internal gov3;
    uint256 internal gov3Key;
    address internal va1;
    uint256 internal va1Key;
    address internal stranger;
    uint256 internal strangerKey;

    bytes2 internal constant JURISDICTION_GB = bytes2("GB");

    // Canonical attribute names per §3.7 are hashed once.
    bytes32 internal constant NAME_RESIDENCY = keccak256("residency");
    bytes32 internal constant NAME_ACCREDITED = keccak256("accredited");

    // Attribute values + blinding salts (off-chain data).
    bytes32 internal residencyValueHash;
    bytes32 internal accreditedValueHash;

    // Leaves and root.
    bytes32 internal leafResidency;
    bytes32 internal leafAccredited;
    bytes32 internal root;

    function setUp() public {
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        (holder, holderKey) = makeAddrAndKey("holder");
        (gov1, gov1Key) = makeAddrAndKey("gov1");
        (gov2, gov2Key) = makeAddrAndKey("gov2");
        (gov3, gov3Key) = makeAddrAndKey("gov3");
        (va1, va1Key) = makeAddrAndKey("va1");
        (stranger, strangerKey) = makeAddrAndKey("stranger");

        address[] memory authorities = new address[](3);
        authorities[0] = gov1;
        authorities[1] = gov2;
        authorities[2] = gov3;
        address[] memory initialVAs = new address[](1);
        initialVAs[0] = va1;

        vm.startPrank(issuer);
        mockVerifier = new MockZKVerifier();
        identity = new IdentityAttestation(authorities, initialVAs, mockVerifier);
        vm.stopPrank();

        // Build a two-leaf attribute tree. Leaf encoding per DESIGN.md §8.3:
        //   leaf = keccak256(abi.encode(nameHash, valueHash))
        residencyValueHash = keccak256(abi.encodePacked("GB", bytes32("salt-residency")));
        accreditedValueHash = keccak256(abi.encodePacked("true", bytes32("salt-accredited")));

        leafResidency = keccak256(abi.encode(NAME_RESIDENCY, residencyValueHash));
        leafAccredited = keccak256(abi.encode(NAME_ACCREDITED, accreditedValueHash));

        // Sorted-pair root for two leaves (OpenZeppelin MerkleProof convention).
        root = _hashPair(leafResidency, leafAccredited);

        // VA issues an attestation with the committed root.
        _grantAttestationWithRoot(holder, JURISDICTION_GB, 2, block.timestamp + 365 days, root);
    }

    // ----- helpers ------------------------------------------------------------

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _signDigest(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _eip712VA(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", identity.DOMAIN_SEPARATOR_VA(), structHash));
    }

    function _eip712Presentation(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", identity.DOMAIN_SEPARATOR_PRESENTATION(), structHash));
    }

    uint256 internal _vaNonce;
    function _grantAttestationWithRoot(
        address who,
        bytes2 j,
        uint8 tier,
        uint256 expiry,
        bytes32 commitmentRoot
    ) internal {
        _vaNonce += 1;
        IdentityAttestation.Attestation memory a = IdentityAttestation.Attestation({
            holder: who,
            hid: keccak256(abi.encodePacked(who, j, uint256(tier))),
            jurisdiction: j,
            tier: tier,
            expiry: expiry,
            nonce: _vaNonce,
            epoch: identity.attestationEpoch(who, j),
            attributeCommitmentsRoot: commitmentRoot,
            zkProof: ""
        });
        bytes32 structHash = keccak256(abi.encode(
            identity.ATTESTATION_TYPEHASH(),
            a.holder, a.hid, a.jurisdiction, a.tier, a.expiry, a.nonce, a.epoch,
            a.attributeCommitmentsRoot,
            keccak256(a.zkProof)
        ));
        bytes memory sig = _signDigest(va1Key, _eip712VA(structHash));
        identity.grantAttestation(a, sig);
    }

    /// @dev Build a presentation disclosing the residency leaf only.
    function _buildResidencyOnlyPresentation(uint256 nonce, uint256 deadline)
        internal
        view
        returns (SelectiveDisclosure.Presentation memory p)
    {
        SelectiveDisclosure.Disclosure[] memory disclosures = new SelectiveDisclosure.Disclosure[](1);
        disclosures[0] = SelectiveDisclosure.Disclosure({
            nameHash: NAME_RESIDENCY,
            valueHash: residencyValueHash
        });
        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = leafAccredited; // sibling for sorted-pair 2-leaf Merkle

        p.holder = holder;
        p.attestationRef = keccak256(abi.encodePacked(holder, JURISDICTION_GB));
        p.commitmentRoot = root;
        p.disclosures = disclosures;
        p.merkleProofs = proofs;
        p.verifier = address(identity);
        p.nonce = nonce;
        p.deadline = deadline;
    }

    function _hashPresentation(SelectiveDisclosure.Presentation memory p) internal pure returns (bytes32) {
        bytes32 discTypehash = keccak256("Disclosure(bytes32 nameHash,bytes32 valueHash)");
        bytes32 presentationTypehash = keccak256(
            "Presentation(address holder,bytes32 attestationRef,bytes32 commitmentRoot,Disclosure[] disclosures,bytes32[][] merkleProofs,address verifier,uint256 nonce,uint256 deadline)Disclosure(bytes32 nameHash,bytes32 valueHash)"
        );

        bytes32[] memory disclosureHashes = new bytes32[](p.disclosures.length);
        for (uint256 i = 0; i < p.disclosures.length; i++) {
            disclosureHashes[i] = keccak256(abi.encode(
                discTypehash,
                p.disclosures[i].nameHash,
                p.disclosures[i].valueHash
            ));
        }
        bytes32 disclosuresHash = keccak256(abi.encodePacked(disclosureHashes));

        bytes32[] memory proofHashes = new bytes32[](p.merkleProofs.length);
        for (uint256 i = 0; i < p.merkleProofs.length; i++) {
            proofHashes[i] = keccak256(abi.encodePacked(p.merkleProofs[i]));
        }
        bytes32 merkleProofsHash = keccak256(abi.encodePacked(proofHashes));

        return keccak256(abi.encode(
            presentationTypehash,
            p.holder,
            p.attestationRef,
            p.commitmentRoot,
            disclosuresHash,
            merkleProofsHash,
            p.verifier,
            p.nonce,
            p.deadline
        ));
    }

    // ----- tests --------------------------------------------------------------

    function test_valid_presentationAcceptedAndNonceConsumed() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        SelectiveDisclosure.Presentation memory p = _buildResidencyOnlyPresentation(nonce, deadline);
        bytes memory sig = _signDigest(holderKey, _eip712Presentation(_hashPresentation(p)));

        assertFalse(identity.hasPresentationNonceBeenUsed(holder, address(identity), nonce));
        identity.verifyPresentation(p, sig);
        assertTrue(identity.hasPresentationNonceBeenUsed(holder, address(identity), nonce));
    }

    function test_replay_reverts() public {
        uint256 nonce = 2;
        uint256 deadline = block.timestamp + 1 hours;
        SelectiveDisclosure.Presentation memory p = _buildResidencyOnlyPresentation(nonce, deadline);
        bytes memory sig = _signDigest(holderKey, _eip712Presentation(_hashPresentation(p)));

        identity.verifyPresentation(p, sig);
        vm.expectRevert(SelectiveDisclosure.NonceAlreadyUsed.selector);
        identity.verifyPresentation(p, sig);
    }

    function test_wrongVerifier_reverts() public {
        // p.verifier says identity, but the library is called with a different
        // msg.sender via a helper contract that wraps the call.
        uint256 nonce = 3;
        uint256 deadline = block.timestamp + 1 hours;
        SelectiveDisclosure.Presentation memory p = _buildResidencyOnlyPresentation(nonce, deadline);
        p.verifier = address(0xBEEF); // different verifier than identity.
        bytes memory sig = _signDigest(holderKey, _eip712Presentation(_hashPresentation(p)));

        vm.expectRevert(SelectiveDisclosure.WrongVerifier.selector);
        identity.verifyPresentation(p, sig);
    }

    function test_expired_reverts() public {
        uint256 nonce = 4;
        uint256 deadline = block.timestamp + 1 hours;
        SelectiveDisclosure.Presentation memory p = _buildResidencyOnlyPresentation(nonce, deadline);
        bytes memory sig = _signDigest(holderKey, _eip712Presentation(_hashPresentation(p)));

        vm.warp(deadline + 1);
        vm.expectRevert(SelectiveDisclosure.PresentationExpired.selector);
        identity.verifyPresentation(p, sig);
    }

    function test_tamperedLeaf_failsMerkleProof() public {
        uint256 nonce = 5;
        uint256 deadline = block.timestamp + 1 hours;
        SelectiveDisclosure.Presentation memory p = _buildResidencyOnlyPresentation(nonce, deadline);
        // Tamper the disclosed value hash — the leaf now hashes to a non-member.
        p.disclosures[0].valueHash = bytes32(uint256(p.disclosures[0].valueHash) ^ 0x01);
        bytes memory sig = _signDigest(holderKey, _eip712Presentation(_hashPresentation(p)));

        vm.expectRevert(abi.encodeWithSelector(SelectiveDisclosure.InvalidMerkleProof.selector, uint256(0)));
        identity.verifyPresentation(p, sig);
    }

    function test_forgedHolderSignature_reverts() public {
        uint256 nonce = 6;
        uint256 deadline = block.timestamp + 1 hours;
        SelectiveDisclosure.Presentation memory p = _buildResidencyOnlyPresentation(nonce, deadline);
        // Sign with stranger key, not holder key.
        bytes memory forged = _signDigest(strangerKey, _eip712Presentation(_hashPresentation(p)));

        vm.expectRevert(SelectiveDisclosure.HolderSignatureInvalid.selector);
        identity.verifyPresentation(p, forged);
    }

    function test_commitmentRootMismatch_revertsAtWrapper() public {
        uint256 nonce = 7;
        uint256 deadline = block.timestamp + 1 hours;
        SelectiveDisclosure.Presentation memory p = _buildResidencyOnlyPresentation(nonce, deadline);
        p.commitmentRoot = bytes32(uint256(root) ^ 0x01); // any root ≠ stored root
        bytes memory sig = _signDigest(holderKey, _eip712Presentation(_hashPresentation(p)));

        // Wrapper on IdentityAttestation runs the storage check before invoking
        // the library.
        vm.expectRevert(bytes("IdentityAttestation: commitment mismatch"));
        identity.verifyPresentation(p, sig);
    }

    function test_proofLengthMismatch_reverts() public {
        uint256 nonce = 8;
        uint256 deadline = block.timestamp + 1 hours;
        SelectiveDisclosure.Presentation memory p = _buildResidencyOnlyPresentation(nonce, deadline);
        // Two disclosures but only one proof.
        SelectiveDisclosure.Disclosure[] memory two = new SelectiveDisclosure.Disclosure[](2);
        two[0] = p.disclosures[0];
        two[1] = SelectiveDisclosure.Disclosure({
            nameHash: NAME_ACCREDITED,
            valueHash: accreditedValueHash
        });
        p.disclosures = two;
        bytes memory sig = _signDigest(holderKey, _eip712Presentation(_hashPresentation(p)));

        vm.expectRevert(SelectiveDisclosure.ProofLengthMismatch.selector);
        identity.verifyPresentation(p, sig);
    }

    function test_multipleDisclosures_acceptedTogether() public {
        // Disclose both leaves with their proofs.
        SelectiveDisclosure.Disclosure[] memory disclosures = new SelectiveDisclosure.Disclosure[](2);
        disclosures[0] = SelectiveDisclosure.Disclosure({nameHash: NAME_RESIDENCY, valueHash: residencyValueHash});
        disclosures[1] = SelectiveDisclosure.Disclosure({nameHash: NAME_ACCREDITED, valueHash: accreditedValueHash});
        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = leafAccredited;
        proofs[1] = new bytes32[](1);
        proofs[1][0] = leafResidency;

        uint256 nonce = 9;
        uint256 deadline = block.timestamp + 1 hours;
        SelectiveDisclosure.Presentation memory p = SelectiveDisclosure.Presentation({
            holder: holder,
            attestationRef: keccak256(abi.encodePacked(holder, JURISDICTION_GB)),
            commitmentRoot: root,
            disclosures: disclosures,
            merkleProofs: proofs,
            verifier: address(identity),
            nonce: nonce,
            deadline: deadline
        });
        bytes memory sig = _signDigest(holderKey, _eip712Presentation(_hashPresentation(p)));

        identity.verifyPresentation(p, sig);
        assertTrue(identity.hasPresentationNonceBeenUsed(holder, address(identity), nonce));
    }

    function test_checkpoint_presentationDomainSeparator() public view {
        bytes32 expected = keccak256(abi.encode(
            keccak256(
                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
            ),
            keccak256(bytes("T3RRA-IdentityAttestation-Presentation")),
            keccak256(bytes("1")),
            block.chainid,
            address(identity)
        ));
        assertEq(
            identity.DOMAIN_SEPARATOR_PRESENTATION(),
            expected,
            "presentation domain separator mismatch"
        );
    }

    function test_checkpoint_threeDomainsDistinct() public view {
        bytes32 gov = identity.DOMAIN_SEPARATOR_GOVERNANCE();
        bytes32 va = identity.DOMAIN_SEPARATOR_VA();
        bytes32 pres = identity.DOMAIN_SEPARATOR_PRESENTATION();
        assertTrue(gov != va, "governance and VA separators collide");
        assertTrue(gov != pres, "governance and presentation separators collide");
        assertTrue(va != pres, "VA and presentation separators collide");
    }
}
