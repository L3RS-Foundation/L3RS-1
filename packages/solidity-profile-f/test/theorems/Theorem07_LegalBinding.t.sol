// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Theorem 15.7 — Legal Binding Integrity.
// Source: L3RS-1 v1.0.0 §15.9. Mapped in 06-theorems.md Part A.
//
// Formal statement: "Legal document reference cannot be altered without detection."
//
// Proof sketch: Legal mirror contains LH = H(document ‖ jurisdiction ‖ version).
// Modification of the document changes LH. Under collision resistance, an
// adversary cannot produce an alternate document with the same LH. Legal binding
// is cryptographically anchored.
//
// Phase One obligation: the LegalMirror object is stored on the L3RS1Asset
// contract per L3RS-1 §13.4 and §12.3. Amendments create a new LH and are recorded
// per §12.6 / §12.7.

import {BaseTest} from "../BaseTest.t.sol";

contract Theorem07_LegalBinding is BaseTest {
    function test_T7_lhCoversDocumentJurisdictionVersion(
        bytes calldata document,
        bytes2 jurisdiction,
        uint64 version
    ) public view {
        vm.assume(version < type(uint64).max); // version + 1 below must not overflow
        bytes32 a = asset.computeLegalHash(document, jurisdiction, version);

        // Mutating any of the three inputs must produce a different LH.
        bytes memory documentMut = bytes.concat(document, bytes("x"));
        assertTrue(
            a != asset.computeLegalHash(documentMut, jurisdiction, version),
            "T7: LH unchanged under document mutation"
        );

        bytes2 jurisdictionMut = jurisdiction == bytes2("ZZ") ? bytes2("AA") : bytes2("ZZ");
        assertTrue(
            a != asset.computeLegalHash(document, jurisdictionMut, version),
            "T7: LH unchanged under jurisdiction mutation"
        );

        assertTrue(
            a != asset.computeLegalHash(document, jurisdiction, version + 1),
            "T7: LH unchanged under version mutation"
        );
    }

    function test_T7_amendmentsRecordNewLh() public {
        bytes32 lhBefore = asset.legalHash();

        bytes memory document = bytes("amended mandate document v2");
        uint64 newVersion = 2;
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendLegalDigest(document, JURISDICTION_GB, newVersion, nonce, deadline);
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, digest);

        asset.amendLegalMirror(document, JURISDICTION_GB, newVersion, nonce, deadline, sigs);

        bytes32 lhAfter = asset.legalHash();
        assertTrue(lhBefore != lhAfter, "T7: amendment did not change legalHash");
        assertEq(asset.legalVersion(), 2, "T7: version not incremented on amendment");
        assertEq(asset.legalAmendmentCount(), 1, "T7: amendment record not created");
    }

    function test_T7_authoritySignatureVerifiesIfPresent() public {
        // L3RS-1 §13.4 makes SIGN optional. If present, it must verify against the
        // registered authority public key. The asset exposes a pure verifier.
        bytes memory payload = bytes("mandate document");
        bytes memory validSig = bytes("authority-sig-valid");
        bytes memory invalidSig = bytes("authority-sig-invalid");

        // The test asserts the contract distinguishes valid from invalid signatures.
        assertTrue(asset.verifyLegalAuthoritySignature(payload, validSig), "T7: valid authority signature rejected");
        assertFalse(asset.verifyLegalAuthoritySignature(payload, invalidSig), "T7: invalid authority signature accepted");
    }
}
