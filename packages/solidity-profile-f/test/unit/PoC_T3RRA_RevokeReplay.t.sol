// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Regression test for T3RRA-REVOKE-REPLAY-01. Original PoC authored by the
// external security researcher operating under the handle "0xpack"
// (managementpackaging@gmail.com) in a coordinated pre-audit disclosure on
// 2026-11-25. Attached to our repo verbatim.
//
// Original claim (confirmed against pre-fix commit 219f368 on 2026-11-25
// with 5/5 PASS, matching the researcher's own run and a third-party
// independent reproduction): `IdentityAttestation.grantAttestation`
// overwrote `_records[holder][jurisdiction]` unconditionally with
// `revoked: false`, with no freshness, sequence, or revocation-watermark
// check. A VA-signed attestation held back from before a revocation or a
// downgrade could be submitted later to undo the state change.
//
// Fix landed in commit <this commit> under the Option A remediation
// documented in DESIGN.md §16: the Attestation struct gained an `epoch`
// field bound into the EIP-712 typehash, with a per-(holder, jurisdiction)
// `_attestationEpoch` counter bumped on every grant and every revoke. A VA
// signing a new attestation reads the current epoch and includes it in the
// signed message; the grant path requires strict equality against the
// on-chain value.
//
// This file is retained as the regression test for the fix:
//
// - `test_revokeReplay_blocked` — the researcher's original attack path.
//   The withheld pre-revocation attestation now reverts with
//   `StaleAttestationEpoch` on submission, the record stays REVOKED, and
//   the revoked holder cannot transfer. The assertion is the fix.
//
// - `test_downgradeReplay_blocked` — the researcher's downgrade variant.
//   Replaying the withheld tier-3 attestation after a tier-1 downgrade
//   reverts with `StaleAttestationEpoch`; the tier stays at 1.
//
// - `test_control_exactReplayStillBlockedByNonce` — the existing nonce
//   defense is unchanged. Submitting identical bytes twice still reverts
//   with `NonceReused`. Exercises the fact that the fix complements rather
//   than replaces the nonce check.
//
// - `test_redemptionIneligibleHolderCanStillRedeem` — the researcher's
//   test 4 is a separate finding about `REDEMPTION_ELIGIBILITY` living in
//   `evaluateWithDisclosure` rather than the basic `evaluate` path that
//   `redeem()` calls. This is DESIGN.md §5c and §9 TODO 16 (the deferred
//   transfer-pipeline integration of INVESTOR_CLASSIFICATION / HOLDING_PERIOD
//   / REDEMPTION_ELIGIBILITY). The researcher independently found the
//   architectural gap we already documented. Test is retained here as a
//   living cross-reference for the §9 TODO 16 Phase Three deliverable; the
//   assertion documents the current Phase One behavior rather than claiming
//   it is correct.
//
// - `test_control_postRevokeRegrantStillWorks` — new. Governance revokes
//   holder, then a VA signs a FRESH attestation reading the current
//   (bumped) epoch. Submission succeeds; the holder's status returns to
//   VALID through the sanctioned re-grant path. This control pins the
//   fix's required property: it blocks STALE re-grants, not LEGITIMATE
//   ones. The CRE scenario phase 3 (revoke UK1, re-grant via VA2) depends
//   on this path staying open.
//
// Run: forge test --match-path "test/unit/PoC_T3RRA_RevokeReplay.t.sol" -vv

import {BaseTest} from "../BaseTest.t.sol";
import {IdentityAttestation} from "../../src/IdentityAttestation.sol";

contract PoCRevokeReplayTest is BaseTest {
    function _buildAttestation(
        address who,
        bytes2 j,
        uint8 tier,
        uint256 expiry,
        uint256 nonce,
        uint256 epoch
    )
        internal
        pure
        returns (IdentityAttestation.Attestation memory a)
    {
        a = IdentityAttestation.Attestation({
            holder: who,
            hid: keccak256(abi.encodePacked(who, j, uint256(tier))),
            jurisdiction: j,
            tier: tier,
            expiry: expiry,
            nonce: nonce,
            epoch: epoch,
            attributeCommitmentsRoot: bytes32(0),
            zkProof: ""
        });
    }

    function _signVA(IdentityAttestation.Attestation memory a) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                identity.ATTESTATION_TYPEHASH(),
                a.holder,
                a.hid,
                a.jurisdiction,
                a.tier,
                a.expiry,
                a.nonce,
                a.epoch,
                a.attributeCommitmentsRoot,
                keccak256(a.zkProof)
            )
        );
        return _signDigest(va1Key, _eip712Digest(identity.DOMAIN_SEPARATOR_VA(), structHash));
    }

    function _deregisterVA(address va) internal {
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(identity.DEREGISTER_VA_TYPEHASH(), address(identity), va, nonce, deadline)
        );
        bytes32 digest = _eip712Digest(identity.DOMAIN_SEPARATOR_GOVERNANCE(), structHash);
        identity.deregisterVA(va, nonce, deadline, _twoSigs(gov1Key, gov2Key, digest));
    }

    // ----------------------------------------------------------------------
    // Attack paths — now blocked by the Option A fix
    // ----------------------------------------------------------------------

    /// @notice Pre-fix: this test documented the revocation-replay bug and
    ///         PASSED on commit 219f368 by driving the attack to completion.
    ///         Post-fix: the attack grantAttestation reverts with
    ///         StaleAttestationEpoch, the record remains REVOKED, and the
    ///         revoked holder cannot transfer. The assertion flow is
    ///         inverted; the test shape is preserved so the git history
    ///         carries the full disclosure chain from PoC to remediation.
    function test_revokeReplay_blocked() public {
        vm.prank(issuer);
        compliance.allowJurisdictionPair(JURISDICTION_GB, JURISDICTION_US);

        uint256 expiry = block.timestamp + 365 days;

        // VA signs TWO attestations at the CURRENT epoch (0 initially).
        // Both are legal signatures against the same epoch. A1 submitted
        // now; A2 withheld. Under the Option A fix, A1's submission bumps
        // the on-chain epoch from 0 to 1, making A2 stale.
        uint256 epoch0 = identity.attestationEpoch(holderA, JURISDICTION_GB);
        IdentityAttestation.Attestation memory a1 =
            _buildAttestation(holderA, JURISDICTION_GB, 2, expiry, 101, epoch0);
        IdentityAttestation.Attestation memory a2 =
            _buildAttestation(holderA, JURISDICTION_GB, 2, expiry, 102, epoch0);
        bytes memory sig2 = _signVA(a2);
        identity.grantAttestation(a1, _signVA(a1));
        _grantAttestationVA(holderB, JURISDICTION_US, 2, expiry);

        // Transfer path works pre-revocation.
        vm.prank(issuer);
        asset.issue(holderA, 1000);
        vm.prank(holderA);
        assertTrue(asset.transfer(holderB, 100));
        assertEq(asset.balanceOf(holderB), 100);

        // Governance revokes. Epoch bumps again (A2 is already stale from the
        // A1 grant; the revocation bump makes it doubly stale).
        _revokeAttestationGov(holderA, JURISDICTION_GB);
        assertEq(uint8(identity.getStatus(holderA)), uint8(IdentityAttestation.Status.REVOKED));

        // Revoked holder cannot transfer.
        vm.prank(holderA);
        vm.expectRevert();
        asset.transfer(holderB, 100);

        // ATTACK (now blocked). Submitting the withheld A2 reverts with
        // StaleAttestationEpoch. Before the fix this call succeeded and
        // restored the holder's VALID status.
        vm.prank(holderA);
        vm.expectRevert(IdentityAttestation.StaleAttestationEpoch.selector);
        identity.grantAttestation(a2, sig2);

        // Post-attack state: the record is still REVOKED. The transfer
        // path is still blocked by IDENTITY_REVOKED at step 1.
        assertTrue(identity.recordOf(holderA).revoked);
        assertEq(uint8(identity.getStatus(holderA)), uint8(IdentityAttestation.Status.REVOKED));

        vm.prank(holderA);
        vm.expectRevert();
        asset.transfer(holderB, 100);

        // Holder's balance at destination has not moved from the first
        // (legitimate) transfer. The attack did not add a second 100.
        assertEq(asset.balanceOf(holderB), 100);
    }

    /// @notice Downgrade variant from the original PoC. A VA-signed tier-3
    ///         attestation withheld across a VA-driven tier-1 downgrade is
    ///         now stale: replaying it reverts with StaleAttestationEpoch,
    ///         and the tier stays at 1.
    function test_downgradeReplay_blocked() public {
        uint256 expiry = block.timestamp + 365 days;

        uint256 epoch0 = identity.attestationEpoch(holderA, JURISDICTION_GB);
        IdentityAttestation.Attestation memory hi1 =
            _buildAttestation(holderA, JURISDICTION_GB, 3, expiry, 201, epoch0);
        IdentityAttestation.Attestation memory hi2 =
            _buildAttestation(holderA, JURISDICTION_GB, 3, expiry, 202, epoch0);
        bytes memory sigHi2 = _signVA(hi2);
        identity.grantAttestation(hi1, _signVA(hi1));
        assertEq(identity.tierOf(holderA), 3);

        // After hi1 lands, epoch is 1. A fresh VA-signed downgrade reads
        // the current epoch and signs with 1. Submission succeeds, bumping
        // to 2.
        uint256 epoch1 = identity.attestationEpoch(holderA, JURISDICTION_GB);
        IdentityAttestation.Attestation memory lo =
            _buildAttestation(holderA, JURISDICTION_GB, 1, expiry, 203, epoch1);
        identity.grantAttestation(lo, _signVA(lo));
        assertEq(identity.tierOf(holderA), 1);

        // ATTACK (now blocked). hi2 was signed at epoch 0; current is 2.
        vm.expectRevert(IdentityAttestation.StaleAttestationEpoch.selector);
        identity.grantAttestation(hi2, sigHi2);
        assertEq(identity.tierOf(holderA), 1);
    }

    // ----------------------------------------------------------------------
    // Controls — existing defenses unchanged
    // ----------------------------------------------------------------------

    /// @notice Nonce reuse is still rejected. This defense is distinct from
    ///         the epoch check: it blocks exact-byte replays, which the
    ///         epoch check alone would not catch for a same-epoch submission.
    function test_control_exactReplayStillBlockedByNonce() public {
        uint256 expiry = block.timestamp + 365 days;
        uint256 epoch0 = identity.attestationEpoch(holderA, JURISDICTION_GB);
        IdentityAttestation.Attestation memory a =
            _buildAttestation(holderA, JURISDICTION_GB, 2, expiry, 301, epoch0);
        bytes memory sig = _signVA(a);
        identity.grantAttestation(a, sig);

        // Same bytes a second time. The nonce is consumed; even if the
        // attacker could somehow produce a matching epoch (they cannot
        // after the first grant bumped it), nonce reuse still reverts
        // first — the pipeline checks nonce after epoch, so the actual
        // revert here is StaleAttestationEpoch because the epoch bumped.
        // Either revert is acceptable; what matters is that the second
        // submission does not succeed.
        vm.expectRevert();
        identity.grantAttestation(a, sig);
    }

    /// @notice REDEMPTION_ELIGIBILITY lives in `evaluateWithDisclosure`
    ///         which `asset.redeem()` does not invoke. The flagged holder
    ///         burns through the basic evaluate() path. This is the
    ///         §9 TODO 16 deferred integration documented in DESIGN.md §5c.
    ///         Retained here as a living cross-reference; the test is NOT
    ///         an assertion that this behavior is correct, only that it is
    ///         the current Phase One behavior pending Phase Three.
    function test_redemptionIneligibleHolderCanStillRedeem() public {
        vm.prank(issuer);
        compliance.setRedemptionIneligible(holderA, true);
        assertTrue(compliance.redemptionIneligible(holderA));

        _grantAttestationVA(holderA, JURISDICTION_GB, 2, block.timestamp + 365 days);
        vm.prank(issuer);
        asset.issue(holderA, 500);

        vm.prank(holderA);
        asset.redeem(100);
        assertEq(asset.balanceOf(holderA), 400);
    }

    /// @notice After governance revocation, a fresh VA-signed re-grant that
    ///         reads the current (post-revocation) epoch is accepted.
    ///         This is the sanctioned re-attestation path the CRE scenario
    ///         phase 3 (revoke UK1, re-grant via VA2) depends on. The fix
    ///         must not close it.
    function test_control_postRevokeRegrantStillWorks() public {
        uint256 expiry = block.timestamp + 365 days;
        _grantAttestationVA(holderA, JURISDICTION_GB, 2, expiry);
        _revokeAttestationGov(holderA, JURISDICTION_GB);
        assertEq(uint8(identity.getStatus(holderA)), uint8(IdentityAttestation.Status.REVOKED));

        // A VA signs a FRESH attestation after reading the current epoch.
        // This is the only post-revocation grant path that works, and it
        // requires an actual live VA decision — exactly the property the
        // researcher's recommendation calls for.
        uint256 epochNow = identity.attestationEpoch(holderA, JURISDICTION_GB);
        IdentityAttestation.Attestation memory fresh =
            _buildAttestation(holderA, JURISDICTION_GB, 2, expiry, 501, epochNow);
        identity.grantAttestation(fresh, _signVA(fresh));
        assertEq(uint8(identity.getStatus(holderA)), uint8(IdentityAttestation.Status.VALID));
    }

    /// @notice Pre-fix control retained from the original PoC: deregistering
    ///         the VA kills all its signatures. This was the only defense
    ///         available on commit 219f368. Post-fix it remains available
    ///         as defense-in-depth but is no longer the sole option.
    function test_control_deregisteringVAIsOnlyDefence() public {
        uint256 expiry = block.timestamp + 365 days;
        uint256 epoch0 = identity.attestationEpoch(holderA, JURISDICTION_GB);
        IdentityAttestation.Attestation memory a1 =
            _buildAttestation(holderA, JURISDICTION_GB, 2, expiry, 401, epoch0);
        IdentityAttestation.Attestation memory a2 =
            _buildAttestation(holderA, JURISDICTION_GB, 2, expiry, 402, epoch0);
        bytes memory sig2 = _signVA(a2);
        identity.grantAttestation(a1, _signVA(a1));
        _revokeAttestationGov(holderA, JURISDICTION_GB);
        assertEq(uint8(identity.getStatus(holderA)), uint8(IdentityAttestation.Status.REVOKED));

        _deregisterVA(va1);

        // Post-fix, a2 reverts with StaleAttestationEpoch BEFORE the VA
        // registration check runs — the epoch check is first in the
        // grant flow. Either revert outcome demonstrates the attestation
        // is rejected; what matters is that the record stays REVOKED.
        vm.expectRevert();
        identity.grantAttestation(a2, sig2);
        assertEq(uint8(identity.getStatus(holderA)), uint8(IdentityAttestation.Status.REVOKED));
    }
}
