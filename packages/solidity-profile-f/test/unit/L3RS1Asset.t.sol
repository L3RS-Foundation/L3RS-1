// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Direct unit tests for L3RS1Asset. Focuses on view accessors and revert-path
// branch coverage missing from the theorem suite. Source: DESIGN.md §12 6A
// priority 4 and priority 5.

import {BaseTest} from "../BaseTest.t.sol";
import {L3RS1Asset} from "../../src/L3RS1Asset.sol";
import {ComplianceModule} from "../../src/ComplianceModule.sol";
import {IdentityAttestation} from "../../src/IdentityAttestation.sol";
import {PolicyRegistry} from "../../src/PolicyRegistry.sol";
import {ILifecycle} from "../../src/interfaces/ILifecycle.sol";
import {ReasonCodes} from "../../src/libraries/ReasonCodes.sol";

contract L3RS1AssetTest is BaseTest {
    // ----- view accessor coverage --------------------------------------------

    function test_view_feeRecipientDefaultsToZero() public view {
        assertEq(asset.feeRecipient(), address(0));
    }

    function test_view_feeRecipientReflectsSetter() public {
        address newRecipient = makeAddr("feeRecipient");
        vm.prank(issuer);
        asset.setFeeRecipient(newRecipient);
        assertEq(asset.feeRecipient(), newRecipient);
    }

    function test_view_distinctTxIdCountMirrorsSeenCount() public view {
        assertEq(asset.distinctTxIdCount(), asset.seenTxIdCount());
    }

    function test_view_authoritiesReturnsFullList() public view {
        address[] memory list = asset.authorities();
        assertEq(list.length, 3);
        assertEq(list[0], gov1);
        assertEq(list[1], gov2);
        assertEq(list[2], gov3);
    }

    // ----- constructor revert branches ---------------------------------------

    function _deployWithParams(
        address issuer_,
        bytes2 jurisdiction_,
        uint8 idTier_,
        ComplianceModule compliance_,
        IdentityAttestation identity_,
        PolicyRegistry registry_,
        address[] memory authorities_
    ) internal returns (L3RS1Asset) {
        return new L3RS1Asset(issuer_, jurisdiction_, idTier_, compliance_, identity_, registry_, authorities_);
    }

    function test_constructor_zeroIssuerReverts() public {
        address[] memory a = new address[](3);
        a[0] = gov1; a[1] = gov2; a[2] = gov3;
        vm.expectRevert(L3RS1Asset.ZeroAddress.selector);
        _deployWithParams(address(0), bytes2("GB"), 2, compliance, identity, registry, a);
    }

    function test_constructor_zeroJurisdictionReverts() public {
        address[] memory a = new address[](3);
        a[0] = gov1; a[1] = gov2; a[2] = gov3;
        vm.expectRevert(L3RS1Asset.ZeroAddress.selector);
        _deployWithParams(issuer, bytes2(0), 2, compliance, identity, registry, a);
    }

    function test_constructor_invalidTierReverts() public {
        address[] memory a = new address[](3);
        a[0] = gov1; a[1] = gov2; a[2] = gov3;
        vm.expectRevert(L3RS1Asset.InvalidTier.selector);
        _deployWithParams(issuer, bytes2("GB"), 4, compliance, identity, registry, a);
    }

    function test_constructor_zeroComplianceReverts() public {
        address[] memory a = new address[](3);
        a[0] = gov1; a[1] = gov2; a[2] = gov3;
        vm.expectRevert(L3RS1Asset.ZeroAddress.selector);
        _deployWithParams(issuer, bytes2("GB"), 2, ComplianceModule(address(0)), identity, registry, a);
    }

    function test_constructor_zeroIdentityReverts() public {
        address[] memory a = new address[](3);
        a[0] = gov1; a[1] = gov2; a[2] = gov3;
        vm.expectRevert(L3RS1Asset.ZeroAddress.selector);
        _deployWithParams(issuer, bytes2("GB"), 2, compliance, IdentityAttestation(address(0)), registry, a);
    }

    function test_constructor_zeroRegistryReverts() public {
        address[] memory a = new address[](3);
        a[0] = gov1; a[1] = gov2; a[2] = gov3;
        vm.expectRevert(L3RS1Asset.ZeroAddress.selector);
        _deployWithParams(issuer, bytes2("GB"), 2, compliance, identity, PolicyRegistry(address(0)), a);
    }

    function test_constructor_tooFewAuthoritiesReverts() public {
        address[] memory a = new address[](2);
        a[0] = gov1; a[1] = gov2;
        vm.expectRevert(L3RS1Asset.InsufficientSignatures.selector);
        _deployWithParams(issuer, bytes2("GB"), 2, compliance, identity, registry, a);
    }

    function test_constructor_zeroAuthorityInListReverts() public {
        address[] memory a = new address[](3);
        a[0] = gov1; a[1] = address(0); a[2] = gov3;
        vm.expectRevert(L3RS1Asset.ZeroAddress.selector);
        _deployWithParams(issuer, bytes2("GB"), 2, compliance, identity, registry, a);
    }

    function test_constructor_duplicateAuthorityReverts() public {
        address[] memory a = new address[](3);
        a[0] = gov1; a[1] = gov1; a[2] = gov3;
        vm.expectRevert(L3RS1Asset.DuplicateSignature.selector);
        _deployWithParams(issuer, bytes2("GB"), 2, compliance, identity, registry, a);
    }

    // ----- access-control branches -------------------------------------------

    function test_issue_revertsForNonIssuer() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(L3RS1Asset.NotIssuer.selector);
        asset.issue(holderA, 1000);
    }

    function test_setFeeRecipient_revertsForNonIssuer() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(L3RS1Asset.NotIssuer.selector);
        asset.setFeeRecipient(makeAddr("fee"));
    }

    // ----- zero-address transfer branches ------------------------------------

    function test_transfer_revertsOnZeroReceiver() public {
        vm.prank(holderA);
        vm.expectRevert(L3RS1Asset.ZeroAddress.selector);
        asset.transfer(address(0), 100);
    }

    function test_issue_revertsOnZeroRecipient() public {
        vm.prank(issuer);
        vm.expectRevert(L3RS1Asset.ZeroAddress.selector);
        asset.issue(address(0), 100);
    }

// ----- governance revert branches ----------------------------------------

    function test_governanceFreeze_revertsOnWrongNonce() public {
        uint256 badNonce = asset.governanceNonce() + 7;
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _freezeDigest(badNonce, deadline));
        vm.expectRevert(L3RS1Asset.InvalidNonce.selector);
        asset.governanceFreeze(badNonce, deadline, sigs);
    }

    function test_governanceFreeze_revertsOnExpiredDeadline() public {
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp - 1;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _freezeDigest(nonce, deadline));
        vm.expectRevert(L3RS1Asset.Expired.selector);
        asset.governanceFreeze(nonce, deadline, sigs);
    }

    function test_rotateAuthority_revertsOnNonAuthorityRemoved() public {
        address outsider = makeAddr("outsider");
        address newAuth = makeAddr("gov4");
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _rotateDigest(outsider, newAuth, nonce, deadline));
        vm.expectRevert(L3RS1Asset.NotAuthority.selector);
        asset.rotateAuthority(outsider, newAuth, nonce, deadline, sigs);
    }

    function test_rotateAuthority_revertsOnZeroAdded() public {
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _rotateDigest(gov3, address(0), nonce, deadline));
        vm.expectRevert(L3RS1Asset.ZeroAddress.selector);
        asset.rotateAuthority(gov3, address(0), nonce, deadline, sigs);
    }

    function test_rotateAuthority_revertsOnDuplicateAddedIsAuthority() public {
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _rotateDigest(gov3, gov1, nonce, deadline));
        vm.expectRevert(L3RS1Asset.DuplicateSignature.selector);
        asset.rotateAuthority(gov3, gov1, nonce, deadline, sigs);
    }

    function test_stateFromIndex_outOfRangeReverts() public {
        vm.expectRevert(bytes("L3RS1Asset: state index out of range"));
        asset.stateFromIndex(7);
    }

    function test_unsafeSetBalance_alwaysReverts() public {
        vm.expectRevert(bytes("L3RS1Asset: direct balance mutation prohibited"));
        asset.unsafeSetBalance(holderA, 1);
    }

    /// @notice 6B: happy-path transfer. Every step 1-7 succeeds and the
    ///         `emit Transfer` + `return true` tail of `transfer()` is reached.
    function test_transfer_happyPath() public {
        _grantAttestationVA(holderA, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantAttestationVA(holderB, JURISDICTION_US, 2, block.timestamp + 365 days);
        vm.startPrank(issuer);
        compliance.allowJurisdictionPair(JURISDICTION_GB, JURISDICTION_US);
        asset.issue(holderA, 10_000);
        vm.stopPrank();

        uint256 aBefore = asset.balanceOf(holderA);
        uint256 bBefore = asset.balanceOf(holderB);

        vm.prank(holderA);
        bool ok = asset.transfer(holderB, 1_000);
        assertTrue(ok);

        // With no fee recipient configured, the fee step short-circuits and
        // `netAmount = amount` (see L3RS1Asset._executeTransfer step 5).
        assertEq(asset.balanceOf(holderA), aBefore - 1_000);
        assertEq(asset.balanceOf(holderB), bBefore + 1_000);
    }

    /// @notice 6B: exercise the INSUFFICIENT_BALANCE path at §2.6 step 4. Set
    ///         identity + compliance so steps 1-3 pass; holder's balance is 0;
    ///         step 4 rejects.
    function test_transfer_revertsOnInsufficientBalance() public {
        _grantAttestationVA(holderA, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantAttestationVA(holderB, JURISDICTION_US, 2, block.timestamp + 365 days);
        vm.prank(issuer);
        compliance.allowJurisdictionPair(JURISDICTION_GB, JURISDICTION_US);

        // holderA has no balance; transfer should reject at step 4.
        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(L3RS1Asset.TransferStepRejected.selector, uint8(4), ReasonCodes.INSUFFICIENT_BALANCE)
        );
        asset.transfer(holderB, 100);
    }

    // ----- lifecycle state-disallows branch ---------------------------------

    function test_transfer_revertsWhenAssetFrozen() public {
        // Grant identity so step 1 passes; freeze the asset; confirm step 3 rejects.
        _grantAttestationVA(holderA, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantAttestationVA(holderB, JURISDICTION_US, 2, block.timestamp + 365 days);
        vm.prank(issuer);
        compliance.allowJurisdictionPair(JURISDICTION_GB, JURISDICTION_US);

        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _freezeDigest(nonce, deadline));
        asset.governanceFreeze(nonce, deadline, sigs);

        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(L3RS1Asset.TransferStepRejected.selector, uint8(3), ReasonCodes.STATE_DISALLOWS)
        );
        asset.transfer(holderB, 100);
    }

    // ----- LegalMirror accessor coverage ------------------------------------

    function test_legalMirror_initialStateIsVersionOneWithEmptyDoc() public view {
        assertEq(asset.legalVersion(), 1);
        assertEq(
            asset.legalHash(),
            asset.computeLegalHash("", bytes2("GB"), 1)
        );
    }

    function test_legalMirror_verifyAuthoritySignaturePositive() public view {
        assertTrue(asset.verifyLegalAuthoritySignature("doc", bytes("authority-sig-valid")));
    }

    function test_legalMirror_verifyAuthoritySignatureNegative() public view {
        assertFalse(asset.verifyLegalAuthoritySignature("doc", bytes("authority-sig-invalid")));
    }

    // ----- cross-chain origin surface reads ---------------------------------

    function test_computeCID_readsLiveValues() public view {
        bytes32 cid = asset.computeCID();
        bytes32 expected = asset.computeCIDWith(
            asset.assetId(),
            asset.currentState(),
            compliance.complianceHash(),
            asset.governanceHash(),
            uint64(block.timestamp)
        );
        assertEq(cid, expected);
    }

    function test_governanceHash_changesOnRotate() public {
        bytes32 before = asset.governanceHash();
        address newAuth = makeAddr("gov4");
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _rotateDigest(gov3, newAuth, nonce, deadline));
        asset.rotateAuthority(gov3, newAuth, nonce, deadline, sigs);
        bytes32 afterH = asset.governanceHash();
        assertTrue(before != afterH);
    }

    // ========================================================================
    // 6E — state machine transitions
    // ========================================================================

    /// @dev Deploy a fresh L3RS1Asset in ISSUED state so tests can drive the
    ///      full state machine from the start. Returns the new asset pranked
    ///      under the existing issuer key.
    function _freshAssetInIssued() internal returns (L3RS1Asset) {
        address[] memory authorities = new address[](3);
        authorities[0] = gov1; authorities[1] = gov2; authorities[2] = gov3;
        vm.prank(issuer);
        return new L3RS1Asset({
            issuer_: issuer,
            jurisdiction_: JURISDICTION_GB,
            idTier_: 2,
            compliance_: compliance,
            identity_: identity,
            registry_: registry,
            authorities_: authorities
        });
    }

    // ----- activate: ISSUED → ACTIVE -----------------------------------------

    function test_6E_activate_transitionsIssuedToActive() public {
        L3RS1Asset fresh = _freshAssetInIssued();
        assertEq(uint8(fresh.currentState()), uint8(ILifecycle.State.ISSUED));

        vm.prank(issuer);
        fresh.activate();
        assertEq(uint8(fresh.currentState()), uint8(ILifecycle.State.ACTIVE));
    }

    function test_6E_activate_rejectsNonIssuer() public {
        L3RS1Asset fresh = _freshAssetInIssued();
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(L3RS1Asset.NotIssuer.selector);
        fresh.activate();
    }

    function test_6E_activate_rejectsDoubleActivation() public {
        // The default `asset` is already ACTIVE via BaseTest.setUp.
        vm.prank(issuer);
        vm.expectRevert(L3RS1Asset.InvalidTransition.selector);
        asset.activate();
    }

    // ----- restrict: ACTIVE → RESTRICTED --------------------------------------

    function test_6E_restrict_activeToRestricted() public {
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _restrictDigest(nonce, deadline));
        asset.restrict(nonce, deadline, sigs);
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.RESTRICTED));
    }

    function test_6E_restrict_rejectsFromNonActive() public {
        // Freeze first.
        uint256 n = asset.governanceNonce();
        uint256 d = block.timestamp + 1 hours;
        asset.governanceFreeze(n, d, _twoSigs(gov1Key, gov2Key, _freezeDigest(n, d)));

        // Attempt restrict from FROZEN.
        uint256 nonce = asset.governanceNonce();
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _restrictDigest(nonce, d));
        vm.expectRevert(L3RS1Asset.InvalidTransition.selector);
        asset.restrict(nonce, d, sigs);
    }

    function test_6E_restrict_requiresQuorum() public {
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _oneSig(gov1Key, _restrictDigest(nonce, deadline));
        vm.expectRevert(L3RS1Asset.InsufficientSignatures.selector);
        asset.restrict(nonce, deadline, sigs);
    }

    // ----- clearRestriction: RESTRICTED → ACTIVE ------------------------------

    function test_6E_clearRestriction_restrictedToActive() public {
        // First restrict.
        uint256 n1 = asset.governanceNonce();
        uint256 d = block.timestamp + 1 hours;
        asset.restrict(n1, d, _twoSigs(gov1Key, gov2Key, _restrictDigest(n1, d)));
        // Then clear.
        uint256 n2 = asset.governanceNonce();
        asset.clearRestriction(n2, d, _twoSigs(gov1Key, gov2Key, _clearRestrictionDigest(n2, d)));
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.ACTIVE));
    }

    function test_6E_clearRestriction_rejectsFromNonRestricted() public {
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _clearRestrictionDigest(nonce, deadline));
        vm.expectRevert(L3RS1Asset.InvalidTransition.selector);
        asset.clearRestriction(nonce, deadline, sigs);
    }

    // ----- assetRedemption: ACTIVE → REDEEMED ---------------------------------

    function test_6E_assetRedemption_activeToRedeemed() public {
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        asset.assetRedemption(nonce, deadline, _twoSigs(gov1Key, gov2Key, _assetRedemptionDigest(nonce, deadline)));
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.REDEEMED));
        assertTrue(asset.isAssetRedeemed());
    }

    function test_6E_transfersRejectWithAssetRedeemedAfterRedemption() public {
        _grantAttestationVA(holderA, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantAttestationVA(holderB, JURISDICTION_US, 2, block.timestamp + 365 days);
        vm.startPrank(issuer);
        compliance.allowJurisdictionPair(JURISDICTION_GB, JURISDICTION_US);
        asset.issue(holderA, 1_000_000);
        vm.stopPrank();

        // Transition to REDEEMED.
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        asset.assetRedemption(nonce, deadline, _twoSigs(gov1Key, gov2Key, _assetRedemptionDigest(nonce, deadline)));

        // Transfer must reject with ASSET_REDEEMED, not STATE_DISALLOWS.
        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(L3RS1Asset.TransferStepRejected.selector, uint8(3), ReasonCodes.ASSET_REDEEMED)
        );
        asset.transfer(holderB, 100);
    }

    function test_6E_redeemWorksPostRedemption() public {
        _grantAttestationVA(holderA, JURISDICTION_GB, 2, block.timestamp + 365 days);
        vm.startPrank(issuer);
        asset.issue(holderA, 1_000_000);
        vm.stopPrank();

        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        asset.assetRedemption(nonce, deadline, _twoSigs(gov1Key, gov2Key, _assetRedemptionDigest(nonce, deadline)));

        // redeem() claim-path must succeed in REDEEMED.
        vm.prank(holderA);
        asset.redeem(1_000_000);
        assertEq(asset.balanceOf(holderA), 0);
        assertEq(asset.totalSupply(), 0);
    }

    function test_6E_issueRejectedInRedeemedState() public {
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        asset.assetRedemption(nonce, deadline, _twoSigs(gov1Key, gov2Key, _assetRedemptionDigest(nonce, deadline)));

        vm.prank(issuer);
        vm.expectRevert(
            abi.encodeWithSelector(L3RS1Asset.TransferStepRejected.selector, uint8(3), ReasonCodes.STATE_DISALLOWS)
        );
        asset.issue(holderA, 100);
    }

    // ----- assetFinalize: REDEEMED → BURNED -----------------------------------

    function test_6E_assetFinalize_redeemedToBurned() public {
        // Redeem first.
        uint256 n1 = asset.governanceNonce();
        uint256 d = block.timestamp + 1 hours;
        asset.assetRedemption(n1, d, _twoSigs(gov1Key, gov2Key, _assetRedemptionDigest(n1, d)));
        // totalSupply is 0 by construction (no issuance in this test).
        uint256 n2 = asset.governanceNonce();
        asset.assetFinalize(n2, d, _twoSigs(gov1Key, gov2Key, _assetFinalizeDigest(n2, d)));
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.BURNED));
    }

    function test_6E_assetFinalize_revertsIfSupplyNotZero() public {
        _grantAttestationVA(holderA, JURISDICTION_GB, 2, block.timestamp + 365 days);
        vm.startPrank(issuer);
        asset.issue(holderA, 500);
        vm.stopPrank();

        uint256 n1 = asset.governanceNonce();
        uint256 d = block.timestamp + 1 hours;
        asset.assetRedemption(n1, d, _twoSigs(gov1Key, gov2Key, _assetRedemptionDigest(n1, d)));

        uint256 n2 = asset.governanceNonce();
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _assetFinalizeDigest(n2, d));
        vm.expectRevert(L3RS1Asset.SupplyNotZero.selector);
        asset.assetFinalize(n2, d, sigs);
    }

    function test_6E_assetFinalize_rejectsFromNonRedeemed() public {
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, _assetFinalizeDigest(nonce, deadline));
        vm.expectRevert(L3RS1Asset.InvalidTransition.selector);
        asset.assetFinalize(nonce, deadline, sigs);
    }

    // ----- view accessor ------------------------------------------------------

    function test_6E_isAssetRedeemed_reflectsState() public {
        assertFalse(asset.isAssetRedeemed());
        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        asset.assetRedemption(nonce, deadline, _twoSigs(gov1Key, gov2Key, _assetRedemptionDigest(nonce, deadline)));
        assertTrue(asset.isAssetRedeemed());
    }

    // ----- full-lifecycle traversal ------------------------------------------

    /// @notice Demonstrates the state machine AS a state machine, not just as
    ///         a collection of individually-correct transitions. The asset
    ///         traverses every lifecycle state in one run:
    ///         ISSUED → ACTIVE → RESTRICTED → ACTIVE → FROZEN → ACTIVE →
    ///         REDEEMED → BURNED. This is Theorem 15.1 State Integrity in
    ///         aggregate per DESIGN.md §6E.
    function test_6E_fullLifecycleTraversal() public {
        L3RS1Asset a = _freshAssetInIssued();
        assertEq(uint8(a.currentState()), uint8(ILifecycle.State.ISSUED));

        // ISSUED → ACTIVE
        vm.prank(issuer);
        a.activate();
        assertEq(uint8(a.currentState()), uint8(ILifecycle.State.ACTIVE));

        uint256 d = block.timestamp + 1 hours;

        // ACTIVE → RESTRICTED
        uint256 n = a.governanceNonce();
        bytes32 rDig = _eip712Digest(a.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            a.RESTRICT_TYPEHASH(), address(a), n, d
        )));
        a.restrict(n, d, _twoSigs(gov1Key, gov2Key, rDig));
        assertEq(uint8(a.currentState()), uint8(ILifecycle.State.RESTRICTED));

        // RESTRICTED → ACTIVE
        n = a.governanceNonce();
        bytes32 cDig = _eip712Digest(a.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            a.CLEAR_RESTRICTION_TYPEHASH(), address(a), n, d
        )));
        a.clearRestriction(n, d, _twoSigs(gov1Key, gov2Key, cDig));
        assertEq(uint8(a.currentState()), uint8(ILifecycle.State.ACTIVE));

        // ACTIVE → FROZEN
        n = a.governanceNonce();
        bytes32 fDig = _eip712Digest(a.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            a.GOVERNANCE_FREEZE_TYPEHASH(), address(a), n, d
        )));
        a.governanceFreeze(n, d, _twoSigs(gov1Key, gov2Key, fDig));
        assertEq(uint8(a.currentState()), uint8(ILifecycle.State.FROZEN));

        // FROZEN → ACTIVE (via emergencyRollback)
        n = a.governanceNonce();
        bytes32 rbDig = _eip712Digest(a.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            a.EMERGENCY_ROLLBACK_TYPEHASH(), address(a), n, d
        )));
        a.emergencyRollback(n, d, _twoSigs(gov1Key, gov2Key, rbDig));
        assertEq(uint8(a.currentState()), uint8(ILifecycle.State.ACTIVE));

        // ACTIVE → REDEEMED
        n = a.governanceNonce();
        bytes32 arDig = _eip712Digest(a.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            a.ASSET_REDEMPTION_TYPEHASH(), address(a), n, d
        )));
        a.assetRedemption(n, d, _twoSigs(gov1Key, gov2Key, arDig));
        assertEq(uint8(a.currentState()), uint8(ILifecycle.State.REDEEMED));
        assertTrue(a.isAssetRedeemed());

        // REDEEMED → BURNED (totalSupply is zero, this fresh asset had no issuance)
        n = a.governanceNonce();
        bytes32 afDig = _eip712Digest(a.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            a.ASSET_FINALIZE_TYPEHASH(), address(a), n, d
        )));
        a.assetFinalize(n, d, _twoSigs(gov1Key, gov2Key, afDig));
        assertEq(uint8(a.currentState()), uint8(ILifecycle.State.BURNED));

        // BURNED is terminal: every governance or transfer path rejects.
        n = a.governanceNonce();
        bytes32 attemptDig = _eip712Digest(a.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            a.GOVERNANCE_FREEZE_TYPEHASH(), address(a), n, d
        )));
        vm.expectRevert(L3RS1Asset.InvalidTransition.selector);
        a.governanceFreeze(n, d, _twoSigs(gov1Key, gov2Key, attemptDig));
    }
}
