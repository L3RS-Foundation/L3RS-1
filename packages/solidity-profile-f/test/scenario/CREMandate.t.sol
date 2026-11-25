// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: DESIGN.md sub-stage 6F (CRE mandate scenario), L3RS-1 v1.0.0 Sections
//         2 (Asset Object), 3 (Identity Binding), 4 (Compliance Engine), 5
//         (Governance), 12 (Legal Mirror). 07-profile-f.md (reason codes).
//
// $50M synthetic commercial real-estate mandate. Profile F REGULATED_SECURITY
// per L3RS-1 Section 2.3, jurisdiction GB, idTier 2, 5-authority governance,
// 2 Verification Authorities, 7 holders (6 investors + 1 tier-1 fail-case).
//
// Five phases:
//   1. Setup               deploys contracts with production-realistic
//                          parameters, configures all nine Section 4.4 rules,
//                          grants attestations, mints $50M.
//   2. Primary Ops         97 successful secondary transfers + 3 rejections.
//                          vm.warp fires at every action.
//   3. Governance Events   compliance rule amendment + version bump, legal
//                          mirror amendment, governance freeze + emergency
//                          rollback, VA revocation + downstream identity fail.
//   4. Redemption          asset-level redemption, 3 pending authenticatedTransfer
//                          attempts rejecting with ASSET_REDEEMED, per-holder
//                          drain to zero, assetFinalize to BURNED.
//   5. Final Assertions    exactly 97 successful transfers, totalSupply == 0,
//                          currentState == BURNED, per-phase supply invariant,
//                          distinct governance + VA nonces, post-BURNED state
//                          changes revert.
//
// DEVIATIONS from the literal 6F brief documented in DESIGN.md Section 12:
//   D1  INVESTOR_CLASSIFICATION rejection runs via direct
//       ComplianceModule.evaluateWithDisclosure call rather than through the
//       L3RS1Asset transfer pipeline, because INVESTOR_CLASS is an extended
//       rule not yet plumbed into the basic evaluate path (TODO 16). The
//       pipeline's third rejection slot demonstrates TRANSFER_INELIGIBLE
//       instead; INVESTOR_CLASS is asserted separately on the compliance
//       module directly.
//   D2  Fee recipient is an attested EOA rather than a multisig contract. A
//       multisig contract would require onFeeReceived support; the Phase One
//       reference has no such contract. The EOA placeholder is attested at
//       setup so that accumulated fees can be drained alongside the six
//       investor holders in phase 4.
//   D3  Asset type REGULATED_SECURITY is implicit in the L3RS1Asset contract
//       (no explicit asset-type enum field in the on-chain struct). The type
//       is documented in this scenario header rather than asserted in code.
//   D4  5 authorities, 4-of-5 quorum. Threshold follows the ceil(2n/3)
//       formula in L3RS-1 Section 5.4; for n = 5 this yields 4. Every
//       governance signature set in the scenario carries four distinct
//       authority signatures.

import {Test} from "forge-std/Test.sol";

import {ComplianceModule} from "../../src/ComplianceModule.sol";
import {IdentityAttestation} from "../../src/IdentityAttestation.sol";
import {L3RS1Asset} from "../../src/L3RS1Asset.sol";
import {PolicyRegistry} from "../../src/PolicyRegistry.sol";
import {MockZKVerifier} from "../../src/MockZKVerifier.sol";
import {IZKVerifier} from "../../src/interfaces/IZKVerifier.sol";
import {ILifecycle} from "../../src/interfaces/ILifecycle.sol";
import {ReasonCodes} from "../../src/libraries/ReasonCodes.sol";

contract CREMandateScenario is Test {
    // ====================================================================
    // Constants
    // ====================================================================

    bytes2 internal constant J_GB = bytes2("GB");
    bytes2 internal constant J_US = bytes2("US");
    bytes2 internal constant J_SG = bytes2("SG");

    uint256 internal constant NOTIONAL = 50_000_000 * 1e18;

    // Wed 2024-06-15 12:00 UTC. Hour 12 is inside the MARKET rule window
    // [8, 20) configured at setup.
    uint256 internal constant T0 = 1_718_452_800;

    uint256 internal constant THRESHOLD_AMOUNT = 10_000_000 * 1e18;
    uint256 internal constant AML_AMOUNT = 20_000_000 * 1e18;

    // ====================================================================
    // Principals
    // ====================================================================

    address internal issuer;

    address internal gov1; uint256 internal gov1Key;
    address internal gov2; uint256 internal gov2Key;
    address internal gov3; uint256 internal gov3Key;
    address internal gov4; uint256 internal gov4Key;
    address internal gov5; uint256 internal gov5Key;

    address internal va1; uint256 internal va1Key;
    address internal va2; uint256 internal va2Key;

    address internal feeRecipient;

    address internal holderUK1;
    address internal holderUK2;
    address internal holderUK3;
    address internal holderUS1;
    address internal holderUS2;
    address internal holderSG;
    address internal holderT1;

    // ====================================================================
    // Contracts
    // ====================================================================

    ComplianceModule internal compliance;
    IdentityAttestation internal identity;
    PolicyRegistry internal registry;
    L3RS1Asset internal asset;
    MockZKVerifier internal zkVerifier;

    // ====================================================================
    // Ghost counters
    // ====================================================================

    /// @dev Increments on every successful `asset.transfer` in phase 2.
    ///      Final assertion asserts this equals exactly 97. Mints, burns,
    ///      and rejected attempts do not count.
    uint256 internal successfulTransferCount;

    /// @dev Monotonic VA nonce cursor. Reuse is rejected by IdentityAttestation
    ///      so non-reversion over 9 grants proves 9 distinct nonces consumed.
    uint256 internal _vaNonceCursor;

    // ====================================================================
    // Phase-boundary checkpoints
    // ====================================================================

    struct PhaseCheckpoint {
        uint256 blockNumber;
        uint256 blockTimestamp;
        uint256 totalSupply;
        ILifecycle.State state;
        uint256 transitionCount;
        bytes32 cid;
        bytes32 complianceHashAt;
        bytes32 governanceHashAt;
    }

    mapping(bytes32 => PhaseCheckpoint) internal _checkpoints;

    event ScenarioCheckpoint(
        bytes32 indexed label,
        uint256 blockNumber,
        uint256 totalSupply,
        ILifecycle.State currentState
    );

    // ====================================================================
    // setUp
    // ====================================================================

    function setUp() public {
        issuer = makeAddr("cre-issuer");
        (gov1, gov1Key) = makeAddrAndKey("cre-gov1");
        (gov2, gov2Key) = makeAddrAndKey("cre-gov2");
        (gov3, gov3Key) = makeAddrAndKey("cre-gov3");
        (gov4, gov4Key) = makeAddrAndKey("cre-gov4");
        (gov5, gov5Key) = makeAddrAndKey("cre-gov5");
        (va1, va1Key) = makeAddrAndKey("cre-va1");
        (va2, va2Key) = makeAddrAndKey("cre-va2");
        feeRecipient = makeAddr("cre-fee-multisig");
        holderUK1 = makeAddr("cre-UK1");
        holderUK2 = makeAddr("cre-UK2");
        holderUK3 = makeAddr("cre-UK3");
        holderUS1 = makeAddr("cre-US1");
        holderUS2 = makeAddr("cre-US2");
        holderSG  = makeAddr("cre-SG");
        holderT1  = makeAddr("cre-T1");
    }

    // ====================================================================
    // The scenario
    // ====================================================================

    function test_6F_CREMandate_FullLifecycle() public {
        _phase1_setup();
        _phase2_primaryOps();
        _phase3_governance();
        _phase4_redemption();
        _phase5_finalAssertions();
    }

    // ====================================================================
    // Phase 1 --- Setup
    // ====================================================================

    function _phase1_setup() internal {
        vm.warp(T0);

        address[] memory authorities = new address[](5);
        authorities[0] = gov1;
        authorities[1] = gov2;
        authorities[2] = gov3;
        authorities[3] = gov4;
        authorities[4] = gov5;

        address[] memory initialVAs = new address[](2);
        initialVAs[0] = va1;
        initialVAs[1] = va2;

        vm.startPrank(issuer);
        zkVerifier = new MockZKVerifier();
        identity = new IdentityAttestation(authorities, initialVAs, zkVerifier);
        compliance = new ComplianceModule(authorities);
        registry = new PolicyRegistry(authorities);
        asset = new L3RS1Asset({
            issuer_: issuer,
            jurisdiction_: J_GB,
            idTier_: 2,
            compliance_: compliance,
            identity_: identity,
            registry_: registry,
            authorities_: authorities
        });

        // N = 5, threshold = ceil(2n/3) = 4 per L3RS-1 Section 5.4.
        assertEq(asset.authorities().length, 5, "N = 5 authorities");

        asset.activate();

        // Configure all nine L3RS-1 Section 4.4 compliance rules.
        // Basic (pipeline) rules:
        //   1. SANCTIONS_SCREENING       -- empty initially, populated in phase 2.
        //   2. TRANSFER_ELIGIBILITY      -- empty initially, populated in phase 2.
        //   3. GEOGRAPHIC_RESTRICTION    -- pairs below.
        //   4. MARKET_RESTRICTION        -- [8, 20) UTC.
        //   5. TRANSACTION_THRESHOLD     -- $10M per transfer.
        //   6. AML_TRIGGER               -- $20M.
        // Extended (evaluateWithDisclosure) rules:
        //   7. INVESTOR_CLASSIFICATION   -- min tier 2.
        //   8. HOLDING_PERIOD            -- 1 day (bumped to 7d in phase 3).
        //   9. REDEMPTION_ELIGIBILITY    -- default empty; all holders eligible.
        compliance.allowJurisdictionPair(J_GB, J_GB);
        compliance.allowJurisdictionPair(J_GB, J_US);
        compliance.allowJurisdictionPair(J_US, J_GB);
        compliance.allowJurisdictionPair(J_US, J_US);
        compliance.allowJurisdictionPair(J_SG, J_GB);
        compliance.allowJurisdictionPair(J_GB, J_SG);
        compliance.allowJurisdictionPair(J_SG, J_SG);
        compliance.allowJurisdictionPair(J_SG, J_US);
        compliance.allowJurisdictionPair(J_US, J_SG);
        compliance.setMarketHours(8, 20);
        compliance.setTransactionThreshold(THRESHOLD_AMOUNT);
        compliance.setAmlThreshold(AML_AMOUNT);
        compliance.setMinInvestorTier(2);
        compliance.setMinHoldingPeriod(1 days);

        asset.setFeeRecipient(feeRecipient);
        vm.stopPrank();

        // Grant attestations.
        //   UK1, UK2, UK3  tier 2 GB          (investor holders)
        //   US1, US2       tier 2 US          (investor holders)
        //   SG             tier 3 GB + SG     (stacked per Section 3.9)
        //   T1             tier 1 GB          (INVESTOR_CLASS fail + SANCTIONS sender)
        //   feeRecipient   tier 2 GB          (per deviation D2)
        _grantAttestation(va1Key, holderUK1, J_GB, 2, T0 + 365 days);
        _grantAttestation(va1Key, holderUK2, J_GB, 2, T0 + 365 days);
        _grantAttestation(va1Key, holderUK3, J_GB, 2, T0 + 365 days);
        _grantAttestation(va1Key, holderUS1, J_US, 2, T0 + 365 days);
        _grantAttestation(va1Key, holderUS2, J_US, 2, T0 + 365 days);
        _grantAttestation(va1Key, holderSG,  J_GB, 3, T0 + 365 days);
        _grantAttestation(va2Key, holderSG,  J_SG, 3, T0 + 365 days);
        _grantAttestation(va1Key, holderT1,  J_GB, 1, T0 + 365 days);
        _grantAttestation(va1Key, feeRecipient, J_GB, 2, T0 + 365 days);

        _snapshotAndEmit("SETUP_COMPLETE");
        assertEq(asset.totalSupply(), 0, "no supply at setup");
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.ACTIVE));

        // Mint $50M across six legitimate investor holders.
        address[] memory mintTo = new address[](6);
        uint256[] memory mintAmts = new uint256[](6);
        mintTo[0] = holderUK1; mintAmts[0] = 10_000_000 * 1e18;
        mintTo[1] = holderUK2; mintAmts[1] = 10_000_000 * 1e18;
        mintTo[2] = holderUK3; mintAmts[2] =  8_000_000 * 1e18;
        mintTo[3] = holderUS1; mintAmts[3] =  8_000_000 * 1e18;
        mintTo[4] = holderUS2; mintAmts[4] =  8_000_000 * 1e18;
        mintTo[5] = holderSG;  mintAmts[5] =  6_000_000 * 1e18;

        vm.startPrank(issuer);
        for (uint256 i = 0; i < 6; i++) {
            vm.warp(block.timestamp + 60);
            asset.issue(mintTo[i], mintAmts[i]);
        }
        vm.stopPrank();

        assertEq(asset.totalSupply(), NOTIONAL, "minted $50M");
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.ACTIVE));

        _snapshotAndEmit("MINT_COMPLETE");
    }

    // ====================================================================
    // Phase 2 --- Primary ops
    // ====================================================================

    function _phase2_primaryOps() internal {
        address[] memory holders = new address[](6);
        holders[0] = holderUK1;
        holders[1] = holderUK2;
        holders[2] = holderUK3;
        holders[3] = holderUS1;
        holders[4] = holderUS2;
        holders[5] = holderSG;

        // 97 successful secondary transfers. Amounts vary 10K..500K, which
        // keeps each holder's balance well above zero across the loop and
        // below the $10M threshold rule. vm.warp fires before each call.
        for (uint256 i = 0; i < 97; i++) {
            vm.warp(block.timestamp + 60);
            address from = holders[i % 6];
            address to = holders[(i + 2) % 6];
            if (from == to) {
                to = holders[(i + 3) % 6];
            }
            uint256 amount = (((i * 7) % 50) + 1) * 10_000 * 1e18;
            vm.prank(from);
            asset.transfer(to, amount);
            successfulTransferCount++;
        }

        // -- Rejection 1: TRANSFER_ELIGIBILITY.
        vm.warp(block.timestamp + 60);
        vm.prank(issuer);
        compliance.setTransferIneligible(holderUK3, true);

        vm.warp(block.timestamp + 60);
        vm.expectRevert(
            abi.encodeWithSelector(
                L3RS1Asset.TransferStepRejected.selector,
                uint8(2),
                ReasonCodes.TRANSFER_INELIGIBLE
            )
        );
        vm.prank(holderUK3);
        asset.transfer(holderUK2, 1_000 * 1e18);

        // Restore eligibility so UK3 can redeem in phase 4.
        vm.prank(issuer);
        compliance.setTransferIneligible(holderUK3, false);

        // -- Rejection 2: MARKET (time outside [8, 20) UTC).
        uint256 outOfHours = ((block.timestamp / 86_400) + 1) * 86_400 + 2 * 3_600;
        vm.warp(outOfHours);
        vm.expectRevert(
            abi.encodeWithSelector(
                L3RS1Asset.TransferStepRejected.selector,
                uint8(2),
                ReasonCodes.MARKET
            )
        );
        vm.prank(holderUK1);
        asset.transfer(holderUK2, 1_000 * 1e18);
        // Warp forward into [8, 20) on the same day: +10 hours = 12:00 UTC.
        vm.warp(outOfHours + 10 * 3_600);

        // -- INVESTOR_CLASSIFICATION direct demo (deviation D1). Extended
        //    rule evaluated directly on ComplianceModule.evaluateWithDisclosure
        //    rather than through the pipeline. Tier 1 receiver (holderT1)
        //    falls below the configured minimum tier of 2.
        //
        //    This must run BEFORE the SANCTIONS rejection below, because
        //    the basic evaluation (which runs first inside
        //    evaluateWithDisclosure) would otherwise short-circuit with
        //    SANCTIONS once holderT1 enters the sanctions list.
        bytes memory ctxDirect = abi.encode(
            bytes32("L3RS-1/CTX/v1"),
            address(asset),
            holderUK1,
            holderT1,
            uint256(1e18),
            J_GB,
            J_GB,
            uint64(block.timestamp),
            uint256(0),
            bytes("")
        );
        (bool okDirect, bytes32 reasonDirect) = compliance.evaluateWithDisclosure(
            address(asset),
            holderUK1,
            holderT1,
            1e18,
            ctxDirect,
            uint8(1),           // receiverTier = 1, below min 2
            uint256(0),         // senderFirstReceivedAt (irrelevant here)
            bytes32("TRANSFER")
        );
        assertFalse(okDirect, "tier-1 receiver rejected");
        assertEq(reasonDirect, ReasonCodes.INVESTOR_CLASS, "reason = INVESTOR_CLASS");

        // -- Rejection 3 + sanctions lifecycle (external scoping review,
        //    DESIGN.md §13.3). Full add → reject → remove-by-quorum → accept
        //    flow for holderT1. Sanctions fires at step 2, ahead of the
        //    balance check at step 4, so holderT1's zero balance does not
        //    change the reason code on the rejection path. After quorum
        //    removal the same address transacts successfully (transferring
        //    zero, which remains a valid no-op through the pipeline and
        //    consumes no balance), demonstrating OFAC-style delisting
        //    semantics end-to-end. The post-removal transfer does not bump
        //    `successfulTransferCount` because that counter tracks the 97
        //    primary-ops transfers — the sanctions-lifecycle exercise is
        //    bookkeeping, not primary trading activity.
        vm.warp(block.timestamp + 60);
        vm.prank(issuer);
        compliance.addSanctionedAddress(holderT1);
        assertTrue(compliance.sanctioned(holderT1), "T1 sanctioned (mapping)");

        vm.warp(block.timestamp + 60);
        vm.expectRevert(
            abi.encodeWithSelector(
                L3RS1Asset.TransferStepRejected.selector,
                uint8(2),
                ReasonCodes.SANCTIONS
            )
        );
        vm.prank(holderT1);
        asset.transfer(holderUK2, 1_000 * 1e18);

        // Quorum-gated removal. Four of five authorities sign.
        vm.warp(block.timestamp + 60);
        {
            uint256 n = compliance.governanceNonce();
            uint256 dl = block.timestamp + 1 hours;
            bytes32 structHash = keccak256(
                abi.encode(
                    compliance.REMOVE_SANCTIONED_TYPEHASH(),
                    address(compliance),
                    holderT1,
                    n,
                    dl
                )
            );
            bytes32 d = _eip712Digest(compliance.DOMAIN_SEPARATOR(), structHash);
            bytes[] memory sigs = _fourAssetSigs(d);
            compliance.removeSanctionedAddress(holderT1, n, dl, sigs);
        }
        assertFalse(compliance.sanctioned(holderT1), "T1 delisted (mapping)");

        // Post-removal: T1 is no longer rejected at the SANCTIONS rule.
        // T1 has zero balance so a non-zero transfer would revert at step 4
        // with INSUFFICIENT_BALANCE — the delisting is observable, but
        // asserting the whole pipeline would require attesting T1 tier 2
        // which is outside the scope of this in-phase check. Instead
        // exercise the basic evaluate path on ComplianceModule directly to
        // confirm SANCTIONS no longer fires for T1.
        bytes memory fullCtx = abi.encode(
            bytes32("L3RS-1/CTX/v1"), address(asset),
            holderT1, holderUK2, uint256(1), J_GB, J_GB,
            uint64(block.timestamp), uint256(0), bytes("")
        );
        (bool postRemovalOk, bytes32 postRemovalReason) =
            compliance.evaluate(address(asset), holderT1, holderUK2, 1, fullCtx);
        assertTrue(postRemovalOk, "T1 not blocked post-delisting");
        assertEq(postRemovalReason, ReasonCodes.NONE, "no reason code");

        assertEq(asset.totalSupply(), NOTIONAL, "primary ops conserve supply");
        assertEq(successfulTransferCount, 97, "97 successful transfers in phase 2");
        _snapshotAndEmit("PRIMARY_COMPLETE");
    }

    // ====================================================================
    // Phase 3 --- Governance events
    // ====================================================================

    function _phase3_governance() internal {
        // 3a. Compliance rule amendment (setter) + version bump (quorum).
        vm.warp(block.timestamp + 60);
        vm.prank(issuer);
        compliance.setMinHoldingPeriod(7 days);

        uint256 cHashChangesBefore = compliance.hashChangeCount();

        vm.warp(block.timestamp + 60);
        _bumpComplianceVersion();

        assertGt(
            compliance.hashChangeCount(),
            cHashChangesBefore,
            "compliance hash change recorded"
        );

        // 3b. Legal mirror amendment (quorum).
        vm.warp(block.timestamp + 60);
        bytes32 legalBefore = asset.legalHash();
        _amendLegalMirror(bytes("CRE Mandate v2 - Risk Amendment 2026-Q2"), J_GB, 2);
        assertTrue(asset.legalHash() != legalBefore, "legal hash updated");
        assertEq(asset.legalVersion(), 2, "legal version bumped");

        // 3c. Governance freeze + emergency rollback.
        vm.warp(block.timestamp + 60);
        _governanceFreeze();
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.FROZEN), "frozen");

        // In FROZEN, transfers revert at step 3 with STATE_DISALLOWS.
        vm.warp(block.timestamp + 60);
        vm.expectRevert(
            abi.encodeWithSelector(
                L3RS1Asset.TransferStepRejected.selector,
                uint8(3),
                ReasonCodes.STATE_DISALLOWS
            )
        );
        vm.prank(holderUK1);
        asset.transfer(holderUK2, 1e18);

        vm.warp(block.timestamp + 60);
        _emergencyRollback();
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.ACTIVE), "rolled back to ACTIVE");

        // 3d. VA revocation + downstream transfer failing identity.
        vm.warp(block.timestamp + 60);
        uint256 revIndexBefore = identity.revocationIndex();
        _revokeAttestation(holderUK1, J_GB);
        assertEq(identity.revocationIndex(), revIndexBefore + 1, "revocationIndex bumped");

        vm.warp(block.timestamp + 60);
        vm.expectRevert(
            abi.encodeWithSelector(
                L3RS1Asset.TransferStepRejected.selector,
                uint8(1),
                ReasonCodes.IDENTITY_REVOKED
            )
        );
        vm.prank(holderUK1);
        asset.transfer(holderUK2, 1e18);

        // Re-grant via VA2 so UK1 can redeem in phase 4.
        vm.warp(block.timestamp + 60);
        _grantAttestation(va2Key, holderUK1, J_GB, 2, block.timestamp + 365 days);

        _snapshotAndEmit("GOVERNANCE_COMPLETE");
        assertEq(asset.totalSupply(), NOTIONAL, "supply preserved through governance");
    }

    // ====================================================================
    // Phase 4 --- Redemption lifecycle
    // ====================================================================

    function _phase4_redemption() internal {
        // Capture a pre-redemption CID for the "changed on transition" check.
        vm.warp(block.timestamp + 60);
        bytes32 cidBefore = asset.computeCID();

        _assetRedemption();
        assertTrue(asset.isAssetRedeemed(), "isAssetRedeemed flips true");
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.REDEEMED), "state REDEEMED");

        bytes32 cidAfter = asset.computeCID();
        assertTrue(cidBefore != cidAfter, "CID differs after REDEEMED transition");

        // CID re-computation check: computeCIDWith, using the current field
        // values, must reproduce the live computeCID exactly.
        bytes32 cidRecomputed = asset.computeCIDWith(
            asset.assetId(),
            ILifecycle.State.REDEEMED,
            compliance.complianceHash(),
            asset.governanceHash(),
            uint64(block.timestamp)
        );
        assertEq(cidAfter, cidRecomputed, "computeCIDWith matches computeCID");

        // Three pending authenticatedTransfer attempts reject with
        // ASSET_REDEEMED. Each attempt uses a fresh nonce; because the
        // pipeline reverts at step 3 before _seenTxId commits, the TxID
        // registry is not mutated.
        for (uint256 i = 0; i < 3; i++) {
            vm.warp(block.timestamp + 60);
            vm.expectRevert(
                abi.encodeWithSelector(
                    L3RS1Asset.TransferStepRejected.selector,
                    uint8(3),
                    ReasonCodes.ASSET_REDEEMED
                )
            );
            vm.prank(holderUK2);
            asset.authenticatedTransfer(holderUS1, 1e18, i + 1, uint64(block.timestamp));
        }

        // Six investor holders plus the attested fee-recipient EOA redeem
        // to zero (deviation D2). redeem() is valid in REDEEMED state per
        // DESIGN.md sub-stage 6E.
        address[] memory drainers = new address[](7);
        drainers[0] = holderUK1;
        drainers[1] = holderUK2;
        drainers[2] = holderUK3;
        drainers[3] = holderUS1;
        drainers[4] = holderUS2;
        drainers[5] = holderSG;
        drainers[6] = feeRecipient;
        for (uint256 i = 0; i < drainers.length; i++) {
            uint256 bal = asset.balanceOf(drainers[i]);
            if (bal > 0) {
                vm.warp(block.timestamp + 60);
                vm.prank(drainers[i]);
                asset.redeem(bal);
            }
        }
        assertEq(asset.totalSupply(), 0, "all holders drained to zero");

        _snapshotAndEmit("REDEMPTION_COMPLETE");

        // Finalize: REDEEMED -> BURNED. Quorum-gated, supply-zero precondition.
        vm.warp(block.timestamp + 60);
        _assetFinalize();
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.BURNED), "state BURNED");

        _snapshotAndEmit("FINALIZED");
    }

    // ====================================================================
    // Phase 5 --- Final assertions
    // ====================================================================

    function _phase5_finalAssertions() internal {
        // Core state assertions.
        assertEq(successfulTransferCount, 97, "exactly 97 successful transfers");
        assertEq(asset.totalSupply(), 0, "totalSupply == 0");
        assertEq(uint8(asset.currentState()), uint8(ILifecycle.State.BURNED), "state BURNED");

        // Per-phase supply invariant.
        assertEq(_cp("SETUP_COMPLETE").totalSupply, 0, "setup supply 0");
        assertEq(_cp("MINT_COMPLETE").totalSupply, NOTIONAL, "mint supply $50M");
        assertEq(_cp("PRIMARY_COMPLETE").totalSupply, NOTIONAL, "primary supply $50M");
        assertEq(_cp("GOVERNANCE_COMPLETE").totalSupply, NOTIONAL, "governance supply $50M");
        assertEq(_cp("REDEMPTION_COMPLETE").totalSupply, 0, "redemption supply 0");
        assertEq(_cp("FINALIZED").totalSupply, 0, "finalized supply 0");

        // Per-phase state progression.
        assertEq(uint8(_cp("SETUP_COMPLETE").state), uint8(ILifecycle.State.ACTIVE));
        assertEq(uint8(_cp("MINT_COMPLETE").state), uint8(ILifecycle.State.ACTIVE));
        assertEq(uint8(_cp("PRIMARY_COMPLETE").state), uint8(ILifecycle.State.ACTIVE));
        assertEq(uint8(_cp("GOVERNANCE_COMPLETE").state), uint8(ILifecycle.State.ACTIVE));
        assertEq(uint8(_cp("REDEMPTION_COMPLETE").state), uint8(ILifecycle.State.REDEEMED));
        assertEq(uint8(_cp("FINALIZED").state), uint8(ILifecycle.State.BURNED));

        // Governance nonce progression: each contract's nonce advanced
        // strictly (no holes, no reuse). Asset consumed 5 actions (freeze,
        // rollback, amendLegalMirror, assetRedemption, assetFinalize).
        // Compliance consumed 2 (removeSanctionedAddress in phase 2's
        // sanctions lifecycle, bumpVersion in phase 3). Identity consumed 1
        // (revokeAttestation).
        assertEq(asset.governanceNonce(), 5, "asset consumed 5 governance nonces");
        assertEq(compliance.governanceNonce(), 2, "compliance consumed 2");
        assertEq(identity.governanceNonce(), 1, "identity consumed 1");

        // VA nonce distinctness: nine grants succeeded (six investor
        // holders + SG second jurisdiction + T1 + fee recipient + UK1 re-grant
        // after revocation in phase 3 = 10 total). Reuse reverts
        // NonceReused, so the cursor advancing past the count proves
        // distinct nonces.
        assertEq(_vaNonceCursor, 10, "10 distinct VA nonces consumed");

        // -- Post-BURNED state changes must revert.

        // (a) restrict from BURNED reverts with InvalidTransition.
        vm.warp(block.timestamp + 60);
        {
            uint256 n = asset.governanceNonce();
            uint256 dl = block.timestamp + 1 hours;
            bytes[] memory sigs = _fourAssetSigs(_restrictDigest(n, dl));
            vm.expectRevert(L3RS1Asset.InvalidTransition.selector);
            asset.restrict(n, dl, sigs);
        }

        // (b) assetFinalize from BURNED reverts with InvalidTransition.
        vm.warp(block.timestamp + 60);
        {
            uint256 n = asset.governanceNonce();
            uint256 dl = block.timestamp + 1 hours;
            bytes[] memory sigs = _fourAssetSigs(_assetFinalizeDigest(n, dl));
            vm.expectRevert(L3RS1Asset.InvalidTransition.selector);
            asset.assetFinalize(n, dl, sigs);
        }

        // (c) assetRedemption from BURNED reverts with InvalidTransition.
        vm.warp(block.timestamp + 60);
        {
            uint256 n = asset.governanceNonce();
            uint256 dl = block.timestamp + 1 hours;
            bytes[] memory sigs = _fourAssetSigs(_assetRedemptionDigest(n, dl));
            vm.expectRevert(L3RS1Asset.InvalidTransition.selector);
            asset.assetRedemption(n, dl, sigs);
        }

        // (d) redeem() in BURNED reverts with STATE_DISALLOWS at step 3.
        //     (State-machine guard runs ahead of balance check; caller has
        //     a zero balance but the reason returned is the state check,
        //     which matches the §2.5 transition matrix.)
        vm.warp(block.timestamp + 60);
        vm.expectRevert(
            abi.encodeWithSelector(
                L3RS1Asset.TransferStepRejected.selector,
                uint8(3),
                ReasonCodes.STATE_DISALLOWS
            )
        );
        vm.prank(holderUK2);
        asset.redeem(1);

        // (e) emergencyRollback from BURNED reverts with InvalidTransition
        //     (BURNED is terminal; cannot roll back).
        vm.warp(block.timestamp + 60);
        {
            uint256 n = asset.governanceNonce();
            uint256 dl = block.timestamp + 1 hours;
            bytes[] memory sigs = _fourAssetSigs(_rollbackDigest(n, dl));
            vm.expectRevert(L3RS1Asset.InvalidTransition.selector);
            asset.emergencyRollback(n, dl, sigs);
        }

        // (f) issue from BURNED reverts with STATE_DISALLOWS.
        vm.warp(block.timestamp + 60);
        vm.expectRevert(
            abi.encodeWithSelector(
                L3RS1Asset.TransferStepRejected.selector,
                uint8(3),
                ReasonCodes.STATE_DISALLOWS
            )
        );
        vm.prank(issuer);
        asset.issue(holderUK2, 1);
    }

    // ====================================================================
    // Helpers --- checkpoint
    // ====================================================================

    function _snapshotAndEmit(string memory labelStr) internal {
        bytes32 label = keccak256(bytes(labelStr));
        PhaseCheckpoint storage c = _checkpoints[label];
        c.blockNumber = block.number;
        c.blockTimestamp = block.timestamp;
        c.totalSupply = asset.totalSupply();
        c.state = asset.currentState();
        c.transitionCount = asset.transitionCount();
        c.cid = asset.computeCID();
        c.complianceHashAt = compliance.complianceHash();
        c.governanceHashAt = asset.governanceHash();
        emit ScenarioCheckpoint(
            label,
            block.number,
            asset.totalSupply(),
            asset.currentState()
        );
    }

    function _cp(string memory labelStr) internal view returns (PhaseCheckpoint memory) {
        return _checkpoints[keccak256(bytes(labelStr))];
    }

    // ====================================================================
    // Helpers --- EIP-712 signing
    // ====================================================================

    function _signDigest(uint256 k, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(k, d);
        return abi.encodePacked(r, s, v);
    }

    function _eip712Digest(bytes32 sep, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", sep, structHash));
    }

    /// @dev Four governance signatures suffice for threshold = 4 at N = 5.
    ///      Same helper used for asset / compliance / identity because
    ///      all three contracts share the same five-authority set and
    ///      differ only by EIP-712 domain separator (baked into the digest).
    function _fourAssetSigs(bytes32 d) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](4);
        sigs[0] = _signDigest(gov1Key, d);
        sigs[1] = _signDigest(gov2Key, d);
        sigs[2] = _signDigest(gov3Key, d);
        sigs[3] = _signDigest(gov4Key, d);
    }

    // ====================================================================
    // Helpers --- digest builders
    // ====================================================================

    function _freezeDigest(uint256 n, uint256 dl) internal view returns (bytes32) {
        return _eip712Digest(
            asset.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(asset.GOVERNANCE_FREEZE_TYPEHASH(), address(asset), n, dl))
        );
    }

    function _rollbackDigest(uint256 n, uint256 dl) internal view returns (bytes32) {
        return _eip712Digest(
            asset.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(asset.EMERGENCY_ROLLBACK_TYPEHASH(), address(asset), n, dl))
        );
    }

    function _restrictDigest(uint256 n, uint256 dl) internal view returns (bytes32) {
        return _eip712Digest(
            asset.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(asset.RESTRICT_TYPEHASH(), address(asset), n, dl))
        );
    }

    function _assetRedemptionDigest(uint256 n, uint256 dl) internal view returns (bytes32) {
        return _eip712Digest(
            asset.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(asset.ASSET_REDEMPTION_TYPEHASH(), address(asset), n, dl))
        );
    }

    function _assetFinalizeDigest(uint256 n, uint256 dl) internal view returns (bytes32) {
        return _eip712Digest(
            asset.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(asset.ASSET_FINALIZE_TYPEHASH(), address(asset), n, dl))
        );
    }

    function _amendLegalDigest(bytes memory doc, bytes2 jur, uint64 ver, uint256 n, uint256 dl)
        internal
        view
        returns (bytes32)
    {
        return _eip712Digest(
            asset.DOMAIN_SEPARATOR(),
            keccak256(
                abi.encode(
                    asset.AMEND_LEGAL_MIRROR_TYPEHASH(),
                    address(asset),
                    keccak256(doc),
                    jur,
                    ver,
                    n,
                    dl
                )
            )
        );
    }

    function _bumpVersionDigest(uint256 n, uint256 dl) internal view returns (bytes32) {
        return _eip712Digest(
            compliance.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(compliance.BUMP_VERSION_TYPEHASH(), address(compliance), n, dl))
        );
    }

    function _revokeAttestationDigest(address holder, bytes2 jur, uint256 n, uint256 dl)
        internal
        view
        returns (bytes32)
    {
        return _eip712Digest(
            identity.DOMAIN_SEPARATOR_GOVERNANCE(),
            keccak256(
                abi.encode(
                    identity.REVOKE_ATTESTATION_TYPEHASH(),
                    address(identity),
                    holder,
                    jur,
                    n,
                    dl
                )
            )
        );
    }

    // ====================================================================
    // Helpers --- governance-action wrappers
    // ====================================================================

    function _governanceFreeze() internal {
        uint256 n = asset.governanceNonce();
        uint256 dl = block.timestamp + 1 hours;
        bytes[] memory sigs = _fourAssetSigs(_freezeDigest(n, dl));
        asset.governanceFreeze(n, dl, sigs);
    }

    function _emergencyRollback() internal {
        uint256 n = asset.governanceNonce();
        uint256 dl = block.timestamp + 1 hours;
        bytes[] memory sigs = _fourAssetSigs(_rollbackDigest(n, dl));
        asset.emergencyRollback(n, dl, sigs);
    }

    function _assetRedemption() internal {
        uint256 n = asset.governanceNonce();
        uint256 dl = block.timestamp + 1 hours;
        bytes[] memory sigs = _fourAssetSigs(_assetRedemptionDigest(n, dl));
        asset.assetRedemption(n, dl, sigs);
    }

    function _assetFinalize() internal {
        uint256 n = asset.governanceNonce();
        uint256 dl = block.timestamp + 1 hours;
        bytes[] memory sigs = _fourAssetSigs(_assetFinalizeDigest(n, dl));
        asset.assetFinalize(n, dl, sigs);
    }

    function _amendLegalMirror(bytes memory doc, bytes2 jur, uint64 ver) internal {
        uint256 n = asset.governanceNonce();
        uint256 dl = block.timestamp + 1 hours;
        bytes[] memory sigs = _fourAssetSigs(_amendLegalDigest(doc, jur, ver, n, dl));
        asset.amendLegalMirror(doc, jur, ver, n, dl, sigs);
    }

    function _bumpComplianceVersion() internal {
        uint256 n = compliance.governanceNonce();
        uint256 dl = block.timestamp + 1 hours;
        bytes[] memory sigs = _fourAssetSigs(_bumpVersionDigest(n, dl));
        compliance.bumpVersion(n, dl, sigs);
    }

    function _revokeAttestation(address holder, bytes2 jur) internal {
        uint256 n = identity.governanceNonce();
        uint256 dl = block.timestamp + 1 hours;
        bytes[] memory sigs = _fourAssetSigs(_revokeAttestationDigest(holder, jur, n, dl));
        identity.revokeAttestation(holder, jur, n, dl, sigs);
    }

    // ====================================================================
    // Helpers --- VA-signed attestation grant
    // ====================================================================

    function _grantAttestation(
        uint256 vaKey,
        address holder,
        bytes2 jur,
        uint8 tier,
        uint256 expiry
    ) internal {
        _vaNonceCursor += 1;
        IdentityAttestation.Attestation memory a = IdentityAttestation.Attestation({
            holder: holder,
            hid: keccak256(abi.encodePacked(holder, jur, uint256(tier))),
            jurisdiction: jur,
            tier: tier,
            expiry: expiry,
            nonce: _vaNonceCursor,
            epoch: identity.attestationEpoch(holder, jur),
            attributeCommitmentsRoot: bytes32(0),
            zkProof: ""
        });
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
        bytes32 d = _eip712Digest(identity.DOMAIN_SEPARATOR_VA(), structHash);
        bytes memory sig = _signDigest(vaKey, d);
        identity.grantAttestation(a, sig);
    }
}
