// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Handler for Foundry invariant campaigns targeting T4 (supply accounting),
// T5 (governance minority resistance), and INV-6 (no layer bypass).
//
// Design per DESIGN.md §9 TODO 10 and step 6C spec:
//
//   1. Parameter bounding via `bound(input, min, max)` rather than
//      `vm.assume(...)` — the latter discards fuzz budget on every rejected
//      run. Every bounded input maps cleanly into a valid range.
//
//   2. Realistic action distribution via targetSelector with weights. The
//      campaign file lists each action's selector once per weight slot,
//      transfers the most common, governance rare. The fuzzer picks uniformly
//      among the slot array, which reproduces the weighting.
//
//   3. Ghost state for invariant observation. Each Handler action that
//      performs a successful state mutation increments a matching ghost
//      counter. Invariants cross-check Handler ghosts against on-chain
//      contract state rather than inferring from contract alone.

import {Test} from "forge-std/Test.sol";

import {L3RS1Asset} from "../../src/L3RS1Asset.sol";
import {ComplianceModule} from "../../src/ComplianceModule.sol";
import {IdentityAttestation} from "../../src/IdentityAttestation.sol";
import {PolicyRegistry} from "../../src/PolicyRegistry.sol";
import {MockZKVerifier} from "../../src/MockZKVerifier.sol";
import {ILifecycle} from "../../src/interfaces/ILifecycle.sol";
import {ReasonCodes} from "../../src/libraries/ReasonCodes.sol";

contract L3RS1Handler is Test {
    // ----- deployed targets ---------------------------------------------------

    L3RS1Asset public asset;
    ComplianceModule public compliance;
    IdentityAttestation public identity;
    PolicyRegistry public registry;
    MockZKVerifier public zkVerifier;

    // ----- principals ---------------------------------------------------------

    address public issuer;
    uint256 private _issuerKey;
    address[3] public govs;
    uint256[3] private _govKeys;
    address public va;
    uint256 private _vaKey;

    address[4] public holders;
    uint256[4] private _holderKeys;
    bytes2[4] public jurisdictions; // one per holder

    uint256 private _vaNonceCursor;

    // ----- ghost state --------------------------------------------------------

    // T4: supply accounting — independent of contract's mintedTotal/burnedTotal.
    uint256 public ghost_totalMinted;
    uint256 public ghost_totalBurned;

    // T5: governance minority resistance — smallest distinctCount across every
    // successful override the Handler has driven.
    uint256 public ghost_minSignersOnSuccessfulOverride;
    uint256 public ghost_overrideSuccessCount;

    // INV-6: per-mutation accounting. `ghost_successfulMutations` increments on
    // every Handler action that returns without reverting after calling a
    // mutable selector. Per-selector ghosts help diagnose which selector caused
    // any divergence.
    uint256 public ghost_successfulMutations;
    mapping(bytes4 => uint256) public ghost_selectorSuccesses;

    // ----- construction -------------------------------------------------------

    constructor() {
        _deriveKeys();
        _deployContracts();
        _bootstrapAttestations();
        _allowAllJurisdictionPairs();
        _seedInitialBalances();

        ghost_minSignersOnSuccessfulOverride = type(uint256).max;
    }

    function _deriveKeys() internal {
        (issuer, _issuerKey) = makeAddrAndKey("handler_issuer");
        (govs[0], _govKeys[0]) = makeAddrAndKey("handler_gov1");
        (govs[1], _govKeys[1]) = makeAddrAndKey("handler_gov2");
        (govs[2], _govKeys[2]) = makeAddrAndKey("handler_gov3");
        (va, _vaKey) = makeAddrAndKey("handler_va");
        (holders[0], _holderKeys[0]) = makeAddrAndKey("handler_holder0");
        (holders[1], _holderKeys[1]) = makeAddrAndKey("handler_holder1");
        (holders[2], _holderKeys[2]) = makeAddrAndKey("handler_holder2");
        (holders[3], _holderKeys[3]) = makeAddrAndKey("handler_holder3");

        jurisdictions[0] = bytes2("GB");
        jurisdictions[1] = bytes2("US");
        jurisdictions[2] = bytes2("GE");
        jurisdictions[3] = bytes2("DE");
    }

    function _deployContracts() internal {
        address[] memory authorities = new address[](3);
        authorities[0] = govs[0];
        authorities[1] = govs[1];
        authorities[2] = govs[2];

        address[] memory initialVAs = new address[](1);
        initialVAs[0] = va;

        vm.startPrank(issuer);
        zkVerifier = new MockZKVerifier();
        identity = new IdentityAttestation(authorities, initialVAs, zkVerifier);
        compliance = new ComplianceModule(authorities);
        registry = new PolicyRegistry(authorities);
        asset = new L3RS1Asset({
            issuer_: issuer,
            jurisdiction_: jurisdictions[0],
            idTier_: 2,
            compliance_: compliance,
            identity_: identity,
            registry_: registry,
            authorities_: authorities
        });
        // Activate after construction (state machine 6E starts at ISSUED).
        // This bumps asset.stateMutationCount by 1, so the ghost moves with it.
        asset.activate();
        ghost_successfulMutations += 1;
        vm.stopPrank();
    }

    function _bootstrapAttestations() internal {
        for (uint256 i = 0; i < 4; i++) {
            _grantVASignedAttestation(holders[i], jurisdictions[i], 2, block.timestamp + 365 days);
        }
    }

    function _allowAllJurisdictionPairs() internal {
        vm.startPrank(issuer);
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = 0; j < 4; j++) {
                if (i != j) compliance.allowJurisdictionPair(jurisdictions[i], jurisdictions[j]);
            }
        }
        vm.stopPrank();
    }

    function _seedInitialBalances() internal {
        vm.startPrank(issuer);
        for (uint256 i = 0; i < 4; i++) {
            asset.issue(holders[i], 1_000_000);
            ghost_totalMinted += 1_000_000;
            // Each `issue` call bumps the asset's stateMutationCount. The INV-6
            // invariant asserts `stateMutationCount == ghost_successfulMutations`,
            // so the initial seeding is folded into the ghost here.
            ghost_successfulMutations += 1;
            ghost_selectorSuccesses[asset.issue.selector] += 1;
        }
        vm.stopPrank();
    }

    // ----- signing helpers ----------------------------------------------------

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _assetDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", asset.DOMAIN_SEPARATOR(), structHash));
    }

    function _complianceDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", compliance.DOMAIN_SEPARATOR(), structHash));
    }

    function _identityVaDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", identity.DOMAIN_SEPARATOR_VA(), structHash));
    }

    function _twoGovSigs(bytes32 digest) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](2);
        sigs[0] = _sign(_govKeys[0], digest);
        sigs[1] = _sign(_govKeys[1], digest);
    }

    function _grantVASignedAttestation(address holder, bytes2 j, uint8 tier, uint256 expiry) internal {
        _vaNonceCursor += 1;
        IdentityAttestation.Attestation memory a = IdentityAttestation.Attestation({
            holder: holder,
            hid: keccak256(abi.encodePacked(holder, j, uint256(tier))),
            jurisdiction: j,
            tier: tier,
            expiry: expiry,
            nonce: _vaNonceCursor,
            epoch: identity.attestationEpoch(holder, j),
            attributeCommitmentsRoot: bytes32(0),
            zkProof: ""
        });
        bytes32 structHash = keccak256(abi.encode(
            identity.ATTESTATION_TYPEHASH(),
            a.holder, a.hid, a.jurisdiction, a.tier, a.expiry, a.nonce, a.epoch,
            a.attributeCommitmentsRoot,
            keccak256(a.zkProof)
        ));
        identity.grantAttestation(a, _sign(_vaKey, _identityVaDigest(structHash)));
    }

    function _recordOverride(uint256 signers) internal {
        ghost_overrideSuccessCount += 1;
        if (signers < ghost_minSignersOnSuccessfulOverride) {
            ghost_minSignersOnSuccessfulOverride = signers;
        }
    }

    // ============================================================================
    // Actions (target-selector surface)
    // ============================================================================

    function transferAction(uint256 senderIdx, uint256 receiverIdx, uint256 amount) public {
        senderIdx = bound(senderIdx, 0, 3);
        receiverIdx = bound(receiverIdx, 0, 3);
        if (senderIdx == receiverIdx) return;
        if (asset.currentState() != ILifecycle.State.ACTIVE) return;
        if (_sanctioned(holders[senderIdx]) || _sanctioned(holders[receiverIdx])) return;
        uint256 balance = asset.balanceOf(holders[senderIdx]);
        if (balance == 0) return;
        amount = bound(amount, 1, balance);

        vm.prank(holders[senderIdx]);
        asset.transfer(holders[receiverIdx], amount);

        ghost_successfulMutations += 1;
        ghost_selectorSuccesses[asset.transfer.selector] += 1;
    }

    function _sanctioned(address who) internal view returns (bool) {
        (bool allow, bytes32 reason) = compliance.evaluate(address(asset), who, who, 0, "");
        return !allow && reason == ReasonCodes.SANCTIONS;
    }

    function authenticatedTransferAction(
        uint256 senderIdx,
        uint256 receiverIdx,
        uint256 amount,
        uint256 nonce
    ) public {
        senderIdx = bound(senderIdx, 0, 3);
        receiverIdx = bound(receiverIdx, 0, 3);
        if (senderIdx == receiverIdx) return;
        // No FROZEN state pre-screen here — authenticatedTransfer is the exploration
        // path for legitimate state-disallows reverts. The transferAction path
        // handles the happy-path flow; this path intentionally lets the fuzzer
        // drive reverts when the asset is mid-freeze so INV-6's compliance-call
        // accounting is exercised against the full pipeline.
        if (_sanctioned(holders[senderIdx]) || _sanctioned(holders[receiverIdx])) return;
        uint256 balance = asset.balanceOf(holders[senderIdx]);
        if (balance == 0) return;
        amount = bound(amount, 1, balance);
        // Keep nonce wide so TxIDs are diverse; the registry dedups naturally.
        nonce = bound(nonce, 1, type(uint64).max);

        vm.prank(holders[senderIdx]);
        asset.authenticatedTransfer(holders[receiverIdx], amount, nonce, uint64(block.timestamp));

        ghost_successfulMutations += 1;
        ghost_selectorSuccesses[asset.authenticatedTransfer.selector] += 1;
    }

    function issueAction(uint256 recipientIdx, uint256 amount) public {
        recipientIdx = bound(recipientIdx, 0, 3);
        if (asset.currentState() != ILifecycle.State.ACTIVE) return;
        if (_sanctioned(holders[recipientIdx])) return;
        amount = bound(amount, 1, 1_000_000);

        vm.prank(issuer);
        asset.issue(holders[recipientIdx], amount);

        ghost_totalMinted += amount;
        ghost_successfulMutations += 1;
        ghost_selectorSuccesses[asset.issue.selector] += 1;
    }

    function redeemAction(uint256 senderIdx, uint256 amount) public {
        senderIdx = bound(senderIdx, 0, 3);
        if (asset.currentState() != ILifecycle.State.ACTIVE) return;
        if (_sanctioned(holders[senderIdx])) return;
        uint256 balance = asset.balanceOf(holders[senderIdx]);
        if (balance == 0) return;
        amount = bound(amount, 1, balance);

        vm.prank(holders[senderIdx]);
        asset.redeem(amount);

        ghost_totalBurned += amount;
        ghost_successfulMutations += 1;
        ghost_selectorSuccesses[asset.redeem.selector] += 1;
    }

    function addSanctionedAction(uint256 whoIdx) public {
        // Sanction only in-pool holders; random addresses are no-ops for the
        // transfer pipeline. Skip if already sanctioned (reason matches).
        whoIdx = bound(whoIdx, 0, 3);
        address target = holders[whoIdx];
        (bool allow, bytes32 reason) = compliance.evaluate(address(asset), target, target, 0, "");
        if (!allow && reason == ReasonCodes.SANCTIONS) return;

        vm.prank(issuer);
        compliance.addSanctionedAddress(target);

        // addSanctionedAddress mutates ComplianceModule state, not L3RS1Asset
        // state. It does not advance asset.stateMutationCount, so we do not
        // bump ghost_successfulMutations (which tracks asset-side mutations).
        ghost_selectorSuccesses[compliance.addSanctionedAddress.selector] += 1;
    }

    function setFeeRecipientAction(uint256 recipientIdx) public {
        recipientIdx = bound(recipientIdx, 0, 3);
        if (_sanctioned(holders[recipientIdx])) return;

        vm.prank(issuer);
        asset.setFeeRecipient(holders[recipientIdx]);

        ghost_successfulMutations += 1;
        ghost_selectorSuccesses[asset.setFeeRecipient.selector] += 1;
    }

    function governanceFreezeAction() public {
        if (asset.currentState() != ILifecycle.State.ACTIVE) return;

        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            asset.GOVERNANCE_FREEZE_TYPEHASH(), address(asset), nonce, deadline
        ));
        bytes[] memory sigs = _twoGovSigs(_assetDigest(structHash));

        asset.governanceFreeze(nonce, deadline, sigs);

        ghost_successfulMutations += 1;
        ghost_selectorSuccesses[asset.governanceFreeze.selector] += 1;
        _recordOverride(2);
    }

    function emergencyRollbackAction() public {
        if (asset.currentState() == ILifecycle.State.ACTIVE) return;

        uint256 nonce = asset.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            asset.EMERGENCY_ROLLBACK_TYPEHASH(), address(asset), nonce, deadline
        ));
        bytes[] memory sigs = _twoGovSigs(_assetDigest(structHash));

        asset.emergencyRollback(nonce, deadline, sigs);

        ghost_successfulMutations += 1;
        ghost_selectorSuccesses[asset.emergencyRollback.selector] += 1;
        _recordOverride(2);
    }

    function bumpVersionAction() public {
        uint256 nonce = compliance.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            compliance.BUMP_VERSION_TYPEHASH(), address(compliance), nonce, deadline
        ));
        bytes[] memory sigs = _twoGovSigs(_complianceDigest(structHash));

        compliance.bumpVersion(nonce, deadline, sigs);

        // bumpVersion is a ComplianceModule mutation, not an L3RS1Asset one.
        // It does not advance `asset.stateMutationCount` and does not count
        // toward ghost_successfulMutations for INV-6. We still record a
        // governance override for T5 purposes.
        ghost_selectorSuccesses[compliance.bumpVersion.selector] += 1;
        _recordOverride(2);
    }
}
