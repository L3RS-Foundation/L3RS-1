// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Shared harness for every Phase One test. Deploys the four contracts into a fresh
// instance per test, seeds a minimal compliant policy, and exposes helper context
// encoders matching the L3RS-1 §13.11 canonical serialization rules for the transfer
// context object.
//
// Since step 5 stage 0 this harness carries private keys for every principal so
// tests can produce real ECDSA signatures via vm.sign. The placeholder byte-string
// signatures from prior phases are gone.

import {Test} from "forge-std/Test.sol";

import {IComplianceModuleF} from "../src/interfaces/IComplianceModuleF.sol";
import {ILifecycle} from "../src/interfaces/ILifecycle.sol";
import {ReasonCodes} from "../src/libraries/ReasonCodes.sol";

import {ComplianceModule} from "../src/ComplianceModule.sol";
import {L3RS1Asset} from "../src/L3RS1Asset.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {IdentityAttestation} from "../src/IdentityAttestation.sol";
import {MockZKVerifier} from "../src/MockZKVerifier.sol";
import {IZKVerifier} from "../src/interfaces/IZKVerifier.sol";

/// @title BaseTest
/// @notice Shared deployment and helper utilities. Every theorem and invariant test
///         inherits this to avoid duplicating harness code. The setUp is intentionally
///         minimal — tests that need custom policies compose additional rules on top.
abstract contract BaseTest is Test {
    ComplianceModule internal compliance;
    IdentityAttestation internal identity;
    PolicyRegistry internal registry;
    L3RS1Asset internal asset;
    MockZKVerifier internal zkVerifier;

    // Governance authorities for the default harness. Quorum is ceil(2/3 * N) = 2 of 3
    // per L3RS-1 §5.4 and §5.5. Keys are generated deterministically from the name so
    // tests get stable addresses and a corresponding signing key.
    address internal gov1;
    uint256 internal gov1Key;
    address internal gov2;
    uint256 internal gov2Key;
    address internal gov3;
    uint256 internal gov3Key;

    // Default counterparties. Canonical alpha-2 jurisdictions per ISO 3166-1 and
    // L3RS-1 §12.4. Keys are carried for completeness even if specific tests do
    // not need to sign from these addresses.
    address internal issuer;
    uint256 internal issuerKey;
    address internal holderA; // declared in "GB"
    uint256 internal holderAKey;
    address internal holderB; // declared in "US"
    uint256 internal holderBKey;

    // Verification Authority key for VA-signed attestations per DESIGN.md §8.2.
    // Seeded at IdentityAttestation construction so tests can issue attestations
    // without first running a governance-quorum registerVA action.
    address internal va1;
    uint256 internal va1Key;

    // Per-test VA nonce counter. The VA nonce registry is a used-set, not a
    // monotonic counter, so any positive distinct nonce works. This counter
    // just keeps tests from colliding on the same value within one setUp.
    uint256 internal _vaNonceCursor;

    // Asset-level parameters. The asset type is REGULATED_SECURITY per L3RS-1 §2.3,
    // which is the type the $50M synthetic commercial real estate mandate maps to.
    bytes2 internal constant JURISDICTION_GB = bytes2("GB");
    bytes2 internal constant JURISDICTION_US = bytes2("US");

    function setUp() public virtual {
        (gov1, gov1Key) = makeAddrAndKey("gov1");
        (gov2, gov2Key) = makeAddrAndKey("gov2");
        (gov3, gov3Key) = makeAddrAndKey("gov3");
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        (holderA, holderAKey) = makeAddrAndKey("holderA");
        (holderB, holderBKey) = makeAddrAndKey("holderB");
        (va1, va1Key) = makeAddrAndKey("va1");

        address[] memory authorities = new address[](3);
        authorities[0] = gov1;
        authorities[1] = gov2;
        authorities[2] = gov3;

        address[] memory initialVAs = new address[](1);
        initialVAs[0] = va1;

        // Deploy as the issuer so ownership-gated contracts record the issuer.
        vm.startPrank(issuer);
        zkVerifier = new MockZKVerifier();
        identity = new IdentityAttestation(authorities, initialVAs, zkVerifier);
        compliance = new ComplianceModule(authorities);
        registry = new PolicyRegistry(authorities);
        asset = new L3RS1Asset({
            issuer_: issuer,
            jurisdiction_: JURISDICTION_GB,
            idTier_: 2,
            compliance_: compliance,
            identity_: identity,
            registry_: registry,
            authorities_: authorities
        });
        // Phase One state machine (6E) starts at ISSUED; test harness activates
        // before running assertions so legacy tests that assume ACTIVE at
        // construction continue to pass without per-test changes.
        asset.activate();
        vm.stopPrank();
    }

    // ----- EIP-712 signing helpers per DESIGN.md §8.2 --------------------------

    /// @dev Sign `digest` with `privateKey` and return a 65-byte compact signature.
    function _signDigest(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Compute the EIP-712 digest per EIP-712 §3 for an arbitrary struct hash.
    function _eip712Digest(bytes32 domainSep, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
    }

    /// @dev Convenience: build a signatures array from two keys signing the same digest.
    function _twoSigs(uint256 keyA, uint256 keyB, bytes32 digest) internal pure returns (bytes[] memory sigs) {
        sigs = new bytes[](2);
        sigs[0] = _signDigest(keyA, digest);
        sigs[1] = _signDigest(keyB, digest);
    }

    /// @dev Convenience: single-signer sigs array.
    function _oneSig(uint256 key, bytes32 digest) internal pure returns (bytes[] memory sigs) {
        sigs = new bytes[](1);
        sigs[0] = _signDigest(key, digest);
    }

    // ----- action-specific digest builders -------------------------------------

    function _freezeDigest(uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            asset.GOVERNANCE_FREEZE_TYPEHASH(), address(asset), nonce, deadline
        ));
        return _eip712Digest(asset.DOMAIN_SEPARATOR(), structHash);
    }

    function _rollbackDigest(uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            asset.EMERGENCY_ROLLBACK_TYPEHASH(), address(asset), nonce, deadline
        ));
        return _eip712Digest(asset.DOMAIN_SEPARATOR(), structHash);
    }

    function _rotateDigest(address removed, address added, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(
            asset.ROTATE_AUTHORITY_TYPEHASH(), address(asset), removed, added, nonce, deadline
        ));
        return _eip712Digest(asset.DOMAIN_SEPARATOR(), structHash);
    }

    function _amendLegalDigest(
        bytes memory document,
        bytes2 jurisdiction_,
        uint64 version_,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            asset.AMEND_LEGAL_MIRROR_TYPEHASH(),
            address(asset),
            keccak256(document),
            jurisdiction_,
            version_,
            nonce,
            deadline
        ));
        return _eip712Digest(asset.DOMAIN_SEPARATOR(), structHash);
    }

    function _bumpVersionDigest(uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            compliance.BUMP_VERSION_TYPEHASH(), address(compliance), nonce, deadline
        ));
        return _eip712Digest(compliance.DOMAIN_SEPARATOR(), structHash);
    }

    // ----- 6E state transition digests ----------------------------------------

    function _restrictDigest(uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        return _eip712Digest(asset.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            asset.RESTRICT_TYPEHASH(), address(asset), nonce, deadline
        )));
    }

    function _clearRestrictionDigest(uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        return _eip712Digest(asset.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            asset.CLEAR_RESTRICTION_TYPEHASH(), address(asset), nonce, deadline
        )));
    }

    function _assetRedemptionDigest(uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        return _eip712Digest(asset.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            asset.ASSET_REDEMPTION_TYPEHASH(), address(asset), nonce, deadline
        )));
    }

    function _assetFinalizeDigest(uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        return _eip712Digest(asset.DOMAIN_SEPARATOR(), keccak256(abi.encode(
            asset.ASSET_FINALIZE_TYPEHASH(), address(asset), nonce, deadline
        )));
    }

    // ----- IdentityAttestation VA + governance helpers -------------------------

    /// @dev Produce a VA-signed attestation and call grantAttestation. HID is the
    ///      Phase One placeholder per DESIGN.md §5a. Stage 4/5 populate ATTR/PROOF.
    function _grantAttestationVA(address holder, bytes2 jurisdiction_, uint8 tier, uint256 expiry) internal {
        _vaNonceCursor += 1;
        IdentityAttestation.Attestation memory a = IdentityAttestation.Attestation({
            holder: holder,
            hid: keccak256(abi.encodePacked(holder, jurisdiction_, uint256(tier))),
            jurisdiction: jurisdiction_,
            tier: tier,
            expiry: expiry,
            nonce: _vaNonceCursor,
            attributeCommitmentsRoot: bytes32(0),
            zkProof: ""
        });
        bytes32 structHash = keccak256(abi.encode(
            identity.ATTESTATION_TYPEHASH(),
            a.holder,
            a.hid,
            a.jurisdiction,
            a.tier,
            a.expiry,
            a.nonce,
            a.attributeCommitmentsRoot,
            keccak256(a.zkProof)
        ));
        bytes32 digest = _eip712Digest(identity.DOMAIN_SEPARATOR_VA(), structHash);
        bytes memory sig = _signDigest(va1Key, digest);
        identity.grantAttestation(a, sig);
    }

    /// @dev Build a quorum-signed revokeAttestation call and submit it. Keys on
    ///      (holder, jurisdiction) per stage 3.
    function _revokeAttestationGov(address holder, bytes2 jurisdiction_) internal {
        uint256 nonce = identity.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            identity.REVOKE_ATTESTATION_TYPEHASH(), address(identity), holder, jurisdiction_, nonce, deadline
        ));
        bytes32 digest = _eip712Digest(identity.DOMAIN_SEPARATOR_GOVERNANCE(), structHash);
        bytes[] memory sigs = _twoSigs(gov1Key, gov2Key, digest);
        identity.revokeAttestation(holder, jurisdiction_, nonce, deadline, sigs);
    }

    // ----- canonical transfer-context encoder ---------------------------------
    //
    // L3RS-1 §13.11 canonical serialization: fixed field order, UTF-8 strings,
    // fixed-width big-endian integers, no ignored fields. Phase One uses abi.encode
    // wrapped by a domain-tag byte because abi.encode already enforces fixed width
    // and field order for the types used here. Where §13.11 requires stricter canonical
    // encoding than abi.encode provides, the production CanonicalSerializer library
    // handles it; the shared context below is the subset the tests need.

    struct TransferContext {
        address assetRef;
        address sender;
        address receiver;
        uint256 amount;
        bytes2 senderJurisdiction;
        bytes2 receiverJurisdiction;
        uint64 timestamp;
        uint256 nonce;
        bytes travelRulePayload;
    }

    function encodeContext(TransferContext memory ctx) internal pure returns (bytes memory) {
        return abi.encode(
            bytes32("L3RS-1/CTX/v1"),
            ctx.assetRef,
            ctx.sender,
            ctx.receiver,
            ctx.amount,
            ctx.senderJurisdiction,
            ctx.receiverJurisdiction,
            ctx.timestamp,
            ctx.nonce,
            ctx.travelRulePayload
        );
    }

    function defaultContext(address sender, address receiver, uint256 amount) internal view
        returns (TransferContext memory ctx)
    {
        ctx.assetRef = address(asset);
        ctx.sender = sender;
        ctx.receiver = receiver;
        ctx.amount = amount;
        ctx.senderJurisdiction = JURISDICTION_GB;
        ctx.receiverJurisdiction = JURISDICTION_US;
        ctx.timestamp = uint64(block.timestamp);
        ctx.nonce = uint256(keccak256(abi.encode(sender, receiver, amount, block.timestamp)));
        ctx.travelRulePayload = "";
    }
}
