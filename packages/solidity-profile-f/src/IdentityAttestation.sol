// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: L3RS-1 v1.0.0 §3 (Identity Binding), §3.2 (ID tier), §3.3 (Identity Record),
//         §3.4 (HID construction), §3.5 (Verification Authority registry),
//         §3.6 (Identity status function), 07-profile-f.md, DESIGN.md §5a (placeholder
//         HID), DESIGN.md §8.2 (shared signature library, two domains on this contract).
//
// Step 5 stage 2 replaces the owner-only grant path with a VA-signed grant path
// per §3.5. The contract now carries two EIP-712 signing surfaces:
//   - "T3RRA-IdentityAttestation-Governance" — governance-quorum actions
//     (registerVA, deregisterVA, revokeAttestation).
//   - "T3RRA-IdentityAttestation-VA" — VA-signed attestation issuance.
//
// The VA registry is storage-separate from the governance authority set. Storage
// naming reflects the two roles explicitly: `_governanceAuthorities` (typed
// GovernanceAuthoritySet per DESIGN.md §8.2) vs `_isVA` (plain mapping).

import {SignatureVerification} from "./libraries/SignatureVerification.sol";
import {SelectiveDisclosure} from "./libraries/SelectiveDisclosure.sol";
import {IZKVerifier} from "./interfaces/IZKVerifier.sol";

/// @title IdentityAttestation
/// @notice VA-signed identity registry with governance-gated VA administration.
contract IdentityAttestation {
    enum Status { UNKNOWN, VALID, EXPIRED, REVOKED }

    // ----- types ---------------------------------------------------------------

    /// @notice Full L3RS-1 §3.3 Identity Record: IR = (HID, VA, JI, EXP, REV, ATTR, PROOF).
    /// @dev Step 5 stage 4 refactors ATTR from `bytes` to `bytes32` — the field now
    ///      holds the Merkle root of the attribute commitment tree per §8.3. The
    ///      off-chain prover MUST build the tree with OpenZeppelin-compatible
    ///      sorted-pair hashing; see `SelectiveDisclosure` library and DESIGN.md §8.3.
    struct Record {
        bytes32 hid;                    // §3.3 HID. Opaque bytes32; computed off-chain by VA per §3.4.
        address verificationAuthority;  // §3.3 VA — the recovered signer.
        bytes2 jurisdiction;            // §3.3 JI — ISO 3166-1 alpha-2.
        uint8 tier;                     // §3.2 ID tier ∈ {1, 2, 3}.
        uint256 expiry;                 // §3.3 EXP — unix seconds; Status = EXPIRED after.
        bool revoked;                   // §3.3 REV — flipped by governance revokeAttestation.
        bytes32 attributeCommitmentsRoot; // §3.3 ATTR — Merkle root per §8.3.
        bytes zkProof;                  // §3.3 PROOF — opaque in Phase One; §3.8 verifies via IZKVerifier.
    }

    /// @notice Attestation payload signed by a Verification Authority.
    struct Attestation {
        address holder;
        bytes32 hid;
        bytes2 jurisdiction;
        uint8 tier;
        uint256 expiry;
        uint256 nonce;
        bytes32 attributeCommitmentsRoot;
        bytes zkProof;
    }

    // ----- governance authority set (typed wrapper per DESIGN.md §8.2) --------

    address[] internal _authorityList;
    SignatureVerification.GovernanceAuthoritySet internal _governanceAuthorities;
    uint256 public governanceNonce;

    // ----- Verification Authority registry (separate storage) -----------------

    mapping(address => bool) internal _isVA;
    address[] internal _vaList;
    mapping(address => mapping(uint256 => bool)) internal _usedVANonce;

    // ----- identity records (stage 3: keyed by (holder, jurisdiction) per §3.9) -----
    //
    // Multi-jurisdiction stacking per §3.9. A holder has at most one record per
    // jurisdiction. Tier-3 validation ("holder satisfies two or more jurisdictional
    // identity attestations") is an O(|ReqJ|) loop of O(1) lookups against
    // `_hasRecord[holder][j]` rather than an O(|records|) scan.
    //
    // `_holderJurisdictions` tracks the per-holder ordered list of jurisdictions
    // that have records. It grows monotonically within Phase One — revocations
    // flip the REV flag inside the existing record rather than deleting it.

    mapping(address => mapping(bytes2 => Record)) internal _records;
    mapping(address => mapping(bytes2 => bool)) internal _hasRecord;
    mapping(address => bytes2[]) internal _holderJurisdictions;

    /// @notice Monotonically increasing counter of revocations. Distinct from
    ///         `governanceNonce` (which counts governance actions of every kind).
    ///         See `AttestationRevoked` event.
    uint256 public revocationIndex;

    // ----- EIP-712 signing surfaces per DESIGN.md §8.2 ------------------------

    bytes32 public immutable DOMAIN_SEPARATOR_GOVERNANCE;
    bytes32 public immutable DOMAIN_SEPARATOR_VA;
    bytes32 public immutable DOMAIN_SEPARATOR_PRESENTATION;

    bytes32 public constant REGISTER_VA_TYPEHASH = keccak256(
        "RegisterVA(address registry,address va,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant DEREGISTER_VA_TYPEHASH = keccak256(
        "DeregisterVA(address registry,address va,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant REVOKE_ATTESTATION_TYPEHASH = keccak256(
        "RevokeAttestation(address registry,address holder,bytes2 jurisdiction,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "Attestation(address holder,bytes32 hid,bytes2 jurisdiction,uint8 tier,uint256 expiry,uint256 nonce,bytes32 attributeCommitmentsRoot,bytes zkProof)"
    );
    bytes32 public constant SET_ZK_VERIFIER_TYPEHASH = keccak256(
        "SetZKVerifier(address registry,address newVerifier,uint256 nonce,uint256 deadline)"
    );

    // ----- ZKP verifier (per L3RS-1 §3.8; mock in Phase One per §5b) ----------

    IZKVerifier public zkVerifier;

    // ----- selective-disclosure used-nonce set (per DESIGN.md §8.3 Q3) --------
    //
    // Keyed on (holder, verifier, nonce). The verifier field in the presentation
    // envelope is EIP-712-bound, so cross-verifier replay is prevented by the
    // signature itself; this mapping prevents same-verifier replay. Unbounded
    // storage growth flagged in DESIGN.md §8.3 as Phase Six/Seven scaling concern.
    mapping(address => mapping(address => mapping(uint256 => bool))) internal _usedPresentationNonce;

    // ----- events -------------------------------------------------------------

    event AttestationGranted(address indexed holder, address indexed va, bytes32 hid, uint256 nonce);

    /// @notice Revocation event — rich indexing per DESIGN.md §5c for Phase Five
    ///         bridge consumption via `eth_getLogs`. `hid` and `issuingVA` are
    ///         indexed so Phase Five's propagation is filter-and-forward, not a
    ///         linear scan. `holder` and `revokingAuthority` are metadata;
    ///         `blockNumber` and `revocationIndex` disambiguate events that
    ///         share indexed topic values.
    /// @param hid The revoked identity hash.
    /// @param issuingVA The VA that originally signed the attestation.
    /// @param holder The address whose attestation is revoked.
    /// @param revokingAuthority `msg.sender` of the revoke call. Typically one
    ///        of the governance authorities relaying the quorum-signed payload,
    ///        but the contract does not enforce that — any account that submits
    ///        a valid quorum signature set is recorded here for audit purposes.
    /// @param blockNumber The block height at which the revocation committed.
    /// @param revocationIndex Monotonically-increasing counter, distinct from
    ///        governanceNonce. Allows Phase Five consumers to order events
    ///        strictly within this contract without needing block.timestamp.
    event AttestationRevoked(
        bytes32 indexed hid,
        address indexed issuingVA,
        address holder,
        address revokingAuthority,
        uint256 blockNumber,
        uint256 revocationIndex
    );

    event VARegistered(address indexed va);
    event VADeregistered(address indexed va);
    event ZKVerifierSet(address indexed oldVerifier, address indexed newVerifier);

    // ----- errors -------------------------------------------------------------

    error ZeroAddress();
    error InvalidTier();
    error NotAttested();
    error UnknownVA();
    error VAAlreadyRegistered();
    error VANotRegistered();
    error NonceReused();
    error InvalidNonce();
    error Expired();
    error InsufficientSignatures();
    error DuplicateAuthority();
    error InvalidZKProof();

    // ----- construction -------------------------------------------------------

    constructor(
        address[] memory governanceAuthorities_,
        address[] memory initialVAs_,
        IZKVerifier zkVerifier_
    ) {
        if (address(zkVerifier_) == address(0)) revert ZeroAddress();
        zkVerifier = zkVerifier_;
        require(governanceAuthorities_.length >= 3, "IdentityAttestation: need >=3 authorities");

        uint256 n = governanceAuthorities_.length;
        _authorityList = governanceAuthorities_;
        _governanceAuthorities.threshold = (2 * n + 2) / 3; // ceil(2n/3) per L3RS-1 §5.4
        for (uint256 i = 0; i < n; i++) {
            if (governanceAuthorities_[i] == address(0)) revert ZeroAddress();
            if (_governanceAuthorities.members[governanceAuthorities_[i]]) revert DuplicateAuthority();
            _governanceAuthorities.members[governanceAuthorities_[i]] = true;
        }

        // Initial VAs seeded at construction so the contract has at least one VA
        // able to issue attestations without a bootstrap quorum action. Additional
        // VAs can be registered later via governance-quorum registerVA.
        for (uint256 i = 0; i < initialVAs_.length; i++) {
            address va = initialVAs_[i];
            if (va == address(0)) revert ZeroAddress();
            if (_isVA[va]) revert VAAlreadyRegistered();
            _isVA[va] = true;
            _vaList.push(va);
            emit VARegistered(va);
        }

        DOMAIN_SEPARATOR_GOVERNANCE = SignatureVerification.domainSeparator(
            SignatureVerification.Domain({
                name: "T3RRA-IdentityAttestation-Governance",
                version: "1",
                chainId: block.chainid,
                verifyingContract: address(this)
            })
        );
        DOMAIN_SEPARATOR_VA = SignatureVerification.domainSeparator(
            SignatureVerification.Domain({
                name: "T3RRA-IdentityAttestation-VA",
                version: "1",
                chainId: block.chainid,
                verifyingContract: address(this)
            })
        );
        DOMAIN_SEPARATOR_PRESENTATION = SignatureVerification.domainSeparator(
            SignatureVerification.Domain({
                name: "T3RRA-IdentityAttestation-Presentation",
                version: "1",
                chainId: block.chainid,
                verifyingContract: address(this)
            })
        );
    }

    // ----- governance surface (quorum-gated, governance domain) ---------------

    function registerVA(address va, uint256 nonce, uint256 deadline, bytes[] calldata signatures) external {
        _consumeGovernanceNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            REGISTER_VA_TYPEHASH, address(this), va, nonce, deadline
        ));
        _requireGovernanceQuorum(structHash, signatures);
        if (va == address(0)) revert ZeroAddress();
        if (_isVA[va]) revert VAAlreadyRegistered();
        _isVA[va] = true;
        _vaList.push(va);
        emit VARegistered(va);
    }

    function deregisterVA(address va, uint256 nonce, uint256 deadline, bytes[] calldata signatures) external {
        _consumeGovernanceNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            DEREGISTER_VA_TYPEHASH, address(this), va, nonce, deadline
        ));
        _requireGovernanceQuorum(structHash, signatures);
        if (!_isVA[va]) revert VANotRegistered();
        _isVA[va] = false;
        for (uint256 i = 0; i < _vaList.length; i++) {
            if (_vaList[i] == va) {
                _vaList[i] = _vaList[_vaList.length - 1];
                _vaList.pop();
                break;
            }
        }
        emit VADeregistered(va);
    }

    /// @notice Replace the ZKP verifier. Governance-quorum-gated per §8.2.
    /// @dev Primary use: swap the Phase One MockZKVerifier for a real verifier
    ///      (Groth16, Plonk, STARK, etc.) before mainnet deployment per §9 TODO 14.
    function setZKVerifier(
        IZKVerifier newVerifier,
        uint256 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        _consumeGovernanceNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            SET_ZK_VERIFIER_TYPEHASH, address(this), address(newVerifier), nonce, deadline
        ));
        _requireGovernanceQuorum(structHash, signatures);
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(zkVerifier);
        zkVerifier = newVerifier;
        emit ZKVerifierSet(old, address(newVerifier));
    }

    function revokeAttestation(
        address holder,
        bytes2 jurisdiction_,
        uint256 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        _consumeGovernanceNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            REVOKE_ATTESTATION_TYPEHASH, address(this), holder, jurisdiction_, nonce, deadline
        ));
        _requireGovernanceQuorum(structHash, signatures);
        if (!_hasRecord[holder][jurisdiction_]) revert NotAttested();
        Record storage r = _records[holder][jurisdiction_];
        r.revoked = true;
        revocationIndex += 1;
        emit AttestationRevoked(
            r.hid,
            r.verificationAuthority,
            holder,
            msg.sender,
            block.number,
            revocationIndex
        );
    }

    // ----- VA-signed grant (VA domain) ----------------------------------------

    /// @notice Grant an identity attestation. The attestation struct is signed by
    ///         a registered VA with an EIP-712 signature over ATTESTATION_TYPEHASH
    ///         under DOMAIN_SEPARATOR_VA. HID is opaque — VA computes it off-chain
    ///         per L3RS-1 §3.4 as H(PII ‖ salt ‖ domain). PII never touches the
    ///         contract. See DESIGN.md §5a and §8.2.
    function grantAttestation(Attestation calldata a, bytes calldata vaSignature) external {
        if (a.holder == address(0)) revert ZeroAddress();
        if (a.tier < 1 || a.tier > 3) revert InvalidTier();

        bytes32 structHash = keccak256(abi.encode(
            ATTESTATION_TYPEHASH,
            a.holder,
            a.hid,
            a.jurisdiction,
            a.tier,
            a.expiry,
            a.nonce,
            a.attributeCommitmentsRoot,
            keccak256(a.zkProof)
        ));
        bytes32 d = SignatureVerification.digest(DOMAIN_SEPARATOR_VA, structHash);
        address va = SignatureVerification.recover(d, vaSignature);
        if (!_isVA[va]) revert UnknownVA();
        if (_usedVANonce[va][a.nonce]) revert NonceReused();
        _usedVANonce[va][a.nonce] = true;

        // ZKP verification per L3RS-1 §3.8. When a proof is attached, delegate to
        // the pluggable verifier. Empty PROOF means no ZK attestation; accepted.
        // Phase One uses MockZKVerifier which accepts any bytes — see §5b.
        if (a.zkProof.length > 0) {
            bytes memory publicInputs = abi.encode(a.holder, a.hid, a.jurisdiction, a.tier);
            if (!zkVerifier.verify(a.zkProof, publicInputs)) revert InvalidZKProof();
        }

        _records[a.holder][a.jurisdiction] = Record({
            hid: a.hid,
            verificationAuthority: va,
            jurisdiction: a.jurisdiction,
            tier: a.tier,
            expiry: a.expiry,
            revoked: false,
            attributeCommitmentsRoot: a.attributeCommitmentsRoot,
            zkProof: a.zkProof
        });
        if (!_hasRecord[a.holder][a.jurisdiction]) {
            _hasRecord[a.holder][a.jurisdiction] = true;
            _holderJurisdictions[a.holder].push(a.jurisdiction);
        }
        emit AttestationGranted(a.holder, va, a.hid, a.nonce);
    }

    // ----- selective disclosure (§3.7, DESIGN.md §8.3) ------------------------

    /// @notice Verify a selective-disclosure presentation against a stored
    ///         attestation. Reverts on any failure (invalid holder signature,
    ///         wrong verifier, expired deadline, reused nonce, bad Merkle
    ///         proof, or commitment-root mismatch). Consumes the per-(holder,
    ///         verifier, nonce) slot on success.
    /// @dev The consuming rule evaluator — IdentityAttestation in Phase One,
    ///      ComplianceModule in Phase Three — calls this function directly.
    ///      `p.verifier` must equal `address(this)`; the library enforces this
    ///      via its `msg.sender == p.verifier` check. `p.commitmentRoot` must
    ///      match the Record's `attributeCommitmentsRoot` derived from the
    ///      holder's first jurisdiction or the one referenced by
    ///      `p.attestationRef`. This function uses the first jurisdiction per
    ///      stage 3 holder-level defaults; Phase Three extends to jurisdiction-
    ///      parametric verification when ComplianceModule adopts the library.
    function verifyPresentation(
        SelectiveDisclosure.Presentation calldata p,
        bytes calldata holderSignature
    ) external {
        // Storage-side root check: the presented root must match what the VA
        // signed at issuance. The library does not read Record storage; this
        // contract enforces the binding between the presentation and a real
        // on-chain attestation.
        bytes32 storedRoot = _records[p.holder][_firstJurisdiction(p.holder)].attributeCommitmentsRoot;
        require(p.commitmentRoot == storedRoot, "IdentityAttestation: commitment mismatch");
        require(p.commitmentRoot != bytes32(0), "IdentityAttestation: holder has no commitment");

        SelectiveDisclosure.verify(
            DOMAIN_SEPARATOR_PRESENTATION,
            p,
            holderSignature,
            _usedPresentationNonce
        );
    }

    function hasPresentationNonceBeenUsed(address holder, address verifier, uint256 nonce)
        external
        view
        returns (bool)
    {
        return _usedPresentationNonce[holder][verifier][nonce];
    }

    // ----- governance quorum helper per DESIGN.md §8.2 ------------------------

    function _requireGovernanceQuorum(bytes32 structHash, bytes[] calldata signatures) internal view {
        (bool ok, ) = SignatureVerification.verifyQuorum(
            DOMAIN_SEPARATOR_GOVERNANCE,
            structHash,
            signatures,
            _governanceAuthorities
        );
        if (!ok) revert InsufficientSignatures();
    }

    function _consumeGovernanceNonceAndCheckDeadline(uint256 nonce, uint256 deadline) internal {
        if (nonce != governanceNonce) revert InvalidNonce();
        if (block.timestamp > deadline) revert Expired();
        governanceNonce = nonce + 1;
    }

    // ----- read access --------------------------------------------------------

    function authorities() external view returns (address[] memory) {
        return _authorityList;
    }

    function vaList() external view returns (address[] memory) {
        return _vaList;
    }

    function isVA(address candidate) external view returns (bool) {
        return _isVA[candidate];
    }

    function hasVANonceBeenUsed(address va, uint256 nonce) external view returns (bool) {
        return _usedVANonce[va][nonce];
    }

    /// @notice Return the four-valued status for a holder in a specific jurisdiction.
    /// @dev Primary status accessor in the multi-jurisdiction model per §3.9.
    function getStatusIn(address who, bytes2 jurisdiction_) public view returns (Status) {
        if (!_hasRecord[who][jurisdiction_]) return Status.UNKNOWN;
        Record storage r = _records[who][jurisdiction_];
        if (r.revoked) return Status.REVOKED;
        if (block.timestamp > r.expiry) return Status.EXPIRED;
        return Status.VALID;
    }

    /// @notice Return a holder-level "any VALID" status. Used by L3RS1Asset's
    ///         transfer pipeline for tier-1 identity checks where any jurisdictional
    ///         attestation suffices. For tier-3 checks, use validJurisdictionCount
    ///         or hasAttestationIn for each required jurisdiction.
    function getStatus(address who) external view returns (Status) {
        bytes2[] storage js = _holderJurisdictions[who];
        if (js.length == 0) return Status.UNKNOWN;
        // Return VALID if any jurisdiction's record is VALID; otherwise surface
        // the most informative non-VALID status in priority order REVOKED > EXPIRED.
        bool sawRevoked = false;
        bool sawExpired = false;
        for (uint256 i = 0; i < js.length; i++) {
            Status s = getStatusIn(who, js[i]);
            if (s == Status.VALID) return Status.VALID;
            if (s == Status.REVOKED) sawRevoked = true;
            else if (s == Status.EXPIRED) sawExpired = true;
        }
        if (sawRevoked) return Status.REVOKED;
        if (sawExpired) return Status.EXPIRED;
        return Status.UNKNOWN;
    }

    /// @notice Return whether a valid attestation exists for (holder, jurisdiction).
    /// @dev O(1). Primary building block for tier-3 ReqJ loops per §3.9.
    function hasAttestationIn(address who, bytes2 jurisdiction_) external view returns (bool) {
        return getStatusIn(who, jurisdiction_) == Status.VALID;
    }

    /// @notice Return the list of jurisdictions the holder has any record in.
    /// @dev Includes revoked and expired records. Use hasAttestationIn for validity.
    function jurisdictionsOf(address who) external view returns (bytes2[] memory) {
        return _holderJurisdictions[who];
    }

    /// @notice Return the number of distinct jurisdictions in which the holder
    ///         currently has a VALID record. Tier-3 per §3.2 requires ≥ 2.
    function validJurisdictionCount(address who) external view returns (uint256 count) {
        bytes2[] storage js = _holderJurisdictions[who];
        for (uint256 i = 0; i < js.length; i++) {
            if (getStatusIn(who, js[i]) == Status.VALID) count++;
        }
    }

    /// @notice Tier-3 existential check per §3.2. For each required jurisdiction
    ///         in `requiredJurisdictions`, verify a VALID record exists for the
    ///         holder. O(|ReqJ|) per the stage 3 design note in DESIGN.md §5c.
    function satisfiesRequiredJurisdictions(address who, bytes2[] calldata requiredJurisdictions)
        external
        view
        returns (bool)
    {
        for (uint256 i = 0; i < requiredJurisdictions.length; i++) {
            if (getStatusIn(who, requiredJurisdictions[i]) != Status.VALID) return false;
        }
        return true;
    }

    // ----- per-jurisdiction field accessors ----------------------------------

    function recordOf(address who, bytes2 jurisdiction_) external view returns (Record memory) {
        return _records[who][jurisdiction_];
    }

    function tierOf(address who, bytes2 jurisdiction_) external view returns (uint8) {
        return _records[who][jurisdiction_].tier;
    }

    function verificationAuthorityOf(address who, bytes2 jurisdiction_) external view returns (address) {
        return _records[who][jurisdiction_].verificationAuthority;
    }

    function attributeCommitmentsRootOf(address who, bytes2 jurisdiction_) external view returns (bytes32) {
        return _records[who][jurisdiction_].attributeCommitmentsRoot;
    }

    function proofOf(address who, bytes2 jurisdiction_) external view returns (bytes memory) {
        return _records[who][jurisdiction_].zkProof;
    }

    // ----- holder-level legacy accessors (first-jurisdiction semantics) ------
    //
    // These delegate to the first jurisdiction the holder registered. They exist
    // for call sites that predate the multi-jurisdiction model (notably
    // L3RS1Asset._holderJurisdiction's transfer-context jurisdiction field).
    // Prefer the per-jurisdiction accessors for new code.

    function _firstJurisdiction(address who) internal view returns (bytes2) {
        bytes2[] storage js = _holderJurisdictions[who];
        if (js.length == 0) return bytes2(0);
        return js[0];
    }

    function jurisdictionOf(address who) external view returns (bytes2) {
        return _firstJurisdiction(who);
    }

    function tierOf(address who) external view returns (uint8) {
        return _records[who][_firstJurisdiction(who)].tier;
    }

    function verificationAuthorityOf(address who) external view returns (address) {
        return _records[who][_firstJurisdiction(who)].verificationAuthority;
    }

    function attributeCommitmentsRootOf(address who) external view returns (bytes32) {
        return _records[who][_firstJurisdiction(who)].attributeCommitmentsRoot;
    }

    function proofOf(address who) external view returns (bytes memory) {
        return _records[who][_firstJurisdiction(who)].zkProof;
    }

    function recordOf(address who) external view returns (Record memory) {
        return _records[who][_firstJurisdiction(who)];
    }
}
