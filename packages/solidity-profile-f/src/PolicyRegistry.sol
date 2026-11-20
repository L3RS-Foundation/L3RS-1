// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: 07-profile-f.md (PolicyRegistry surface), L3RS-1 v1.0.0 §5 (Governance,
//         quorum), Whitepaper v3.3 (L3RS-1 amendment process).
//
// The PolicyRegistry binds a policyId to the current ComplianceModule. Phase One
// owns registration (issuer-gated) and amendment / retirement (quorum-gated).
// Every amendment appends a new Binding version and retires the previous one.
// Phase Five's cross-chain bridge consumer reads `currentHash(policyId)` via
// a staticcall to confirm the ComplianceHash expected in the CrossChainMetadata
// object X per L3RS-1 §13.9.

import {ComplianceModule} from "./ComplianceModule.sol";
import {SignatureVerification} from "./libraries/SignatureVerification.sol";

/// @title PolicyRegistry
/// @notice Versioned binding from policyId to ComplianceModule with quorum-gated
///         amendment.
contract PolicyRegistry {
    // ----- types ---------------------------------------------------------------

    struct Binding {
        address complianceModule;
        bytes32 canonicalHash;
        uint256 version;
        uint256 activatedAt;
        uint256 retiredAt; // 0 if still active
    }

    // ----- errors --------------------------------------------------------------

    error NotOwner();
    error InsufficientSignatures();
    error DuplicateSignature();
    error ZeroAddress();
    error UnknownPolicy();
    error AlreadyRegistered();
    error PolicyAlreadyRetired();
    error VersionOutOfRange();
    error InvalidNonce();
    error Expired();

    // ----- events --------------------------------------------------------------

    event PolicyRegistered(bytes32 indexed policyId, address indexed complianceModule, bytes32 canonicalHash);
    event PolicyAmended(bytes32 indexed policyId, address indexed oldModule, address indexed newModule, uint256 newVersion);
    event PolicyRetired(bytes32 indexed policyId, uint256 finalVersion);

    // ----- storage -------------------------------------------------------------

    address public immutable owner;
    address[] internal _authorities;
    SignatureVerification.GovernanceAuthoritySet internal _governanceAuthorities;

    bytes32[] internal _policyIds;
    mapping(bytes32 => bool) internal _policyExists;
    mapping(bytes32 => Binding[]) internal _history;
    mapping(bytes32 => bool) internal _isRetired;

    // ----- EIP-712 governance signing per DESIGN.md §8.2 -----------------------

    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 public governanceNonce;

    bytes32 public constant AMEND_TYPEHASH = keccak256(
        "AmendPolicy(address registry,bytes32 policyId,address newComplianceModule,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant RETIRE_TYPEHASH = keccak256(
        "RetirePolicy(address registry,bytes32 policyId,uint256 nonce,uint256 deadline)"
    );

    // ----- construction --------------------------------------------------------

    constructor(address[] memory authorities_) {
        require(authorities_.length >= 3, "PolicyRegistry: need >=3 authorities");
        owner = msg.sender;
        _authorities = authorities_;
        uint256 n_ = authorities_.length;
        _governanceAuthorities.threshold = (2 * n_ + 2) / 3; // ceil(2n/3) per L3RS-1 §5.4
        for (uint256 i = 0; i < n_; i++) {
            if (authorities_[i] == address(0)) revert ZeroAddress();
            if (_governanceAuthorities.members[authorities_[i]]) revert DuplicateSignature();
            _governanceAuthorities.members[authorities_[i]] = true;
        }

        DOMAIN_SEPARATOR = SignatureVerification.domainSeparator(
            SignatureVerification.Domain({
                name: "T3RRA-PolicyRegistry",
                version: "1",
                chainId: block.chainid,
                verifyingContract: address(this)
            })
        );
    }

    function authorities() external view returns (address[] memory) {
        return _authorities;
    }

    // ----- registration (issuer-gated) ----------------------------------------

    /// @notice Register a new policy. Only callable by the registry owner (the
    ///         issuer / SPV operator). Establishes version 1 of the policy's
    ///         binding history.
    function register(bytes32 policyId, address complianceModule) external {
        if (msg.sender != owner) revert NotOwner();
        if (complianceModule == address(0)) revert ZeroAddress();
        if (_policyExists[policyId]) revert AlreadyRegistered();

        bytes32 hash = ComplianceModule(complianceModule).complianceHash();

        _policyIds.push(policyId);
        _policyExists[policyId] = true;
        _history[policyId].push(Binding({
            complianceModule: complianceModule,
            canonicalHash: hash,
            version: 1,
            activatedAt: block.timestamp,
            retiredAt: 0
        }));

        emit PolicyRegistered(policyId, complianceModule, hash);
    }

    // ----- amendment (quorum-gated) -------------------------------------------

    /// @notice Amend the binding. Retires the current version and appoints a new
    ///         one at version N+1. Requires authority quorum per L3RS-1 §5.4.
    function amend(
        bytes32 policyId,
        address newComplianceModule,
        uint256 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        if (nonce != governanceNonce) revert InvalidNonce();
        if (block.timestamp > deadline) revert Expired();

        bytes32 structHash = keccak256(abi.encode(
            AMEND_TYPEHASH, address(this), policyId, newComplianceModule, nonce, deadline
        ));
        _requireAuthorityQuorum(structHash, signatures);
        governanceNonce = nonce + 1;

        if (!_policyExists[policyId]) revert UnknownPolicy();
        if (_isRetired[policyId]) revert PolicyAlreadyRetired();
        if (newComplianceModule == address(0)) revert ZeroAddress();

        Binding[] storage history = _history[policyId];
        uint256 priorIndex = history.length - 1;
        history[priorIndex].retiredAt = block.timestamp;
        address oldModule = history[priorIndex].complianceModule;

        bytes32 newHash = ComplianceModule(newComplianceModule).complianceHash();
        uint256 newVersion = history[priorIndex].version + 1;

        history.push(Binding({
            complianceModule: newComplianceModule,
            canonicalHash: newHash,
            version: newVersion,
            activatedAt: block.timestamp,
            retiredAt: 0
        }));

        emit PolicyAmended(policyId, oldModule, newComplianceModule, newVersion);
    }

    // ----- retirement (quorum-gated) ------------------------------------------

    /// @notice Retire the policy entirely. After retirement no further amendments
    ///         are permitted. Quorum-gated per L3RS-1 §5.4.
    function retire(bytes32 policyId, uint256 nonce, uint256 deadline, bytes[] calldata signatures) external {
        if (nonce != governanceNonce) revert InvalidNonce();
        if (block.timestamp > deadline) revert Expired();

        bytes32 structHash = keccak256(abi.encode(
            RETIRE_TYPEHASH, address(this), policyId, nonce, deadline
        ));
        _requireAuthorityQuorum(structHash, signatures);
        governanceNonce = nonce + 1;

        if (!_policyExists[policyId]) revert UnknownPolicy();
        if (_isRetired[policyId]) revert PolicyAlreadyRetired();

        Binding[] storage history = _history[policyId];
        uint256 finalIndex = history.length - 1;
        history[finalIndex].retiredAt = block.timestamp;
        _isRetired[policyId] = true;

        emit PolicyRetired(policyId, history[finalIndex].version);
    }

    // ----- read access ---------------------------------------------------------

    function getCurrent(bytes32 policyId) external view returns (Binding memory) {
        if (!_policyExists[policyId]) revert UnknownPolicy();
        Binding[] storage history = _history[policyId];
        return history[history.length - 1];
    }

    function getBinding(bytes32 policyId, uint256 version) external view returns (Binding memory) {
        if (!_policyExists[policyId]) revert UnknownPolicy();
        Binding[] storage history = _history[policyId];
        if (version == 0 || version > history.length) revert VersionOutOfRange();
        return history[version - 1];
    }

    function getHistory(bytes32 policyId) external view returns (Binding[] memory) {
        if (!_policyExists[policyId]) revert UnknownPolicy();
        return _history[policyId];
    }

    function versionCount(bytes32 policyId) external view returns (uint256) {
        if (!_policyExists[policyId]) revert UnknownPolicy();
        return _history[policyId].length;
    }

    function isActive(bytes32 policyId) external view returns (bool) {
        if (!_policyExists[policyId]) return false;
        return !_isRetired[policyId];
    }

    function currentHash(bytes32 policyId) external view returns (bytes32) {
        if (!_policyExists[policyId]) revert UnknownPolicy();
        Binding[] storage history = _history[policyId];
        return history[history.length - 1].canonicalHash;
    }

    function policyIds() external view returns (bytes32[] memory) {
        return _policyIds;
    }

    // ----- registry root -------------------------------------------------------

    /// @notice Return a hash of the current state of the registry. Changes on
    ///         every registration, amendment, and retirement. Phase Five's
    ///         bridge consumer uses this to detect registry drift.
    function registryRoot() external view returns (bytes32) {
        uint256 n = _policyIds.length;
        bytes32[] memory entries = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 id = _policyIds[i];
            Binding storage b = _history[id][_history[id].length - 1];
            entries[i] = keccak256(abi.encode(id, b.complianceModule, b.canonicalHash, b.version, b.retiredAt));
        }
        return keccak256(abi.encode(bytes32("L3RS-1/RegistryRoot/v1"), entries));
    }

    // ----- authority quorum per L3RS-1 §5.4 and DESIGN.md §8.2 ----------------

    function _requireAuthorityQuorum(bytes32 structHash, bytes[] calldata signatures) internal view {
        (bool ok, ) = SignatureVerification.verifyQuorum(
            DOMAIN_SEPARATOR,
            structHash,
            signatures,
            _governanceAuthorities
        );
        if (!ok) revert InsufficientSignatures();
    }

}
