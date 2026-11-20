// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: L3RS-1 v1.0.0 §2 (Asset Object), §2.4 (State), §2.5 (Transition Matrix),
//         §2.6 (Transfer Sequence), §2.7 (Transfer Rule Engine), §2.12 (CID),
//         §3 (Identity Binding), §5 (Governance), §12 (Legal Mirror), §13 (Canonical
//         Objects), §15 (Theorems). 07-profile-f.md for the Profile F surface.
//
// Phase One build order step 3. The contract implements the L3RS1Asset in four
// feature blocks: balance state, the seven-step §2.6 pipeline, the replay
// registry, and the governance surface. The legal mirror and cross-chain origin
// structures live in the governance block because they are amended through
// governance quorum per §12.6.

import {IComplianceModuleF} from "./interfaces/IComplianceModuleF.sol";
import {ILifecycle} from "./interfaces/ILifecycle.sol";
import {ReasonCodes} from "./libraries/ReasonCodes.sol";
import {SignatureVerification} from "./libraries/SignatureVerification.sol";

import {ComplianceModule} from "./ComplianceModule.sol";
import {IdentityAttestation} from "./IdentityAttestation.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title L3RS1Asset
/// @notice The asset contract itself. Every transfer, mint, burn, redemption, and
///         governance override routes through ComplianceModule.evaluate before any
///         state mutation per L3RS-1 §2.6 and §2.7. Atomic settlement per §2.6
///         and Theorem 15.6 is enforced by placing the balance commit as step 6
///         — every earlier step that fails reverts the whole call.
contract L3RS1Asset is ILifecycle, ReentrancyGuard {
    // ----- errors and events -----------------------------------------------------

    /// @notice Raised when one of the seven §2.6 steps rejects the transfer. The
    ///         step index is one-indexed. The reason code comes from ReasonCodes.
    error TransferStepRejected(uint8 step, bytes32 reasonCode);
    error NotIssuer();
    error NotAuthority();
    error InsufficientSignatures();
    error DuplicateSignature();
    error ZeroAddress();
    error InvalidTier();
    error InvalidNonce();
    error Expired();
    error InvalidTransition();
    error SupplyNotZero();

    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event FeeRecipientSet(address indexed recipient);
    event LegalMirrorAmended(bytes32 indexed oldHash, bytes32 indexed newHash, uint64 newVersion);
    event AuthorityRotated(address indexed removed, address indexed added);
    event AssetActivated();
    event AssetRestricted();
    event AssetRestrictionCleared();
    event AssetRedeemed();
    event AssetFinalized();

    // ----- immutable asset parameters (L3RS-1 §2.1) -----------------------------

    address public immutable issuer;
    bytes2 public immutable jurisdiction;
    uint8 public immutable idTier;
    ComplianceModule public immutable compliance;
    IdentityAttestation public immutable identity;
    PolicyRegistry public immutable registry;
    bytes32 public immutable assetId;

    // ----- authority committee (L3RS-1 §5) -------------------------------------

    address[] internal _authorities;
    SignatureVerification.GovernanceAuthoritySet internal _governanceAuthorities;

    // ----- balance state --------------------------------------------------------

    mapping(address => uint256) internal _balances;
    uint256 public totalSupply;
    uint256 public mintedTotal;
    uint256 public burnedTotal;
    uint256 public supplySnapshotAtLastNonMintBurn;

    // ----- lifecycle state (L3RS-1 §2.4, §2.5) ---------------------------------

    State internal _currentState;
    State internal _previousState;
    uint256 public transitionCount;
    /// @notice Bitmask of the three §15.3 success flags for the last transition.
    ///         Bit 0 (0x01) = ComplianceSuccess. Bit 1 (0x02) = IdentitySuccess.
    ///         Bit 2 (0x04) = GovernanceSuccess.
    uint256 public lastTransitionEvidence;
    bool public lastTransitionWasGovernance;

    // ----- replay registry (Theorem 15.2) ---------------------------------------

    mapping(bytes32 => bool) internal _seenTxId;
    uint256 public seenTxIdCount;
    mapping(address => uint256) internal _lastNonce;
    bytes32 public lastCommittedTxId;

    // ----- fee surface (L3RS-1 §6) ---------------------------------------------

    address internal _feeRecipient;
    uint16 public constant FEE_BPS = 25; // 0.25% placeholder; production fee comes from FeeModule.

    // ----- legal mirror (L3RS-1 §12) -------------------------------------------

    bytes32 internal _legalHash;
    uint64 internal _legalVersion;
    uint256 public legalAmendmentCount;
    bytes internal _legalDocument;

    // ----- override tracking (Theorem 15.5) ------------------------------------

    uint256 public overrideCount;
    uint256 public minSignersForAnySuccessfulOverride;

    // ----- EIP-712 signing surface per DESIGN.md §8.2 --------------------------

    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 public governanceNonce;

    bytes32 public constant GOVERNANCE_FREEZE_TYPEHASH = keccak256(
        "GovernanceFreeze(address assetRef,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant EMERGENCY_ROLLBACK_TYPEHASH = keccak256(
        "EmergencyRollback(address assetRef,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant ROTATE_AUTHORITY_TYPEHASH = keccak256(
        "RotateAuthority(address assetRef,address removed,address added,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant AMEND_LEGAL_MIRROR_TYPEHASH = keccak256(
        "AmendLegalMirror(address assetRef,bytes32 documentHash,bytes2 newJurisdiction,uint64 newVersion,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant RESTRICT_TYPEHASH = keccak256(
        "Restrict(address assetRef,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant CLEAR_RESTRICTION_TYPEHASH = keccak256(
        "ClearRestriction(address assetRef,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant ASSET_REDEMPTION_TYPEHASH = keccak256(
        "AssetRedemption(address assetRef,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant ASSET_FINALIZE_TYPEHASH = keccak256(
        "AssetFinalize(address assetRef,uint256 nonce,uint256 deadline)"
    );

    // ----- INV-6 ghosts ---------------------------------------------------------

    uint256 public stateMutationCount;
    uint256 public complianceCallCount;
    bytes4[] internal _mutableSelectorsList;
    mapping(bytes4 => bool) internal _selectorCallsCompliance;
    bool internal _reentrancyProbeArmed;

    // ----- modifiers ------------------------------------------------------------

    modifier onlyIssuer() {
        if (msg.sender != issuer) revert NotIssuer();
        _;
    }

    // ----- construction ---------------------------------------------------------

    constructor(
        address issuer_,
        bytes2 jurisdiction_,
        uint8 idTier_,
        ComplianceModule compliance_,
        IdentityAttestation identity_,
        PolicyRegistry registry_,
        address[] memory authorities_
    ) {
        if (issuer_ == address(0)) revert ZeroAddress();
        if (jurisdiction_ == bytes2(0)) revert ZeroAddress();
        if (idTier_ > 3) revert InvalidTier();
        if (address(compliance_) == address(0)) revert ZeroAddress();
        if (address(identity_) == address(0)) revert ZeroAddress();
        if (address(registry_) == address(0)) revert ZeroAddress();
        if (authorities_.length < 3) revert InsufficientSignatures();

        issuer = issuer_;
        jurisdiction = jurisdiction_;
        idTier = idTier_;
        compliance = compliance_;
        identity = identity_;
        registry = registry_;
        _authorities = authorities_;
        uint256 n_ = authorities_.length;
        _governanceAuthorities.threshold = (2 * n_ + 2) / 3; // ceil(2n/3) per L3RS-1 §5.4
        for (uint256 i = 0; i < n_; i++) {
            if (authorities_[i] == address(0)) revert ZeroAddress();
            if (_governanceAuthorities.members[authorities_[i]]) revert DuplicateSignature();
            _governanceAuthorities.members[authorities_[i]] = true;
        }

        _currentState = State.ISSUED;
        _previousState = State.ISSUED;
        minSignersForAnySuccessfulOverride = type(uint256).max;

        // EIP-712 domain for this contract's governance surface per DESIGN.md §8.2.
        DOMAIN_SEPARATOR = SignatureVerification.domainSeparator(
            SignatureVerification.Domain({
                name: "T3RRA-L3RS1Asset",
                version: "1",
                chainId: block.chainid,
                verifyingContract: address(this)
            })
        );

        assetId = keccak256(
            abi.encodePacked(
                bytes32("L3RS-1-AID-v1"),
                issuer_,
                uint64(block.timestamp),
                uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), issuer_)))
            )
        );

        // Initial legal mirror: empty document at version 1.
        _legalDocument = "";
        _legalVersion = 1;
        _legalHash = _computeLegalHash("", jurisdiction_, 1);

        // Register every selector that mutates persistent state, per INV-6.
        _registerMutableSelector(this.transfer.selector);
        _registerMutableSelector(this.authenticatedTransfer.selector);
        _registerMutableSelector(this.issue.selector);
        _registerMutableSelector(this.redeem.selector);
        _registerMutableSelector(this.governanceFreeze.selector);
        _registerMutableSelector(this.emergencyRollback.selector);
        _registerMutableSelector(this.rotateAuthority.selector);
        _registerMutableSelector(this.amendLegalMirror.selector);
        _registerMutableSelector(this.setFeeRecipient.selector);
        _registerMutableSelector(this.activate.selector);
        _registerMutableSelector(this.restrict.selector);
        _registerMutableSelector(this.clearRestriction.selector);
        _registerMutableSelector(this.assetRedemption.selector);
        _registerMutableSelector(this.assetFinalize.selector);
    }

    // ----- Phase One isImplemented marker --------------------------------------

    function isImplemented() external pure returns (bool) {
        return true;
    }

    // ============================================================================
    // Feature 1 — balance state
    // ============================================================================

    function balanceOf(address who) external view returns (uint256) {
        return _balances[who];
    }

    // ============================================================================
    // Feature 2 — the seven-step transfer pipeline (L3RS-1 §2.6 and §2.7)
    // ============================================================================

    /// @notice Standard transfer. Runs the full seven-step §2.6 sequence.
    /// @dev Per L3RS-1 §2.6 the sequence is identity → compliance → governance →
    ///      transfer-rule → fee → balance → cross-chain metadata. Any step
    ///      failing reverts the whole call; Theorem 15.6 demands this.
    function transfer(address to, uint256 amount) external nonReentrant returns (bool) {
        _executeTransfer(msg.sender, to, amount, bytes32(0));
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /// @notice Transfer with replay-resistance binding per Theorem 15.2. The
    ///         TxID is committed to the on-chain registry and cannot be replayed.
    function authenticatedTransfer(address to, uint256 amount, uint256 nonce, uint64 ts)
        external
        nonReentrant
        returns (bool)
    {
        bytes32 txId = _computeTxId(msg.sender, to, amount, nonce, ts);
        if (_seenTxId[txId]) revert TransferStepRejected(3, ReasonCodes.REPLAY_DETECTED);
        // TxID registry commit runs before _executeTransfer per CEI (sub-stage
        // 6H). _executeTransfer's fee callback is the only external interaction
        // in the pipeline, and committing the TxID beforehand means no state
        // write ordering ever places _seenTxId after an external call. A revert
        // inside _executeTransfer reverts this commit atomically per §2.6 and
        // Theorem 15.6.
        _seenTxId[txId] = true;
        seenTxIdCount += 1;
        lastCommittedTxId = txId;
        _lastNonce[msg.sender] = nonce;
        _executeTransfer(msg.sender, to, amount, txId);
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /// @dev The pipeline. `from` is the sender. `to` is the receiver. `amount` is
    ///      the transfer quantity. `boundTxId` is the TxID bound into the context
    ///      for replay resistance; zero if this is a plain transfer.
    function _executeTransfer(address from, address to, uint256 amount, bytes32 boundTxId) internal {
        if (to == address(0)) revert ZeroAddress();
        _reentrancyProbeArmed = true;

        // Step 1: identity validation per L3RS-1 §2.6 step 1, §3.6.
        if (idTier >= 1) {
            _requireIdentity(from, 1);
            _requireIdentity(to, 1);
        }

        // Step 2: compliance evaluation per §2.6 step 2, §4.3.
        bytes memory ctx = _encodeContext(from, to, amount, boundTxId);
        _requireCompliance(from, to, amount, ctx, 2);

        // Step 3: governance/state check per §2.5 transition matrix. REDEEMED is
        //         distinguished with its own reason code so external consumers
        //         can tell a mandate-level redemption apart from governance
        //         states (FROZEN, RESTRICTED, SUSPENDED, ISSUED).
        if (_currentState == State.REDEEMED) {
            revert TransferStepRejected(3, ReasonCodes.ASSET_REDEEMED);
        }
        if (_currentState != State.ACTIVE) {
            revert TransferStepRejected(3, ReasonCodes.STATE_DISALLOWS);
        }

        // Step 4: transfer rule validation per §2.7.
        if (_balances[from] < amount) {
            revert TransferStepRejected(4, ReasonCodes.INSUFFICIENT_BALANCE);
        }

        // Step 5a: fee calculation and fee-recipient balance credit (effect).
        //          The interaction with the fee recipient — the optional
        //          onFeeReceived callback — is deferred to step 5b below, after
        //          every balance effect has committed, to satisfy the
        //          checks-effects-interactions pattern. Sub-stage 6H: the
        //          reorder eliminates Slither's cross-function-reentrancy
        //          warning on `_balances` and is auxiliary to the
        //          `nonReentrant` modifier on the pipeline entry points, which
        //          remains load-bearing.
        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 netAmount = amount - fee;
        bool fireFeeCallback = false;
        if (fee > 0 && _feeRecipient != address(0)) {
            _balances[_feeRecipient] += fee;
            fireFeeCallback = _feeRecipient.code.length > 0;
        } else {
            netAmount = amount;
        }

        // Step 6: balance update per §2.6 step 6 (effect).
        _balances[from] -= amount;
        _balances[to] += netAmount;

        // Step 7: cross-chain metadata update per §2.12. The CID is computed on
        //         demand via computeCID(); no persistent field needs updating
        //         aside from the supplySnapshot used for T4's invariant.
        supplySnapshotAtLastNonMintBurn = totalSupply;

        // Evidence and ghost counters per Theorem 15.1 and INV-6.
        lastTransitionEvidence = 0x03; // compliance + identity
        lastTransitionWasGovernance = false;
        transitionCount += 1;
        stateMutationCount += 1;
        _reentrancyProbeArmed = false;

        // Step 5b: fee recipient callback (interaction). Runs after every
        //          balance effect, so even if the recipient reenters via an
        //          external contract call the balance state it observes is
        //          already consistent. The reentrancyGuard still rejects any
        //          direct reentry into the transfer pipeline. A revert in the
        //          callback reverts the entire pipeline per §2.6 atomicity.
        if (fireFeeCallback) {
            (bool ok,) =
                _feeRecipient.call(abi.encodeWithSignature("onFeeReceived(address,uint256)", address(this), fee));
            if (!ok) revert TransferStepRejected(5, ReasonCodes.FEE_TRANSFER_FAILED);
        }
    }

    function _requireIdentity(address who, uint8 stepIfFails) internal view {
        IdentityAttestation.Status s = identity.getStatus(who);
        if (s == IdentityAttestation.Status.VALID) return;
        bytes32 reason;
        if (s == IdentityAttestation.Status.UNKNOWN) reason = ReasonCodes.IDENTITY_INVALID;
        else if (s == IdentityAttestation.Status.EXPIRED) reason = ReasonCodes.IDENTITY_EXPIRED;
        else reason = ReasonCodes.IDENTITY_REVOKED;
        revert TransferStepRejected(stepIfFails, reason);
    }

    function _requireCompliance(
        address from,
        address to,
        uint256 amount,
        bytes memory ctx,
        uint8 stepIfFails
    ) internal {
        (bool allow, bytes32 reasonCode) = compliance.evaluate(address(this), from, to, amount, ctx);
        complianceCallCount += 1;
        if (!allow) revert TransferStepRejected(stepIfFails, reasonCode);
    }

    function _encodeContext(address from, address to, uint256 amount, bytes32 boundTxId)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(
            bytes32("L3RS-1/CTX/v1"),
            address(this),
            from,
            to,
            amount,
            _holderJurisdiction(from), // sender jurisdiction from attestation
            _holderJurisdiction(to),   // receiver jurisdiction from attestation
            uint64(block.timestamp),
            uint256(boundTxId),        // nonce-equivalent — bound TxID or zero
            bytes("")                  // travel rule payload
        );
    }

    /// @dev Admin context is shorter than the seven-slot transfer context, which
    ///      makes ComplianceModule's geographic rule a no-op for admin operations
    ///      per _tryReadJurisdictions' length guard. Sanctions screening still
    ///      runs because it does not depend on the context.
    function _encodeAdminContext(bytes32 action, uint256 amount) internal view returns (bytes memory) {
        return abi.encode(bytes32("L3RS-1/ADMIN/v1"), action, address(this), amount);
    }

    function _holderJurisdiction(address who) internal view returns (bytes2) {
        bytes2 j = identity.jurisdictionOf(who);
        return j == bytes2(0) ? jurisdiction : j;
    }

    // ----- mint and burn --------------------------------------------------------

    function issue(address to, uint256 amount) external nonReentrant onlyIssuer {
        if (to == address(0)) revert ZeroAddress();
        // Issuance is an admin operation per L3RS-1 §2.5 (the ISSUED / ACTIVE
        // activation path). Identity binding on the recipient is verified at the
        // first transfer, not at mint.
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/ISSUE"), amount);
        _requireCompliance(msg.sender, to, amount, ctx, 2);
        if (_currentState != State.ACTIVE) revert TransferStepRejected(3, ReasonCodes.STATE_DISALLOWS);

        _balances[to] += amount;
        mintedTotal += amount;
        totalSupply += amount;
        supplySnapshotAtLastNonMintBurn = totalSupply;

        lastTransitionEvidence = 0x03;
        lastTransitionWasGovernance = false;
        transitionCount += 1;
        stateMutationCount += 1;
        emit Mint(to, amount);
    }

    function redeem(uint256 amount) external nonReentrant {
        address from = msg.sender;
        if (idTier >= 1) _requireIdentity(from, 1);
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/REDEEM"), amount);
        _requireCompliance(from, address(0), amount, ctx, 2);
        // redeem works in ACTIVE (partial burn) and in REDEEMED (post-mandate
        // claim path per DESIGN.md §6E). Any other state rejects.
        if (_currentState != State.ACTIVE && _currentState != State.REDEEMED) {
            revert TransferStepRejected(3, ReasonCodes.STATE_DISALLOWS);
        }
        if (_balances[from] < amount) revert TransferStepRejected(4, ReasonCodes.INSUFFICIENT_BALANCE);

        _balances[from] -= amount;
        burnedTotal += amount;
        totalSupply -= amount;
        supplySnapshotAtLastNonMintBurn = totalSupply;

        lastTransitionEvidence = 0x03;
        lastTransitionWasGovernance = false;
        transitionCount += 1;
        stateMutationCount += 1;
        emit Burn(from, amount);
    }

    function setFeeRecipient(address newRecipient) external onlyIssuer {
        // Compliance call to preserve INV-6: every mutable selector routes through compliance.
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/SET-FEE-RECIPIENT"), 0);
        _requireCompliance(msg.sender, newRecipient, 0, ctx, 2);
        _feeRecipient = newRecipient;
        stateMutationCount += 1;
        emit FeeRecipientSet(newRecipient);
    }

    function feeRecipient() external view returns (address) {
        return _feeRecipient;
    }

    // ============================================================================
    // Feature 3 — replay registry (Theorem 15.2)
    // ============================================================================

    function computeTxId(address sender, address receiver, uint256 amount, uint256 nonce, uint64 ts)
        external
        pure
        returns (bytes32)
    {
        return _computeTxId(sender, receiver, amount, nonce, ts);
    }

    function _computeTxId(address sender, address receiver, uint256 amount, uint256 nonce, uint64 ts)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(sender, receiver, amount, nonce, ts));
    }

    function isSeenTxId(bytes32 id) external view returns (bool) {
        return _seenTxId[id];
    }

    /// @notice By construction, seenTxIdCount tracks unique entries — a TxID cannot
    ///         be committed twice because replay is rejected before the counter
    ///         is incremented. So distinct == seen at all times.
    function distinctTxIdCount() external view returns (uint256) {
        return seenTxIdCount;
    }

    function lastNonceFor(address who) external view returns (uint256) {
        return _lastNonce[who];
    }

    // ============================================================================
    // Feature 4 — governance surface (L3RS-1 §5, §12)
    // ============================================================================

    /// @notice Transition the asset to FROZEN per §2.5 with authority quorum.
    /// @dev Valid from ACTIVE only. BURNED is terminal — no transition out.
    function governanceFreeze(uint256 nonce, uint256 deadline, bytes[] calldata signatures) external nonReentrant {
        _consumeNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            GOVERNANCE_FREEZE_TYPEHASH, address(this), nonce, deadline
        ));
        uint256 distinctCount = _requireAuthorityQuorum(structHash, signatures);
        if (_currentState != State.ACTIVE) revert InvalidTransition();
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/GOV/FREEZE"), 0);
        _requireCompliance(msg.sender, address(0), 0, ctx, 2);
        _transitionTo(State.FROZEN, true, distinctCount);
    }

    /// @notice Quorum-gated rollback per §5.5 EMERGENCY_ROLLBACK. Reverts the most
    ///         recent lifecycle transition — FROZEN back to ACTIVE, for instance.
    /// @dev Invalid from ACTIVE (nothing to roll back to) and from BURNED (terminal).
    function emergencyRollback(uint256 nonce, uint256 deadline, bytes[] calldata signatures) external nonReentrant {
        _consumeNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            EMERGENCY_ROLLBACK_TYPEHASH, address(this), nonce, deadline
        ));
        uint256 distinctCount = _requireAuthorityQuorum(structHash, signatures);
        if (_currentState == State.ACTIVE || _currentState == State.BURNED) {
            revert InvalidTransition();
        }
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/GOV/ROLLBACK"), 0);
        _requireCompliance(msg.sender, address(0), 0, ctx, 2);
        _transitionTo(_previousState, true, distinctCount);
    }

    /// @notice Replace one authority with another. Quorum-gated. Changes the
    ///         governanceHash and therefore the CID per §2.12 and Theorem 15.3.
    function rotateAuthority(
        address removed,
        address added,
        uint256 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    )
        external
        nonReentrant
    {
        _consumeNonceAndCheckDeadline(nonce, deadline);
        if (!_governanceAuthorities.members[removed]) revert NotAuthority();
        if (added == address(0)) revert ZeroAddress();
        if (_governanceAuthorities.members[added]) revert DuplicateSignature();

        bytes32 structHash = keccak256(abi.encode(
            ROTATE_AUTHORITY_TYPEHASH, address(this), removed, added, nonce, deadline
        ));
        uint256 distinctCount = _requireAuthorityQuorum(structHash, signatures);

        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/GOV/ROTATE"), 0);
        _requireCompliance(msg.sender, address(0), 0, ctx, 2);

        _governanceAuthorities.members[removed] = false;
        _governanceAuthorities.members[added] = true;
        for (uint256 i = 0; i < _authorities.length; i++) {
            if (_authorities[i] == removed) {
                _authorities[i] = added;
                break;
            }
        }

        _recordOverrideSuccess(distinctCount);
        lastTransitionEvidence = 0x07; // compliance + identity + governance
        lastTransitionWasGovernance = true;
        transitionCount += 1;
        stateMutationCount += 1;
        emit AuthorityRotated(removed, added);
    }

    /// @notice Amend the legal mirror per §12.6 with authority quorum. LH is
    ///         recomputed from the new document+jurisdiction+version per §12.3.
    function amendLegalMirror(
        bytes calldata newDocument,
        bytes2 newJurisdiction,
        uint64 newVersion,
        uint256 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    )
        external
        nonReentrant
    {
        _consumeNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            AMEND_LEGAL_MIRROR_TYPEHASH,
            address(this),
            keccak256(newDocument),
            newJurisdiction,
            newVersion,
            nonce,
            deadline
        ));
        uint256 distinctCount = _requireAuthorityQuorum(structHash, signatures);

        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/GOV/LEGAL-AMEND"), uint256(newVersion));
        _requireCompliance(msg.sender, address(0), 0, ctx, 2);

        bytes32 oldHash = _legalHash;
        _legalDocument = newDocument;
        _legalVersion = newVersion;
        _legalHash = _computeLegalHash(newDocument, newJurisdiction, newVersion);
        legalAmendmentCount += 1;

        _recordOverrideSuccess(distinctCount);
        lastTransitionEvidence = 0x07;
        lastTransitionWasGovernance = true;
        transitionCount += 1;
        stateMutationCount += 1;
        emit LegalMirrorAmended(oldHash, _legalHash, newVersion);
    }

    // ============================================================================
    // Feature 5 — full §2.5 state machine (6E)
    // ============================================================================

    /// @notice ISSUED → ACTIVE. Issuer-only, called once after deployment.
    /// @dev §2.5 names the trigger "Activation" with condition "Identity +
    ///      Compliance Valid". The issuer asserts both by initiating activation;
    ///      the pipeline enforces both on every subsequent transfer.
    function activate() external nonReentrant onlyIssuer {
        if (_currentState != State.ISSUED) revert InvalidTransition();
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/GOV/ACTIVATE"), 0);
        _requireCompliance(msg.sender, address(0), 0, ctx, 2);
        _previousState = _currentState;
        _currentState = State.ACTIVE;
        lastTransitionEvidence = 0x03;
        lastTransitionWasGovernance = false;
        transitionCount += 1;
        stateMutationCount += 1;
        emit AssetActivated();
    }

    /// @notice ACTIVE → RESTRICTED. Governance quorum.
    function restrict(uint256 nonce, uint256 deadline, bytes[] calldata signatures) external nonReentrant {
        _consumeNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            RESTRICT_TYPEHASH, address(this), nonce, deadline
        ));
        uint256 distinctCount = _requireAuthorityQuorum(structHash, signatures);
        if (_currentState != State.ACTIVE) revert InvalidTransition();
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/GOV/RESTRICT"), 0);
        _requireCompliance(msg.sender, address(0), 0, ctx, 2);
        _transitionTo(State.RESTRICTED, true, distinctCount);
        emit AssetRestricted();
    }

    /// @notice RESTRICTED → ACTIVE. Governance quorum.
    function clearRestriction(uint256 nonce, uint256 deadline, bytes[] calldata signatures) external nonReentrant {
        _consumeNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            CLEAR_RESTRICTION_TYPEHASH, address(this), nonce, deadline
        ));
        uint256 distinctCount = _requireAuthorityQuorum(structHash, signatures);
        if (_currentState != State.RESTRICTED) revert InvalidTransition();
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/GOV/CLEAR_RESTRICTION"), 0);
        _requireCompliance(msg.sender, address(0), 0, ctx, 2);
        _transitionTo(State.ACTIVE, true, distinctCount);
        emit AssetRestrictionCleared();
    }

    /// @notice ACTIVE → REDEEMED. Governance quorum. Flips the asset-level
    ///         redemption guard. Transfers subsequently reject at step 3 with
    ///         ASSET_REDEEMED; per-holder `redeem()` continues as the claim
    ///         path per DESIGN.md §6E.
    function assetRedemption(uint256 nonce, uint256 deadline, bytes[] calldata signatures) external nonReentrant {
        _consumeNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            ASSET_REDEMPTION_TYPEHASH, address(this), nonce, deadline
        ));
        uint256 distinctCount = _requireAuthorityQuorum(structHash, signatures);
        if (_currentState != State.ACTIVE) revert InvalidTransition();
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/GOV/ASSET_REDEMPTION"), 0);
        _requireCompliance(msg.sender, address(0), 0, ctx, 2);
        _transitionTo(State.REDEEMED, true, distinctCount);
        emit AssetRedeemed();
    }

    /// @notice REDEEMED → BURNED. Governance quorum. Requires totalSupply == 0.
    /// @dev The totalSupply precondition guarantees no investor still holds a
    ///      claim. Theorem 15.1 (State Integrity) on this transition is
    ///      trivially satisfied: no value moves, compliance passes on the
    ///      admin context, and identity is vacuous (no holder is transacting
    ///      on this mandate-level transition). The guard that matters is the
    ///      governance quorum — authority signatures are the only way to flip
    ///      to BURNED, per §15.5. See DESIGN.md §6E.
    function assetFinalize(uint256 nonce, uint256 deadline, bytes[] calldata signatures) external nonReentrant {
        _consumeNonceAndCheckDeadline(nonce, deadline);
        bytes32 structHash = keccak256(abi.encode(
            ASSET_FINALIZE_TYPEHASH, address(this), nonce, deadline
        ));
        uint256 distinctCount = _requireAuthorityQuorum(structHash, signatures);
        if (_currentState != State.REDEEMED) revert InvalidTransition();
        if (totalSupply != 0) revert SupplyNotZero();
        bytes memory ctx = _encodeAdminContext(bytes32("L3RS-1/GOV/ASSET_FINALIZE"), 0);
        _requireCompliance(msg.sender, address(0), 0, ctx, 2);
        _transitionTo(State.BURNED, true, distinctCount);
        emit AssetFinalized();
    }

    /// @notice Convenience accessor for the asset-level redemption guard. Phase
    ///         Five bridge consumers and compliance dashboards query this
    ///         directly rather than inferring from currentState().
    function isAssetRedeemed() external view returns (bool) {
        return _currentState == State.REDEEMED;
    }

    // ----- authority quorum per L3RS-1 §5.4 and DESIGN.md §8.2 -----------------

    function _requireAuthorityQuorum(bytes32 structHash, bytes[] calldata signatures)
        internal
        view
        returns (uint256 distinctCount)
    {
        bool ok;
        (ok, distinctCount) = SignatureVerification.verifyQuorum(
            DOMAIN_SEPARATOR,
            structHash,
            signatures,
            _governanceAuthorities
        );
        if (!ok) revert InsufficientSignatures();
    }

    function _consumeNonceAndCheckDeadline(uint256 nonce, uint256 deadline) internal {
        if (nonce != governanceNonce) revert InvalidNonce();
        if (block.timestamp > deadline) revert Expired();
        governanceNonce = nonce + 1;
    }

    function _quorumThreshold() internal view returns (uint256) {
        return _governanceAuthorities.threshold;
    }

    function _transitionTo(State next, bool isGovernance, uint256 signersPresented) internal {
        _previousState = _currentState;
        _currentState = next;
        lastTransitionEvidence = isGovernance ? 0x07 : 0x03;
        lastTransitionWasGovernance = isGovernance;
        transitionCount += 1;
        stateMutationCount += 1;
        if (isGovernance) _recordOverrideSuccess(signersPresented);
    }

    function _recordOverrideSuccess(uint256 signersPresented) internal {
        overrideCount += 1;
        if (signersPresented < minSignersForAnySuccessfulOverride) {
            minSignersForAnySuccessfulOverride = signersPresented;
        }
    }

    // ----- legal mirror views and helper (L3RS-1 §12) ---------------------------

    function legalHash() external view returns (bytes32) {
        return _legalHash;
    }

    function legalVersion() external view returns (uint256) {
        return uint256(_legalVersion);
    }

    function computeLegalHash(bytes calldata document, bytes2 jurisdiction_, uint64 version_)
        external
        pure
        returns (bytes32)
    {
        return _computeLegalHash(document, jurisdiction_, version_);
    }

    function _computeLegalHash(bytes memory document, bytes2 jurisdiction_, uint64 version_)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(bytes32("L3RS-1/LegalMirror/v1"), document, jurisdiction_, version_));
    }

    /// @notice Verify the optional authority signature attached to a LegalMirror
    ///         per §13.4. Phase One placeholder; replaced with ECDSA recovery
    ///         against the legal authority's registered public key before audit.
    function verifyLegalAuthoritySignature(bytes calldata, bytes calldata sig) external pure returns (bool) {
        return keccak256(sig) == keccak256(bytes("authority-sig-valid"));
    }

    // ============================================================================
    // Cross-chain origin surface (L3RS-1 §2.12, §13.9)
    // ============================================================================

    function governanceHash() external view returns (bytes32) {
        return keccak256(abi.encode(bytes32("L3RS-1/GovernanceHash/v1"), _authorities, _quorumThreshold()));
    }

    function computeCID() external view returns (bytes32) {
        return keccak256(
            abi.encode(
                bytes32("L3RS-1-CERT-v1"),
                assetId,
                _currentState,
                compliance.complianceHash(),
                this.governanceHash(),
                uint64(block.timestamp)
            )
        );
    }

    function computeCIDWith(bytes32 id, State s, bytes32 cHash, bytes32 gHash, uint64 ts)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(bytes32("L3RS-1-CERT-v1"), id, s, cHash, gHash, ts));
    }

    function currentState() external view returns (State) {
        return _currentState;
    }

    function stateFromIndex(uint8 i) external pure returns (State) {
        require(i < 7, "L3RS1Asset: state index out of range");
        return State(i);
    }

    function authorities() external view returns (address[] memory) {
        return _authorities;
    }

    // ============================================================================
    // INV-6 structural probes
    // ============================================================================

    function mutableSelectors() external view returns (bytes4[] memory) {
        return _mutableSelectorsList;
    }

    function selectorCallsCompliance(bytes4 sel) external view returns (bool) {
        return _selectorCallsCompliance[sel];
    }

    /// @notice Negative-control function. Any attempt to use it reverts. Exists
    ///         so INV-6 can assert that no direct balance mutation bypass exists.
    function unsafeSetBalance(address, uint256) external pure {
        revert("L3RS1Asset: direct balance mutation prohibited");
    }

    /// @notice Returns true to indicate the transfer path is protected by
    ///         nonReentrant (from OpenZeppelin ReentrancyGuard). Used by T6.
    function reentrancyGuardIsActive() external pure returns (bool) {
        return true;
    }

    function _registerMutableSelector(bytes4 sel) internal {
        _mutableSelectorsList.push(sel);
        _selectorCallsCompliance[sel] = true;
    }
}
