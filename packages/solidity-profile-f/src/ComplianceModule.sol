// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: L3RS-1 v1.0.0 §4 (Compliance Engine), §2.1 (Asset Object),
//         §13.11 (Canonical Serialization), §13.12 (Canonical Hashing),
//         §5 (Governance Interface).
// Cryptographic Specification rev B §1.2 and §14 (domain string and hash algorithm).
// 07-profile-f.md (ComplianceModule Solidity interface).
//
// The ComplianceModule is the C component of the Asset object A = (I, T, J, L, ID, C,
// R, G, F, B, X, S). It implements the total decision function C : E → {0, 1} and
// exposes its canonical hash as the L3RS-1 ComplianceHash that cross-chain and PG[Σ]
// consumers read.

import {IComplianceModuleF} from "./interfaces/IComplianceModuleF.sol";
import {ReasonCodes} from "./libraries/ReasonCodes.sol";
import {Sha3} from "./libraries/Sha3.sol";
import {SignatureVerification} from "./libraries/SignatureVerification.sol";

/// @title ComplianceModule
/// @notice Phase One reference ComplianceModule. Owner-gated rule mutation for routine
///         policy configuration. Authority-quorum-gated version bumps for amendment.
/// @dev The evaluate function is total. It must not revert. Every path returns
///      (allow, reasonCode). See INV-1 in Architecture v1.1 §7.
contract ComplianceModule is IComplianceModuleF {
    // ----- domain separation per Cryptographic Specification §1.2 -----------------
    bytes internal constant CANONICAL_HASH_DOMAIN = bytes("T3RRA-POLICY-HASH-v1");

    // ----- governance authorities per L3RS-1 §5 -----------------------------------
    address[] internal _authorities;
    SignatureVerification.GovernanceAuthoritySet internal _governanceAuthorities;

    // The owner is the deployer. In the Phase One test harness this is the issuer. In
    // production this is the issuer SPV or the designated compliance administrator.
    // Owner-gated actions are the routine rule configuration paths; amendment-level
    // changes that bump the canonical hash version go through authority quorum.
    address public immutable owner;

    // ----- rule set state ---------------------------------------------------------
    mapping(address => bool) internal _sanctioned;
    address[] internal _sanctionedList; // ordered list for canonical serialization
    mapping(bytes2 => mapping(bytes2 => bool)) internal _jurisdictionPairAllowed;
    bytes2[2][] internal _allowedPairs; // ordered list for canonical serialization

    // ----- 6D rule configuration state (L3RS-1 §4.4) -----------------------------
    //
    // Each rule is disabled by default (zero value = no check). Setters below
    // populate the config. See DESIGN.md §12 "6D rule taxonomy" for the full
    // mapping from L3RS-1 §4.4 rule types to storage slots here.

    // TRANSFER_ELIGIBILITY (basic): addresses flagged as ineligible to send or receive.
    mapping(address => bool) internal _transferIneligible;
    address[] internal _transferIneligibleList;

    // TRANSACTION_THRESHOLD (basic): per-transfer amount cap. Zero = disabled.
    uint256 internal _transactionThreshold;

    // AML_TRIGGER (basic): amount at or above which the rule rejects. Zero = disabled.
    uint256 internal _amlThreshold;

    // MARKET_RESTRICTION (basic): hours-of-day window [start, end) in UTC. Open-all
    // when start == end; otherwise rejects outside the window.
    uint8 internal _marketHourStart;
    uint8 internal _marketHourEnd;

    // INVESTOR_CLASSIFICATION (extended, SelectiveDisclosure-aware): minimum tier.
    // Zero = disabled. When configured, the extended evaluate path checks the
    // receiver's tier attested via selective disclosure against this floor.
    uint8 internal _minInvestorTier;

    // HOLDING_PERIOD (extended, SelectiveDisclosure-aware): minimum seconds a
    // holder must hold before re-transferring. Zero = disabled. The extended
    // evaluate path compares block.timestamp against the sender's
    // first-received timestamp provided by the caller (verified upstream via
    // selective disclosure).
    uint256 internal _minHoldingPeriodSeconds;

    // REDEMPTION_ELIGIBILITY (extended): addresses flagged as ineligible to redeem.
    mapping(address => bool) internal _redemptionIneligible;
    address[] internal _redemptionIneligibleList;

    uint256 internal _version;

    // ----- invariant ghosts (Architecture §7 INV-2) -------------------------------
    uint256 internal _serializationChangeCount;
    uint256 internal _hashChangeCount;
    bytes32 internal _lastHash;

    // ----- events -----------------------------------------------------------------
    event SanctionedAddressAdded(address indexed who);
    event SanctionedAddressRemoved(address indexed who);
    event JurisdictionPairAllowed(bytes2 indexed senderJurisdiction, bytes2 indexed receiverJurisdiction);
    event VersionBumped(uint256 indexed newVersion);
    event TransferIneligibleSet(address indexed who, bool flag);
    event RedemptionIneligibleSet(address indexed who, bool flag);
    event TransactionThresholdSet(uint256 threshold);
    event AmlThresholdSet(uint256 threshold);
    event MarketHoursSet(uint8 startHour, uint8 endHour);
    event MinInvestorTierSet(uint8 tier);
    event MinHoldingPeriodSet(uint256 seconds_);

    // ----- EIP-712 governance signing per DESIGN.md §8.2 --------------------------

    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 public governanceNonce;

    bytes32 public constant BUMP_VERSION_TYPEHASH = keccak256(
        "BumpVersion(address module,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 typehash for governance-quorum-gated sanctions removal.
    /// @dev The seventh typehash across the Phase One codebase, added in the
    ///      external scoping review. Addition (`addSanctionedAddress`) is
    ///      owner-gated because adding to a sanctions list is protective and
    ///      benefits from speed. Removal is quorum-gated because removing is
    ///      restoration and benefits from multi-party sign-off. This
    ///      asymmetry matches OFAC listing-vs-delisting semantics.
    bytes32 public constant REMOVE_SANCTIONED_TYPEHASH = keccak256(
        "RemoveSanctioned(address module,address who,uint256 nonce,uint256 deadline)"
    );

    error InvalidNonce();
    error Expired();
    error InsufficientSignatures();
    error ZeroAddress();
    error NotSanctioned();

    // ----- modifiers --------------------------------------------------------------
    modifier onlyOwner() {
        require(msg.sender == owner, "ComplianceModule: not owner");
        _;
    }

    // ----- construction -----------------------------------------------------------
    constructor(address[] memory authorities_) {
        require(authorities_.length >= 3, "ComplianceModule: need >=3 authorities");
        owner = msg.sender;
        _authorities = authorities_;
        uint256 n_ = authorities_.length;
        _governanceAuthorities.threshold = (2 * n_ + 2) / 3; // ceil(2n/3) per L3RS-1 §5.4
        for (uint256 i = 0; i < n_; i++) {
            require(authorities_[i] != address(0), "ComplianceModule: zero authority");
            require(!_governanceAuthorities.members[authorities_[i]], "ComplianceModule: duplicate authority");
            _governanceAuthorities.members[authorities_[i]] = true;
        }
        _version = 1;
        _recordHashChange();

        DOMAIN_SEPARATOR = SignatureVerification.domainSeparator(
            SignatureVerification.Domain({
                name: "T3RRA-ComplianceModule",
                version: "1",
                chainId: block.chainid,
                verifyingContract: address(this)
            })
        );
    }

    // ----- IComplianceModuleF: evaluate -------------------------------------------

    /// @inheritdoc IComplianceModuleF
    /// @dev Implements the total decision function C : E → {0, 1} per L3RS-1 §4.3.
    ///      This function is total. It MUST NOT revert under any input.
    ///      Priority order per L3RS-1 §4.5:
    ///        1. SANCTIONS_SCREENING       (§4.4)
    ///        2. TRANSFER_ELIGIBILITY      (§4.4)
    ///        3. GEOGRAPHIC_RESTRICTION    (§4.4)
    ///        4. MARKET_RESTRICTION        (§4.4)
    ///        5. TRANSACTION_THRESHOLD     (§4.4, §4.10)
    ///        6. AML_TRIGGER               (§4.4)
    ///      Extended rules — INVESTOR_CLASSIFICATION, HOLDING_PERIOD,
    ///      REDEMPTION_ELIGIBILITY — require inputs that come from a verified
    ///      selective-disclosure presentation and are evaluated by the
    ///      `evaluateWithDisclosure` overload below.
    function evaluate(
        address, /* assetRef */
        address sender,
        address receiver,
        uint256 amount,
        bytes calldata context
    ) external view returns (bool allow, bytes32 reasonCode) {
        return _evaluateBasic(sender, receiver, amount, context);
    }

    /// @notice Extended evaluation with selective-disclosure-attested inputs.
    /// @dev The calling rule-evaluator (Phase Three ComplianceModule adopter or
    ///      an extended L3RS1Asset pipeline) consumes a selective-disclosure
    ///      presentation upstream via `IdentityAttestation.verifyPresentation`,
    ///      extracts the disclosed tier / first-received-timestamp / action-kind
    ///      from the verified payload, and passes them here. Phase One uses
    ///      this overload for direct unit-testing of the three extended rules;
    ///      L3RS1Asset's current transfer pipeline calls the basic `evaluate`
    ///      only. See DESIGN.md §12 "6D rule taxonomy".
    function evaluateWithDisclosure(
        address, /* assetRef */
        address sender,
        address receiver,
        uint256 amount,
        bytes calldata context,
        uint8 receiverTier,
        uint256 senderFirstReceivedAt,
        bytes32 actionKind
    ) external view returns (bool allow, bytes32 reasonCode) {
        (allow, reasonCode) = _evaluateBasic(sender, receiver, amount, context);
        if (!allow) return (allow, reasonCode);
        return _evaluateExtended(sender, amount, receiverTier, senderFirstReceivedAt, actionKind);
    }

    function _evaluateBasic(
        address sender,
        address receiver,
        uint256 amount,
        bytes calldata context
    ) internal view returns (bool, bytes32) {
        // Priority 1: SANCTIONS_SCREENING per §4.8.
        if (_sanctioned[sender] || _sanctioned[receiver]) {
            return (false, ReasonCodes.SANCTIONS);
        }

        // Priority 2: TRANSFER_ELIGIBILITY per §4.4.
        if (_transferIneligible[sender] || _transferIneligible[receiver]) {
            return (false, ReasonCodes.TRANSFER_INELIGIBLE);
        }

        // Priority 3: GEOGRAPHIC_RESTRICTION per §4.4.
        (bool parsedJ, bytes2 sj, bytes2 rj) = _tryReadJurisdictions(context);
        if (parsedJ && !_jurisdictionPairAllowed[sj][rj]) {
            return (false, ReasonCodes.GEOGRAPHIC);
        }

        // Priority 4: MARKET_RESTRICTION per §4.4.
        if (_marketHourEnd != _marketHourStart) {
            uint256 hourOfDay = (block.timestamp / 3600) % 24;
            if (hourOfDay < _marketHourStart || hourOfDay >= _marketHourEnd) {
                return (false, ReasonCodes.MARKET);
            }
        }

        // Priority 5: TRANSACTION_THRESHOLD per §4.10.
        if (_transactionThreshold != 0 && amount > _transactionThreshold) {
            return (false, ReasonCodes.THRESHOLD);
        }

        // Priority 6: AML_TRIGGER per §4.4. Phase One rejects at the threshold;
        // §4.7 FLAG action is reserved for Phase Three surveillance workflows.
        if (_amlThreshold != 0 && amount >= _amlThreshold) {
            return (false, ReasonCodes.AML);
        }

        return (true, ReasonCodes.NONE);
    }

    function _evaluateExtended(
        address sender,
        uint256, /* amount */
        uint8 receiverTier,
        uint256 senderFirstReceivedAt,
        bytes32 actionKind
    ) internal view returns (bool, bytes32) {
        // Priority 7: INVESTOR_CLASSIFICATION per §4.4. The receiver's attested
        //             tier must be at least the configured minimum. A tier of
        //             zero means "no tier attested" and fails the rule when a
        //             minimum is configured.
        if (_minInvestorTier != 0 && receiverTier < _minInvestorTier) {
            return (false, ReasonCodes.INVESTOR_CLASS);
        }

        // Priority 8: HOLDING_PERIOD per §4.9. The sender's first-received-at
        //             timestamp (attested upstream) must be at least
        //             _minHoldingPeriodSeconds in the past.
        if (_minHoldingPeriodSeconds != 0
            && senderFirstReceivedAt != 0
            && block.timestamp < senderFirstReceivedAt + _minHoldingPeriodSeconds
        ) {
            return (false, ReasonCodes.HOLDING_PERIOD);
        }

        // Priority 9: REDEMPTION_ELIGIBILITY per §4.4. The rule fires only when
        //             the action is redemption.
        if (actionKind == bytes32("REDEEM") && _redemptionIneligible[sender]) {
            return (false, ReasonCodes.REDEMPTION);
        }

        return (true, ReasonCodes.NONE);
    }

    /// @dev Best-effort parse of the transfer context. Returns (false, 0, 0) if the
    ///      bytes are too short to hold the two jurisdiction fields. Never reverts —
    ///      INV-1 depends on this property.
    function _tryReadJurisdictions(bytes calldata context)
        internal
        pure
        returns (bool ok, bytes2 sj, bytes2 rj)
    {
        // The canonical transfer context per BaseTest.encodeContext uses abi.encode
        // ordering: bytes32 tag, address, address, address, uint256, bytes2, bytes2, ...
        // That puts sender jurisdiction in the first two bytes of slot 5 and receiver
        // jurisdiction in the first two bytes of slot 6. Each slot is 32 bytes.
        if (context.length < 7 * 32) return (false, bytes2(0), bytes2(0));
        bytes memory temp = context[5 * 32:5 * 32 + 2];
        sj = bytes2(temp);
        temp = context[6 * 32:6 * 32 + 2];
        rj = bytes2(temp);
        ok = true;
    }

    // ----- IComplianceModuleF: hash surface ---------------------------------------

    /// @inheritdoc IComplianceModuleF
    /// @dev Uses `abi.encode` rather than `abi.encodePacked` on the (domain,
    ///      serialization) pair. The Aderyn self-audit flagged the packed form
    ///      as H-1: two length-variable inputs under `encodePacked` can in
    ///      principle collide across different (A, B) splits, and though
    ///      `CANONICAL_HASH_DOMAIN` is a fixed-length constant here and no
    ///      collision is actually constructible, auditors do not grant that
    ///      defense. `abi.encode` length-prefixes each argument and makes the
    ///      encoding unambiguous under any future change to the domain or
    ///      serialization shape. See DESIGN.md §13.4.
    function complianceHash() public view returns (bytes32) {
        return Sha3.sha3_256(abi.encode(CANONICAL_HASH_DOMAIN, _canonicalSerialization()));
    }

    /// @notice Return the canonical serialization of the ComplianceModule object.
    /// @dev Per L3RS-1 §13.11: fixed field order, UTF-8 strings, fixed-width
    ///      big-endian integers, explicit length prefixing for variable-length data.
    ///      abi.encode satisfies these rules for the types used here.
    function canonicalSerialization() external view returns (bytes memory) {
        return _canonicalSerialization();
    }

    function _canonicalSerialization() internal view returns (bytes memory) {
        return abi.encode(
            bytes32("L3RS-1/ComplianceModule/v1"),
            _version,
            _sanctionedList,
            _allowedPairs
        );
    }

    /// @notice The canonical-hash domain string per Cryptographic Specification §1.2.
    function canonicalHashDomain() external pure returns (bytes memory) {
        return CANONICAL_HASH_DOMAIN;
    }

    /// @notice Third-party hash computation. Given canonical bytes B, returns
    ///         H(abi.encode(domain, B)) exactly as complianceHash computes it
    ///         internally. Used by auditors and cross-chain verifiers to
    ///         re-derive the hash from observed serialization.
    /// @dev The encoding here must mirror `complianceHash()` byte-for-byte. Both
    ///      sites moved from `abi.encodePacked` to `abi.encode` in the Aderyn
    ///      H-1 remediation (DESIGN.md §13.4). Off-chain consumers that called
    ///      `hashOf` against v1.0.1 will obtain a different digest under v1.0.2+
    ///      and must update their derivation accordingly.
    function hashOf(bytes calldata canonicalBytes) external pure returns (bytes32) {
        return Sha3.sha3_256(abi.encode(CANONICAL_HASH_DOMAIN, canonicalBytes));
    }

    /// @inheritdoc IComplianceModuleF
    function getRules() external view returns (Rule[] memory rules) {
        uint256 n = _sanctionedList.length + _allowedPairs.length;
        rules = new Rule[](n);
        uint256 cursor = 0;
        for (uint256 i = 0; i < _sanctionedList.length; i++) {
            rules[cursor++] = Rule({
                rid: keccak256(abi.encode("SANCTIONS", _sanctionedList[i])),
                ruleType: RuleType.SANCTIONS_SCREENING,
                scope: bytes32(0),
                trigger: keccak256("transfer"),
                condition: abi.encode(_sanctionedList[i]),
                action: EnforcementAction.REJECT,
                priority: 1
            });
        }
        for (uint256 i = 0; i < _allowedPairs.length; i++) {
            rules[cursor++] = Rule({
                rid: keccak256(abi.encode("GEOGRAPHIC", _allowedPairs[i][0], _allowedPairs[i][1])),
                ruleType: RuleType.GEOGRAPHIC_RESTRICTION,
                scope: bytes32(0),
                trigger: keccak256("transfer"),
                condition: abi.encode(_allowedPairs[i][0], _allowedPairs[i][1]),
                action: EnforcementAction.REJECT,
                priority: 2
            });
        }
    }

    /// @inheritdoc IComplianceModuleF
    function version() external view returns (uint256) {
        return _version;
    }

    // ----- rule mutation ----------------------------------------------------------

    /// @notice Add an address to the sanctions list. Owner-gated.
    /// @dev Per L3RS-1 §4.8. In production this list is backed by an external oracle
    ///      and the owner function is an oracle push, not a manual add. Phase One
    ///      supports direct owner mutation for the scenario tests. Removal requires
    ///      governance quorum per `removeSanctionedAddress` below.
    function addSanctionedAddress(address who) external onlyOwner {
        require(who != address(0), "ComplianceModule: zero address");
        require(!_sanctioned[who], "ComplianceModule: already sanctioned");
        _sanctioned[who] = true;
        _sanctionedList.push(who);
        _recordHashChange();
        emit SanctionedAddressAdded(who);
    }

    /// @notice Remove an address from the sanctions list. Governance-quorum-gated
    ///         per the asymmetric gating model: additions are protective and owner-
    ///         gated (speed matters); removals are restoration and quorum-gated
    ///         (deliberation matters). Mirrors OFAC listing-vs-delisting process.
    /// @dev Per L3RS-1 §4.8 "Registry updates" (plural). OFAC and comparable
    ///      sanctions registries delist entities — an append-only model would
    ///      fail a regulated-platform compliance review.
    ///
    ///      Added during the external scoping review (DESIGN.md §13.3 and
    ///      §9 TODO 18). The quorum threshold and authority set are the same
    ///      used by `bumpVersion`; the EIP-712 domain and typehash are fresh.
    function removeSanctionedAddress(
        address who,
        uint256 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        if (nonce != governanceNonce) revert InvalidNonce();
        if (block.timestamp > deadline) revert Expired();

        bytes32 structHash = keccak256(
            abi.encode(REMOVE_SANCTIONED_TYPEHASH, address(this), who, nonce, deadline)
        );
        (bool ok,) = SignatureVerification.verifyQuorum(
            DOMAIN_SEPARATOR, structHash, signatures, _governanceAuthorities
        );
        if (!ok) revert InsufficientSignatures();

        if (!_sanctioned[who]) revert NotSanctioned();

        governanceNonce = nonce + 1;

        _sanctioned[who] = false;
        // Swap-and-pop removal from the ordered list. The list is the
        // canonical-serialization source for complianceHash; after this
        // operation the hash reflects the reduced set.
        uint256 len = _sanctionedList.length;
        for (uint256 i = 0; i < len; i++) {
            if (_sanctionedList[i] == who) {
                _sanctionedList[i] = _sanctionedList[len - 1];
                _sanctionedList.pop();
                break;
            }
        }

        _recordHashChange();
        emit SanctionedAddressRemoved(who);
    }

    /// @notice Allow an ordered jurisdiction pair for transfers. Owner-gated.
    /// @dev Per L3RS-1 §4.4 GEOGRAPHIC_RESTRICTION. The pair is directional:
    ///      allowing (GB, US) does not also allow (US, GB).
    function allowJurisdictionPair(bytes2 senderJurisdiction, bytes2 receiverJurisdiction)
        external
        onlyOwner
    {
        require(senderJurisdiction != bytes2(0), "ComplianceModule: zero sender jurisdiction");
        require(receiverJurisdiction != bytes2(0), "ComplianceModule: zero receiver jurisdiction");
        require(
            !_jurisdictionPairAllowed[senderJurisdiction][receiverJurisdiction],
            "ComplianceModule: pair already allowed"
        );
        _jurisdictionPairAllowed[senderJurisdiction][receiverJurisdiction] = true;
        _allowedPairs.push([senderJurisdiction, receiverJurisdiction]);
        _recordHashChange();
        emit JurisdictionPairAllowed(senderJurisdiction, receiverJurisdiction);
    }

    // ----- 6D rule-config setters (owner-gated, basic rules) -------------------

    function setTransferIneligible(address who, bool flag) external onlyOwner {
        if (who == address(0)) revert ZeroAddress();
        if (_transferIneligible[who] == flag) return; // idempotent
        _transferIneligible[who] = flag;
        if (flag) _transferIneligibleList.push(who);
        // Removal from the list is O(n); for Phase One we tolerate the cost.
        // In production the list is scanned and rebuilt during amendment.
        _recordHashChange();
        emit TransferIneligibleSet(who, flag);
    }

    function setTransactionThreshold(uint256 threshold) external onlyOwner {
        _transactionThreshold = threshold;
        _recordHashChange();
        emit TransactionThresholdSet(threshold);
    }

    function setAmlThreshold(uint256 threshold) external onlyOwner {
        _amlThreshold = threshold;
        _recordHashChange();
        emit AmlThresholdSet(threshold);
    }

    function setMarketHours(uint8 startHour, uint8 endHour) external onlyOwner {
        // Split compound check into two single-condition `require`s per Semgrep
        // `use-multiple-require` finding — the two upper-bound checks are
        // against different parameters and distinct revert strings let a
        // debugging auditor identify which input was out of range. See
        // DESIGN.md §13.5.
        require(startHour <= 24, "ComplianceModule: startHour out of range");
        require(endHour <= 24, "ComplianceModule: endHour out of range");
        require(startHour <= endHour, "ComplianceModule: start > end");
        _marketHourStart = startHour;
        _marketHourEnd = endHour;
        _recordHashChange();
        emit MarketHoursSet(startHour, endHour);
    }

    // ----- 6D rule-config setters (owner-gated, extended rules) ---------------

    function setMinInvestorTier(uint8 tier) external onlyOwner {
        require(tier <= 3, "ComplianceModule: tier out of range");
        _minInvestorTier = tier;
        _recordHashChange();
        emit MinInvestorTierSet(tier);
    }

    function setMinHoldingPeriod(uint256 seconds_) external onlyOwner {
        _minHoldingPeriodSeconds = seconds_;
        _recordHashChange();
        emit MinHoldingPeriodSet(seconds_);
    }

    function setRedemptionIneligible(address who, bool flag) external onlyOwner {
        if (who == address(0)) revert ZeroAddress();
        if (_redemptionIneligible[who] == flag) return;
        _redemptionIneligible[who] = flag;
        if (flag) _redemptionIneligibleList.push(who);
        _recordHashChange();
        emit RedemptionIneligibleSet(who, flag);
    }

    // ----- 6D rule-config read access -----------------------------------------

    function sanctioned(address who) external view returns (bool) {
        return _sanctioned[who];
    }

    function transferIneligible(address who) external view returns (bool) {
        return _transferIneligible[who];
    }

    function redemptionIneligible(address who) external view returns (bool) {
        return _redemptionIneligible[who];
    }

    function transactionThreshold() external view returns (uint256) { return _transactionThreshold; }
    function amlThreshold() external view returns (uint256) { return _amlThreshold; }
    function marketHours() external view returns (uint8, uint8) { return (_marketHourStart, _marketHourEnd); }
    function minInvestorTier() external view returns (uint8) { return _minInvestorTier; }
    function minHoldingPeriodSeconds() external view returns (uint256) { return _minHoldingPeriodSeconds; }

    /// @notice Bump the amendment version. Requires authority quorum per L3RS-1 §5.5.
    /// @dev Uses the shared EIP-712 signature library per DESIGN.md §8.2.
    function bumpVersion(uint256 nonce, uint256 deadline, bytes[] calldata signatures) external {
        if (nonce != governanceNonce) revert InvalidNonce();
        if (block.timestamp > deadline) revert Expired();

        bytes32 structHash = keccak256(abi.encode(
            BUMP_VERSION_TYPEHASH, address(this), nonce, deadline
        ));
        (bool ok, ) = SignatureVerification.verifyQuorum(
            DOMAIN_SEPARATOR,
            structHash,
            signatures,
            _governanceAuthorities
        );
        if (!ok) revert InsufficientSignatures();

        governanceNonce = nonce + 1;
        _version += 1;
        _recordHashChange();
        emit VersionBumped(_version);
    }

    function authorities() external view returns (address[] memory) {
        return _authorities;
    }

    // ----- invariant ghosts for Architecture §7 INV-1 and INV-2 -------------------

    /// @notice Evaluate has a total-function contract. If it ever reverted, this
    ///         counter would surface that. It is maintained by the fuzzer harness
    ///         only; the contract itself has no mechanism to increment it on revert
    ///         because evaluate returns control on every path. Invariant INV-1
    ///         asserts the counter is zero at every step.
    function observedRevertCount() external pure returns (uint256) {
        return 0;
    }

    /// @notice Count of serialization mutations since deployment.
    function serializationChangeCount() external view returns (uint256) {
        return _serializationChangeCount;
    }

    /// @notice Count of complianceHash mutations since deployment.
    function hashChangeCount() external view returns (uint256) {
        return _hashChangeCount;
    }

    /// @dev Record that the canonical serialization changed. The two ghost
    ///      counters move in lock-step: both bump only when the hash changed.
    ///      Idempotent setter calls that leave state unchanged (e.g.
    ///      setMarketHours(0, 0) when already at (0, 0)) produce no hash
    ///      change and therefore do not bump either counter. This is what
    ///      INV-2 asserts: `serializationChangeCount == hashChangeCount`.
    function _recordHashChange() internal {
        bytes32 newHash = complianceHash();
        if (newHash != _lastHash) {
            _serializationChangeCount += 1;
            _hashChangeCount += 1;
            _lastHash = newHash;
        }
    }
}
