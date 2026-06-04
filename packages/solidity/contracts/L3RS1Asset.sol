// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./interfaces/IL3RS1Asset.sol";
import "./libraries/L3RS1Hashing.sol";

/**
 * @title IComplianceOracle
 * @notice External, hash-anchored compliance evaluator (§4 + §10.15). The host
 *         wires an evaluator that consults attested data (sanctions/AML/etc.).
 *         A view call (STATICCALL) keeps compliance side-effect-free per §4.6.
 */
interface IComplianceOracle {
    function evaluate(bytes32 assetId, address sender, address receiver, uint256 amount)
        external view returns (bool allowed, bytes32 blockingRuleId);
}

/**
 * @title L3RS1Asset
 * @notice L3RS-1 Reference Implementation — EVM Profile A (§17.2).
 *         Compliance and identity are enforced PRIOR to state mutation, per the
 *         §17.8 Compliance Execution Location Constraint (applies to every profile).
 */
contract L3RS1Asset is IL3RS1Asset {

    // §3.6 identity status held on-chain so identity can gate settlement (I₃).
    enum IdentityStatus { UNKNOWN, VALID, EXPIRED, REVOKED }

    error NotIssuer();
    error NotIdentityOracle();
    error ComplianceBlocked(bytes32 ruleId);

    bytes32 private immutable _assetId;
    AssetState private _state;
    uint16 private immutable _feeRateBps;

    address public immutable issuer;        // settlement & supply authority
    address public identityOracle;          // may set identity status
    address public complianceOracle;        // external rule evaluator (§4)

    mapping(bytes32 => bool)          private _usedNonces;     // §9.6 replay
    mapping(address => uint256)       private _balances;
    mapping(address => IdentityStatus) public identityStatusOf; // §3.6

    constructor(bytes memory issuerPubkey, uint16 feeRateBps, bytes32 nonce) {
        _assetId    = L3RS1Hashing.constructAssetId(issuerPubkey, block.timestamp, nonce);
        _state      = AssetState.ISSUED;
        _feeRateBps = feeRateBps;
        issuer      = msg.sender;
    }

    modifier onlyIssuer() {
        if (msg.sender != issuer) revert NotIssuer();
        _;
    }

    // ── Administration ──────────────────────────────────────────────────────
    function setIdentityOracle(address oracle)   external onlyIssuer { identityOracle   = oracle; }
    function setComplianceOracle(address oracle) external onlyIssuer { complianceOracle = oracle; }

    function setIdentityStatus(address holder, IdentityStatus status) external {
        if (msg.sender != identityOracle) revert NotIdentityOracle();
        identityStatusOf[holder] = status;
    }

    // ── View functions ────────────────────────────────────────────────────────
    function assetId() external view override returns (bytes32) { return _assetId; }
    function currentState() external view override returns (AssetState) { return _state; }
    function standardVersion() external pure override returns (string memory) { return "L3RS-1.0.0"; }
    function feeRateBasisPoints() external view override returns (uint16) { return _feeRateBps; }

    function crossChainCertificateId() external view override returns (bytes32) {
        return L3RS1Hashing.constructCID(
            _assetId, bytes32(uint256(uint8(_state))), bytes32(0), bytes32(0), block.timestamp
        );
    }

    // ── State machine ─────────────────────────────────────────────────────────
    function activate() external onlyIssuer {
        require(_state == AssetState.ISSUED, "L3RS1: not ISSUED");
        emit StateTransition(_assetId, AssetState.ISSUED, AssetState.ACTIVE, bytes32("ACTIVATION"));
        _state = AssetState.ACTIVE;
    }

    // ── Compliance (§4) ─────────────────────────────────────────────────────────
    // Fails closed: inactive state, non-VALID identity, or an unset oracle all BLOCK.
    function _evaluate(address sender, address receiver, uint256 amount)
        internal view returns (bool allowed, bytes32 blockingRuleId)
    {
        if (_state != AssetState.ACTIVE)                       return (false, bytes32("STATE"));
        if (identityStatusOf[sender]   != IdentityStatus.VALID) return (false, bytes32("ID_SENDER"));
        if (identityStatusOf[receiver] != IdentityStatus.VALID) return (false, bytes32("ID_RECEIVER"));
        if (complianceOracle == address(0))                    return (false, bytes32("NO_ORACLE"));
        return IComplianceOracle(complianceOracle).evaluate(_assetId, sender, receiver, amount);
    }

    function checkCompliance(address sender, address receiver, uint256 amount)
        external view override returns (bool allowed, bytes32 blockingRuleId)
    {
        return _evaluate(sender, receiver, amount);
    }

    // ── Transfer ──────────────────────────────────────────────────────────────
    function transfer(address receiver, uint256 amount, bytes32 nonce)
        external override returns (bytes32 txId)
    {
        require(_state == AssetState.ACTIVE, "L3RS1: not ACTIVE");
        require(!_usedNonces[nonce], "L3RS1: replay");

        // §17.8: identity + compliance MUST execute prior to any state mutation.
        (bool ok, bytes32 ruleId) = _evaluate(msg.sender, receiver, amount);
        if (!ok) revert ComplianceBlocked(ruleId);

        require(_balances[msg.sender] >= amount, "L3RS1: insufficient balance");

        _usedNonces[nonce] = true;
        uint256 fee = (amount * _feeRateBps) / 10_000;
        _balances[msg.sender] -= amount;
        _balances[receiver]   += (amount - fee);

        txId = L3RS1Hashing.constructTxId(msg.sender, receiver, amount, nonce, block.timestamp);
        emit Transfer(txId, msg.sender, receiver, amount);
    }

    // ── Supply (issuer-gated) ───────────────────────────────────────────────────
    function mint(address to, uint256 amount) external onlyIssuer {
        require(_state == AssetState.ISSUED || _state == AssetState.ACTIVE, "L3RS1: bad state");
        _balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
}
