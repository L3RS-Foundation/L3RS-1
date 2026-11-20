// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: DESIGN.md §8.2 (approved design), EIP-712 §3 (domain separator and
//         signing-digest construction), EIP-2 (ECDSA malleability guards),
//         L3RS-1 v1.0.0 §5.4 (quorum threshold).
//
// This library is the single signature-verification surface for every authorized
// action in Phase One. Five call sites are expected: governance quorum on
// L3RS1Asset, ComplianceModule, PolicyRegistry, and IdentityAttestation, plus VA
// attestation issuance on IdentityAttestation. Per-contract-surface domains keep
// each of the five isolated from the other four.

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title SignatureVerification
/// @notice EIP-712 signing primitives. Five functions, two structs, one constant.
///         Wraps OpenZeppelin `ECDSA.tryRecover(bytes32, bytes)` only — the
///         two-argument overload.
library SignatureVerification {
    // ----- types and constants --------------------------------------------------

    struct Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    /// @notice Typed wrapper around the governance authority set.
    /// @dev This wrapper exists so that `verifyQuorum` cannot be accidentally
    ///      called with a non-governance `mapping(address => bool)` storage
    ///      reference — for example, the sanctions list in ComplianceModule,
    ///      the VA registry that IdentityAttestation will introduce in step 5
    ///      stage 2, or any other same-shape mapping a future contract might
    ///      hold. The compiler enforces that the fourth argument is a
    ///      `GovernanceAuthoritySet storage` reference, which is a distinct
    ///      type from a plain `mapping` storage reference even though the
    ///      underlying slot layout is compatible. DESIGN.md §8.2 documents the
    ///      motivation and the preceding audit note.
    struct GovernanceAuthoritySet {
        mapping(address => bool) members;
        uint256 threshold;
    }

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    error InvalidSignature();

    // ----- functions ------------------------------------------------------------

    /// @notice Compute the EIP-712 domain separator per EIP-712 §3.
    /// @dev domainSep = keccak256(abi.encode(
    ///          EIP712_DOMAIN_TYPEHASH,
    ///          keccak256(bytes(name)),
    ///          keccak256(bytes(version)),
    ///          chainId,
    ///          verifyingContract));
    function domainSeparator(Domain memory d) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes(d.name)),
            keccak256(bytes(d.version)),
            d.chainId,
            d.verifyingContract
        ));
    }

    /// @notice Compute the EIP-712 signing digest per EIP-712 §3.
    /// @dev digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash)).
    function digest(bytes32 domainSep, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
    }

    /// @notice Recover the signer from a 65-byte ECDSA signature over `d`.
    /// @dev Wraps OpenZeppelin `ECDSA.tryRecover(bytes32, bytes)`. Reverts with
    ///      InvalidSignature on RecoverError ≠ NoError. EIP-2 low-s malleability
    ///      guard is enforced by OpenZeppelin's implementation.
    function recover(bytes32 d, bytes memory signature) internal pure returns (address) {
        (address signer, ECDSA.RecoverError err, ) = ECDSA.tryRecover(d, signature);
        if (err != ECDSA.RecoverError.NoError) revert InvalidSignature();
        return signer;
    }

    /// @notice Non-reverting single-signature verifier. Returns false on any
    ///         recovery error or mismatch.
    function verifySingle(bytes32 d, bytes memory signature, address expectedSigner)
        internal
        pure
        returns (bool)
    {
        (address signer, ECDSA.RecoverError err, ) = ECDSA.tryRecover(d, signature);
        if (err != ECDSA.RecoverError.NoError) return false;
        return signer == expectedSigner;
    }

    /// @notice Verify a quorum of signatures. Each element of `signatures` is
    ///         recovered to a candidate signer; only recoveries that (a)
    ///         succeed and (b) land in `authorities.members` are counted.
    ///         Deduplication is by recovered address: presenting the same
    ///         signer's signature twice adds one to the count, not two.
    /// @dev This behavior is load-bearing. Under the placeholder scheme replaced
    ///      here, deduplication was by signature-bytes fingerprint, which made
    ///      quorum forgeable by an attacker holding one authority's key plus
    ///      arbitrary byte strings from others. Dedup-by-recovered-address
    ///      prevents that forgery — any byte string that is not a valid ECDSA
    ///      signature over `d` either fails recovery (skipped) or recovers to
    ///      an address outside `authorities.members` (skipped). See DESIGN.md
    ///      §4 for the exploit and §8.2 for the fix.
    /// @dev The `authorities` parameter is a typed storage reference to a
    ///      `GovernanceAuthoritySet`. It is NOT a bare `mapping(address => bool)`
    ///      storage reference. The compiler rejects any attempt to pass a plain
    ///      mapping in this position. DESIGN.md §8.2 documents the anti-swap
    ///      motivation.
    /// @param domainSep The EIP-712 domain separator of the calling surface.
    /// @param structHash The EIP-712 struct hash of the action being authorized.
    /// @param signatures Array of 65-byte ECDSA signatures.
    /// @param authorities Typed storage reference to the governance authority set.
    /// @return success True iff distinctCount ≥ authorities.threshold.
    /// @return distinctCount Number of distinct authorized signers who produced
    ///         valid signatures over `d`.
    function verifyQuorum(
        bytes32 domainSep,
        bytes32 structHash,
        bytes[] calldata signatures,
        GovernanceAuthoritySet storage authorities
    ) internal view returns (bool success, uint256 distinctCount) {
        bytes32 d = digest(domainSep, structHash);
        uint256 n = signatures.length;
        address[] memory seen = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            (address signer, ECDSA.RecoverError err, ) = ECDSA.tryRecover(d, signatures[i]);
            if (err != ECDSA.RecoverError.NoError) continue;
            if (!authorities.members[signer]) continue;
            bool isDuplicate = false;
            for (uint256 j = 0; j < distinctCount; j++) {
                if (seen[j] == signer) {
                    isDuplicate = true;
                    break;
                }
            }
            if (isDuplicate) continue;
            seen[distinctCount] = signer;
            distinctCount++;
        }
        success = distinctCount >= authorities.threshold;
    }
}
