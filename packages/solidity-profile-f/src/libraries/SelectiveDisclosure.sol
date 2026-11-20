// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: L3RS-1 v1.0.0 §3.7 (Selective Disclosure), DESIGN.md §8.3 (approved
//         architecture and the four resolved decisions), DESIGN.md §8.2
//         (shared EIP-712 signing library and per-contract-surface domains).
//
// This library is the single selective-disclosure verifier for every Phase One
// rule evaluator. Phase One's consumer is IdentityAttestation; Phase Three's
// ComplianceModule rule-evaluator expansion (INVESTOR_CLASSIFICATION,
// HOLDING_PERIOD) will adopt the same library without changes.

import {SignatureVerification} from "./SignatureVerification.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title SelectiveDisclosure
/// @notice Verify a holder-signed selective-disclosure presentation and consume
///         its nonce. Reverts on any failure. Single public entry point.
library SelectiveDisclosure {
    // ----- types --------------------------------------------------------------

    struct Disclosure {
        bytes32 nameHash;   // keccak256 of the canonical attribute name
        bytes32 valueHash;  // keccak256(attribute_value ‖ salt)
    }

    struct Presentation {
        address holder;
        bytes32 attestationRef;   // keccak256(holder, jurisdiction) — identifies a Record
        bytes32 commitmentRoot;   // Merkle root; must match the Record's stored root
        Disclosure[] disclosures;
        bytes32[][] merkleProofs; // one proof per disclosure
        address verifier;         // the contract receiving the presentation
        uint256 nonce;            // per-(holder, verifier) replay protection
        uint256 deadline;
    }

    // ----- EIP-712 typehashes -------------------------------------------------

    bytes32 internal constant DISCLOSURE_TYPEHASH = keccak256(
        "Disclosure(bytes32 nameHash,bytes32 valueHash)"
    );

    bytes32 internal constant PRESENTATION_TYPEHASH = keccak256(
        "Presentation(address holder,bytes32 attestationRef,bytes32 commitmentRoot,Disclosure[] disclosures,bytes32[][] merkleProofs,address verifier,uint256 nonce,uint256 deadline)Disclosure(bytes32 nameHash,bytes32 valueHash)"
    );

    // ----- errors -------------------------------------------------------------

    error HolderSignatureInvalid();
    error WrongVerifier();
    error PresentationExpired();
    error NonceAlreadyUsed();
    error ProofLengthMismatch();
    error InvalidMerkleProof(uint256 disclosureIndex);

    // ----- leaf encoding ------------------------------------------------------

    /// @notice Compute the canonical Merkle leaf for a disclosure.
    /// @dev Leaf = keccak256(abi.encode(nameHash, valueHash)). This is the
    ///      exact bytes-level rule documented in DESIGN.md §8.3. Off-chain
    ///      provers must match this encoding — using `abi.encodePacked` or
    ///      omitting the hash of the attribute name silently produces a
    ///      different leaf and fails Merkle verification with no diagnostic.
    function leafOf(Disclosure memory d) internal pure returns (bytes32) {
        return keccak256(abi.encode(d.nameHash, d.valueHash));
    }

    // ----- primary entry point ------------------------------------------------

    /// @notice Verify a selective-disclosure presentation and consume its nonce.
    /// @dev Reverts on any failure. The verifier-is-caller check (`address(this) ==
    ///      p.verifier`) ensures a signature bound to verifier A cannot be
    ///      consumed by verifier B even if A's storage is inaccessible. Because
    ///      this library function is `internal`, Solidity inlines the code into
    ///      the calling contract — `address(this)` therefore refers to the
    ///      consuming contract (IdentityAttestation, ComplianceModule, etc.),
    ///      not to the library itself. The EIP-712 signature also binds
    ///      `verifier`, so this check is defense-in-depth.
    /// @param domainSep The EIP-712 domain separator of the consuming contract's
    ///        presentation surface (e.g. DOMAIN_SEPARATOR_PRESENTATION on
    ///        IdentityAttestation).
    /// @param p The presentation.
    /// @param holderSignature 65-byte ECDSA signature from the holder over the
    ///        EIP-712 digest.
    /// @param usedNonces Storage reference to the consumer's per-(holder,
    ///        verifier, nonce) used-set. Consumed on success.
    function verify(
        bytes32 domainSep,
        Presentation calldata p,
        bytes calldata holderSignature,
        mapping(address => mapping(address => mapping(uint256 => bool))) storage usedNonces
    ) internal {
        if (address(this) != p.verifier) revert WrongVerifier();
        if (block.timestamp > p.deadline) revert PresentationExpired();
        if (usedNonces[p.holder][p.verifier][p.nonce]) revert NonceAlreadyUsed();
        if (p.disclosures.length != p.merkleProofs.length) revert ProofLengthMismatch();

        bytes32 structHash = _hashPresentation(p);
        bytes32 digest = SignatureVerification.digest(domainSep, structHash);
        address signer = SignatureVerification.recover(digest, holderSignature);
        if (signer != p.holder) revert HolderSignatureInvalid();

        for (uint256 i = 0; i < p.disclosures.length; i++) {
            bytes32 leaf = leafOf(p.disclosures[i]);
            if (!MerkleProof.verify(p.merkleProofs[i], p.commitmentRoot, leaf)) {
                revert InvalidMerkleProof(i);
            }
        }

        usedNonces[p.holder][p.verifier][p.nonce] = true;
    }

    // ----- EIP-712 struct hash ------------------------------------------------

    /// @dev Per EIP-712 §3, arrays of structs hash as the concatenation of each
    ///      element's struct hash; arrays of `bytes32` hash as the concatenation
    ///      of the elements themselves. Nested `bytes32[][]` applies the inner
    ///      concatenation first, then hashes the outer array of those hashes.
    function _hashPresentation(Presentation calldata p) private pure returns (bytes32) {
        bytes32[] memory disclosureHashes = new bytes32[](p.disclosures.length);
        for (uint256 i = 0; i < p.disclosures.length; i++) {
            disclosureHashes[i] = keccak256(abi.encode(
                DISCLOSURE_TYPEHASH,
                p.disclosures[i].nameHash,
                p.disclosures[i].valueHash
            ));
        }
        bytes32 disclosuresHash = keccak256(abi.encodePacked(disclosureHashes));

        bytes32[] memory proofHashes = new bytes32[](p.merkleProofs.length);
        for (uint256 i = 0; i < p.merkleProofs.length; i++) {
            proofHashes[i] = keccak256(abi.encodePacked(p.merkleProofs[i]));
        }
        bytes32 merkleProofsHash = keccak256(abi.encodePacked(proofHashes));

        return keccak256(abi.encode(
            PRESENTATION_TYPEHASH,
            p.holder,
            p.attestationRef,
            p.commitmentRoot,
            disclosuresHash,
            merkleProofsHash,
            p.verifier,
            p.nonce,
            p.deadline
        ));
    }
}
