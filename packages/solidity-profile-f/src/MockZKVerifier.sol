// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: DESIGN.md §5b. Phase One mock verifier. NOT FOR MAINNET.

import {IZKVerifier} from "./interfaces/IZKVerifier.sol";

/// @title MockZKVerifier
/// @notice A mock IZKVerifier that accepts any proof bytes as valid. Phase One
///         uses this so the IdentityAttestation contract can exercise the
///         ZKP-compatible code path (public-input encoding, verifier calls,
///         storage of PROOF field) without depending on a real proving system.
///
/// @dev WARNING: this contract is clearly marked as a mock. It MUST NOT be
///      deployed to mainnet. It has no cryptographic meaning. Any signature
///      attached in the PROOF field of a Record is trivially accepted. Mainnet
///      deployment replaces this with a real verifier — Groth16 on BN254,
///      Plonk, STARK, or an equivalent — per DESIGN.md §5b and §9 TODO 14.
///      The governance-gated `setZKVerifier` in IdentityAttestation performs
///      the swap without requiring a redeploy of the attestation contract.
contract MockZKVerifier is IZKVerifier {
    function verify(bytes calldata, bytes calldata) external pure returns (bool) {
        // MOCK: accept any proof. See DESIGN.md §5b security warning.
        return true;
    }

    function verifierId() external pure returns (string memory) {
        return "mock";
    }
}
