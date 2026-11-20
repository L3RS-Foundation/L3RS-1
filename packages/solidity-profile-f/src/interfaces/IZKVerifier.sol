// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: L3RS-1 v1.0.0 §3.8 (ZKP compatibility), §14.4 (fixed proof size for
//         ZKP), DESIGN.md §5b (mock verifier warning and production scope).

/// @title IZKVerifier
/// @notice Verifier-agnostic interface for zero-knowledge proofs attached to
///         identity attestations per L3RS-1 §3.8. A single verify() function
///         takes opaque proof bytes and public inputs and returns a boolean.
/// @dev Phase One ships with a MockZKVerifier that accepts any proof bytes. It
///      is clearly labelled as a mock per DESIGN.md §5b. Mainnet deployment
///      MUST replace the mock with a real proving-system verifier before §9
///      TODO 14 is closed. The interface is deliberately generic so any
///      Groth16, Plonk, STARK, Halo2, or custom verifier can implement it.
interface IZKVerifier {
    /// @notice Verify a zero-knowledge proof against public inputs.
    /// @param proof The serialized proof bytes. Opaque at this interface.
    /// @param publicInputs The canonical-encoded public inputs.
    /// @return valid True iff the proof is cryptographically valid against
    ///               the public inputs under this verifier's proving system.
    function verify(bytes calldata proof, bytes calldata publicInputs)
        external
        view
        returns (bool valid);

    /// @notice A short string identifying the proving system, for logging
    ///         and auditor inspection. The mock returns "mock"; production
    ///         verifiers return "groth16-bn254", "plonk-bn254", etc.
    function verifierId() external pure returns (string memory);
}
