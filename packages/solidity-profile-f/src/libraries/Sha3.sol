// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: NIST FIPS 202 — SHA-3 Standard: Permutation-Based Hash and Extendable-Output
//         Functions. Algorithm identifier SHA3-256 with rate = 1088 bits (136 bytes) and
//         capacity = 512 bits. Implementation of the Keccak-f[1600] permutation follows
//         FIPS 202 §3.2. Domain separation byte 0x06 is the SHA-3 suffix per §B.2.
//
// The Ethereum Virtual Machine exposes Keccak-256 as a precompile (opcode SHA3 / keccak256).
// It does not expose SHA-3-256. Keccak-256 and SHA-3-256 use the same Keccak-f[1600]
// permutation but differ in the padding suffix (0x01 vs 0x06). Phase One requires SHA-3-256
// per Cryptographic Specification §1.2 and §14, so this library computes it directly. See
// DESIGN.md §3 for the discussion of this on-chain cost and the conflict-4 resolution that
// chose Solidity emulation over an off-chain hash.

/// @title Sha3
/// @notice SHA-3-256 implementation per NIST FIPS 202.
/// @dev Test vectors from FIPS 202 appendix A.3 are exercised in
///      test/unit/Sha3.t.sol (empty string, "abc", 1 000 000 copies of "a").
library Sha3 {
    uint256 private constant RATE_BYTES = 136; // 17 lanes of 64 bits each

    // Rho rotation offsets, packed one byte per lane in index order i = x + 5*y.
    // Bytes 0..24 (MSB..lane-24) hold r[0..24]; bytes 25..31 are zero padding.
    // The uint256 literal is exactly 32 bytes (64 hex chars); the extraction
    // formula `(RHO_OFFSETS >> (8 * (31 - i))) & 0xFF` maps i = 0 to the MSB
    // and i = 24 to byte 24. Source: FIPS 202 §3.2.2 Table 2, giving
    // r = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15,
    //      21, 8, 18, 2, 61, 56, 14].
    //
    // external scoping-review finding (see DESIGN.md §13.3). The prior
    // literal was 33 bytes: a leading 0x00 plus the 25 offsets plus 7 trailing
    // zeros plus one stray trailing 0x00. Solidity stripped the leading zero
    // when parsing the hex literal as a uint256, shifting every offset left by
    // one byte position, so _rhoOffset(i) returned r[i+1] instead of r[i].
    // Every rho rotation was off by one table index. The fix removes the
    // stray trailing 0x00 so the literal is a clean 32 bytes and the MSB byte
    // is r[0] = 0x00 as intended.
    uint256 private constant RHO_OFFSETS =
        0x00013E1C1B242C063714030A2B1927292D0F150812023D380E00000000000000;

    /// @notice Compute SHA-3-256 of the input.
    /// @dev Implements the sponge construction: absorb rate-sized blocks with Keccak-f[1600]
    ///      permutations between blocks, pad the final partial block per FIPS 202 §B.2 with
    ///      suffix byte 0x06 and final bit 0x80, then squeeze 256 bits of state.
    function sha3_256(bytes memory data) internal pure returns (bytes32) {
        uint64[25] memory state;
        uint256 len = data.length;
        uint256 offset = 0;

        // Absorb every full rate-sized block.
        while (len - offset >= RATE_BYTES) {
            _absorbBlock(state, data, offset, RATE_BYTES);
            _keccakF1600(state);
            offset += RATE_BYTES;
        }

        // Pad the final block with the SHA-3 suffix 0x06 ‖ zeros ‖ 0x80.
        // Per FIPS 202 §B.2: a single byte 0x06 at position |M|, then zeros, then 0x80 at
        // the last byte of the rate. If 0x06 and 0x80 collide in the same byte, combine
        // them as 0x86.
        uint256 remaining = len - offset;
        bytes memory finalBlock = new bytes(RATE_BYTES);
        for (uint256 i = 0; i < remaining; i++) {
            finalBlock[i] = data[offset + i];
        }
        finalBlock[remaining] = 0x06;
        finalBlock[RATE_BYTES - 1] = bytes1(uint8(finalBlock[RATE_BYTES - 1]) | 0x80);

        _absorbBlock(state, finalBlock, 0, RATE_BYTES);
        _keccakF1600(state);

        // Squeeze the first 256 bits (four lanes, little-endian per FIPS 202 §6.1).
        bytes memory output = new bytes(32);
        for (uint256 i = 0; i < 4; i++) {
            uint64 lane = state[i];
            for (uint256 j = 0; j < 8; j++) {
                output[i * 8 + j] = bytes1(uint8(lane >> (8 * j)));
            }
        }

        bytes32 result;
        assembly {
            result := mload(add(output, 0x20))
        }
        return result;
    }

    /// @dev Absorb a block: XOR each 8-byte lane (little-endian) into the state.
    function _absorbBlock(uint64[25] memory state, bytes memory block_, uint256 offset, uint256 size)
        private
        pure
    {
        unchecked {
            for (uint256 i = 0; i < size; i += 8) {
                uint64 lane = 0;
                for (uint256 j = 0; j < 8; j++) {
                    lane |= uint64(uint8(block_[offset + i + j])) << uint64(8 * j);
                }
                state[i / 8] ^= lane;
            }
        }
    }

    /// @dev Keccak-f[1600] permutation per FIPS 202 §3.2. 24 rounds, each applying
    ///      theta, rho, pi, chi, iota.
    function _keccakF1600(uint64[25] memory state) private pure {
        uint64[24] memory rc = [
            uint64(0x0000000000000001),
            uint64(0x0000000000008082),
            uint64(0x800000000000808A),
            uint64(0x8000000080008000),
            uint64(0x000000000000808B),
            uint64(0x0000000080000001),
            uint64(0x8000000080008081),
            uint64(0x8000000000008009),
            uint64(0x000000000000008A),
            uint64(0x0000000000000088),
            uint64(0x0000000080008009),
            uint64(0x000000008000000A),
            uint64(0x000000008000808B),
            uint64(0x800000000000008B),
            uint64(0x8000000000008089),
            uint64(0x8000000000008003),
            uint64(0x8000000000008002),
            uint64(0x8000000000000080),
            uint64(0x000000000000800A),
            uint64(0x800000008000000A),
            uint64(0x8000000080008081),
            uint64(0x8000000000008080),
            uint64(0x0000000080000001),
            uint64(0x8000000080008008)
        ];

        unchecked {
            for (uint256 r = 0; r < 24; r++) {
                // --- Theta: column parity mixing per FIPS 202 §3.2.1 ---
                uint64[5] memory C;
                for (uint256 x = 0; x < 5; x++) {
                    C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
                }
                uint64[5] memory D;
                for (uint256 x = 0; x < 5; x++) {
                    D[x] = C[(x + 4) % 5] ^ _rotl64(C[(x + 1) % 5], 1);
                }
                for (uint256 y = 0; y < 5; y++) {
                    for (uint256 x = 0; x < 5; x++) {
                        state[x + 5 * y] ^= D[x];
                    }
                }

                // --- Rho and pi combined per FIPS 202 §3.2.2 and §3.2.3 ---
                uint64[25] memory B;
                for (uint256 y = 0; y < 5; y++) {
                    for (uint256 x = 0; x < 5; x++) {
                        uint256 idx = x + 5 * y;
                        uint256 target = y + 5 * ((2 * x + 3 * y) % 5);
                        B[target] = _rotl64(state[idx], _rhoOffset(idx));
                    }
                }

                // --- Chi: nonlinear mixing per FIPS 202 §3.2.4 ---
                for (uint256 y = 0; y < 5; y++) {
                    for (uint256 x = 0; x < 5; x++) {
                        state[x + 5 * y] = B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y]);
                    }
                }

                // --- Iota: round-constant XOR per FIPS 202 §3.2.5 ---
                state[0] ^= rc[r];
            }
        }
    }

    /// @dev 64-bit left rotation. n is already in [0, 63] for every call site because the
    ///      rho offsets are bounded by 62.
    function _rotl64(uint64 x, uint256 n) private pure returns (uint64) {
        if (n == 0) return x;
        unchecked {
            uint256 left = (uint256(x) << n) & 0xFFFFFFFFFFFFFFFF;
            uint256 right = uint256(x) >> (64 - n);
            return uint64(left | right);
        }
    }

    /// @dev Fetch the rho rotation offset for lane index i, i ∈ [0, 24]. The byte order is
    ///      MSB-first: i = 0 is the high byte of RHO_OFFSETS.
    function _rhoOffset(uint256 i) private pure returns (uint256) {
        return (RHO_OFFSETS >> (8 * (31 - i))) & 0xFF;
    }
}
