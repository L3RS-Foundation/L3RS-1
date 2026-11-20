# L3RS-1 Profile F reference contracts (Solidity)

Reference implementation of L3RS-1 v1.0.0 **Profile F — Hybrid Public-Private Architecture** (§17.7), conformance class CROSSCHAIN (§11.2), with cross-chain verification deferred.

This package publishes four contracts that the standard describes and that the repository did not previously contain:

| Contract | Standard reference | Purpose |
| --- | --- | --- |
| `IdentityAttestation` | §3 | Identity records signed by registered Verification Authorities; governance-quorum revocation; selective-disclosure presentations |
| `ComplianceModule` | §4 | The nine rule types of §4.4, canonical compliance hash (§13.12), quorum-gated version changes |
| `PolicyRegistry` | §5, §13.9 | Versioned binding of a policy identifier to a compliance module; quorum-gated amendment and retirement |
| `L3RS1Asset` | §2, §12 | The §2.4 state machine, the seven-step §2.6 transfer pipeline, the legal mirror, the replay registry |

Shared libraries: `SignatureVerification` (EIP-712 governance quorum), `SelectiveDisclosure` (Merkle-proof attribute disclosure), `Sha3` (SHA-3-256 per NIST FIPS 202), `ReasonCodes`.

It sits beside [`packages/solidity`](../solidity), the minimal EVM Profile A contract, which is unchanged.

## Status

**Pre-audit reference implementation. Not for production use.**

The code has passed its own test suite and static analysis and has had an external scoping review. It has not completed an independent security audit. The formal-verification specifications in `DESIGN.md` §13.2 are written but have not been executed.

### Known limitations

Each item below must be closed before any deployment that carries real assets.

1. **Zero-knowledge verifier is a mock.** `MockZKVerifier` accepts any proof. A real verifier is installed through the governance-quorum `setZKVerifier` call. See `DESIGN.md` §5b.
2. **Extended rules are not evaluated on each transfer.** `INVESTOR_CLASSIFICATION` and `HOLDING_PERIOD` are implemented in `ComplianceModule.evaluateWithDisclosure` and unit-tested, but the asset's transfer pipeline calls the basic `evaluate` only. See `DESIGN.md` §5c.
3. **The identity hash is not checked on-chain.** The Verification Authority supplies the `HID` inside the attestation it signs. Its construction under §3.4 (`H(PII ‖ salt ‖ domain)`) is the authority's responsibility; the contract cannot verify it. `DESIGN.md` §5a records the earlier placeholder and the reasoning.
4. **Legal-authority signature check is a placeholder.** `L3RS1Asset.verifyLegalAuthoritySignature` does not perform signature recovery. See `DESIGN.md` §9, item 2.
5. **Asset type is implicit.** The contract assumes regulated-security semantics and does not expose `Asset_Type` as a field (§2.1, §2.3). See `DESIGN.md` §9, item 17.
6. **Cross-chain verification is deferred.** The certificate and metadata objects are built; verification by a bridge consumer is outside this package.
7. **SHA-3-256 is computed in Solidity.** The EVM exposes Keccak-256, not SHA-3-256, so the compliance hash is costly in gas. It is not on a transfer path. See `DESIGN.md` §3.

## Build and test

Requires the [Foundry](https://book.getfoundry.sh/getting-started/installation) toolchain. Dependencies are git submodules pinned in `foundry.lock`: `forge-std` v1.15.0 and OpenZeppelin Contracts v5.6.1.

```
git submodule update --init --recursive
cd packages/solidity-profile-f
forge build
forge test
```

Solidity 0.8.26, `evm_version = "cancun"`, optimizer at 200 runs. A full test run takes a few minutes: fuzz tests run 1,024 times each, and invariant campaigns run 256 times at depth 64.

```
forge test --match-path "test/theorems/*"      # the seven L3RS-1 theorems (§15)
forge test --match-path "test/invariants/*"    # invariants and handler campaigns
forge test --match-path "test/scenario/*"      # end-to-end scenario
forge test --match-path "test/unit/*"          # per-contract unit tests
```

## Documents

- [`DESIGN.md`](DESIGN.md) — architecture, deviations from the literal text of the standard, the signature and selective-disclosure designs, the pre-audit list, static-analysis triage, and the formal-verification specifications.
- [`spec/07-profile-f.md`](spec/07-profile-f.md) — the subset of L3RS-1 v1.0.0 that this package implements.
- [`spec/06-theorems.md`](spec/06-theorems.md) — the theorems and invariants, each mapped to its test.

`DESIGN.md` was written as a working record during development. It cites documents that are not part of this repository (a cryptographic specification, a deployment plan, raw analyzer output) and it keeps superseded sections for traceability. Where it and this README differ on current status, this README governs.

## Provenance

These contracts were developed by the author of L3RS-1 as "Phase One" of the T3RRA stack and are contributed to this repository as its Profile F reference implementation. The EIP-712 domain names in the contracts keep the `T3RRA-` prefix; changing them would change the signed messages and the compiled code.

The source is the development repository at tag `v1.0.2-audit-candidate` plus two later commits that add the deployment script, its tests and documentation. Contract code under `src/` is unchanged from that tag except for the license identifier and comments; the compiled bytecode is identical.

## License

Apache License 2.0, as for the rest of this repository. See [`LICENSE`](../../LICENSE).
