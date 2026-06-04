# L3RS-1 SDK — Reference Implementation

**Layer-3 Regulated Asset Standard — reference implementation of [L3RS-1 v1.0.0](https://l3rs.foundation), mandated by §11.6 of the standard.**

> **Status: pre-release.** Conformance is asserted per capability and per language in the tables below, not as a single blanket class. The *target* conformance class is **CROSSCHAIN**; self-asserted conformance is pending full cross-language test-vector parity (see [Conformance status](#conformance-status-by-capability)). This build is not yet tagged as a release.

All implementations are pure deterministic libraries — no transport, no ledger coupling, ledger-agnostic by design.

## Languages

| Package | Language | Target Environment |
|---|---|---|
| `packages/typescript` | TypeScript 5 | Web3, dApps, tooling, dashboards |
| `packages/python` | Python 3.11+ | Analytics, compliance pipelines, reporting |
| `packages/go` | Go 1.22+ | Institutional backends, validators, cloud |
| `packages/rust` | Rust 1.77+ | High-perf nodes, WASM, cryptographic core |
| `packages/java` | Java 21+ | Enterprise banking, Spring Boot, legacy infra |
| `packages/solidity` | Solidity 0.8.24 | EVM on-chain enforcement (Profile A, §17.2) |

## Implementation status by language

| Package | Core modules | Fail-closed §4 compliance engine | Notes |
|---|---|---|---|
| `packages/go` | Present | **Implemented & tested** | reference implementation of the compliance engine |
| `packages/solidity` | Present | **Implemented & tested** | on-chain identity + compliance enforced before mutation (§17.8) |
| `packages/typescript` | Present | In progress | being aligned to the Go reference engine |
| `packages/python` | Present | In progress | ZK verifier deferred (fail-closed) |
| `packages/rust` | Present | In progress | |
| `packages/java` | Present | In progress | |

Until every package mirrors the Go engine, the cross-language parity requirement (see [Test Vectors](#test-vectors)) is not yet met.

## Conformance status by capability

| Capability | Spec | Status |
|---|---|---|
| Formal asset model — state machine, Asset_ID | §2 | Enforced & tested |
| Identity status (valid / expired / revoked) | §3.6 | Enforced & tested |
| Identity validation before settlement | §3.11, I₃ | Enforced (Solidity); libraries expose it for the host |
| Zero-knowledge proof verification | §3.8, §3.13 | **Deferred** — interface level only; proofs evaluate to BLOCK |
| Compliance as a total decision function; all nine §4.4 categories; first-blocking; fail-closed | §4.3–4.6, I₂ | Enforced & tested (Go, Solidity); other languages in progress |
| Sanctions screening / AML trigger / redemption eligibility | §4.4, §10.15 | **Attested-oracle** — deployer supplies a hash-anchored, versioned feed; unknown/stale/mismatched state blocks |
| Governance quorum (⌈2/3 × N⌉) | §5.5 | Enforced & tested |
| Fee integrity (allocations sum to 10000 bps) | §6.12 | Enforced & tested |
| Reserve interface / redemption logic | §7 | Types defined; attestation deployer-supplied |
| Cross-chain certificate (CID) construction | §8, I₁₁ | Enforced & tested (deterministic) |
| Settlement finality — TxID, replay protection | §9.6 | Enforced & tested |
| Canonical serialization | §13 | Enforced & tested |

## Compliance execution location (§17.8)

Per §17.8, which applies regardless of profile — *compliance MUST execute prior to state mutation; identity validation MUST execute prior to settlement*:

- **Solidity (Profile A):** `transfer()` evaluates identity and compliance and reverts before any balance or nonce mutation. External rule data is consulted through a view (`IComplianceOracle`) hook; an unset hook blocks (fail-closed).
- **Pure libraries:** expose `EvaluateCompliance` for the host to invoke ahead of settlement. The host is responsible for calling it before mutating ledger state.

## Architecture

Every implementation is a **pure function library**. No I/O, no transport, no network. Implementers integrate this library into their chosen ledger platform (EVM, Hyperledger Fabric, Corda, Cosmos, sovereign chain, or private system).

```
┌─────────────────────────────────────────┐
│         Your ledger / platform          │
├─────────────────────────────────────────┤
│         L3RS-1 SDK (this repo)          │
│  types · state machine · compliance     │
│  identity · governance · settlement     │
│  cross-chain CID · canonical hashing    │
├─────────────────────────────────────────┤
│   Crypto primitives (SHA-256, EdDSA)    │
└─────────────────────────────────────────┘
```

## Test Vectors

`/test-vectors/` contains canonical JSON test vectors per §11.5, covering:
- Asset_ID construction
- State transition validity
- Compliance rule evaluation (each §4.4 category, including fail-closed paths)
- Cross-chain CID verification
- Settlement TxID replay protection

All six language implementations are **required** to produce identical outputs for identical inputs. Parity is being re-established as the compliance engine is propagated across languages; vectors are being regenerated to cover every rule category and every fail-closed path.

## Known limitations

- **ZK verification is deferred.** It is required at the interface level only (§3.13); a production verifier is not shipped. Proofs currently evaluate to BLOCK (fail-closed), consistent with §3.8.
- **Attested-oracle categories.** Sanctions screening, AML triggers, and redemption eligibility require a deployer-supplied, hash-anchored, versioned data feed (§10.15). Absent, stale, or mismatched attestations block.
- **Cross-language parity is in progress.** The fail-closed compliance engine is currently implemented in Go (reference) and enforced on-chain in Solidity; TypeScript, Python, Rust, and Java are being aligned.

## License

Open Standard – Royalty Free Implementation (per L3RS-1 §1 metadata)
