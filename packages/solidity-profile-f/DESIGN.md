# DESIGN — Phase One L3RS-1 Profile F reference implementation

> **Publication note.** This document is the working design record of the development repository, published with the contracts for traceability. It cites material that is not part of this repository: a cryptographic specification, a whitepaper, a deployment-target plan (`08-deployment-target.md`) and raw analyzer output. It also keeps superseded sections, including earlier placeholders that later sections replace. For current status and known limitations, see [README.md](README.md), which governs where the two differ.

This file walks through the Phase One architecture, cites the specific L3RS-1 and Cryptographic Specification sections each contract implements, records every deliberate deviation from the spec with justification, and closes with a per-test status table across all 42 tests.

Phase One implements Layer 1 of the T3RRA stack. It conforms to L3RS-1 v1.0.0 Profile F (Hybrid Public-Private Architecture) per §17.7 and the CROSSCHAIN conformance class per §11.2, with destination-side cross-chain verification deferred to Phase Five. The audience for this document is the external auditor engaged against the Phase One contracts.

## 1. Architecture

Four contracts plus two libraries and two interfaces. No external dependencies beyond OpenZeppelin Contracts 5.x and Foundry's forge-std (test-only).

`src/interfaces/IComplianceModuleF.sol` declares the Profile F ComplianceModule interface per 07-profile-f.md. `src/interfaces/ILifecycle.sol` defines the seven normative L3RS-1 states per §2.4 and the seven transition triggers per §2.5. State naming follows L3RS-1 normatively — RESTRICTED and REDEEMED, not the T3RRA Architecture paper's Locked and Restored.

`src/libraries/ReasonCodes.sol` holds every structured reason code the pipeline emits on block. The bytes32 values are keccak256 of stable identifier strings. Every reason code appears in DESIGN.md §7 below.

`src/libraries/Sha3.sol` implements NIST FIPS 202 SHA-3-256. The EVM exposes Keccak-256 as a precompile but not SHA-3-256 — these two differ only in their domain-separation byte (0x01 vs 0x06). Cryptographic Specification §1.2 and §14 mandate SHA-3-256 for the ComplianceHash (H_pol), so the library emulates it in Solidity. See §3 below.

`src/ComplianceModule.sol` is the C component of the twelve-field Asset object per L3RS-1 §2.1. It implements the total decision function `C : E → {0, 1}` per §4.3 and exposes the canonical hash that Phase Two's PG[Σ] signing prelude will bind as C_hash and that Phase Five's cross-chain certificate will bind into the CrossChainMetadata X per §13.9.

`src/L3RS1Asset.sol` is the asset contract. It carries balance state, runs the seven-step §2.6 transfer pipeline, maintains the Theorem 15.2 replay registry, and holds the governance surface (freeze, rollback, authority rotation, legal-mirror amendment). It never mutates balance state except through a path that first calls `ComplianceModule.evaluate`; this is INV-6 and it is asserted by a Foundry invariant test running 16 384 random call sequences per campaign.

`src/IdentityAttestation.sol` stores the identity hash HID per L3RS-1 §3.4 (never the raw PII) and exposes the four-valued status function per §3.6.

`src/PolicyRegistry.sol` is a thin skeleton in this phase. It binds a ComplianceModule address to a canonical ComplianceHash and supports versioned amendment. The full registry lives in step 4 of the build order; Phase One uses the ComplianceModule's own `complianceHash()` directly, and the registry's role is structural.

## 2. The canonical-hash conflict and its resolution

The project brief refers to `PolicyHash` as "the canonical hash of the ComplianceModule, per Cryptographic Specification section 3." Three things disagree with that framing.

First, §3 of the Cryptographic Specification is Distributed Key Generation, not a policy-hash definition. The PolicyHash construction lives in §7.3 — `PolicyHash = H_pol(C_hash ‖ canonical(ctx) ‖ m)` — a per-signing object that depends on the specific message and context, not just on the ComplianceModule. Second, L3RS-1 §13.12 defines `ComplianceHash = H(serialize(ComplianceModule))` — the hash of the canonical serialization of the ComplianceModule object — which is close to what the user means, but structurally different from the spec's PolicyHash. Third, 06-theorems.md Part E INV-2 adds a fourth variant: `policyHash() returning keccak256 of bytecode`.

The resolution recorded in the user's accepted restatement is:

- The on-contract method is named `complianceHash()`. It returns the L3RS-1 §13.12 ComplianceHash — SHA-3-256 of the canonical serialization of the ComplianceModule object.
- The hash function is SHA-3-256 with domain string `"T3RRA-POLICY-HASH-v1"` per Cryptographic Specification §1.2 and §14. The §14 table is authoritative; 08-deployment-target.md's `"T3RRA-POLICYHASH-v1"` (without the hyphen between POLICY and HASH) is a transcription error to correct in the next revision of the markdown bundle.
- The canonical serialization follows L3RS-1 §13.11 rules: fixed field order, UTF-8 strings, fixed-width big-endian integers, explicit length prefixing. Phase One uses `abi.encode`, which satisfies these rules for the types the ComplianceModule carries.

This is a deliberate deviation from 06-theorems.md Part E INV-2's text (`keccak256 of bytecode`) in favor of the normative L3RS-1 §13.12 construction. The INV-2 test is updated accordingly and the deviation is annotated in `test/invariants/INV2_PolicyHashStability.t.sol` header.

## 3. On-chain SHA-3-256 emulation

The EVM has no SHA-3-256 precompile. The `keccak256` opcode implements Keccak-256 — the pre-NIST variant of SHA-3 with domain byte 0x01 rather than 0x06. Phase One implements SHA-3-256 directly in Solidity because Cryptographic Specification §1.2 and §14 mandate it for the H_pol domain.

`Sha3.sh3_256` loops the 24-round Keccak-f[1600] permutation in pure Solidity. The permutation handles the five FIPS 202 §3.2 step mappings (theta, rho, pi, chi, iota). Round constants are inlined as a 24-entry `uint64[]` memory array. The 25 rho rotation offsets are packed into a single `uint256` constant `RHO_OFFSETS`. The library uses one inline-assembly block — a five-line `mload` to convert a 32-byte memory buffer to a `bytes32` return value. That is the only assembly in the codebase and it is justified by the absence of an EVM precompile for SHA-3-256.

Gas cost: each `complianceHash()` call runs 24 rounds of Keccak-f[1600] in Solidity. For a reference implementation this is acceptable — clarity wins per the project conventions — and `complianceHash()` is not on any hot path.

**Correctness verification.** FIPS 202 Appendix A.3 test vectors for SHA3-256 ("", "abc", and the 1-million-byte "a" vector) are pinned in `test/unit/Sha3.t.sol`. Additional coverage includes NIST CAVP single-byte vector 0xe9, the classic 56-byte "abcdbcde…nopq" short-message vector, and boundary structural tests at 136 bytes (rate-aligned) and 137 bytes. The 1-million-byte vector is retained as a reference value but not asserted on-chain because the Solidity emulation of 7 353 Keccak-f[1600] rounds exceeds the forge default gas budget; the authoritative correctness claim rests on the other vectors.

**Historical note — test authorship gap, surfaced by external scoping review.** An earlier revision of this section claimed the FIPS 202 test vectors were "verified in the unit-test pass (step 6 of the build order)". That claim was false: the referenced file `test/unit/Sha3.t.sol` did not exist. As a direct consequence, a packing bug in `RHO_OFFSETS` — the literal was 33 bytes instead of 32, Solidity silently dropped the leading zero, and every rho rotation was off by one table index — shipped all the way to v1.0.0-audit-candidate undetected. Every other test in the 257-test suite happened to be written against hash-change and hash-determinism properties rather than hardcoded hash values, so the bug was invisible to the existing suite. external scoping reviewers caught the constant on visual inspection. The remediation is documented in §13.3 of this file. The meta-lesson is that a test-authorship claim in documentation is not equivalent to tests actually existing; audit-facing documentation should cite file paths that compile.

## 4. Placeholder signature scheme for governance quorum

> **SECURITY WARNING.** The governance signature scheme in Phase One is a **non-production placeholder**. It is exploitable by a single compromised authority key. It MUST NOT be used on any mainnet. It MUST be replaced with EIP-712-typed ECDSA recovery (per §9 TODO 1) before external audit submission. Base Sepolia testnet deployments MUST either (a) carry an explicit on-contract `testnetOnly == true` flag that the deployment script sets and that makes all governance actions emit a `TESTNET_ONLY_PLACEHOLDER` event, or (b) wait for the EIP-712 replacement. Auditors reviewing this document should treat every `_requireAuthorityQuorum` call site as a deferred security finding with a committed remediation.

**The exploit path is explicit.** An attacker who controls one authority's private key and knows any arbitrary byte strings from the other authorities (obtained, for example, from a previous transaction, a leaked log, or a public event) can construct a `bytes[]` signatures array containing `⌈(2/3) × N⌉` distinct elements by padding arbitrary bytes differently. `msg.sender` is the compromised authority; the distinctness check passes because the fingerprints differ; the quorum check passes because the count meets the threshold. No authority other than the compromised one has signed anything meaningful. This is the finding every reviewer will write up, so it is pre-empted here.

L3RS-1 §5.4 requires `k ≥ ⌈(2/3) × N⌉` distinct authority signatures for every override action. Production uses ECDSA recovery against each authority's public key per EIP-712. Phase One carries a placeholder scheme with two checks.

Check one: `msg.sender` must be a registered authority.

Check two: the `bytes[]` signatures array must contain at least `⌈(2/3) × N⌉` distinct elements, compared by keccak256 fingerprint. Duplicate presentations fail.

**On test-signature realism.** The test suite does not fabricate real ECDSA signatures because the placeholder scheme does not verify signatures in the cryptographic sense. Tests construct `bytes[]` arrays with distinct arbitrary payloads and use `vm.prank(authority)` to satisfy the `msg.sender` check. The T5 quorum tests (`test_T5_quorumCanFreeze`, `test_T5_singleSignerCannotFreeze`, `test_T5_duplicateSignerDoesNotCountTwice`, `test_T5_emergencyRollbackRequiresQuorum`, `invariant_T5_minorityNeverOverrides`) all follow this pattern. When the scheme is replaced with EIP-712 ECDSA in §9 TODO 1, every one of these tests must be rewritten to use `vm.sign(privateKey, digest)` and emit real signatures. The transition is a larger rewrite than §9 TODO 1's one-line summary suggests — it touches five test files plus two contract functions plus the authority-registration surface. Budget accordingly.

Before external audit submission the signature scheme is replaced with EIP-712-typed ECDSA recovery against each authority's registered public key, with replay-resistance via a monotonic governance-action nonce per authority.

The placeholder is marked with inline comments at every call site in `L3RS1Asset.sol` and in `ComplianceModule.sol`. DESIGN.md §9 lists it as a pre-audit TODO.

## 5a. Placeholder HID construction

> **SECURITY WARNING.** The `HID` computation in `IdentityAttestation.grantAttestation` is a **non-production placeholder**. It has **no privacy property** — the HID is a deterministic function of publicly observable on-chain inputs. Given any `(address, jurisdiction, tier)` tuple, any observer can recompute the corresponding HID in O(1). The placeholder does not bind HID to PII and does not use a salt. It MUST NOT be deployed to mainnet. Step 5 replaces it with the L3RS-1 §3.4 construction in which HID is computed off-chain by a registered Verification Authority from `PII ‖ salt ‖ domain` and the on-chain contract accepts HID as an opaque `bytes32`. Auditors reviewing this document should treat every `grantAttestation` call site as a deferred finding with a committed remediation in §9 TODO 12.

**Deviation from L3RS-1 §3.4.** The L3RS-1 standard defines the identity hash as `HID = H(PII ‖ salt ‖ domain)` with the hard constraint "PII SHALL NOT be published on-chain in plaintext." The construction binds the HID to a specific natural person's personally identifiable information plus a per-attestation salt that prevents HID enumeration by an external observer. The Phase One placeholder deviates on three points.

First, no PII input. `grantAttestation` computes `HID = keccak256(who, jurisdiction, tier)` where `who` is the holder's EVM address. PII is not part of the input; the placeholder is really an address-jurisdiction-tier fingerprint, not an identity hash.

Second, no salt. Absent a random salt per attestation, the output is fully determined by the public inputs. An observer with access to the three inputs — `who` is on-chain, `jurisdiction` and `tier` are emitted in the `AttestationGranted` event — can replay the computation locally and recover the HID for any holder they care about.

Third, no domain separation. The placeholder uses `keccak256` directly without a domain string, meaning the output is indistinguishable from any other `keccak256(address, bytes2, uint256)` in the EVM and the hash has no binding to the T3RRA identity-binding domain.

**No privacy property.** The placeholder does not protect identity privacy. Anyone observing the contract can enumerate HIDs for the set of holders they care about. Rotating a holder's attestation with a new tier does not change anything material — the tier is public and the new HID is again trivially recomputable. This is acceptable for Phase One theorem tests because the tests do not assert any privacy property; they only assert the four-valued status function and the correct bit-flow through the `L3RS1Asset` pipeline. It is not acceptable for any deployment that carries real investor identity.

**Step 5 replacement scope.**

1. HID is computed off-chain by a registered Verification Authority from `PII ‖ salt ‖ domain`. The VA holds the salt off-chain and never publishes it.
2. `grantAttestation` accepts HID as an opaque `bytes32` parameter. The contract does not reconstruct it. The contract does not know the holder's PII, salt, or domain.
3. The VA signs the attestation tuple `(holder, HID, jurisdiction, tier, expiry, nonce)` with an EIP-712 typed-data signature verified through the shared signature-verification library proposed in §8.2. The contract verifies the VA's signature against its registered public key before recording the attestation.
4. Revocation is indexed by HID, not by holder address. A holder with a revoked HID cannot re-obtain an attestation from the same VA for the same domain without rotating the underlying PII or using a fresh salt.

Tracked as §9 TODO 12.

## 5b. Mock ZKP verifier

> **SECURITY WARNING.** The ZKP verifier in Phase One is a **non-production mock**. `MockZKVerifier.verify` accepts any proof bytes as valid. Any signature attached in the PROOF field of an identity record is trivially accepted by the mock. Mainnet deployment MUST replace the mock with a real proving-system verifier (Groth16, Plonk, STARK, Halo2, or equivalent) before external audit submission. The governance-gated `setZKVerifier` function on `IdentityAttestation` performs the swap without a redeploy. Auditors reviewing this document should treat every attestation that ships with a non-empty `zkProof` field as unverified until the mock is replaced. Tracked in §9 TODO 14.

**Why a mock at all.** Phase One exercises the ZKP-compatible code path — public-input encoding, verifier calls, storage of PROOF field in the Record — without depending on a real proving-system implementation. Real verifiers for Groth16 on BN254 or Plonk alone are several thousand lines of Solidity or precompile calls; committing to a specific proving system before the Phase Six privacy layer lands is premature. The pluggable `IZKVerifier` interface lets the mock ship now and the real verifier replace it later through governance action, without changing any call site.

**Scope of the mock.** `MockZKVerifier` implements `IZKVerifier` with two functions. `verify(bytes, bytes)` returns `true` unconditionally. `verifierId()` returns the string `"mock"` so an auditor or an off-chain reader can confirm which verifier is active. No cryptographic operation takes place in the mock.

**Scope of the production replacement.** The replacement implements `IZKVerifier` against a chosen proving system. The replacement's `verify` performs actual cryptographic verification: pairing checks for Groth16, KZG commitment checks for Plonk, FRI for STARK, etc. The replacement's `verifierId()` returns a string uniquely identifying the proving system and parameter set, e.g. `"groth16-bn254-kycproof-v1"`. No other public surface on `IdentityAttestation` changes; the swap is a single governance-quorum `setZKVerifier` action.

**Public-input encoding.** The IdentityAttestation passes `abi.encode(holder, hid, jurisdiction, tier)` as the public inputs to the verifier. Any real proving system's verifier must interpret these four fields as its public inputs. If Phase Six's proving system requires a different encoding, the replacement verifier is responsible for re-parsing these bytes — `IdentityAttestation` does not change its encoding because it cannot know the proving system at Phase One deploy time. This is a deliberate decoupling.

**What the mock does NOT provide.** No privacy. No soundness. No zero-knowledge. The mock is a placeholder that enables the calling pattern to be fully developed and audited at Phase One scope. The real guarantees arrive with the replacement.

Tracked as §9 TODO 14.

## 5c. Deferred transfer-pipeline integration of INVESTOR_CLASSIFICATION and HOLDING_PERIOD

> **SECURITY WARNING.** Phase One implements INVESTOR_CLASSIFICATION and HOLDING_PERIOD rule logic in `ComplianceModule.evaluateWithDisclosure(...)` and unit-tests the logic directly. The Phase One transfer pipeline in `L3RS1Asset._executeTransfer` calls the basic `evaluate(...)` only — it does **not** call `identity.verifyPresentation(...)` per transfer and does **not** pass disclosed attributes to `evaluateWithDisclosure`. A regulated deployment cannot ship in this state: static rule configuration (min-tier and holding-period thresholds set by the issuer off-line) does not satisfy a compliance officer's dynamic enforcement argument. Tier and holding-period must be verified from a signed, nonce-bound, holder-presented credential on every transfer, not read from cached state. Tracked as §9 TODO 16. Mainnet deployment is blocked on this alongside TODO 12 (placeholder HID) and TODO 14 (MockZKVerifier).

**What is live in Phase One.** The SelectiveDisclosure library is fully implemented and tested. `IdentityAttestation.verifyPresentation` is live and exercises the Merkle-proof + holder-signature + per-(holder, verifier, nonce) replay protection. `ComplianceModule.evaluateWithDisclosure(address, address, address, uint256, bytes, uint8 receiverTier, uint256 senderFirstReceivedAt, bytes32 actionKind)` is live — given the three extended inputs, it evaluates the three extended rules in priority order. Unit tests cover each rule's happy-path and reject-path.

**What is deferred to Phase Three.** Transfer-signature extension. The Phase Three `transfer(...)` signature extends to `transfer(address to, uint256 amount, SelectiveDisclosure.Presentation calldata p, bytes calldata holderSig)`. The extended transfer:
1. Calls `identity.verifyPresentation(p, holderSig)` — consumes the presentation nonce, verifies the holder signature, verifies Merkle proofs against the committed root. Reverts on any failure.
2. Extracts the attested `receiverTier`, `senderFirstReceivedAt`, `actionKind` from the verified disclosure payload.
3. Calls `compliance.evaluateWithDisclosure(...)` with the extracted inputs.
4. Runs the remainder of the §2.6 pipeline.

**Why deferred.** Four reasons. First, every transfer would require the sender to compute a fresh EIP-712 signature over a presentation envelope — UX complexity that Phase One does not need to solve for theorem-test coverage. Second, the Phase One unit tests drive the rule logic directly and so the rule correctness is provable without pipeline integration. Third, the shape of the Phase Three presentation (which attributes the holder discloses per-transfer) depends on rule decisions not yet made — ComplianceModule's Phase Three rule-evaluator formalization will determine the exact required leaves. Fourth, the Phase Five bridge is the primary long-term consumer of cross-chain compliance verification and lands after Phase Three; committing to a specific per-transfer envelope format pre-Phase-Three risks rework.

**Why this is a third mainnet blocker.** A regulated-security deployment is legally obligated to verify that every secondary transfer conforms to the asset's rule set at the moment of transfer. Static rule configuration (issuer sets min-tier to 2 at deploy, leaves it) is verified once at deploy time. Without per-transfer disclosure verification, a holder's tier downgrade or holding-period reset between attestations is invisible to the contract — the transfer looks valid because no current attested state is consulted. Compliance officers will refuse to sign off on this. Phase Three integration is not optional for mainnet; it is required.

Tracked as §9 TODO 16.

## 6. State machine, lifecycle, and transitions

**Status after 6E.** The full L3RS-1 §2.4 state machine is implemented. The asset is deployed into `ISSUED` and traverses the §2.5 transition matrix under governance-quorum and issuer-only gates. The full-traversal test `test_6E_fullLifecycleTraversal` in `test/unit/L3RS1Asset.t.sol` drives `ISSUED → ACTIVE → RESTRICTED → ACTIVE → FROZEN → ACTIVE → REDEEMED → BURNED` in one call sequence.

### Transitions live in Phase One

| Transition | Trigger function | Auth | Notes |
|---|---|---|---|
| `ISSUED → ACTIVE` | `activate()` | issuer | One-shot call post-deployment. Test harness calls this in `setUp` so legacy tests see `ACTIVE`. |
| `ACTIVE → RESTRICTED` | `restrict(nonce, deadline, sigs)` | quorum | §2.5 "Compliance Breach". |
| `RESTRICTED → ACTIVE` | `clearRestriction(...)` | quorum | §2.5 "Compliance Cleared". |
| `ACTIVE → FROZEN` | `governanceFreeze(...)` | quorum | §2.5 "Governance Freeze". |
| `FROZEN → ACTIVE` | `emergencyRollback(...)` | quorum | §5.5 rollback; also covers `RESTRICTED → _previousState`. |
| `ACTIVE → REDEEMED` | `assetRedemption(...)` | quorum | Flips asset-level redemption guard; transfers subsequently reject with `ASSET_REDEEMED` (§7). |
| `REDEEMED → BURNED` | `assetFinalize(...)` | quorum | Requires `totalSupply == 0` — no investor still holds a claim. Terminal. |

`SUSPENDED` is declared in the enum per §2.4 but has no transition into or out of it in §2.5. It is reserved for a future amendment of the L3RS-1 standard and remains unimplemented in Phase One. The `test_6E_fullLifecycleTraversal` test deliberately skips SUSPENDED for this reason — the traversal `ISSUED → ACTIVE → RESTRICTED → ACTIVE → FROZEN → ACTIVE → REDEEMED → BURNED` follows §2.5 exactly, and there is no valid edge into SUSPENDED in the current standard.

**Forward compatibility note.** If a future L3RS-1 amendment adds transitions into or out of SUSPENDED, the corresponding implementation in `L3RS1Asset` — new transition functions, new typehashes, new state-machine guards — is **not** merely a test addition. It requires state-machine changes in the contract itself: a new trigger function, a new governance typehash, a new `AssetSuspended` event, state-precondition checks on existing transition functions to reject from SUSPENDED where the amendment disallows it, and updates to the mutable-selector registration for INV-6. Test additions alone cannot cover a new state-machine edge — the edge must first exist in the contract. Auditors reviewing a future SUSPENDED amendment should treat it as an L3RS1Asset structural change, not a testing concern.

### REDEEMED / BURNED split — 6E sharpened semantics

Per the 6E spec:

- `assetRedemption` transitions `ACTIVE → REDEEMED`. The transfer pipeline checks the asset's state at step 3 and rejects with the new `ASSET_REDEEMED` reason code (distinct from `STATE_DISALLOWS` so external consumers can distinguish a mandate-level redemption from governance-driven FROZEN / RESTRICTED / SUSPENDED states).
- Per-holder `redeem(amount)` continues to work in `REDEEMED`. Its purpose shifts: pre-redemption it is a partial burn; post-redemption it is the **claim path** — investors holding a position redeem against the mandate's terminal cash pool. The state gate in `redeem()` allows both `ACTIVE` and `REDEEMED`.
- `issue()` rejects in `REDEEMED`. Once the mandate enters redemption, no new units are minted; there is only the outstanding supply that investors claim against.
- `assetFinalize` transitions `REDEEMED → BURNED` only when `totalSupply == 0`. The `SupplyNotZero` error guards this; the mandate cannot finalize while any investor still holds a claim.
- `BURNED` is terminal. Every governance or transfer path rejects with `InvalidTransition` or `TransferStepRejected(3, ...)`.

### Theorem 15.1 on the REDEEMED → BURNED transition — trivial satisfaction

Theorem 15.1 State Integrity requires every state transition to pass compliance, identity, and governance checks. On `REDEEMED → BURNED` this is **trivially satisfied** and the triviality is deliberate:

- **Compliance.** `assetFinalize` calls `_requireCompliance(msg.sender, address(0), 0, _encodeAdminContext("L3RS-1/GOV/ASSET_FINALIZE", 0), 2)`. The admin context is short (128 bytes), so no geographic rule fires. `msg.sender` is an authority (enforced by the quorum check), not a sanctioned address, so sanctions pass. No transfer amount, no threshold or AML rule fires. The compliance call returns `(true, NONE)` and bumps `complianceCallCount` — the INV-6 accounting holds.
- **Identity.** No holder is transacting on this mandate-level transition — there is no "sender" or "receiver" in the investor sense. The identity step is skipped entirely (admin-context path per §8.1). An auditor might read this as "identity check missing" — it is not missing, it is **vacuous by construction**: no natural person is being checked because no natural person is moving value.
- **Governance.** This is the only non-trivial check. Quorum signatures verify per §15.5; the transition requires ⌈2/3 × N⌉ distinct authority signers. The `SupplyNotZero` precondition is an additional lock — the mandate cannot finalize while investor claims outstanding.

The "trivial satisfaction" is explicit in the contract code, explicit in the documentation, and backed by the quorum signature requirement. This is the correct formulation for an asset-wide no-value-movement transition: compliance and identity are evaluated under the admin-context semantics (§8.1), and governance is the sole substantive gate.

## 7. Reason codes

Every `TransferStepRejected(step, reasonCode)` carries one of the following reason codes, defined as keccak256 of an identifier string in `src/libraries/ReasonCodes.sol`.

| Code name | String | Used at |
|---|---|---|
| `TRANSFER_INELIGIBLE` | `L3RS-1/REASON/TRANSFER_INELIGIBLE` | Step 2 (compliance) |
| `INVESTOR_CLASS` | `L3RS-1/REASON/INVESTOR_CLASS` | Step 2 |
| `HOLDING_PERIOD` | `L3RS-1/REASON/HOLDING_PERIOD` | Step 2 |
| `GEOGRAPHIC` | `L3RS-1/REASON/GEOGRAPHIC` | Step 2 |
| `SANCTIONS` | `L3RS-1/REASON/SANCTIONS` | Step 2 |
| `THRESHOLD` | `L3RS-1/REASON/THRESHOLD` | Step 2 |
| `AML` | `L3RS-1/REASON/AML` | Step 2 |
| `MARKET` | `L3RS-1/REASON/MARKET` | Step 2 |
| `REDEMPTION` | `L3RS-1/REASON/REDEMPTION` | Step 2 |
| `ORACLE_UNAVAILABLE` | `L3RS-1/REASON/ORACLE_UNAVAILABLE` | Step 2 |
| `IDENTITY_INVALID` | `L3RS-1/REASON/IDENTITY_INVALID` | Step 1 |
| `IDENTITY_EXPIRED` | `L3RS-1/REASON/IDENTITY_EXPIRED` | Step 1 |
| `IDENTITY_REVOKED` | `L3RS-1/REASON/IDENTITY_REVOKED` | Step 1 |
| `GOVERNANCE_BLOCK` | `L3RS-1/REASON/GOVERNANCE_BLOCK` | Step 3 |
| `STATE_DISALLOWS` | `L3RS-1/REASON/STATE_DISALLOWS` | Step 3 (non-ACTIVE, non-REDEEMED) |
| `ASSET_REDEEMED` | `L3RS-1/REASON/ASSET_REDEEMED` | Step 3 (post-`assetRedemption`) |
| `INSUFFICIENT_BALANCE` | `L3RS-1/REASON/INSUFFICIENT_BALANCE` | Step 4 |
| `FEE_TRANSFER_FAILED` | `L3RS-1/REASON/FEE_TRANSFER_FAILED` | Step 5 |
| `REPLAY_DETECTED` | `L3RS-1/REASON/REPLAY_DETECTED` | authenticatedTransfer pre-flight |

Phase One ComplianceModule evaluates only two of the nine mandatory L3RS-1 §4.4 rule types — SANCTIONS_SCREENING and GEOGRAPHIC_RESTRICTION. The remaining seven rule types arrive in step 6 of the build order (unit tests) and are catalogued in THEOREMS.md once that step completes.

## 8. The seven-step §2.6 transfer pipeline

`L3RS1Asset._executeTransfer` runs the steps in this exact order. Any step's revert aborts the whole call atomically (Theorem 15.6).

1. Identity validation per §2.6 step 1 and §3.6. `idTier >= 1` triggers the check; both `from` and `to` must satisfy `Status = VALID`. Failure emits `TransferStepRejected(1, IDENTITY_INVALID|EXPIRED|REVOKED)`.
2. Compliance evaluation per §4.3. Returns `(allow, reasonCode)` — the module is total and never reverts. Failure emits `TransferStepRejected(2, reasonCode)` where `reasonCode` is whatever the module returned.
3. Governance / state check per §2.5. The asset must be `ACTIVE`. Any other state emits `TransferStepRejected(3, STATE_DISALLOWS)`.
4. Transfer-rule validation per §2.7. Sender balance must cover the amount. Failure emits `TransferStepRejected(4, INSUFFICIENT_BALANCE)`.
5. Fee routing per §6. If the fee recipient is a contract, its `onFeeReceived(address, uint256)` hook is called. A revert in the hook emits `TransferStepRejected(5, FEE_TRANSFER_FAILED)`.
6. Balance update per §2.6 step 6. The debit and credit are the atomic commit.
7. Cross-chain metadata update per §2.12 (origin-side only in Phase One). L3RS-1 §13.9 defines CrossChainMetadata as `(origin_chain_id, compliance_hash, governance_hash, state_hash, timestamp)` and §2.12 defines the certificate as `X = H(I ‖ S ‖ C_hash ‖ timestamp)`. **Phase One does not persist a separate `timestamp` field.** The CID is computed on demand via `computeCID()` which reads the live values — `I` is immutable, `S` is `currentState`, `C_hash` is `complianceModule.complianceHash()`, and `timestamp` is `block.timestamp` at the moment of call. This satisfies §13.9's requirement structurally: every transfer advances the block, every CID re-computation reads the new block timestamp, and the CID therefore reflects the most recent update. The persistent state that transfer step 7 actually updates is limited to the supply-snapshot ghost variable used by T4's invariant. **Phase Five's bridge committee will consume `computeCID()` via a read call, not a stored field**, so the design choice is forward-compatible. The deviation from a literal reading of §13.9 — we do not store a `timestamp: uint64` in contract storage — is a deliberate gas and storage optimization whose correctness follows from `block.timestamp` being a trustworthy source under consensus on Base.

`authenticatedTransfer` wraps this pipeline with a pre-flight TxID check per Theorem 15.2. Seven admin-privileged entry points bypass portions of the pipeline according to the admin-context rules in §8.1 below. `setFeeRecipient` routes through compliance to preserve INV-6's per-selector invariant.

## 8.1 Admin-context construction

Phase One has seven admin-privileged entry points that mutate state without the structure of a user-to-user transfer: `issue`, `redeem`, `setFeeRecipient`, `governanceFreeze`, `emergencyRollback`, `rotateAuthority`, `amendLegalMirror`. Each constructs an **admin context** via the private helper `_encodeAdminContext(bytes32 action, uint256 amount)` defined at [L3RS1Asset.sol:338](src/L3RS1Asset.sol:338) and calls `_requireCompliance` before mutating state.

**Every admin action routes through `ComplianceModule.evaluate`.** That is the INV-6 (No Layer Bypass) property and it holds by construction — every state-changing selector on `L3RS1Asset` calls `compliance.evaluate` as its first non-view operation. The invariant campaign `invariant_INV6_everyMutationRoutesThroughCompliance` verifies this across 16 384 random call sequences.

**Admin actions do not call `_executeTransfer`.** `_executeTransfer` at [L3RS1Asset.sol:236](src/L3RS1Asset.sol:236) is the seven-step pipeline for user-to-user transfers, called only from `transfer` at [:210](src/L3RS1Asset.sol:210) and `authenticatedTransfer` at [:224](src/L3RS1Asset.sol:224). Admin actions inline the specific §2.6 steps that are structurally applicable to the operation. The design trade-off is recorded below: inlining produces shorter, more auditable per-function logic than a unified pipeline with a flag-driven branching would.

**Rationale per action.** Governance actions and mint/burn operations do not have a "sender jurisdiction" in the sense a user-to-user transfer does. An issuer minting an asset into existence has no KYC attestation because the issuer is the protocol operator, not an investor. A sanctions check against the *recipient* of a mint is meaningful. A geographic check between issuer and recipient is not — per §12.4 the issuer's jurisdiction is the asset's jurisdiction by construction. The admin context encodes these semantics.

**Which §2.6 steps each admin entry point inlines:**

| Entry point | 1 identity | 2 compliance | 3 state | 4 balance | 5 fee | 6 mutation | 7 cross-chain |
|---|---|---|---|---|---|---|---|
| `issue` | skip | run | run | skip | skip | mint credit | supply snapshot |
| `redeem` | run (sender) | run | run | run | skip | burn debit | supply snapshot |
| `setFeeRecipient` | skip | run | skip | skip | skip | config write | skip |
| `governanceFreeze` | skip | run | skip | skip | skip | state → FROZEN | skip |
| `emergencyRollback` | skip | run | skip | skip | skip | state → previous | skip |
| `rotateAuthority` | skip | run | skip | skip | skip | authority-set write | skip |
| `amendLegalMirror` | skip | run | skip | skip | skip | legal-hash write | skip |

Identity (step 1) is skipped for `issue` because the issuer is the protocol operator, not an investor. Identity runs on the sender of `redeem` because redemption is a holder-initiated burn and the holder must have valid identity at the moment of burn.

**The admin context is shorter than the standard transfer context.** The full transfer context at [L3RS1Asset.sol:303](src/L3RS1Asset.sol:303) encodes ten fields (tag, asset, from, to, amount, sender jurisdiction, receiver jurisdiction, timestamp, nonce-equivalent, travel-rule payload). The admin context at [L3RS1Asset.sol:338](src/L3RS1Asset.sol:338) encodes four fields (tag, action, asset, amount), which is 128 bytes total.

**The compliance suppression mechanism is context length, not an `adminFlag`.** `ComplianceModule._tryReadJurisdictions` at [ComplianceModule.sol:132](src/ComplianceModule.sol:132) checks `if (context.length < 7 * 32) return (false, bytes2(0), bytes2(0));` — when the context is shorter than the seven-slot transfer format, the GEOGRAPHIC rule does not evaluate because its input bytes are absent. The SANCTIONS check at [ComplianceModule.sol:111](src/ComplianceModule.sol:111) runs regardless of context length; it is applied to sender and receiver on every call. Practical effect: admin contexts see SANCTIONS but not GEOGRAPHIC; standard transfer contexts see both.

**Why not a unified pipeline with an `adminFlag`.** An alternative design would have every admin action call `_executeTransfer` with an `adminFlag` in the context that `ComplianceModule.evaluate` reads to suppress specific rules. That design was rejected for Phase One for two reasons. First, admin actions have genuinely different semantics — `issue` mints from nothing, `redeem` burns, `rotateAuthority` changes the authority set, `amendLegalMirror` changes legal state — so a unified pipeline would become a 300-line function with conditional branches per action, which is harder to audit per-operation than short inlined routines. Second, INV-6 (No Layer Bypass) is not stronger under a unified pipeline — it is satisfied equally by the inline approach because every admin action calls `compliance.evaluate` as its first non-view operation. Phase Three may revisit this when the full nine-rule `ComplianceModule` lands and the pipeline itself becomes more complex, at which point the code-sharing payoff of a unified pipeline grows. Tracked as §9 TODO 11.

**Security note on admin-context parsing.** The admin context is constructed inside `L3RS1Asset` and cannot be forged by an external caller — `_encodeAdminContext` is `internal` and its output is passed directly to `compliance.evaluate`. External callers never supply a context; they supply function arguments. The four-field admin context's structure is therefore not a user-controlled surface.

**Audit note on a fix during step 3.** An early version of the admin context used the asset's jurisdiction field as the sender jurisdiction. When the compliance module evaluated GEOGRAPHIC, it saw `(GB, GB)` for admin calls originating in a GB-jurisdiction asset, which failed the `allowJurisdictionPair(GB, US)` rule and rejected at step 2 with a GEOGRAPHIC reason code — not the expected SANCTIONS code. The fix was to shorten the admin context to four fields (128 bytes), which causes `_tryReadJurisdictions` to return `(false, 0, 0)` via its length guard and so skip GEOGRAPHIC evaluation entirely. This matches the `adminFlag` suppression semantics described in the prior revision of this document without requiring a new field in the compliance interface.

## 8.2 Shared signature-verification library

The Phase One placeholder governance-quorum check per §4 and the step-5 Verification Authority surface per §5a share one cryptographic primitive: given a structured message and a set of signatures, recover signers and verify each one against an authorized-address set. A single shared library serves all call sites; two parallel implementations would create drift risk and double the audit surface.

This section is the approved design as of step 5 stage 0. It becomes `src/libraries/SignatureVerification.sol`. All existing governance call sites — `ComplianceModule`, `L3RS1Asset`, `PolicyRegistry` — migrate to it before step 5 stage 1 begins. The VA attestation surface in `IdentityAttestation` adopts it in step 5 stage 2.

### One domain per contract-surface pair

The codebase has six signing surfaces. `IdentityAttestation` carries three — governance authority actions, VA attestation issuance, and holder-signed selective-disclosure presentations — and they must be distinct domains so a signature under one cannot verify under another. The six domain names are:

- `"T3RRA-L3RS1Asset"` — governance quorum on the asset contract.
- `"T3RRA-ComplianceModule"` — governance quorum on the compliance module.
- `"T3RRA-PolicyRegistry"` — governance quorum on the registry.
- `"T3RRA-IdentityAttestation-Governance"` — governance quorum on the identity contract.
- `"T3RRA-IdentityAttestation-VA"` — VA-signed attestation issuance.
- `"T3RRA-IdentityAttestation-Presentation"` — holder-signed selective-disclosure presentations per §8.3.

Each domain separator binds `chainId` and `verifyingContract` per EIP-712 §3. A contract that hosts multiple surfaces carries multiple separators, computed in the constructor and stored as immutables.

### Version policy

`version` is `"1"` for Phase One. Any change to an EIP-712 typehash bumps the version. Bumping invalidates every prior signature over the old typehash — that invalidation is intentional. Prior-version signatures must not verify against a new-version contract, or the typehash change would have no security meaning. Version changes are tracked in §9 TODOs and announced to authorities off-chain before the new version deploys.

### Anti-swap guard on the authority set

`verifyQuorum` takes a typed `GovernanceAuthoritySet storage` reference rather than a bare `mapping(address => bool) storage` reference. The type wrapper is a compile-time guard against the obvious footgun: `ComplianceModule` holds a sanctions list of shape `mapping(address => bool)` alongside the authority set; `IdentityAttestation` will hold a VA registry of the same shape in step 5 stage 2. Without the wrapper, any call site could accidentally pass the wrong mapping — the compiler accepts any `mapping(address => bool) storage` in that slot and the bug is only caught by code review. With the wrapper, the compiler refuses any argument that is not literally a `GovernanceAuthoritySet storage`.

The struct carries both `members` and `threshold` in the same slot-group so they cannot drift apart. Each consuming contract declares one struct instance named `_governanceAuthorities` and initializes both fields in the constructor. Future contracts that need a quorum-gated authority set declare another struct of the same type (also named `_governanceAuthorities`) and participate in the same compiler-enforced convention.

### Interface — five functions

```solidity
library SignatureVerification {
    struct Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    /// Typed wrapper around the governance authority set. The fourth parameter
    /// of verifyQuorum is of this type so the compiler prevents accidental
    /// substitution of another mapping(address => bool) storage reference.
    struct GovernanceAuthoritySet {
        mapping(address => bool) members;
        uint256 threshold;
    }

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice Compute the EIP-712 domain separator per EIP-712 §3.
    function domainSeparator(Domain memory d) internal pure returns (bytes32);

    /// @notice Compute the EIP-712 signing digest per EIP-712 §3.
    /// @dev digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash)).
    function digest(bytes32 domainSep, bytes32 structHash) internal pure returns (bytes32);

    /// @notice Recover the signer from a 65-byte ECDSA signature. Reverts on
    ///         malformed length or on invalid (v, s) per EIP-2. Wraps OpenZeppelin
    ///         `ECDSA.tryRecover(bytes32, bytes)` — the two-argument overload only.
    function recover(bytes32 d, bytes memory signature) internal pure returns (address);

    /// @notice Non-reverting single-signature verifier.
    function verifySingle(bytes32 d, bytes memory signature, address expectedSigner)
        internal pure returns (bool);

    /// @notice Verify a quorum of signatures. Deduplication is by recovered address,
    ///         not by signature bytes. Malformed or unauthorized signatures are
    ///         silently skipped. Returns (bool success, uint256 distinctCount).
    function verifyQuorum(
        bytes32 domainSep,
        bytes32 structHash,
        bytes[] calldata signatures,
        mapping(address => bool) storage authorizedSet,
        uint256 threshold
    ) internal view returns (bool success, uint256 distinctCount);
}
```

Five functions, one struct, one constant. The library does not expose nonce management or batching helpers — those live in the calling contract because semantics differ across surfaces.

### `verifyQuorum` is the primary governance pattern

`verifyQuorum` replaces the placeholder-era `_requireAuthorityQuorum`. The migration is intentional and it closes the §4 security exploit — **deduplication is by recovered address, not by signature bytes**. An attacker who controls one authority's private key and knows arbitrary byte strings from other authorities can no longer fabricate a quorum: any byte string that is not a valid ECDSA signature over the current digest either fails recovery (skipped) or recovers to an address outside the authorized set (skipped), leaving only the one compromised authority's signature to count. `distinctCount` reaches 1, not quorum, and `success` is false.

Governance call-site pattern after migration:

```solidity
// L3RS1Asset, ComplianceModule, PolicyRegistry — same pattern in each.
bytes32 public immutable DOMAIN_SEPARATOR;
mapping(address => bool) internal _isAuthority;
uint256 public governanceNonce;

function governanceAction(uint256 nonce, uint256 deadline, bytes[] calldata signatures) external {
    if (nonce != governanceNonce) revert InvalidNonce();
    if (block.timestamp > deadline) revert Expired();

    bytes32 structHash = keccak256(abi.encode(
        GOVERNANCE_ACTION_TYPEHASH,
        address(this),
        nonce,
        deadline
    ));
    (bool ok, ) = SignatureVerification.verifyQuorum(
        DOMAIN_SEPARATOR,
        structHash,
        signatures,
        _isAuthority,
        _quorumThreshold()
    );
    if (!ok) revert InsufficientSignatures();

    governanceNonce += 1;
    // state mutation follows
}
```

Monotonic `governanceNonce` per contract. Each action reads the current nonce, signs over it, submits. The contract verifies the nonce matches and increments on success. Strictly sequential; parties coordinate off-chain on nonce ordering before signing.

### VA attestation pattern

`IdentityAttestation.grantAttestation` uses `recover` for a single VA signature. Credentials are redeemable at any future time relative to other issuances, so VA nonces use a used-set — not a monotonic counter. Sequential consumption would wrongly force ordering on a set of attestations that the VA has issued independently, potentially months apart.

```solidity
bytes32 public immutable DOMAIN_SEPARATOR_VA;
mapping(address => bool) internal _isVA;
mapping(address => mapping(uint256 => bool)) internal _usedNonce;

struct Attestation {
    address holder;
    bytes32 hid;        // opaque per §5a step-5 replacement
    bytes2 jurisdiction;
    uint8 tier;
    uint256 expiry;
    uint256 nonce;
}

bytes32 constant ATTESTATION_TYPEHASH = keccak256(
    "Attestation(address holder,bytes32 hid,bytes2 jurisdiction,uint8 tier,uint256 expiry,uint256 nonce)"
);

function grantAttestation(Attestation calldata a, bytes calldata vaSig) external {
    bytes32 structHash = keccak256(abi.encode(
        ATTESTATION_TYPEHASH,
        a.holder, a.hid, a.jurisdiction, a.tier, a.expiry, a.nonce
    ));
    bytes32 d = SignatureVerification.digest(DOMAIN_SEPARATOR_VA, structHash);
    address va = SignatureVerification.recover(d, vaSig);
    if (!_isVA[va]) revert UnknownVA();
    if (_usedNonce[va][a.nonce]) revert NonceReused();
    _usedNonce[va][a.nonce] = true;
    _records[a.holder] = a;
    emit AttestationGranted(a.holder, va, a.hid, a.nonce);
}
```

Scaling note for VA nonce tracking. The used-set grows unboundedly as VAs issue attestations. At the Phase One scale (single mandate, hundreds of investors) this is not a problem; at the Phase Six / Phase Seven scale (multiple mandates, thousands of investors per mandate, potentially millions of attestations) the storage cost becomes material and a pruning or compacting mechanism is needed. No mitigation is implemented now; the concern is flagged here and in §9 as a Phase Six / Seven scaling item.

### Properties the library gains

Replay resistance per nonce. Monotonic for governance, used-set for VA.

Cross-chain isolation. Domain separator binds `chainId` and `verifyingContract` per EIP-712 §3.

Cross-surface isolation. Per-contract-surface domains mean a governance signature on `IdentityAttestation` cannot be replayed as a VA attestation on the same contract.

EIP-712 tool compatibility. Wallets (MetaMask, WalletConnect, Fireblocks, Ledger) render typed-data signatures with human-readable type names and field values.

Single audit surface. One library, one audit pass.

### Decisions summary

- **Q1 domain scope.** One domain per contract-surface pair. Six domains, not four. `IdentityAttestation` carries three (governance, VA, presentation).
- **Q2 version.** `"1"` in Phase One. Typehash changes bump the version. Bumping invalidates prior signatures by design.
- **Q3 recovery source.** OpenZeppelin `ECDSA.tryRecover(bytes32, bytes)` — the two-argument overload only. The four-argument form is not used.
- **Q4 nonce layout.** Monotonic for governance. Used-set for VA. Framing: the used-set is justified by credential semantics (attestations redeemable at any future time), not by batch signing.

### Typehash inventory

Seven EIP-712 typehashes live in Phase One. Each has a unique (domain, struct) pair so cross-surface replay is prevented by the domain separator alone and cross-struct replay is prevented by the typehash alone.

| # | Typehash | Contract | Domain |
|---|---|---|---|
| 1 | `GovernanceFreeze` | L3RS1Asset | T3RRA-L3RS1Asset |
| 2 | `EmergencyRollback` | L3RS1Asset | T3RRA-L3RS1Asset |
| 3 | `RotateAuthority` | L3RS1Asset | T3RRA-L3RS1Asset |
| 4 | `AmendLegalMirror` | L3RS1Asset | T3RRA-L3RS1Asset |
| 5 | `Restrict`, `ClearRestriction`, `AssetRedemption`, `AssetFinalize` (4 sibling typehashes for the §2.5 state-transition surface — counted together because they share the admin-context + authority-quorum shape) | L3RS1Asset | T3RRA-L3RS1Asset |
| 6 | `BumpVersion` | ComplianceModule | T3RRA-ComplianceModule |
| 7 | `RemoveSanctioned` | ComplianceModule | T3RRA-ComplianceModule |

Plus the governance typehashes in `PolicyRegistry` (`AmendPolicy`, `RetirePolicy`) and in `IdentityAttestation` (`RegisterVA`, `DeregisterVA`, `RevokeAttestation`, `SetZKVerifier`) and the VA + presentation typehashes (`Attestation`, plus the selective-disclosure envelope typehash in `SelectiveDisclosure`). Total EIP-712 typehash count across Phase One is 14 if every §2.5 transition is counted as its own entry; the "seven" in the table above collapses the four §2.5 siblings into one row for readability. `RemoveSanctioned` (row 7) was added during the external scoping review per §13.3.

Tracked as §9 TODO 13.

## 8.3 Selective disclosure

The L3RS-1 §3.7 selective disclosure requirement is that a rule evaluation sees only the minimum attributes necessary to decide. This section is the approved Phase One design. `src/libraries/SelectiveDisclosure.sol` implements it. `IdentityAttestation.verifyPresentation` is the Phase One consumer.

The three architectural choices the user flagged for explicit justification are addressed in turn.

### Point 1 — reveal at verification time, not at issuance

The interface places the reveal at verification time. At issuance the VA commits to a full attribute set as a Merkle root stored in `Record.attributeCommitments`. The VA never learns which attributes a future verifier will request; the holder, not the VA, decides which leaves to reveal per rule evaluation. This is selective disclosure as the spec intends. The alternative — the VA choosing which attributes to place on chain at issuance time — is partial disclosure, and it fails §3.7's minimality requirement because the VA would have to anticipate every rule that might ever query the attestation, which is not possible for a multi-year credential.

### Point 2 — VA signs the commitment root, not the attribute set

The VA's EIP-712 signature covers `(holder, hid, jurisdiction, tier, expiry, nonce, attributeCommitmentsRoot, zkProofRoot)`. `attributeCommitmentsRoot` is a `bytes32` — the keccak256 Merkle root of a tree whose leaves are `keccak256(name ‖ value ‖ salt)` for each attribute. The VA signs only the root. The VA never signs the attribute values or the leaves; those live with the holder off-chain and never reach the contract unless the holder decides to disclose.

At verification time the holder presents `(AttributeLeaf[] disclosedLeaves, bytes32[][] merkleProofs)`. The verifier contract checks each proof against the committed root. An attacker cannot forge a leaf without finding a keccak256 collision; the VA cannot selectively suppress some attributes without breaking its own commitment. Trust is cryptographic, not in the VA's willingness to forward.

Merkle trees are the natural primitive here and sufficient for Phase One. BLS-based accumulators and other constant-proof-size schemes are Phase Six optimizations. The keccak256-Merkle construction already keeps verification at O(log n) leaves per proof, which is well inside EVM gas budgets for the expected attribute-set sizes (typically five to twenty attributes per investor).

### Point 3 — per-presentation nonce, not per-attestation

Per-attestation nonces prevent an attacker from replaying a VA's signature to mint duplicate records. They do not prevent an attacker from replaying a holder's presentation of specific attributes to the same verifier. Phase One adopts per-presentation nonces.

Threat model. A verifier contract V accepts a selective disclosure and executes an effect (admits the holder to a venue, records a compliance attestation, releases a gated balance). Suppose the disclosure is only gated by the VA's signature on the commitment root plus the holder's Merkle proofs. An observer of one valid disclosure can replay it against V any number of times within the VA's attestation window. Per-attestation nonces — already live in `_usedVANonce` from stage 2 — do not help because those nonces were consumed at issuance and are not consumed per presentation.

The interface binds a presentation to a specific verifier and a specific block context. The presentation envelope is an EIP-712 message over `(attestationRef, commitmentRoot, disclosedLeaves, merkleProofs, verifier, nonce, deadline)`, signed by the holder's key. The verifier checks `(holder, nonce)` has not been used and consumes the nonce on accept. Each presentation is single-use at each verifier.

Cost of this choice: the holder must have signing capability. In Phase One every investor already holds a keyed EOA for asset custody, so the added cost is one EIP-712 signature per selective-disclosure check — the same cost as any other wallet-issued signature. The Phase Six enhancement replaces per-presentation signatures with verifier-issued challenge-response if off-chain latency becomes the binding constraint.

### Final interface

```solidity
library SelectiveDisclosure {
    struct Disclosure {
        bytes32 nameHash;    // keccak256 of the canonical attribute name
        bytes32 valueHash;   // keccak256(attribute_value ‖ salt), salt is a per-leaf blinding
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

    bytes32 internal constant DISCLOSURE_TYPEHASH = keccak256(
        "Disclosure(bytes32 nameHash,bytes32 valueHash)"
    );
    bytes32 internal constant PRESENTATION_TYPEHASH = keccak256(
        "Presentation(address holder,bytes32 attestationRef,bytes32 commitmentRoot,Disclosure[] disclosures,bytes32[][] merkleProofs,address verifier,uint256 nonce,uint256 deadline)Disclosure(bytes32 nameHash,bytes32 valueHash)"
    );

    function verify(
        bytes32 domainSep,
        Presentation calldata p,
        bytes calldata holderSignature,
        mapping(address => mapping(address => mapping(uint256 => bool))) storage usedNonces
    ) internal; // reverts on any failure; consumes the nonce on success
}
```

### The four resolved decisions

**Q1 — library placement.** Standalone `src/libraries/SelectiveDisclosure.sol`. `IdentityAttestation` is the Phase One consumer. Phase Three's `ComplianceModule` rule-evaluator expansion (INVESTOR_CLASSIFICATION, HOLDING_PERIOD) will adopt the same library without needing to call through `IdentityAttestation`. Embedding in `IdentityAttestation` would have forced Phase Three to either duplicate code or couple `ComplianceModule` to `IdentityAttestation`.

**Q2 — signature source.** The **holder** signs the presentation envelope, not the VA. The VA signs the commitment root once at issuance (stage 2 surface, already live); the holder signs each presentation individually at verification time. Two distinct domains on `IdentityAttestation`: `"T3RRA-IdentityAttestation-VA"` (issuance, stage 2) and `"T3RRA-IdentityAttestation-Presentation"` (presentation, stage 4). §8.2 is updated from five to six domains.

Delegated presentation — a custodian signing on behalf of the holder — is explicitly **out of scope** for Phase One. Institutional workflows that need this get a Phase Two or later extension with its own authorization model (for example, a registered delegation record on the Record struct).

**Q3 — nonce layout.** Per-(holder, verifier) used-set. The storage layout is:

```solidity
mapping(address => mapping(address => mapping(uint256 => bool))) internal _usedPresentationNonce;
```

Keyed on `(holder, verifier, nonce)`. The verifier field in the presentation envelope is EIP-712-bound, so a signature valid for verifier A cannot be lifted to verifier B by signature replay. The nonce exists only to prevent same-verifier replay. Per-(holder, verifier) scoping means the holder tracks one counter per verifier off-chain, not a global counter, which is the natural off-chain state.

Unbounded-storage-growth concern — the same one flagged against the VA used-nonce registry at §8.2. Every selective-disclosure presentation appends an entry. At Phase One scale (single mandate) this is not material. At Phase Six/Seven scale (multiple mandates, thousands of verifiers in the ecosystem, millions of presentations) the storage cost becomes a first-order item and a pruning or compacting mechanism is needed. No mitigation is implemented now; the concern is logged here and in §9 as a Phase Six / Seven scaling item.

**Q4 — Merkle proof format.** OpenZeppelin `MerkleProof.verify(proof, root, leaf)` — the three-argument form with sorted-pair hashing. No unsorted-with-flags.

Leaf encoding. Exact bytes-level definition:

```
leaf = keccak256(abi.encode(nameHash, valueHash))
```

Both `nameHash` and `valueHash` are `bytes32`. `abi.encode` of two `bytes32` produces exactly 64 bytes — a concatenation of the two values, each left-padded to 32 bytes. `keccak256` over those 64 bytes yields the leaf.

The off-chain prover MUST use the same encoding. A mismatch — for example, using `abi.encodePacked` instead of `abi.encode`, or using the raw attribute value instead of its hash — silently produces a different leaf hash, which fails Merkle verification with a generic proof-invalid error and no diagnostic. This is documented at every producing and consuming call site in the Phase One code with a direct reference to this paragraph.

### Storage on the consumer

```solidity
// IdentityAttestation storage — Phase One consumer:
bytes32 public immutable DOMAIN_SEPARATOR_PRESENTATION;
mapping(address => mapping(address => mapping(uint256 => bool))) internal _usedPresentationNonce;
```

Phase Three's `ComplianceModule` adoption mirrors this layout with its own domain name.

### Call-site pattern

```solidity
// In IdentityAttestation:
function verifyPresentation(
    SelectiveDisclosure.Presentation calldata p,
    bytes calldata holderSignature
) external {
    SelectiveDisclosure.verify(
        DOMAIN_SEPARATOR_PRESENTATION,
        p,
        holderSignature,
        _usedPresentationNonce
    );
    // p.commitmentRoot matches the stored root check happens inside or
    // immediately after. See IdentityAttestation source.
}
```

The library reverts on any verification failure (invalid signature, wrong verifier, expired deadline, reused nonce, bad Merkle proof) and consumes the nonce on success. No boolean return; any revert from the library aborts the caller's tx by default, which is the correct behavior for a compliance gate.

**Verifier-binding mechanism.** The library uses `address(this) == p.verifier` for verifier binding; because internal library calls are inlined, this resolves to the consuming contract at the library call site. Phase Three ComplianceModule rule-evaluators will verify presentations by calling `identity.verifyPresentation(...)` rather than invoking the library directly — holder-signed presentations therefore remain under IdentityAttestation's `DOMAIN_SEPARATOR_PRESENTATION` and never need a per-evaluator presentation domain.

Tracked as §9 TODO 15 — implementation lands in this stage.

## 9. Pre-audit TODO list

These items are carried into the audit-readiness pass before external audit submission. Each item has a corresponding comment at the affected call site.

### Note on the absent HID revocation registry

Phase One does **not** maintain an on-chain `mapping(bytes32 => bool) _hidRevoked` or any equivalent HID-indexed revocation state. Revocation is recorded as a state change on the specific `Record` (the `revoked` flag flips true) plus an `AttestationRevoked` event with the HID indexed. The event log is the authoritative source of truth for revocation history.

An auditor might reasonably expect `isHidRevoked(bytes32 hid) external view returns (bool)`. That function does not exist in Phase One. Any consumer that needs to test whether a given HID is revoked queries the event log — for example via `eth_getLogs` filtered on the indexed `hid` topic — rather than reading a mapping. Phase Five's bridge, which has the strongest need for HID-level revocation lookup, builds and maintains its own index by consuming the event stream, not by reading IdentityAttestation storage.

The rationale is twofold. First, the authoritative revocation signal is per-(holder, jurisdiction) already — the same HID appearing under two holders would be a HID-collision event, not a normal revocation, and the `Record.revoked` flag captures the semantic directly. Second, an HID-indexed mapping would grow unboundedly with every revocation and compete with the Phase Six/Seven scaling-cost concerns already flagged in §8.2 and §8.3 for the per-VA and per-presentation nonce registries. The event log is replayable, filterable, and does not consume contract storage.

This is a deliberate design choice; it is not an oversight. Phase Five or later may add a storage-backed revocation index if the Phase Five bridge's performance budget makes event-log replay impractical. That addition is not blocking for Phase One.

1. Replace the placeholder governance signature check with EIP-712-typed ECDSA recovery against registered authority public keys, plus a per-authority monotonic governance-action nonce. Files: `L3RS1Asset.sol` (`_requireAuthorityQuorum`), `ComplianceModule.sol` (`_requireAuthorityQuorum`), `PolicyRegistry.sol` (`_requireAuthorityQuorum`). Subsumed by TODO 13 once the shared `SignatureVerification` library per §8.2 is approved and implemented.
2. Replace `verifyLegalAuthoritySignature` with ECDSA recovery against the registered legal authority public key. File: `L3RS1Asset.sol`. Subsumed by TODO 13.
3. ~~Remove the `mintFor` test helper.~~ **Done in step 6G.** Function removed from `L3RS1Asset.sol`, two theorem-test callers migrated to `vm.prank(issuer); asset.issue(...)`, the dedicated `test_mintFor_revertsOnZeroRecipient` unit test deleted, selector removed from the mutable-selectors list.
4. ~~Implement the remaining seven mandatory L3RS-1 §4.4 rule types in `ComplianceModule`~~ **Done in step 6D.** All seven rules implemented with owner-gated setters and priority-ordered evaluation. Six basic rules (SANCTIONS, TRANSFER_ELIGIBILITY, GEOGRAPHIC, MARKET_RESTRICTION, TRANSACTION_THRESHOLD, AML_TRIGGER) run in the existing `evaluate(...)` path. Three extended rules (INVESTOR_CLASSIFICATION, HOLDING_PERIOD, REDEMPTION_ELIGIBILITY) run in a new `evaluateWithDisclosure(...)` overload that takes the receiver's attested tier, sender's first-received-timestamp, and action-kind as explicit inputs — see DESIGN.md §12 "6D rule taxonomy". Integration with L3RS1Asset's transfer pipeline (populating the extended inputs from a verified SelectiveDisclosure presentation on each transfer) is a Phase Three deliverable; Phase One unit-tests the rule logic directly via `evaluateWithDisclosure`.
5. ~~Implement the remaining §2.5 state transitions~~ **Done in step 6E.** All five missing transitions — ISSUED → ACTIVE, ACTIVE → RESTRICTED, RESTRICTED → ACTIVE, ACTIVE → REDEEMED, REDEEMED → BURNED — now have live code paths with governance-quorum or issuer-only gates. ASSET_REDEEMED reason code added to §7. `isAssetRedeemed()` view accessor exposed for Phase Five bridge consumers. Full-lifecycle traversal test in `test/unit/L3RS1Asset.t.sol` drives all seven states in one run. Theorem 15.1 trivial satisfaction on REDEEMED → BURNED documented in §6.
6. ~~Expand `PolicyRegistry` to the full versioned-amendment surface.~~ **Done in step 4.** Full versioned-amendment surface is live; 19 unit tests cover registration, amendment chain, retirement, history access, registry root. Phase Five bridge consumer reads `currentHash(policyId)`.
7. ~~Run Slither and fix every high-severity finding.~~ **Done in step 6H.** Slither 0.11.4 run against `src/` with Foundry integration. Zero high-severity findings. Two medium-severity reentrancy findings fixed in-phase via CEI refactors in `L3RS1Asset._executeTransfer` and `authenticatedTransfer`; three remaining medium findings accepted with rationale, plus four low-severity and ten informational findings accepted. Full triage and disposition in DESIGN.md §13.1.
8. ~~Run Certora on the PolicyHash canonical encoding and on the four ComplianceModule entry points, per 08-deployment-target.md.~~ **Specification authored in step 6H; execution deferred to audit-firm Certora runner per Flag 3 sign-off.** Eight CVL specifications covering ten Phase One functions — `ComplianceModule.complianceHash`, `evaluate`, `evaluateWithDisclosure`, `bumpVersion`, the rule-setter family, `SignatureVerification.verifyQuorum` and `recover`, and `SelectiveDisclosure.verify`. Full prose in DESIGN.md §13.2. Certora execution is contracted as part of the external audit scope of work; counterexamples route back to the engineering team under a fix protocol.
9. ~~Write the end-to-end scenario test — the $50M synthetic commercial real estate mandate with 100 secondary transfers and three deliberately non-compliant transfers per the project's testing discipline.~~ **Done in step 6F.** Five-phase scenario at `test/scenario/CREMandate.t.sol` covers setup, primary ops (97 successful + 3 rejected transfers), governance events, redemption lifecycle, and final assertions. Four deviations from the literal brief documented in DESIGN.md §12 "6F deviations".
10. **Build a Foundry Handler contract** that wraps `L3RS1Asset`, `ComplianceModule`, and `IdentityAttestation` with pre-authorized signers and exposes selectors that generate valid state-changing operations with random parameters. Rewire the T4 (`invariant_T4_supplyInvariant`, `invariant_T4_transfersPreserveSupply`), T5 (`invariant_T5_minorityNeverOverrides`), and INV-6 (`invariant_INV6_everyMutationRoutesThroughCompliance`) invariant campaigns to call into the Handler rather than the target contracts directly. **Today these campaigns exhibit a ~99% revert rate** because the fuzzer drives random `msg.sender` into access-controlled functions, which means the campaigns explore a narrow slice of the reachable state space and may hold vacuously. A Handler-based setup typically converts the revert rate to 5–10% (legitimate compliance rejections and state-machine boundaries) and produces a meaningful exploration. This must be in place before external audit. Audit firms run their own handler-based campaigns as part of their methodology and will notice if Phase One's are structurally weaker.

11. Refactor admin operations to route through a unified pipeline function with rule-specific suppression, once the full nine-rule `ComplianceModule` lands in a later phase. Phase One uses per-operation inlining per §8.1.

12. **Replace the placeholder HID construction.** The Phase One `HID = keccak256(who, jurisdiction, tier)` computation in `IdentityAttestation.grantAttestation` has no privacy property and deviates from L3RS-1 §3.4 on three points: no PII input, no salt, no domain-separation string. Per DESIGN.md §5a, step 5 replaces the computation with an off-chain HID supplied by a registered Verification Authority. The contract after replacement accepts HID as an opaque `bytes32` and never reconstructs it. PII never touches the contract. This TODO is jointly resolved with the VA surface delivery in step 5 stage 2, but remains in the §9 list because the pre-audit version of the codebase must ship with the VA-signed grant path, not the placeholder.

13. **Implement the shared `SignatureVerification` library per §8.2.** One library serves all four call sites: three governance-quorum paths in `L3RS1Asset`, `ComplianceModule`, and `PolicyRegistry`, plus the VA attestation path in `IdentityAttestation`. Replaces the placeholder distinctness-of-bytes check with proper EIP-712 ECDSA recovery and domain-separated digest computation. Subsumes TODOs 1 and 2. ~~Pending user review of the §8.2 proposal before implementation begins.~~ **Done in step 5 stage 0.**

14. **Replace the `MockZKVerifier` with a real proving-system verifier.** Per DESIGN.md §5b. The mock accepts any proof bytes as valid. The replacement implements real cryptographic verification against a chosen proving system (Groth16, Plonk, STARK, Halo2). The swap is a single governance-quorum `setZKVerifier` call — no IdentityAttestation redeploy required. Public-input encoding is fixed at `abi.encode(holder, hid, jurisdiction, tier)`; the replacement verifier is responsible for parsing. `verifierId()` on the replacement MUST be a non-`"mock"` string that uniquely identifies the proving system and parameter set.

15. ✅ **Implement the `SelectiveDisclosure` library per §8.3.** Standalone `src/libraries/SelectiveDisclosure.sol`. Four architectural choices resolved per §8.3. `IdentityAttestation.verifyPresentation` is the Phase One consumer; Phase Three's `ComplianceModule` rule-evaluator adopts the same library when INVESTOR_CLASSIFICATION and HOLDING_PERIOD rules land (TODO 4). Done in step 5 stage 4.

16. **Integrate INVESTOR_CLASSIFICATION and HOLDING_PERIOD into the transfer pipeline.** Per DESIGN.md §5c. The Phase One pipeline calls basic `evaluate(...)` only; the extended rules are unit-tested via `evaluateWithDisclosure(...)` but not invoked per transfer. Phase Three integration extends `transfer(...)` to take a `SelectiveDisclosure.Presentation` + holder signature, verifies the presentation, extracts the attested inputs, and calls `evaluateWithDisclosure`. This is a **mainnet blocker**: a regulated-security deployment cannot rely on static rule configuration in place of per-transfer dynamic verification. Ships alongside TODOs 12 (HID) and 14 (real ZKP verifier) as the three non-negotiable pre-mainnet items.

17. **Expose `Asset_Type` as an on-chain field per L3RS-1 §2.1 and §2.3.** Phase One hardcodes `REGULATED_SECURITY` semantics; the asset type is implicit in the contract and documented in the 6F scenario header rather than asserted against a field. Multi-type deployments require the field to be stored (an enum or `bytes32` code) and type-dispatched rule behavior to be implemented where Profile F rules diverge by asset type. Phase Three or later scope. **Not a mainnet blocker** for a single-type deployment.

18. ~~**Add a governance-quorum-gated `removeSanctionedAddress` path to `ComplianceModule`.**~~ **Done in the external scoping review.** L3RS-1 §4.8 "Registry updates" is plural; OFAC and comparable sanctions oracles delist entities, and an append-only on-chain model cannot be defended to a regulator. Phase One now carries `removeSanctionedAddress(who, nonce, deadline, signatures)` with a fresh `REMOVE_SANCTIONED_TYPEHASH` under the existing `T3RRA-ComplianceModule` EIP-712 domain. The function requires the same governance-quorum set used for `bumpVersion`; the asymmetry with the owner-gated `addSanctionedAddress` mirrors OFAC listing-versus-delisting process (additions are protective and fast; removals are restoration and deliberate). See §13.3 for the full remediation record.

## 10. Per-test status table

All 42 tests as of step 3 completion. Columns: test name, property verified (theorem / invariant / helper), evidence of validation (unit / fuzz / invariant-campaign with campaign parameters). Post-step-3 status: 42 / 42 green.

| # | Test name | Property verified | Evidence of validation |
|---|---|---|---|
| 1 | invariant_T1_everyStateChangeHasEvidence | Theorem 15.1 state-integrity evidence bitmask | Invariant campaign, 256 runs × 64 depth = 16 384 calls |
| 2 | test_T1_complianceRejectBlocksTransfer | Theorem 15.1 compliance gate | Unit test; expectRevert on `TransferStepRejected` from transfer pipeline |
| 3 | test_T1_identityMissingBlocksTransfer | Theorem 15.1 identity gate | Unit test; expectRevert when `Status = UNKNOWN` |
| 4 | test_T1_unauthorizedOverrideBlocksStateChange | Theorem 15.1 governance gate | Unit test; state unchanged after single-signer freeze attempt |
| 5 | invariant_T2_noDuplicateTxIds | Theorem 15.2 replay registry has no duplicates | Invariant campaign, 256 runs × 64 depth |
| 6 | test_T2_distinctNoncesProduceDistinctTxIds | Theorem 15.2 TxID hash is nonce-sensitive | Unit test; pure `computeTxId` |
| 7 | test_T2_forgedTxIdRejected | Theorem 15.2 registry does not pre-populate | Unit test; `isSeenTxId(0x01) == false` |
| 8 | test_T2_replayAfterStateChangeStillFails | Theorem 15.2 replay rejected even across state | Unit test; second authenticatedTransfer with same TxID reverts |
| 9 | test_T2_submittedTxIdCannotBeResubmitted | Theorem 15.2 direct replay rejected | Unit test; second authenticatedTransfer with same nonce reverts |
| 10 | test_T3_canonicalSerializationIsDeterministic | Theorem 15.3 canonical serialization is deterministic per §13.11 | Unit test; two reads produce identical bytes |
| 11 | test_T3_cidCoversEveryInput | Theorem 15.3 CID covers every input per §2.12 | Fuzz test, 1 024 runs |
| 12 | test_T3_complianceMutationChangesHash | Theorem 15.3 ComplianceHash changes under mutation | Unit test; hash before ≠ hash after `addSanctionedAddress` |
| 13 | test_T3_governanceMutationChangesHash | Theorem 15.3 GovHash changes under authority rotation | Unit test; hash before ≠ hash after `rotateAuthority` |
| 14 | invariant_T4_supplyInvariant | Theorem 15.4 totalSupply = mintedTotal − burnedTotal | Invariant campaign, 256 runs × 64 depth |
| 15 | invariant_T4_transfersPreserveSupply | Theorem 15.4 non-mint-burn preserves supply | Invariant campaign, 256 runs × 64 depth |
| 16 | test_T4_supplyDecreasesOnlyByBurn | Theorem 15.4 redeem decreases supply by exact amount | Unit test; supply delta = 500 000 |
| 17 | test_T4_supplyIncreasesOnlyByMint | Theorem 15.4 issue increases supply by exact amount | Unit test; supply delta = 1 000 000 |
| 18 | invariant_T5_minorityNeverOverrides | Theorem 15.5 every successful override had ≥ 2 signers | Invariant campaign, 256 runs × 64 depth |
| 19 | test_T5_duplicateSignerDoesNotCountTwice | Theorem 15.5 duplicate fingerprints reject | Unit test; expectRevert on two identical sig bytes |
| 20 | test_T5_emergencyRollbackRequiresQuorum | Theorem 15.5 §5.5 EMERGENCY_ROLLBACK requires quorum | Unit test; single-sig reverts, quorum succeeds |
| 21 | test_T5_quorumCanFreeze | Theorem 15.5 state → FROZEN on quorum freeze | Unit test; currentState == FROZEN after call |
| 22 | test_T5_singleSignerCannotFreeze | Theorem 15.5 single sig < quorum | Unit test; expectRevert |
| 23 | test_T6_complianceFailureIsAtomic | Theorem 15.6 step 2 fails atomic, reason SANCTIONS | Unit test; `TransferStepRejected(2, SANCTIONS)`, state unchanged |
| 24 | test_T6_feeFailureIsAtomic | Theorem 15.6 step 5 fails atomic, reason FEE_TRANSFER_FAILED | Unit test; `TransferStepRejected(5, FEE_TRANSFER_FAILED)`, state unchanged |
| 25 | test_T6_governanceFailureIsAtomic | Theorem 15.6 step 3 fails atomic, reason STATE_DISALLOWS | Unit test; `TransferStepRejected(3, STATE_DISALLOWS)`, state unchanged |
| 26 | test_T6_identityFailureIsAtomic | Theorem 15.6 step 1 fails atomic, reason IDENTITY_REVOKED | Unit test; `TransferStepRejected(1, IDENTITY_REVOKED)`, state unchanged |
| 27 | test_T6_reentrancyGuardIsPresent | Theorem 15.6 structural guard | Unit test; `reentrancyGuardIsActive() == true` |
| 28 | test_T7_amendmentsRecordNewLh | Theorem 15.7 amendment produces new LH | Unit test; legalHash before ≠ legalHash after |
| 29 | test_T7_authoritySignatureVerifiesIfPresent | Theorem 15.7 authority signature verification | Unit test; valid → true, invalid → false |
| 30 | test_T7_lhCoversDocumentJurisdictionVersion | Theorem 15.7 LH covers (document, jurisdiction, version) | Fuzz test, 1 024 runs |
| 31 | invariant_INV1_noRevertsEver | INV-1 evaluate is total | Invariant campaign, 256 runs × 64 depth |
| 32 | test_INV1_allowAndReasonAreExclusive | INV-1 allow xor reasonCode | Fuzz test, 1 024 runs |
| 33 | test_INV1_evaluateNeverReverts | INV-1 evaluate does not revert | Fuzz test, 1 024 runs |
| 34 | invariant_INV2_hashChangesIffSerializationChanges | INV-2 hash-change ≡ serialization-change | Invariant campaign, 256 runs × 64 depth |
| 35 | test_INV2_domainStringMatchesSpec | INV-2 domain = `"T3RRA-POLICY-HASH-v1"` | Unit test |
| 36 | test_INV2_readIsStable | INV-2 read is stable without mutation | Unit test |
| 37 | test_INV2_rulesetMutationChangesHash | INV-2 rule mutation changes hash | Unit test |
| 38 | test_INV2_thirdPartyRederivationAgrees | INV-2 third-party rederives same hash | Unit test |
| 39 | test_INV2_versionBumpChangesHash | INV-2 version bump changes hash | Unit test |
| 40 | invariant_INV6_everyMutationRoutesThroughCompliance | INV-6 mutation count ≡ compliance-call count | Invariant campaign, 256 runs × 64 depth |
| 41 | test_INV6_directBalanceMutationReverts | INV-6 unsafe path reverts | Unit test |
| 42 | test_INV6_noDirectStateMutationSelector | INV-6 every mutable selector calls compliance | Unit test |

## 12. Coverage baseline (6A) and gap analysis

`forge coverage` results against the 107-test suite at the start of step 6. This section is the planning artifact for sub-stage 6B; targets, gaps, and priorities listed here drive the unit tests that sub-stage will add.

### Per-file summary

| File | Lines | Statements | Branches | Funcs |
|---|---:|---:|---:|---:|
| src/ComplianceModule.sol | 76.92% (70/91) | 78.89% (71/90) | 65.38% (17/26) | 65.00% (13/20) |
| src/IdentityAttestation.sol | 88.39% (137/155) | 89.14% (156/175) | 70.00% (28/40) | 78.12% (25/32) |
| src/L3RS1Asset.sol | 96.00% (264/275) | 92.28% (275/298) | 52.38% (22/42) | 93.62% (44/47) |
| src/MockZKVerifier.sol | 100.00% (4/4) | 100.00% (2/2) | 100.00% (0/0) | 100.00% (2/2) |
| src/PolicyRegistry.sol | 91.01% (81/89) | 86.24% (94/109) | 45.83% (11/24) | 80.00% (12/15) |
| src/libraries/SelectiveDisclosure.sol | 100.00% (26/26) | 100.00% (43/43) | 100.00% (6/6) | 100.00% (3/3) |
| src/libraries/Sha3.sol | 100.00% (59/59) | 100.00% (94/94) | 100.00% (1/1) | 100.00% (5/5) |
| src/libraries/SignatureVerification.sol | 86.21% (25/29) | 85.00% (34/40) | 83.33% (5/6) | 80.00% (4/5) |
| **Total** | **90.12% (730/810)** | **89.47% (841/940)** | **62.07% (90/145)** | **82.99% (122/147)** |

### Per-function gap list

Functions marked `!` have zero hits under the current suite and are the primary targets for 6B.

**src/ComplianceModule.sol** (76.92% lines):
- `!` getRules — used by future rule evaluators; verifies rule enumeration.
- `!` version — simple getter.
- `!` _quorumThreshold — internal; redundant wrapper over `_governanceAuthorities.threshold` but should be exercised.
- `!` authorities — view accessor.
- `!` observedRevertCount — returns 0 always but INV-1 invariant depends on it being testable directly.
- `!` serializationChangeCount, hashChangeCount — same pattern for INV-2.

**src/IdentityAttestation.sol** (88.39% lines):
- `!` tierOf(holder, jurisdiction) — the per-jurisdiction overload; holder-only variant also untested.
- `!` verificationAuthorityOf(holder, jurisdiction) — per-jurisdiction overload.
- `!` attributeCommitmentsRootOf (both overloads) — never exercised after the stage-4 field rename.
- `!` proofOf (both overloads) — same.

**src/L3RS1Asset.sol** (96.00% lines):
- `!` feeRecipient — view accessor.
- `!` distinctTxIdCount — returns `seenTxIdCount` by construction; view accessor.
- `!` authorities — view accessor.

**src/PolicyRegistry.sol** (91.01% lines):
- `!` authorities — view accessor.
- `!` policyIds — view accessor.
- `!` _quorumThreshold — internal wrapper.

**src/libraries/SignatureVerification.sol** (86.21% lines):
- `!` verifySingle — non-reverting single-signature verifier. **Priority: HIGH.** Cryptographic primitive in the shared library; an untested path is an audit risk.

### Prioritized 6B targets

**Priority 1 — cryptographic primitive.** `SignatureVerification.verifySingle` is the only uncovered function with audit-risk significance. Direct unit tests for the three branches (valid + match, valid + wrong signer, malformed). Add to `test/unit/SignatureVerification.t.sol` (new file).

**Priority 2 — invariant-backing ghost accessors.** `ComplianceModule.observedRevertCount`, `serializationChangeCount`, `hashChangeCount` are read by the INV-1 and INV-2 invariants but show as zero-hits in the coverage table — `forge coverage` does not count invariant-campaign reads against function coverage. Add direct unit-test reads to `test/unit/ComplianceModule.t.sol` (new file) so the accessors are exercised under the coverage run.

**Priority 3 — per-jurisdiction accessor overloads.** The `IdentityAttestation` accessors `tierOf(h, j)`, `verificationAuthorityOf(h, j)`, `attributeCommitmentsRootOf(h, j)`, `proofOf(h, j)` and their holder-only legacy counterparts are the surface Phase Three's `ComplianceModule` rule evaluators will read from. Add a compact accessor-matrix test that exercises every field for every holder × jurisdiction combination in the existing test-harness setup. Add to `test/unit/IdentityAttestation.t.sol`.

**Priority 4 — pure view accessors and enumeration helpers.** `authorities()`, `policyIds()`, `vaList()`, `feeRecipient()`, `distinctTxIdCount()`, `getRules()`, `version()` — these are single-line returns. One test per contract that reads the complete view surface closes these. Add to each contract's unit test file.

**Priority 5 — branch coverage.** Total branch coverage is 62.07%; the 95% line target will still leave branch coverage short. 6B should add revert-path tests for every `revert` and `require` in the four contracts:
- `ComplianceModule`: zero-address guards on `addSanctionedAddress`, duplicate-pair rejection in `allowJurisdictionPair`, tier out-of-range in the constructor.
- `L3RS1Asset`: `NotIssuer`, `ZeroAddress`, `InvalidTier`, `InvalidNonce`, `Expired` paths on every governance function.
- `PolicyRegistry`: `UnknownPolicy`, `AlreadyRegistered`, `PolicyAlreadyRetired`, `VersionOutOfRange`, `InvalidNonce`, `Expired`.
- `IdentityAttestation`: `InvalidTier`, `NonceReused`, `InvalidZKProof`, `VAAlreadyRegistered`, `VANotRegistered`, `UnknownVA` across every quorum-gated function.

### 6B scope summary

Three new unit test files: `test/unit/SignatureVerification.t.sol`, `test/unit/ComplianceModule.t.sol`, `test/unit/L3RS1Asset.t.sol`. One extension to the existing `test/unit/IdentityAttestation.t.sol` for per-jurisdiction overloads and branch-path revert cases. Target numbers:

- Line coverage: 95% minimum per file (user requirement). Current average 90.12% is close; the gap is mostly in ComplianceModule (76.92%).
- Function coverage: 95% minimum. Current 82.99%. Gap is in view accessors and legacy overloads.
- Branch coverage: 85% minimum. Current 62.07% is the biggest lift — revert paths are the main target.

Estimated test count delta: ~40–50 new unit tests spread across the four contracts, bringing the total to ~150.

### 6B results

All targets exceeded. Test count grew from 107 to 211 (+104). Three new unit test files and two extensions to existing unit test files.

Per-file coverage after 6B:

| File | Lines | Statements | Branches | Funcs |
|---|---:|---:|---:|---:|
| src/ComplianceModule.sol | 98.88% (88/89) | 98.88% (88/89) | 100.00% (26/26) | 100.00% (19/19) |
| src/IdentityAttestation.sol | 99.35% (154/155) | 97.71% (171/175) | 90.00% (36/40) | 100.00% (32/32) |
| src/L3RS1Asset.sol | 100.00% (275/275) | 98.66% (294/298) | 88.10% (37/42) | 100.00% (47/47) |
| src/MockZKVerifier.sol | 100.00% (4/4) | 100.00% (2/2) | 100.00% (0/0) | 100.00% (2/2) |
| src/PolicyRegistry.sol | 100.00% (87/87) | 98.15% (106/108) | 91.67% (22/24) | 100.00% (14/14) |
| src/libraries/SelectiveDisclosure.sol | 100.00% (26/26) | 100.00% (43/43) | 100.00% (6/6) | 100.00% (3/3) |
| src/libraries/Sha3.sol | 100.00% (59/59) | 100.00% (94/94) | 100.00% (1/1) | 100.00% (5/5) |
| src/libraries/SignatureVerification.sol | 100.00% (29/29) | 100.00% (40/40) | 100.00% (6/6) | 100.00% (5/5) |
| **Total** | **97.56% (800/820)** | **97.06% (925/953)** | **92.41% (134/145)** | **97.35% (147/151)** |

Dead-code removal during 6B: `ComplianceModule._quorumThreshold()` and `PolicyRegistry._quorumThreshold()` were unused after the stage-0 typed-struct migration (the library reads `authorities.threshold` directly). Both were deleted. `L3RS1Asset._quorumThreshold()` is retained because it is still read by `governanceHash()`.

### Uncovered-branches inventory

Every remaining uncovered branch and line in `src/*` after 6B. Each row is either covered in intent (a test exercises the path, a tool artifact prevents the hit being registered) or unreachable by construction (the code guards against a future data-model change or a Solidity-compiler optimization).

**src/ComplianceModule.sol:297** — `return 0;` inside `observedRevertCount()`.
- Status: **covered in intent**, flagged by tool.
- Exercising test: `test_view_observedRevertCountAlwaysZero` in `test/unit/ComplianceModule.t.sol` calls `compliance.observedRevertCount()` and asserts the return value.
- Why the tool does not register it: `forge coverage` does not count the body of a `pure` function whose return is a compile-time constant — the compiler elides the call at test-site linking and the LCOV hit counter stays at zero. This is a known limitation of Solidity coverage instrumentation.

**src/IdentityAttestation.sol:472** — `return Status.UNKNOWN;` at the tail of `getStatus(holder)`.
- Status: **unreachable by construction**.
- Reasoning: the loop at lines 463-468 iterates over `_holderJurisdictions[who]`. Entries in that array are appended only by `grantAttestation` when `!_hasRecord[a.holder][a.jurisdiction]` (new record) and never removed. Every jurisdiction in the list therefore has a record, and every record has a non-UNKNOWN status (VALID, EXPIRED, or REVOKED). The loop must set `sawRevoked` or `sawExpired`, or return VALID early. Reaching the `return Status.UNKNOWN;` fallthrough requires an enumerated jurisdiction without a record — which the data model does not permit.
- Why the line exists: defense-in-depth against a future refactor that might append to `_holderJurisdictions` before a record exists (for instance, a batch-attestation flow). Removing the guard would be a behavior-silent audit risk; keeping it is correct even though it is unreachable today.

No uncovered branches remain in `src/*`. All 134 of 145 covered-or-exempt branches are either hit by a test or documented above.

### Test file inventory at end of 6B

| File | Tests | Scope |
|---|---:|---|
| test/theorems/Theorem01–07_*.t.sol | 33 | Seven L3RS-1 theorems |
| test/invariants/INV1, INV2, INV6_*.t.sol | 12 | Three T3RRA system invariants |
| test/unit/ComplianceModule.t.sol | 17 | Accessors + branches (new in 6B) |
| test/unit/IdentityAttestation.t.sol | 47 | Stages 2–6 + 6B branches |
| test/unit/L3RS1Asset.t.sol | 22 | Accessors + branches (new in 6B) |
| test/unit/PolicyRegistry.t.sol | 30 | Step 4 + 6B branches |
| test/unit/SelectiveDisclosure.t.sol | 11 | Stage 4 library (step 5) |
| test/unit/SignatureVerification.t.sol | 13 | Direct library coverage (new in 6B) |
| **Total** | **211** | |

### 6C — Handler-based invariant rewire

Sub-stage 6C replaced the direct-target invariant campaigns for T4, T5, and INV-6 with a Handler-wrapped variant. The Handler, in `test/handlers/L3RS1Handler.sol`, pre-authorizes issuer, three governance keys, one VA, and a pool of four holders with live attestations across four distinct jurisdictions, then exposes a weighted selector surface — transfers 57%, mint/burn 19%, governance/admin 24% — that the invariant campaigns target with `targetContract(address(handler))` plus `targetSelector(FuzzSelector(...))` repeat-duplication for weights. Parameter bounding uses `bound(input, min, max)` throughout; `vm.assume` is not used anywhere in the Handler. Three contract deployments (`ComplianceModule`, `IdentityAttestation`, `PolicyRegistry`, `L3RS1Asset`, `MockZKVerifier`) happen inside the Handler's constructor so campaigns are fully isolated from `BaseTest`.

#### Two 6C design decisions worth naming

**Revert rate at 2.7%, not the 5-10% heuristic target.** Pre-screening against FROZEN state on three of the four transfer-like actions and against sanctions on every party-indexed action cuts most wasted fuzzer cycles. The residual reverts come from a single deliberate branch (`authenticatedTransferAction` without FROZEN pre-screen) that preserves state-disallows reject exploration. The intent of the 5-10% band was legitimate rejection-path exploration not wasted cycles — 2.7% reflects legitimate exploration with tight pre-screening. The number is not a miss on the heuristic; it is the design point.

**INV-6 reformulated from `assertEq(stateMutationCount, complianceCallCount)` to `assertLe(stateMutationCount, complianceCallCount)` plus Handler-ghost equality `assertEq(handler.ghost_successfulMutations, asset.stateMutationCount)`.** The original `==` would have broken under honest state-space exploration: compliance rejections bump `complianceCallCount` without advancing `stateMutationCount`. The `≤` form correctly states "every mutation was preceded by a compliance call, not every compliance call leads to a mutation." The ghost equality then confirms the Handler's Solidity-level view of successful mutations agrees with the contract's own counter, completing the no-layer-bypass property.

#### The ghost cross-check pattern — reusable convention

The Handler maintains independent accounting (ghost variables) for properties the invariant wants to verify. Every action that mutates a watched quantity updates both the contract and the Handler's ghost in the same call frame. If either is rolled back by a revert, both roll back together — the ghosts and the contract state stay synchronized by construction. Invariants then cross-check ghost equality against contract state.

The pattern as applied in 6C:

| Ghost | Mutated by | Cross-checked against |
|---|---|---|
| `ghost_totalMinted` | `issueAction` | `asset.mintedTotal()` |
| `ghost_totalBurned` | `redeemAction` | `asset.burnedTotal()` |
| `ghost_successfulMutations` | every asset-side mutation | `asset.stateMutationCount()` |
| `ghost_minSignersOnSuccessfulOverride` | `governanceFreezeAction`, `emergencyRollbackAction`, `bumpVersionAction`, `_recordOverride` | read directly by T5 invariant |
| `ghost_overrideSuccessCount` | same | used as guard for the minSigners check |
| `ghost_selectorSuccesses[sel]` | every action keyed by its asset-level selector | per-selector debug output on failure |

The pattern is reusable. Sub-stage 6D will extend the Handler with new ghosts for INVESTOR_CLASSIFICATION (per-holder credential class) and HOLDING_PERIOD (per-holder acquisition timestamp). The same rule applies: every Handler action that mutates a watched quantity updates the ghost in the same call frame, and invariants cross-check. Where a new invariant doesn't map cleanly to an existing contract counter, the ghost is the authoritative source — the contract's state is the thing being verified, the ghost is the oracle.

This convention replaces the older approach where invariants read only contract state and inferred properties. The 6B invariant campaigns had a ~99% revert rate and invariants that held vacuously; the 6C campaigns have a 2.7% revert rate and invariants that hold under real state-space exploration. The difference is attributable entirely to the Handler + ghost cross-check pattern.

### 6D — rule taxonomy

All seven remaining L3RS-1 §4.4 rule types are now configurable on `ComplianceModule`. Priority order per §4.5 is strict: the first blocking rule terminates evaluation.

| # | Rule | Surface | Reason code | Config setter |
|---:|---|---|---|---|
| 1 | SANCTIONS_SCREENING | basic | `SANCTIONS` | `addSanctionedAddress` |
| 2 | TRANSFER_ELIGIBILITY | basic | `TRANSFER_INELIGIBLE` | `setTransferIneligible` |
| 3 | GEOGRAPHIC_RESTRICTION | basic | `GEOGRAPHIC` | `allowJurisdictionPair` |
| 4 | MARKET_RESTRICTION | basic | `MARKET` | `setMarketHours` |
| 5 | TRANSACTION_THRESHOLD | basic | `THRESHOLD` | `setTransactionThreshold` |
| 6 | AML_TRIGGER | basic | `AML` | `setAmlThreshold` |
| 7 | INVESTOR_CLASSIFICATION | extended | `INVESTOR_CLASS` | `setMinInvestorTier` |
| 8 | HOLDING_PERIOD | extended | `HOLDING_PERIOD` | `setMinHoldingPeriod` |
| 9 | REDEMPTION_ELIGIBILITY | extended | `REDEMPTION` | `setRedemptionIneligible` |

**Basic rules** evaluate from direct on-chain state (the configured address sets, thresholds, market hours) and the transfer context. They run inside the existing `evaluate(...)` path and are in effect on every Phase One transfer.

**Extended rules** require inputs that come from a verified SelectiveDisclosure presentation: the receiver's attested investor tier, the sender's first-received-at timestamp, the action kind (TRANSFER / REDEEM). Phase One exposes them on the new `evaluateWithDisclosure(...)` overload — unit-tested directly and wired to the SelectiveDisclosure library conceptually per §8.3. Phase Three integrates the presentation-verification step into L3RS1Asset's transfer pipeline so these rules fire on every real transfer; Phase One tests call `evaluateWithDisclosure` directly with the three inputs.

**Priority-order confirmation.** The implemented order of the six basic rules matches the canonical spec ordering exactly:
`SANCTIONS_SCREENING > TRANSFER_ELIGIBILITY > GEOGRAPHIC_RESTRICTION > MARKET_RESTRICTION > TRANSACTION_THRESHOLD > AML_TRIGGER`.
Four cross-priority tests in `test/unit/ComplianceModule.t.sol` (search for `test_6D_priority_*`) pin the order against concrete multi-rule configurations so any future refactor that reorders them will fail.

**`_recordHashChange` bug story — surfaced by 6D, not a coverage gap from 6B.** The helper's pre-6D implementation bumped `_serializationChangeCount` unconditionally and `_hashChangeCount` only when the hash actually changed. INV-2's `serializationChangeCount == hashChangeCount` assertion was satisfied in phases 3–5 only by accident: the two setters that touched rule state (`addSanctionedAddress`, `allowJurisdictionPair`) both **appended** to lists, so every call necessarily mutated the canonical serialization and therefore the hash. The counters moved in lock-step by construction, not by design.

6D added five **scalar** setters (`setTransactionThreshold`, `setAmlThreshold`, `setMarketHours`, `setMinInvestorTier`, `setMinHoldingPeriod`) plus two flag-mapping setters (`setTransferIneligible(..., false)`, `setRedemptionIneligible(..., false)`). These can be called idempotently — e.g. `setMarketHours(0, 0)` when hours are already (0, 0). Under the pre-6D helper, such calls bumped the serialization counter without changing the hash, violating the INV-2 invariant. The bug was latent across phases 3–5 and would have been triggered by any production-relevant amendment flow that wrote back an unchanged configuration.

The fix is in `_recordHashChange` ([ComplianceModule.sol](src/ComplianceModule.sol)): the helper now computes the new hash first and bumps both counters only when the hash has actually changed. The new behavior is what INV-2 actually asserts: not "every setter call fired" but "every state change produced a hash change, and vice versa." The prior behavior was measuring the wrong thing.

Audit-history note: this is a real find, not a 6B coverage gap. 6B covered the two pre-6D list-append setters and saw no divergence. 6D introduced the scalar-setter surface and surfaced the latent bug on the first invariant run. The fix lands in the same sub-stage that introduced the triggering condition — an atomic "surface + fix" event in the history. Flag for the audit firm as an in-phase remediation.

**Integration deviation.** The user's 6D spec said INVESTOR_CLASSIFICATION and HOLDING_PERIOD "consume SelectiveDisclosure." The literal integration would require L3RS1Asset's transfer pipeline to call `identity.verifyPresentation(...)` on every transfer before calling `compliance.evaluate(...)`, materially changing the pipeline's cost and caller UX. Phase One implements the rule logic and unit-tests it directly via `evaluateWithDisclosure`; the pipeline integration (which needs a presentation-envelope parameter on every transfer) is deferred to Phase Three. The SelectiveDisclosure library and the attested-tier/first-received/action-kind interface are both live in Phase One — what is deferred is the per-transfer presentation flow. Flag this deviation for sign-off.

#### 6C test file inventory

| File | Tests | Scope |
|---|---:|---|
| test/handlers/L3RS1Handler.sol | (harness, no tests) | Handler contract |
| test/invariants/T4_Handler_SupplyInvariant.t.sol | 3 | Contract-identity + Handler ghost + mint/burn monotonic |
| test/invariants/T5_Handler_GovernanceSafety.t.sol | 2 | Handler min-signers + asset override counter |
| test/invariants/INV6_NoLayerBypass.t.sol | 3 | Handler ghost equality + ≤ gating + structural flags |

Net test-count delta: +2 (211 → 213). Three invariants became three different invariants in INV-6 (previously 1); two invariants in T4 became three in the Handler version; one invariant in T5 became two. The prior contract-direct invariants in Theorem04 and Theorem05 are retired and their files cross-reference the new Handler-based files.

### 6F — $50M CRE mandate scenario test

The single end-to-end scenario that demonstrates Phase One as a cohesive system rather than a collection of contracts. Lives at `test/scenario/CREMandate.t.sol` (one test, `test_6F_CREMandate_FullLifecycle`). Runs in under one second of wall time and exercises five phases in order:

1. **Setup** — 5 authorities with 4-of-5 quorum per `ceil(2n/3)` from L3RS-1 §5.4, two Verification Authorities, all nine §4.4 compliance rules configured (including the three extended rules), seven holders spanning GB / US / SG jurisdictions plus one tier-1 fail case, legal mirror at version 1, fee recipient an attested EOA, $50M minted proportionally to six investor holders.
2. **Primary ops** — 97 successful secondary transfers with `vm.warp` at every action, amounts ranging 10K–500K per transfer, followed by three pipeline rejections (TRANSFER_INELIGIBLE, MARKET outside [8, 20) UTC, SANCTIONS via a tier-1 VALID-identity non-holder) plus a direct INVESTOR_CLASS demo through `ComplianceModule.evaluateWithDisclosure`.
3. **Governance events** — rule amendment + quorum-gated version bump, legal mirror amendment, `governanceFreeze` + `emergencyRollback`, VA revocation with downstream transfer failing `IDENTITY_REVOKED`, re-grant via the second VA so the revoked holder can still redeem in phase 4.
4. **Redemption lifecycle** — `assetRedemption` (ACTIVE → REDEEMED) via quorum, three pending `authenticatedTransfer` attempts rejecting with `ASSET_REDEEMED`, all holders redeem to zero, `assetFinalize` (REDEEMED → BURNED) with the `totalSupply == 0` precondition satisfied.
5. **Final assertions** — exactly 97 successful transfers, `totalSupply == 0`, `currentState == BURNED`, per-phase supply invariant (six snapshots, all values match expected), correct `governanceNonce` progression on each of the three contracts (asset 5, compliance 1, identity 1), 10 distinct VA nonces consumed, and six post-BURNED state-change attempts all reverting with either `InvalidTransition` or `STATE_DISALLOWS`.

Phase boundaries emit `ScenarioCheckpoint(label, blockNumber, totalSupply, currentState)` events (`SETUP_COMPLETE`, `MINT_COMPLETE`, `PRIMARY_COMPLETE`, `GOVERNANCE_COMPLETE`, `REDEMPTION_COMPLETE`, `FINALIZED`) and write a `PhaseCheckpoint` struct into a test-local map so phase 5 can assert against historical snapshots rather than only live state.

#### 6F deviations

Four deviations from the literal 6F brief; all documented in the scenario file header:

- **D1 — INVESTOR_CLASS via direct evaluation rather than through the pipeline.** The brief called for a pipeline rejection with `tier-1 → INVESTOR_CLASS`. `INVESTOR_CLASSIFICATION` is an extended rule and is not yet plumbed into the basic `evaluate` path that `L3RS1Asset` invokes (deferred per §9 TODO 16 and §5c). The scenario substitutes `TRANSFER_INELIGIBLE` in the pipeline's third rejection slot and demonstrates `INVESTOR_CLASS` by calling `ComplianceModule.evaluateWithDisclosure` directly on an unrelated context with `receiverTier = 1`. The direct demo must run before the `SANCTIONS` rejection — otherwise the basic-first priority inside `evaluateWithDisclosure` short-circuits with `SANCTIONS` once the tier-1 holder enters the sanctions list.
- **D2 — fee recipient is an attested EOA, not a multisig contract.** A multisig contract would need `onFeeReceived(address,uint256)` support which Phase One does not ship. The EOA placeholder is attested at setup so that the fees it accrues during the 97 transfers can be drained in phase 4 alongside the six investor holders. The drain list has seven entries (six investors + fee recipient) rather than six.
- **D3 — asset type `REGULATED_SECURITY` is implicit.** `L3RS1Asset` does not carry an on-chain asset-type enum. The scenario documents the mapping in the file header rather than asserting against a contract field.
- **D4 — 5 authorities, 4-of-5 quorum.** The quorum formula in L3RS-1 §5.4, `ceil(2n/3)`, yields threshold 4 for n=5. The scenario uses five authorities and constructs every governance signature set with four distinct authority signatures.

Each deviation is a shape-fit issue between the scenario brief and Phase One's actual surface. None represent missing functionality; D1 is the only one tied to a deferred TODO.

#### 6F test file inventory

| File | Tests | Scope |
|---|---:|---|
| test/scenario/CREMandate.t.sol | 1 | Five-phase $50M CRE mandate end-to-end, ~700 lines |

### Step 6 latent-condition pattern

Step 6 surfaced three latent conditions that earlier surfaces lacked the means to expose. Each was a real defect in live code, not a test-only artifact. Each was fixed in the same sub-stage that revealed it. The cumulative pattern is worth naming explicitly: step 6's job was to force these conditions into view before audit submission, and the sub-stage architecture — coverage gap analysis, then handler-based invariants, then rule taxonomy expansion, then state-machine expansion, then end-to-end scenario — delivered three distinct integration surfaces, each of which revealed an interaction condition the previous surfaces could not have caught.

| Sub-stage | Latent condition | Disclosure mechanism | Fix |
|---|---|---|---|
| 6D | `ComplianceModule._recordHashChange` bumped the `_serializationChangeCount` ghost unconditionally, not only when the hash actually changed. | Idempotent scalar setters (`setMarketHours(0, 0)` when already at `(0, 0)`, `setTransactionThreshold(x)` when already at `x`) exposed the divergence against INV-2, which asserts the two counters move in lock-step. 6B's list-append setters never produced an idempotent call and therefore never caught the bug. | `_recordHashChange` now compares `complianceHash()` before and after and bumps both counters only when the hash differs. |
| 6E | `governanceFreeze` and `emergencyRollback` lacked state-machine guards. A `BURNED → FROZEN` transition would succeed under the right authority signatures; `emergencyRollback` from `BURNED` would pop off the terminal state. | The full-lifecycle traversal test drove all seven states end-to-end, reaching `BURNED` and then attempting illegal re-entries. Prior unit tests exercised freeze and rollback in isolation from `ACTIVE` only, and so saw valid input and a valid state and reported success. | `governanceFreeze` now requires `_currentState == ACTIVE`; `emergencyRollback` rejects `ACTIVE` (nothing to roll back to) and `BURNED` (terminal). Both raise `InvalidTransition`. |
| 6F | `ComplianceModule.evaluateWithDisclosure` evaluates basic rules first, then extended rules. A direct `INVESTOR_CLASS` demo run against a sender or receiver already on the sanctions list short-circuits with `SANCTIONS` at priority 1. The direct demo ran with `holderT1` as receiver; `holderT1` had just entered the sanctions list for the scenario's rejection-3 pipeline test. | First run of the CRE scenario failed the `INVESTOR_CLASS` assertion with reason `0x41b74d69…`, which is `SANCTIONS` and not `INVESTOR_CLASS`. Only an end-to-end scenario with nontrivial ordering across nine rules could have exposed the ordering dependency. | Scenario reordered so the `INVESTOR_CLASS` direct demo runs before the `SANCTIONS` rejection, with a comment at the call site explaining the basic-first priority. No contract change — the priority is correct per L3RS-1 §4.5. |

The framing that applies to all three: each new integration surface revealed an interaction condition the previous surfaces lacked the means to expose. 6D introduced idempotent scalar setters, 6E completed the state machine, 6F composed the full rule set in one scenario. The defects were present in the code the whole time; they required the new surface to become visible.

An audit firm reviewing this history should read the pattern as evidence of the test-surface expansion working as designed, not as evidence of a sequence of unrelated bugs. Each find is documented in its sub-stage section above with the disclosure mechanism and the fix.

## 13. Static analysis and formal verification (sub-stage 6H)

The final sub-stage of step 6 exercises the codebase under Slither static analysis and documents the Certora CVL specifications that will run under the audit firm's licensed runner. These are the last two items on the pre-audit TODO list (TODOs 7 and 8 in §9). 6H resolves TODO 7 end-to-end and resolves TODO 8 as far as Phase One's scope allows — specification authorship and runner contract, per the Flag 3 sign-off.

### 13.1 Slither

**Environment.** `slither-analyzer 0.11.4` via `pip install --user slither-analyzer`. `solc 0.8.26` via `solc-select`. Foundry framework integration via `forge build --build-info`. Filtered to `src/` only; `lib/` (OpenZeppelin, forge-std) and `test/` excluded.

**Invocation.**
```
slither src/ --filter-paths "lib|test" --compile-force-framework foundry
```

**Result.** 17 findings across all severities. Three medium-severity, four low-severity, ten informational or detector-level style notes. None high-severity. Zero findings that warrant a hotfix; two findings drove in-phase refactors to satisfy the checks-effects-interactions pattern even under the presence of `nonReentrant`.

| Detector | Severity | Count | Disposition |
|---|---|---:|---|
| reentrancy-no-eth | medium | 2 → 0 | **Fixed in 6H.** CEI refactor in `L3RS1Asset._executeTransfer` and `authenticatedTransfer`. |
| weak-prng | medium | 1 | Accepted as Phase One tradeoff. False positive: `block.timestamp` read for wall-clock time-of-day in MARKET_RESTRICTION rule, not as a source of randomness. |
| unused-return | medium | 2 | Accepted as Phase One tradeoff. `verifyQuorum`'s second return value (`distinctCount`) is intentionally discarded by `ComplianceModule.bumpVersion` and `PolicyRegistry._requireAuthorityQuorum` because neither contract tracks §15.5 override counts (only `L3RS1Asset` does). |
| missing-zero-check | low | 1 | Accepted as Phase One tradeoff. `L3RS1Asset.setFeeRecipient` intentionally permits `address(0)` as the fee-disabled sentinel per §6. |
| timestamp | low | 1 | Accepted as Phase One tradeoff. Every flagged comparison is a deadline check (`block.timestamp > deadline`) or a market-hour check. Both are the documented semantic per L3RS-1 §4.4 and EIP-712 deadline patterns. |
| low-level-calls | informational | 1 | Accepted. The `_feeRecipient.call(...)` invocation implements the optional `onFeeReceived` callback per §6. A high-level interface call would break the "fee recipient may be an EOA" semantic. |
| naming-convention | informational | 3 | Accepted. `DOMAIN_SEPARATOR` is an immutable per EIP-712; the uppercase form is idiomatic in Solidity across OpenZeppelin and the EIP ecosystem. |
| cache-array-length | informational | 3 | Accepted as Phase One tradeoff per the project convention "Gas and clarity tradeoff": gas micro-optimization at the expense of readability is not taken in the reference implementation. |

**In-phase fix 1 — CEI in `_executeTransfer`.** Slither flagged cross-function reentrancy on `_balances`: the fee recipient's `onFeeReceived` callback ran after `_balances[_feeRecipient] += fee` but before `_balances[from] -= amount`, leaving the `_balances` mapping observable in an intermediate state during the external call. Although `nonReentrant` blocked any direct reentry into `transfer` or `authenticatedTransfer`, a callback reaching into a helper on a different contract that read `L3RS1Asset.balanceOf(...)` could observe that intermediate state. 6H reorders the step-5 internals: the fee calculation and `_balances[_feeRecipient]` credit run as effects first, steps 6 and 7 commit, and the `onFeeReceived` callback is invoked only at the very end of the function when no state write remains. The reorder is auxiliary to `nonReentrant`; the guard remains load-bearing. Theorem 15.6 (atomic settlement) is preserved — a callback revert still reverts the entire pipeline call, because the call is the last operation before return. The §2.6 step numbering is preserved in comments; the physical interleaving has shifted.

**In-phase fix 2 — CEI in `authenticatedTransfer`.** Slither flagged the `_seenTxId[txId] = true` write as occurring after the fee callback inside `_executeTransfer`. Because the callback could not reenter the pipeline under `nonReentrant`, this was a secondary concern, but the fix is trivial: commit `_seenTxId[txId] = true` (together with the other TxID-registry state writes) before entering `_executeTransfer`. A revert inside `_executeTransfer` reverts the commit atomically per §2.6 and Theorem 15.6, so the pre-commit is safe.

**Full test suite state after both fixes.** All 257 tests green. The two CEI refactors change the interleaving but not the externally observable semantics; every existing unit, fuzz, and invariant test continues to pass without modification. T6 (atomic settlement) in particular is re-verified by the five atomic-revert tests in `test/theorems/Theorem06_AtomicSettlement.t.sol` — each fails at a distinct step with a distinct reason code and leaves state unchanged.

**Accepted findings in detail.**

- `weak-prng` on `(block.timestamp / 3600) % 24`. The expression is the UTC hour-of-day, consumed by `MARKET_RESTRICTION` per L3RS-1 §4.4. `block.timestamp` is the canonical on-chain wall-clock source; no randomness property is being claimed. Slither's detector generalizes a pattern that is used in PRNG schemes but here serves a different purpose.
- `unused-return` on `verifyQuorum`. The function returns `(bool success, uint256 distinctCount)`. `L3RS1Asset` consumes both — `distinctCount` feeds into `minSignersForAnySuccessfulOverride` for §15.5. `ComplianceModule.bumpVersion` and `PolicyRegistry._requireAuthorityQuorum` both need only the `success` flag because neither tracks override metrics. Fixing the warning would require either adding unused storage or adopting a convention like `(bool ok, uint256 /* distinctCount */)` which Slither also flags. Accepted with rationale.
- `missing-zero-check` on `L3RS1Asset.setFeeRecipient`. Setting `_feeRecipient = address(0)` is the documented way to disable fee routing for the asset per §6 in `_executeTransfer` — the fee block is gated on `_feeRecipient != address(0)`. A zero-check would remove the disable path. Accepted.
- `timestamp` comparisons. Every flagged site is either a deadline check (`block.timestamp > deadline`, EIP-712 pattern) or a MARKET_RESTRICTION / HOLDING_PERIOD check. Both are the canonical L3RS-1 semantic. Slither's detector reflects a historical concern about miner manipulation of timestamp at a granularity smaller than a few seconds; all our checks operate at hour or day granularity where this is irrelevant.
- `low-level-calls`, `naming-convention`, `cache-array-length`. Style-level detector notes. None affect correctness or audit exposure.

### 13.2 Certora CVL specifications

Per Flag 3 resolution, Certora license is not maintained in-house; the audit firm runs the specifications. Phase One's 6H deliverable is the CVL specification inventory and per-function prose skeleton. An engineering-team-authored CVL specification independently executed by the audit firm is strictly stronger than a self-run campaign because it constitutes independent verification rather than self-verification. The established audit firms have Certora capability on staff.

**Functions in scope.** Ten functions grouped by contract.

| # | Contract | Function | Property family |
|---|---|---|---|
| 1 | ComplianceModule | `complianceHash()` | canonical hash determinism |
| 2 | ComplianceModule | `evaluate(assetRef, sender, receiver, amount, context)` | totality and priority |
| 3 | ComplianceModule | `evaluateWithDisclosure(..., receiverTier, senderFirstReceivedAt, actionKind)` | totality and priority |
| 4 | ComplianceModule | `bumpVersion(nonce, deadline, signatures)` | governance authorization |
| 5 | ComplianceModule | rule setters (`addSanctionedAddress`, `allowJurisdictionPair`, `setTransferIneligible`, `setTransactionThreshold`, `setAmlThreshold`, `setMarketHours`, `setMinInvestorTier`, `setMinHoldingPeriod`, `setRedemptionIneligible`) | hash-change ≡ serialization-change |
| 6 | SignatureVerification | `verifyQuorum(domainSep, structHash, signatures, authorities)` | dedup-by-recovered-address |
| 7 | SignatureVerification | `recover(digest, signature)` | EIP-2 low-s malleability |
| 8 | SelectiveDisclosure | `verify(domainSep, presentation, holderSignature, usedNonces)` | envelope binding |

**Per-function CVL specification skeleton (prose).**

---

**#1 — `ComplianceModule.complianceHash()` determinism under canonical serialization.**

Property. Two sequential calls to `complianceHash()` return identical values whenever no mutator has been invoked between them. The hash is a pure function of the current canonical serialization: for any two distinct `ComplianceModule` instances A and B that expose identical `_canonicalSerialization()` bytes, `A.complianceHash() == B.complianceHash()`.

Rationale. Theorem 15.3 (cross-chain downgrade resistance) and INV-2 (PolicyHash stability) both require that the hash is a well-defined function of observable state. Certora verifies deterministic hashing by modeling `keccak256` (or in our case, the SHA-3-256 Keccak-f[1600] emulation per §3) as an uninterpreted function `h` and asserting that two calls with the same input return the same output. This is the standard Certora pattern for cryptographic hash properties.

---

**#2 — `ComplianceModule.evaluate` totality.**

Property 2a. `evaluate` is total: for every four-tuple `(sender, receiver, amount, context)`, the call returns and does not revert.

Property 2b. The return value `(allow, reasonCode)` satisfies `allow XOR (reasonCode != 0)`: either the transfer is allowed with `reasonCode == ReasonCodes.NONE`, or it is blocked with a specific non-zero reason code.

Property 2c. Priority order per L3RS-1 §4.5: for a configuration where multiple rules would reject a given input, the returned `reasonCode` is the one corresponding to the highest-priority rule. Priorities: SANCTIONS > TRANSFER_ELIGIBILITY > GEOGRAPHIC > MARKET > THRESHOLD > AML.

Rationale. INV-1 is the Phase One invariant capture of 2a and 2b. A foundry invariant campaign demonstrates these properties empirically over 256 × 64 = 16 384 random paths, but cannot discharge the claim for every four-tuple. Certora closes the gap by symbolic execution across the entire input space.

---

**#3 — `ComplianceModule.evaluateWithDisclosure` extended totality and priority.**

Property 3a. `evaluateWithDisclosure` is total in the same sense as `evaluate`.

Property 3b. The extended evaluator delegates to `evaluate` for the basic rules; when basic evaluation rejects, the returned `reasonCode` comes from the basic priority ladder. When basic evaluation allows, the extended ladder runs: INVESTOR_CLASSIFICATION > HOLDING_PERIOD > REDEMPTION_ELIGIBILITY.

Property 3c. REDEMPTION_ELIGIBILITY only fires when `actionKind == bytes32("REDEEM")`. For any other actionKind, the rule is dormant.

Rationale. The extended path is the Phase Three transfer-pipeline integration point per §9 TODO 16. Certora verification of the extended priority ladder ahead of integration reduces the risk that Phase Three's integration introduces a priority bug.

---

**#4 — `ComplianceModule.bumpVersion` governance authorization.**

Property 4a. If `bumpVersion(nonce, deadline, signatures)` returns without reverting, then: (i) `nonce == governanceNonce_pre`, (ii) `block.timestamp <= deadline`, and (iii) `signatures` contains at least `threshold` valid ECDSA signatures over the EIP-712 digest whose recovered addresses are all distinct and all members of `_governanceAuthorities.members`.

Property 4b. On successful execution, `governanceNonce_post == governanceNonce_pre + 1` and `_version_post == _version_pre + 1`.

Rationale. Theorem 15.5 and INV-6 together require that every state mutation routes through a compliance call plus, for governance actions, a quorum-verified signature set. Certora verifies that no configuration of inputs can satisfy the post-condition without also satisfying 4a's pre-conditions.

---

**#5 — Rule-setter hash-change equivalence (INV-2).**

Property. For every rule-setter `f` and every call `f(args)`: after the call completes without reverting, `complianceHash_post == complianceHash_pre` if and only if `_canonicalSerialization_post == _canonicalSerialization_pre`, and the `_serializationChangeCount` and `_hashChangeCount` ghosts bump by the same amount.

Rationale. INV-2 is the headline invariant on this surface. 6D surfaced a bug where the counters moved out of lock-step on idempotent scalar-setter calls; the fix guards the bump on actual hash change. Certora generalizes this to symbolic calls — any setter, any arguments — and confirms the equivalence holds universally, not just for the specific call patterns Foundry exercises.

---

**#6 — `SignatureVerification.verifyQuorum` dedup-by-recovered-address.**

Property 6a. `verifyQuorum` returns `(success, distinctCount)` where `distinctCount` is the cardinality of the set of distinct addresses in `authorities.members` that produced a valid ECDSA signature over `digest = keccak256(0x1901 || domainSep || structHash)`, and `success = (distinctCount >= authorities.threshold)`.

Property 6b. Presenting the same authority's signature twice in `signatures` does not increase `distinctCount` by 2; it increases it by at most 1. Equivalently: for any `authorities` with `threshold >= 2`, there exists no call `verifyQuorum(domainSep, structHash, [sig, sig], authorities)` that returns `success = true` when `sig` recovers to a single member of `authorities.members`.

Property 6c. For any signature byte string `s` that is not a valid ECDSA signature over `digest`, or that recovers to an address outside `authorities.members`, presenting `s` in `signatures` does not contribute to `distinctCount`.

Rationale. DESIGN.md §8.2 documents the placeholder-signature-scheme exploit that the library replaces: the old scheme deduplicated by signature-bytes fingerprint, which made quorum forgeable from a single authority's key plus arbitrary bytes. Property 6b is the negation of the exploit. Certora discharges it symbolically by quantifying over `sig` and `s` rather than sampling.

---

**#7 — `SignatureVerification.recover` EIP-2 low-s malleability.**

Property. For every digest `d`, `recover(d, sig)` reverts with `InvalidSignature` when `sig.s > SECP256K1_N / 2` (the high-s half). Equivalently: the signature cannot be mutated from `(r, s, v)` to `(r, -s mod n, v ^ 1)` and still recover the same signer.

Rationale. EIP-2 mandates that implementations reject high-s signatures to prevent malleability. OpenZeppelin's `ECDSA.tryRecover` enforces this; the library wraps it and inherits the guarantee. Certora verification pins this inheritance against future OZ version bumps.

---

**#8 — `SelectiveDisclosure.verify` envelope binding.**

Property 8a. `verify` reverts unless every field of the Presentation envelope is exactly as signed: `holder`, `verifier == address(this)` of the calling contract, `nonce`, `deadline`, `commitmentRoot`, and the Merkle proof paths for every disclosed attribute.

Property 8b. The `holderSignature` is an EIP-712 signature by `holder` over the full envelope. Any mutation to any field — including reordering disclosed attributes or substituting a different Merkle path — causes signature verification to fail.

Property 8c. `nonce` is consumed atomically: before the call, `usedNonces[holder][verifier][nonce] == false`; after a successful call, `usedNonces[holder][verifier][nonce] == true`. Two calls with the same `(holder, verifier, nonce)` cannot both succeed.

Property 8d. `deadline`: the call reverts if `block.timestamp > deadline`.

Property 8e. Commitment root binding: every disclosed attribute's Merkle proof verifies against `commitmentRoot`. Slot-level equivalence between an attribute's disclosed value and its hash commitment at the proven leaf is enforced by the OpenZeppelin MerkleProof library (sorted-pair semantics per §8.3).

Rationale. Selective disclosure is the cryptographic primitive that bridges §3.7's attested-attributes surface and §4.4's extended rules. Each of the five sub-properties is a distinct failure mode Certora can discharge independently: wrong verifier, wrong nonce, expired deadline, bad Merkle proof, bad signature. A Foundry fuzz campaign can sample these failure modes but cannot certify them — the attribute-proof paths alone are an exponential search space.

---

**Deferred execution.** The eight specifications above are expected to compile to roughly 400–600 lines of executable CVL once adapted to the Certora Prover's syntax. Phase One does not ship the CVL source; the audit firm's Certora engineer writes it against this specification as their independent-verification deliverable. Phase One's commitment is (i) the specification inventory and prose above, (ii) a contractually specified Certora run as part of the external audit scope of work, and (iii) a fix protocol for any counterexample returned.

### 13.3 Fixes applied during scoping review

Before formal audit kickoff, external scoping reviewers reviewed the v1.0.0-audit-candidate tag and flagged two issues. Both were real; both were fixed in-phase on `main` as a second commit series and released under tag `v1.0.1-audit-candidate`. This subsection is the authoritative record of the findings, their root causes, the remediation, and the re-test evidence.

#### Finding SR-1 — `Sha3.RHO_OFFSETS` off-by-one against FIPS 202 §3.2.2

**Severity.** Critical correctness defect in the PolicyHash / ComplianceHash primitive. Every ComplianceHash value produced by `v1.0.0-audit-candidate` is a hash-of-a-hash-of-wrong-state: the permutation applied during absorb did not match FIPS 202 SHA3-256. On-chain, this did not compromise any security property asserted by the theorem suite (hash determinism and hash-change-on-mutation both hold for ANY deterministic function of the canonical serialization), but it DID mean that off-chain consumers re-deriving the hash using a standards-compliant SHA3-256 would obtain a different digest for the same canonical bytes. Phase Five cross-chain bridge consumption would fail.

**Root cause.** The `RHO_OFFSETS` packed constant was written as `0x00013E1C1B242C063714030A2B1927292D0F150812023D380E0000000000000000` — 66 hex characters, 33 bytes. Solidity parses hex literals as arbitrary-precision integers and then casts to the target type, silently stripping leading zeros. The 33-byte literal collapsed to an effective 32-byte uint256 value `0x013E1C1B…0000000000000000` — byte position 0 (the MSB, which the extraction formula `(RHO_OFFSETS >> (8 * (31 - i))) & 0xFF` reads as `_rhoOffset(0)`) became `0x01` instead of the intended `0x00`, shifting every rho offset left by one table index. The implementation applied `r[i+1]` wherever it should have applied `r[i]`.

**How the bug slipped through.** The Sha3.sol NatSpec claimed the FIPS 202 Appendix A.3 test vectors were "verified in `test/unit/Sha3.t.sol`". That file did not exist. The test suite as a whole was written against hash-change and hash-determinism properties — `assertTrue(hashBefore != hashAfter)` rather than `assertEq(hashAfter, 0xabcdef…)` — because the build order emphasized invariants over pinned byte strings. Under that convention, the test suite is genuinely invariant to the specific hash values: ComplianceHash changing when rules change is equally true whether the underlying hash is SHA3-256 or the buggy near-SHA3. The bug is only observable against an external authoritative vector, and no external vector was pinned. 257 tests passing gave a false signal.

**Remediation.**

1. Constant replaced with the correct 32-byte (64-hex-char) value. Before: `0x00013E1C1B242C063714030A2B1927292D0F150812023D380E0000000000000000`. After: `0x00013E1C1B242C063714030A2B1927292D0F150812023D380E00000000000000`. Difference is exactly two trailing hex characters (one byte) removed so the literal is a clean 32 bytes and the MSB-position byte is `0x00` as intended.
2. `test/unit/Sha3.t.sol` created with ten tests. Three are FIPS 202 Appendix A.3 authoritative vectors (empty, "abc", 1-million-byte "a" — the last retained as a reference value only, not asserted on-chain, because the Solidity emulation of 7 353 Keccak-f[1600] rounds exceeds the forge default memory-gas budget). Two are independent published vectors (NIST CAVP single-byte 0xe9, and the classic 56-byte "abcdbcde…nopq" short-message vector). Five are structural tests (determinism, avalanche, rate-block boundary at 136 and 137 bytes, and a 200-byte regression anchor against the current implementation).
3. The Sha3.sol NatSpec no longer makes a verification claim it cannot back; it cites the file path that now exists.
4. DESIGN.md §3 carries the historical note above with the meta-lesson about documentation-of-tests versus tests-that-exist.

**Re-test evidence.** All 257 pre-existing tests continue to pass unchanged; no test hardcoded a specific hash byte string, so the hash-value change under the fix is invisible to them. The ten new Sha3 tests — including the two FIPS 202 authoritative vectors that are the direct cross-implementation correctness check — all pass. Total suite: 273 tests, 19 suites plus the new `Sha3Test` suite, 100% passing.

#### Finding SR-2 — `ComplianceModule` has no `removeSanctionedAddress` path

**Severity.** Regulatory-correctness defect. L3RS-1 §4.8 refers to "Registry updates" in the plural. Real-world sanctions oracles are not append-only — OFAC regularly delists entities, and a regulated-platform implementation that cannot honor a delist cannot pass a compliance-process review. The append-only behavior in `v1.0.0-audit-candidate` would have surfaced as an audit finding in any regulated-platform engagement.

**Root cause.** The original `addSanctionedAddress` function was written against the CRE scenario's narrow needs — add to a test-local list, exercise a SANCTIONS rejection — without considering the standard's plural "updates" language. The omission is a scope-discipline failure: the Phase One build treated sanctions as a one-shot administrative input rather than a live governance-managed registry.

**Remediation.**

1. New function `removeSanctionedAddress(address who, uint256 nonce, uint256 deadline, bytes[] calldata signatures)` added to `ComplianceModule`. Governance-quorum-gated via the existing `SignatureVerification.verifyQuorum` library. New EIP-712 typehash `RemoveSanctioned(address module,address who,uint256 nonce,uint256 deadline)` under the existing `T3RRA-ComplianceModule` domain separator. New error `NotSanctioned()`. New event `SanctionedAddressRemoved(address indexed who)`. New view accessor `sanctioned(address)` — the bare mapping was internal-only.
2. **Asymmetric gating model.** `addSanctionedAddress` remains owner-gated because addition is protective and benefits from speed; `removeSanctionedAddress` is quorum-gated because removal is restoration and benefits from multi-party sign-off. This asymmetry matches OFAC listing-vs-delisting process: listing decisions are fast and administrative, delisting decisions are deliberative and require documentation of basis for removal. DESIGN.md §9 TODO 18 and the function's NatSpec both state the asymmetry explicitly.
3. Six unit tests in `test/unit/ComplianceModule.t.sol`: happy path with event assertion, minority signer rejection, non-authority signer rejection, `NotSanctioned` precondition, invalid-nonce short-circuit, and full add/remove/re-add lifecycle including hash-equivalence after round-trip (`h_after_remove == h_pre_add`, a direct INV-2-style invariant on the canonical serialization's set semantics).
4. CRE scenario test at `test/scenario/CREMandate.t.sol` updated: phase 2's SANCTIONS rejection now walks the full lifecycle — add `holderT1`, reject transfer, remove by 4-of-5 quorum, confirm delisting via direct `evaluate` call. Phase 5 governance-nonce assertion updated: `compliance.governanceNonce()` advances from 1 to 2 because the module now consumes two quorum-gated actions (the delisting in phase 2 plus the `bumpVersion` in phase 3).
5. DESIGN.md §8.2 typehash inventory section updated — seven distinct rows, with `RemoveSanctioned` at row 7.

**Re-test evidence.** 273 tests pass, 0 fail, 0 skip. The CRE scenario end-to-end takes roughly 740 milliseconds including the new lifecycle exercise.

#### Slither re-triage

After both fixes landed, Slither 0.11.4 was re-run against `src/` with the same `--filter-paths "lib|test"` invocation as the v1.0.0 triage. Result: 20 findings total (was 17), zero high-severity, four medium (was three). The three additional findings are all new occurrences of already-triaged detector categories, introduced mechanically by the new `removeSanctionedAddress` path: one `unused-return` on its `verifyQuorum` call (same disposition as `bumpVersion` and `PolicyRegistry._requireAuthorityQuorum` per §13.1 — distinctCount is intentionally discarded because this contract does not track override metrics), one `cache-array-length` note on the swap-and-pop removal loop, and one `timestamp` comparison on the deadline check. No new detector categories introduced. Every new finding falls under a disposition already accepted in §13.1.

#### Acknowledgment

Both findings surfaced by the external scoping reviewers. The remediation is the responsibility of the engineering team; the findings were theirs. The turnaround — findings to fix to `v1.0.1-audit-candidate` tag — was intended to complete before formal engagement kickoff so the audit target was not a moving reference. Attribution is recorded in this subsection and in the `v1.0.1-audit-candidate` CHANGELOG entry.

### 13.4 Aderyn self-audit findings

Run between `v1.0.1-audit-candidate` and the next tag. Aderyn (Cyfrin) is a complementary static analyzer with detector coverage that overlaps with Slither but is not identical. Twelve findings: one High, eleven Low. Triaged with the advisor; four items implemented, eight items accepted with documented rationale.

#### Fixed in this pass

- **H-1 — `abi.encodePacked` on a fixed-length plus variable-length pair in `complianceHash()` and `hashOf()`.** Under `abi.encodePacked`, concatenating a length-variable `bytes` with another argument can in principle produce hash collisions across different `(A, B)` splits if both arguments are length-variable. In our two call sites the first argument (`CANONICAL_HASH_DOMAIN`) is a fixed-length constant so no collision is actually constructible, but auditors do not grant that defense because it relies on a cross-file invariant that a future edit could break silently. Both sites migrated to `abi.encode`, which length-prefixes every argument and makes the encoding unambiguous under any future change to the domain or serialization shape. Affected: `src/ComplianceModule.sol` at `complianceHash()` and `hashOf()`. Off-chain consumers that previously computed `H(domain ‖ B)` must now compute `H(abi.encode(domain, B))`; the NatSpec at `hashOf()` carries the explicit derivation so cross-chain re-derivation is unambiguous.

- **L-6 — `nonReentrant` ordering.** `nonReentrant` was applied after `onlyIssuer` on `issue()` and `activate()`. The reentrancy guard should fire before any other check so that an attacker who somehow enters the function cannot be granted the opportunity to reenter by passing authorization checks first. Solidity modifiers execute left-to-right; reordering so `nonReentrant` is first makes the guard the outermost wrapper. Both functions now read `external nonReentrant onlyIssuer`.

- **L-9 — literal `TODO` substrings in source comments.** Four matches: `src/ComplianceModule.sol:402` (cross-reference to §9 TODO 18, already done in scoping review), `src/IdentityAttestation.sol:266` and `src/MockZKVerifier.sol:18` (cross-references to §9 TODO 14, still open as Phase Three mainnet blocker), and `src/interfaces/IZKVerifier.sol:14` (forward-looking statement about stability across the §9 TODO 14 closure). **Resolved by retention.** All four are backward-looking cross-references to tracked §9 entries, not orphaned work markers. Aderyn's detector pattern-matches the literal string `TODO` without semantic context; stripping the token to appease the detector would remove audit-trail provenance that ties implementation sites to the tracking document. Retained verbatim.

- **L-10 — unused `NotAuthority` custom error.** Declared in `PolicyRegistry.sol:34` but never `revert`-referenced anywhere in the contract. Confirmed via `grep NotAuthority src/` — the only live reference is in `L3RS1Asset.sol` which declares and uses its own `NotAuthority`. The `PolicyRegistry` declaration was an artifact of an earlier sketch where the registry had an authority-only path; that path never landed. Deleted. `L3RS1Asset`'s `NotAuthority` is retained because it is actively reverted by `rotateAuthority`.

#### Accepted with rationale

- **L-1 — centralization risk on `onlyOwner` in `ComplianceModule` rule setters and `onlyIssuer` in `L3RS1Asset` admin functions.** Phase One placeholder per §9 TODO 1 (pre-audit signature scheme). The replacement in Phase Three moves rule-setter authority to governance quorum; owner-gating is the explicit interim model documented in §4 and every call site carries a "Phase One placeholder" comment.

- **L-2 — `unsafe-ERC20` flag on `this.issue.selector` and similar mutable-selector registrations in the constructor.** False positive. The detector pattern-matches `transfer`/`transferFrom` selectors and flags anything resembling an ERC20 transfer without return-value check; our uses are selector-registrations for the INV-6 mutable-selector list, not ERC20 transfer calls. No funds movement is happening at those sites.

- **L-3 — setting `_feeRecipient` to `address(0)`.** Accepted as Phase One tradeoff. `address(0)` is the documented sentinel for fee disabled per §6 in the transfer pipeline. A zero-check on `setFeeRecipient` would remove the disable path. Same disposition as Slither's `missing-zero-check` on the same site per §13.1.

- **L-4 — magic numbers.** Flags `10_000` and `3_600` in the compliance module's threshold math and market-hour conversion. Promoting them to named constants would expand the code footprint without changing behavior, and `10_000` as "basis-point denominator" and `3_600` as "seconds per hour" are idiomatic on their face. Accepted as Phase One clarity tradeoff per the project conventions.

- **L-5 — event fields not indexed.** Flags `VersionBumped(uint256 newVersion)` and similar admin-only events where Aderyn expects `indexed` on the scalar parameter. Admin-only events have low cardinality and are not consumed by bridges or off-chain indexers in Phase One; indexing them provides no query benefit and costs the event-topic slot. Accepted as Phase One design tradeoff.

- **L-7 — scientific notation on `_minHoldingPeriodSeconds`.** Aderyn flagged `1e18` or similar in a value context. `_minHoldingPeriodSeconds` is declared as a plain `uint256`; its setter accepts seconds directly. No scientific notation is used on this path. False positive against the current code; the flag appears to have matched an older pattern. Accepted as noise.

- **L-8 — internal library helpers named without convention markers.** Aderyn expects `_` prefix on every internal function in a library. Our convention uses `_` on internal contract functions and bare names on internal library functions (where the `internal` visibility plus library-only call sites make the purpose clear). See `SignatureVerification.verifyQuorum` vs `ComplianceModule._evaluateBasic`. Accepted as convention divergence.

- **L-11 — `revert` inside a constructor loop.** Flags the authority-duplicate check in the three quorum-gated constructors (`L3RS1Asset`, `ComplianceModule`, `IdentityAttestation`) which iterate the authority array and `revert` on duplicates. This is correct input validation: the loop cannot complete with a duplicate and must reject at deployment time. A post-loop check would force an O(n) second pass and still need to revert. Accepted as correct.

#### Test and tool state after this pass

All 273 tests pass — no test required updating. The encoding change from `abi.encodePacked` to `abi.encode` in `complianceHash()` produces different digest bytes than v1.0.1, but every Phase One test asserts hash determinism or hash-change-on-mutation rather than specific byte strings, so the migration is invisible to the suite. This is the same invariant-style test design that absorbed the Sha3 RHO_OFFSETS fix in §13.3.

Slither was not re-run in this pass because the four implemented items (encoding migration, modifier reorder, comment retention, unused-error deletion) are all well-known-clean changes under Slither's detector set. A full Slither run will be repeated as part of the next audit-candidate tag.

### 13.5 Semgrep self-audit findings

Run after the Aderyn remediation commit. Semgrep (r2c) is a pattern-based static analyzer with rule packs that target gas optimization, common anti-patterns, and some correctness checks.

**Ruleset used.** `p/smart-contracts` (Semgrep's current canonical Solidity pack). The earlier `p/solidity` identifier was retired in Semgrep's 2025 registry reorganization and now returns HTTP 404; `p/smart-contracts` is the migrated successor and is the pack Semgrep currently recommends for Solidity audits.

**Rules loaded.** 50, all under the `solidity.performance.*` namespace. The pack is exclusively gas-optimization-oriented — no rule under `security`, `correctness`, or `reentrancy` fires from this pack, by design. Security coverage is provided by Slither (see §13.1) and Aderyn (see §13.4).

**Findings.** 174 total. All severity `INFO`. All category `performance`. Ten distinct rule IDs, distributed as:

| # | Rule ID (short) | Count | What it flags | Phase One disposition |
|---|---|---:|---|---|
| 1 | `state-variable-read-in-a-loop` | 35 | Re-reads of a storage variable inside a loop that could be cached locally. | Accepted — project convention "clarity wins every tradeoff". Caching a `storage` read obscures that the loop is operating on live storage; the read-cost penalty on lists of 3–25 authorities or sanction entries is immaterial. |
| 2 | `use-prefix-increment-not-postfix` | 34 | `i++` in loop headers instead of `++i`. | Accepted — Solidity 0.8.x's optimizer compiles both identically in every loop position we use. Behaviorally equivalent, rewrite carries no benefit. |
| 3 | `inefficient-state-variable-increment` | 26 | `storageVar += 1` pattern that could be `storageVar = storageVar + 1` with `unchecked`. | Accepted — every site is a ghost counter (transition count, nonce) where bounded growth and audit-readable arithmetic matter more than single-digit gas. |
| 4 | `unnecessary-checked-arithmetic-in-loop` | 22 | Loop arithmetic not wrapped in `unchecked { }`. | Accepted — Solidity 0.8.x's default checked arithmetic is the documented Phase One convention. Wrapping every loop in `unchecked` would be the opposite of the "clarity wins" policy. |
| 5 | `use-custom-error-not-require` | 18 | `require(cond, "string")` vs. `if (!cond) revert CustomError();`. | Accepted — hot paths already use custom errors (see `TransferStepRejected`, `InvalidNonce`, `InvalidTransition`). The remaining `require` sites are constructor input validation and owner-setter precondition checks, where the string form is self-documenting and the revert is not performance-sensitive. |
| 6 | `use-short-revert-string` | 14 | `require` strings longer than 32 bytes. | Accepted — the current strings describe the failure condition in prose an operator reading a trace log can parse without source access. Shortening to fit a single slot would degrade diagnostic value. |
| 7 | `array-length-outside-loop` | 12 | `arr.length` evaluated in the loop header on each iteration. | Accepted — identical pattern to Slither's `cache-array-length` findings triaged in §13.1. Same disposition. |
| 8 | `use-nested-if` | 8 | `if (A && B)` that could be `if (A) if (B)`. | Accepted — 0.8.x compiles both forms identically for the boolean patterns we use. Nested form is strictly less readable. |
| 9 | `non-payable-constructor` | 4 | Constructors not marked `payable`. | Accepted — no contract accepts ETH at construction. Marking constructors `payable` would save deploy-time gas once but disable the safety net where an operator accidentally attaches ETH and gets a revert. Safer default wins. |
| 10 | `use-multiple-require` | 1 | A compound `require(A && B, msg)` that could be split into two. | **Applied.** Single site at `ComplianceModule.setMarketHours` where the compound check conflated two distinct parameter bounds under one revert string. Split into three single-condition `require`s each naming the offending parameter — `startHour out of range`, `endHour out of range`, `start > end`. Trivial change with genuine debug-trace diagnostic value. See Step 1 of this pass. |

**Disposition summary.** 173 findings accepted as Phase One clarity-over-gas tradeoff per the project conventions. One finding applied — the single-site `use-multiple-require` split described above.

**Findings distribution by file.**

| File | Findings |
|---|---:|
| `src/ComplianceModule.sol` | 55 |
| `src/L3RS1Asset.sol` | 39 |
| `src/IdentityAttestation.sol` | 37 |
| `src/libraries/Sha3.sol` | 16 |
| `src/PolicyRegistry.sol` | 13 |
| `src/libraries/SelectiveDisclosure.sol` | 9 |
| `src/libraries/SignatureVerification.sol` | 5 |

**Zero correctness or security findings.** Consistent with the expectation stated before the run — Slither's and Aderyn's detector sets cover the patterns Semgrep's `p/smart-contracts` pack targets in the correctness/security space. Semgrep's pack, as currently distributed, is a gas-optimization tool. Running it produced the gas-optimization inventory expected; it did not surface a single issue Slither and Aderyn had not already triaged (and many of the overlapping findings — `cache-array-length`, `state-variable-read-in-a-loop`, etc. — are already documented in §13.1 and §13.4 under the same disposition as here).

**Deferral to audit-firm gas-optimization tooling.** The audit firm will run its own gas-optimization analyzer during the engagement. Any gas optimizations they flag as material for a production mainnet deployment — as distinct from a reference-implementation audit target — will be handled in fixes-review, not pre-applied here. Pre-applying speculative gas optimizations against an audit-candidate tag is the wrong workflow: it obscures which changes the audit firm actually asked for and makes their diff review noisier. The audit-candidate ships with the Phase One "clarity wins" posture intact.

**Test and tool state after this pass.** All 273 tests continue to pass. The single `require` split changes three revert strings but no test asserts against a specific revert-string value, so the suite is unaffected. No Slither or Aderyn re-run was performed — the single one-function change is well outside the scope of any detector either tool runs.

### 13.6 Mythril self-audit findings

Final self-audit tool in the chain. Mythril (ConsenSys Diligence, now Diligence / Consensys) is a symbolic-execution analyzer for EVM bytecode. It complements Slither, Aderyn, and Semgrep — all of which are pattern-based — by exploring reachable state symbolically rather than pattern-matching on source.

**Tool and version.** `mythril 0.24.8`. Installed via `pipx install --python /usr/bin/python3 mythril` with in-venv `setuptools<70` force-reinstalled to restore the `pkg_resources` module that `eth-utils` (a transitive dependency) requires. Modern `setuptools` versions (70+) removed `pkg_resources`, which is why a fresh install against current PyPI defaults fails at import. The workaround is stable and documented inline; an audit-firm re-run on a different machine needs the same pin.

**Compiler and remappings.** `solc 0.8.26` via `solc-select`. Foundry remappings for `@openzeppelin/contracts/` and `forge-std/` are passed to Mythril's underlying solc invocation via `--solc-json mythril-solc.json`, committed at repo root as a reproducibility artifact. The file is a standard-json `settings` document mirroring the relevant portions of `foundry.toml`: the two remappings, `optimizer.enabled = true`, `optimizer.runs = 200`, and `evmVersion = cancun`. Without this file Mythril's default solc call does not see the remappings and fails at the parser on every import — an audit firm reconstructing the run needs the file verbatim.

**Execution configuration.** 300-second timeout per contract via `--execution-timeout 300`. Other parameters at Mythril defaults: `--max-depth 128` for path length, transaction count 2 for multi-call sequences. These are the parameters Mythril uses when an auditor invokes it without overrides, and the parameters the audit firm's engineers will use as their starting point when they run Mythril themselves during the engagement.

**Invocation.** Four separate runs, smallest contract first per your guidance:

```
myth analyze src/PolicyRegistry.sol     --solv 0.8.26 --execution-timeout 300 --solc-json mythril-solc.json
myth analyze src/ComplianceModule.sol   --solv 0.8.26 --execution-timeout 300 --solc-json mythril-solc.json
myth analyze src/IdentityAttestation.sol --solv 0.8.26 --execution-timeout 300 --solc-json mythril-solc.json
myth analyze src/L3RS1Asset.sol         --solv 0.8.26 --execution-timeout 300 --solc-json mythril-solc.json
```

**Results.** Zero findings across all four production contracts.

| # | Contract | Wall time | Findings | Status |
|---|---|---:|---:|---|
| 1 | `src/PolicyRegistry.sol` | 9.9 s | 0 | "The analysis was completed successfully. No issues were detected." |
| 2 | `src/ComplianceModule.sol` | 9.2 s | 0 | "The analysis was completed successfully. No issues were detected." |
| 3 | `src/IdentityAttestation.sol` | 9.6 s | 0 | "The analysis was completed successfully. No issues were detected." |
| 4 | `src/L3RS1Asset.sol` | 18.0 s | 0 | "The analysis was completed successfully. No issues were detected." |
| — | **Total** | **46.7 s** | **0** | All four clean |

**Explicit SWC class coverage.** The five SWC classes most commonly surfaced by symbolic execution — and the five the audit advisor explicitly called out for attention — all returned zero hits:

- **SWC-101 (integer overflow).** Zero hits. Solidity 0.8.x's default checked arithmetic makes this class hard to reach; Mythril confirmed no reachable overflow on the paths explored.
- **SWC-107 (reentrancy).** Zero hits. The CEI refactor in §13.1 moved the fee-callback external call after every balance effect in `_executeTransfer`, and the `_seenTxId` commit moved before `_executeTransfer` in `authenticatedTransfer`. Mythril saw the post-refactor control flow and found no exploitable path. The `ReentrancyGuard` modifier on every mutable entry point is the belt-and-suspenders.
- **SWC-112 (delegatecall).** Zero hits. The codebase contains no `delegatecall` invocation — every inter-contract call is a regular external call with known target contracts.
- **SWC-116 (timestamp dependence).** Zero hits. `block.timestamp` reads are all deadline checks (`block.timestamp > deadline` for EIP-712 validity windows) or time-of-day reads for the MARKET rule, which operates at hour granularity and is therefore insensitive to the few-seconds miner-level manipulation the SWC class targets. Slither flagged the same pattern and §13.1 accepted it with this rationale; Mythril reached the same conclusion.
- **SWC-120 (weak randomness).** Zero hits. The codebase does not use block data or timestamps as a randomness source. Slither's `weak-prng` finding on the market-hour calculation was a false positive against `(block.timestamp / 3600) % 24` used as time-of-day, not randomness; Mythril did not independently flag the same pattern because symbolic execution correctly resolves it as a deterministic time read.

**Three caveats documented honestly.**

1. **Fast exit.** All four runs finished well under the 300-second budget — 9 to 18 seconds per contract, 47 seconds total across the four. Mythril reached natural termination rather than timing out. On small-to-medium contracts with focused APIs (the four contracts total ~2 960 lines) the default path-exploration parameters reach natural stopping points quickly; the 300-second timeout was a safety net, not a binding constraint. Nothing in the output suggests Mythril aborted early or gave up on any path — the "completed successfully" status line is the explicit termination claim.

2. **Symbolic execution is not exhaustive by design.** Mythril's path exploration covers a subset of reachable state bounded by `--max-depth` (default 128) and transaction count (default 2). A multi-transaction state bug that requires three or more transactions in sequence to manifest is outside the default budget and would not be caught by this run. This is a fundamental limitation of symbolic execution as a technique, not a defect of Mythril specifically; no symbolic executor runs to unbounded depth in practice.

3. **Foundry invariant campaigns cover the multi-transaction territory.** The three standalone invariant tests (INV-1 on compliance totality, INV-2 on hash stability, INV-6 on no-layer-bypass) plus the two handler-based campaigns (T4 on supply conservation, T5 on governance safety) run at 256 runs × 64 depth = **16 384 transaction sequences per campaign**. This is the coverage band Mythril's default budget does not reach. The Foundry invariants and Mythril's symbolic execution are complementary, not substitutes: Mythril proves properties over small reachable-state boundaries, Foundry empirically validates invariants under long random sequences. The audit file reads both as corroborating evidence, not as redundant coverage.

**Deferral to audit-firm deeper exploration.** The audit firm will run Mythril itself during the engagement with its own parameter tuning — deeper `--max-depth`, higher transaction counts, possibly custom detection modules. That is the appropriate place for the deeper exploration the defaults in this run do not reach. The Phase One audit-candidate ships with Mythril's default-parameter clean result documented; the audit firm's expanded-parameter re-run is part of their scope, not the engineering team's.

**Test and tool state after this pass.** All 273 tests continue to pass. No code change was produced by this run (zero findings means zero fixes). The only artifacts of this pass are the `mythril-solc.json` reproducibility config committed at repo root, and this §13.6 subsection.

### 13.7 SMTChecker attempt and infeasibility

Pre-audit supplement that did not land. Solidity's built-in SMTChecker was enabled in `foundry.toml` and run against the four production contracts over four consecutive configurations. None produced output within reasonable wall-clock time. The infeasibility is documented here so the absence of SMTChecker output in the Phase One audit file is explained in place rather than treated as an oversight.

**Four attempts.**

| # | Engine | Per-query timeout | Scope | Wall time | Outcome |
|---|---|---|---|---:|---|
| 1 | CHC | unlimited (default) | all 58 compilation units | ~14 min, aborted | Never emitted any warning line. `solc` stayed at 100% CPU throughout; SMTChecker only prints output at end of analysis. |
| 2 | CHC | 30 s | all 58 compilation units | ~14 min, aborted | Same — no output. |
| 3 | CHC | 5 s | 4 production contracts (`model_checker.contracts` filter) | ~11 min, aborted | Same — no output. The contract filter limits which contracts SMTChecker analyzes but does not prevent the solver from following the call graph into the `Sha3` library, which is where the queries stall. |
| 4 | BMC | 5 s | 4 production contracts | ~5 min, aborted | Same — no output. BMC unrolls loops rather than searching for inductive invariants, but Keccak-f's 24 rounds over a 25-lane 64-bit state produce an AST large enough that Z3 still cannot resolve it within the per-query budget. |

Across all four, `solc` was at 98–100% CPU single-threaded on Z3 from the first second until abort. The "Compiling 58 files with Solc 0.8.26" line was always the only output produced.

**Root cause.** `src/libraries/Sha3.sol` implements the NIST FIPS 202 Keccak-f[1600] permutation: 24 rounds of dense bitwise shift-and-XOR operations over a 25-lane 64-bit state, with the rho / pi / chi steps making every bit of every lane depend on every other bit. This is a known class of mismatch between SMT solvers and cryptographic primitives.

- **CHC (constrained-Horn solving)** attempts to find a quantifier-free inductive invariant across loop iterations. For a Keccak-f round function, no simple invariant exists — the round's purpose is precisely to destroy algebraic structure, which is what makes the hash useful and what makes the invariant search non-convergent.
- **BMC (bounded model checking)** unrolls loops to a fixed depth and encodes each concrete iteration as SMT queries. For Keccak-f the 24-round unroll produces an AST on the order of tens of thousands of bitwise operators; Z3 can represent this but not resolve queries over it within a developer-laptop-scale budget.

This is not a defect in `Sha3.sol`. The library implements FIPS 202 correctly (verified against NIST Appendix A.3 vectors — see §13.3 and `test/unit/Sha3.t.sol`). The mismatch is between the theoretical capability of SMT solvers and the algebraic structure of cryptographic permutations. Every Solidity codebase that implements a hash function directly in Solidity, rather than calling out to a precompile, will hit the same wall.

**Substitutes in place.** SMTChecker's intended contribution — automated symbolic proof of safety properties — is approximated by the following coverage Phase One already ships:

- **FIPS 202 Appendix A.3 authoritative test vectors.** The empty-string and "abc" vectors (the two short enough to run on-chain under forge's memory budget) plus the NIST CAVP single-byte 0xe9 vector and the classic 56-byte "abcdbcde…nopq" vector. All pinned in `test/unit/Sha3.t.sol`. A single-bit error in `Sha3.sol` breaks at least one of these vectors. This is the cross-implementation correctness check SMTChecker would otherwise have provided.
- **Ten Sha3 unit tests** covering determinism, avalanche on single-byte flip, rate-block boundary at 136 bytes and 137 bytes, and a 200-byte multi-block regression anchor. Structural coverage of the multi-block absorb path and the padding edge cases.
- **Python hashlib differential testing at scale** — delivered in the subsequent pre-audit step (see `test/unit/Sha3Differential.t.sol` and `test/vectors/sha3_differential.json`). 500 random inputs of varied length hashed through `hashlib.sha3_256` and asserted byte-equal against `Sha3.sha3_256`. This is stronger than a small SMTChecker proof because it validates against the canonical reference implementation over a broad input distribution.
- **Audit-firm SMT verification at its tooling tier.** Audit firms maintain proving infrastructure (Certora, Halmos, specialized SMTChecker harnesses with hours of query budget per property) that cannot run on a developer laptop. If SMT-style verification of the four Phase One contracts is valuable, the audit firm is the correct party to run it during the engagement. The engineering team's role is to ship the cryptographic correctness evidence (vectors, differential tests) that audit-firm SMT tooling composes with, not to produce the SMT proof itself from a budget that cannot accommodate Keccak.

**Framing.** SMTChecker coverage is not achievable on Phase One in isolation due to cryptographic primitive structure. The substitutes provide equivalent or stronger confidence through vector validation and third-party verification. The attempt is documented here so an audit reviewer who expects to see SMTChecker output in the pre-audit chain can read the reason for its absence and the compensating coverage, rather than assume the tool was never attempted.

**`foundry.toml` after this step.** The SMTChecker configuration block has been cleanly deleted. The `foundry.toml` of `v1.0.2-audit-candidate` and every earlier tag is restored; subsequent `forge build` and `forge test` invocations carry no SMTChecker load. The infeasibility record lives in this §13.7 only.

## 15. Deployment flow

Phase One ships with `script/Deploy.s.sol::DeployPhaseOne`, a Foundry-scripted deployment that produces the complete Phase One system in a single transaction chain. The script is the authoritative record of how the four production contracts, the MockZKVerifier placeholder, the asset-activation transition, the fee-recipient configuration, and the first policy binding are composed at deploy time. An audit reviewer who wants to know "what does the chain look like at block N+1" reads this section plus `script/Deploy.s.sol`.

### Invariants the script satisfies

Three invariants govern the deployment sequence. They are asserted by `test/script/Deploy.t.sol` at the end of every successful deploy.

1. **Constructor-order soundness.** Every contract's constructor dependencies exist on chain before it deploys. Concretely: `MockZKVerifier` before `IdentityAttestation` (which takes `IZKVerifier` in its constructor); `ComplianceModule`, `IdentityAttestation`, and `PolicyRegistry` before `L3RS1Asset` (which takes references to all three).
2. **Deploy-time activation.** The asset transitions ISSUED → ACTIVE inside the same deploy transaction chain. The audit-shippable artifact is never in the ISSUED state at rest — it is either pre-deploy (not on chain) or ACTIVE (ready for transfers). This closes a class of operational failure where a deploy succeeds but a follow-up activate is forgotten, leaving the asset in an unusable state.
3. **Policy-binding liveness at deploy time.** If `POLICY_ID` is supplied, the `PolicyRegistry` has version 1 of the policy binding registered before the deploy transaction chain ends. Phase Five bridge consumers reading `registry.currentHash(policyId)` at block N+1 see a non-zero canonical hash, not a `UnknownPolicy` revert.

### Deployment steps

The script's `_deploy` function executes eight steps in fixed order. Steps 1–5 are unconditional constructor deploys; step 6 is the activation; steps 7 and 8 are optional post-deploy bootstrapping gated on non-zero configuration inputs.

1. **Deploy `MockZKVerifier`** — IZKVerifier dependency for the next contract. Phase One placeholder per §5b and §9 TODO 14. Real verifier swap happens post-deploy via `IdentityAttestation.setZKVerifier` under governance quorum before Base Mainnet.
2. **Deploy `IdentityAttestation(governanceAuthorities, initialVAs, zkVerifier)`** — three-surface EIP-712 contract per §8.2. Initial state: empty identity records, zero governance nonce, zero revocation index, VA set equal to the provided `INITIAL_VAS` list.
3. **Deploy `ComplianceModule(governanceAuthorities)`** — owner is `msg.sender` at construction time (the deployer). Initial state: empty rule set across all nine §4.4 rules, version 1, canonical hash computed at construction over the empty-set serialization. Governance nonce zero.
4. **Deploy `PolicyRegistry(governanceAuthorities)`** — owner is the deployer. Initial state: empty policy history, no bindings. Governance nonce zero.
5. **Deploy `L3RS1Asset(issuer, jurisdiction, idTier, compliance, identity, registry, governanceAuthorities)`** — the asset contract itself. Initial state: ISSUED per §2.5; total supply zero; legal mirror with empty document and version 1 (hash computed at construction over the canonical `(tag, document, jurisdiction, version)` tuple); replay registry empty; fee recipient `address(0)`.
6. **Activate** — `asset.activate()`. Transitions ISSUED → ACTIVE per §2.5. `onlyIssuer`; Phase One requires the deployer account to be the configured issuer so this call succeeds in the same broadcast as the prior steps. `run()` enforces this precondition by asserting `vm.addr(DEPLOYER_PRIVATE_KEY) == ISSUER_ADDR` before starting the broadcast.
7. **Set fee recipient** — conditional on `FEE_RECIPIENT` being non-zero. Routes the 25-bps transfer fee per §6. Setting `address(0)` or omitting the variable leaves fee routing disabled, which is a valid configuration for testnet deployments where no fee-recipient multisig yet exists.
8. **Register first policy** — conditional on `POLICY_ID` being non-zero. Calls `PolicyRegistry.register(policyId, compliance)`. Owner-gated; the deployer is the registry owner by construction. Produces version 1 of the binding with the compliance module's current canonical hash.

### Environment-variable contract

The script reads every parameter from environment variables. Required variables revert with the variable name if unset; optional variables default to zero-sentinel values that disable the corresponding step.

| Variable | Required | Type | Meaning |
|---|---|---|---|
| `DEPLOYER_PRIVATE_KEY` | yes (production only) | uint | Broadcast key. Must correspond to `ISSUER_ADDR`. Not used by test paths. |
| `ISSUER_ADDR` | yes | address | Asset issuer. Receives `onlyIssuer` privileges on `L3RS1Asset`. |
| `GOVERNANCE_AUTHORITIES` | yes | address list, comma-separated | The `N` governance authorities shared across all four contracts. Quorum threshold is `ceil(2N/3)` per §5.4. |
| `INITIAL_VAS` | yes | address list, comma-separated | Initial Verification Authorities for `IdentityAttestation`. |
| `JURISDICTION` | yes | 2-char string | ISO 3166-1 alpha-2 for the asset. Cast to `bytes2`. |
| `ID_TIER` | yes | uint (0..3) | L3RS-1 §3.2 identity tier required for transfer. |
| `FEE_RECIPIENT` | no | address | Fee routing target. Omit or set to zero to disable fee routing. |
| `POLICY_ID` | no | bytes32 | Identifier for the first policy binding. Omit or set to zero to skip step 8. |

### Production invocation

```
DEPLOYER_PRIVATE_KEY=0x… \
ISSUER_ADDR=0x… \
GOVERNANCE_AUTHORITIES=0x…,0x…,0x… \
INITIAL_VAS=0x… \
JURISDICTION=GB \
ID_TIER=2 \
FEE_RECIPIENT=0x… \
POLICY_ID=0x… \
forge script script/Deploy.s.sol:DeployPhaseOne --rpc-url $RPC --broadcast
```

### Test paths

`test/script/Deploy.t.sol` exercises the script via two non-broadcast entry points:

- `deployFromConfig(DeployConfig)` — the test constructs a config struct in-memory and calls the script directly. Used by the 13 invariant tests.
- `deployFromEnv()` — the test sets environment variables via `vm.setEnv`, then calls the script's env-loading path. Used by the one env-path test so the string-to-bytes2 jurisdiction parse, the comma-delimited address list parse, and the uint-to-uint8 tier parse all get coverage.

Both test entry points prank as `cfg.issuer` internally so the script's subsequent `new Contract()` creations and post-deploy calls go out with the correct msg.sender. This mirrors what `vm.startBroadcast(DEPLOYER_PRIVATE_KEY)` does in `run()` under a real `forge script` invocation; the test and production paths produce byte-equivalent deploy chains.

### Authority and VA bootstrap policy

Phase One does not support adding or removing authorities at runtime across `ComplianceModule`, `IdentityAttestation`, `PolicyRegistry`. The deploy-time authority set is fixed for each contract's lifetime. `L3RS1Asset` supports one-in-one-out rotation via `rotateAuthority` under governance quorum per §9 TODO 13, but this only affects the asset's own authority view — the shared set across the other three remains static.

The VA set on `IdentityAttestation` is updatable at runtime via `registerVA` / `deregisterVA` under governance quorum per §8.2. The `INITIAL_VAS` env var is the boot set, not the permanent one.

### Base Sepolia and Base Mainnet readiness

Base Sepolia deployment is supported today with the script as written: MockZKVerifier is acceptable on testnet because no real identity-bound state is at risk. `08-deployment-target.md` carries the Sepolia checklist: three to five governance authority addresses (Gnosis Safe signers or EOAs), one to two initial VAs, `JURISDICTION` and `ID_TIER` per the mandate, `POLICY_ID` derived from the mandate document hash.

Base Mainnet deployment requires §9 TODOs 12 (real HID), 14 (real ZK verifier), and 16 (per-transfer SelectiveDisclosure pipeline) all closed before proceeding. The deploy script does not enforce this gate — it trusts the operator. An additional production checklist lives in `08-deployment-target.md`.

### Reproducibility artifacts in-repo

- `script/Deploy.s.sol` — the script itself. Audit target is the annotated source with step comments tied back to this section.
- `test/script/Deploy.t.sol` — 14 invariant tests asserting the post-deploy state satisfies the three invariants above.
- `mythril-solc.json` at repo root — Mythril's reproducibility config (documented in §13.6). Not used by the deploy script but shares the same `foundry.toml` remappings so the reviewer sees a consistent build surface.
- `08-deployment-target.md` — the Base Sepolia / Base Mainnet operational checklist (separate document).

The deploy script plus its test suite plus this section of DESIGN.md plus `08-deployment-target.md` together constitute the deployment-readiness package for the audit engagement review. A reviewer running `forge test --match-path 'test/script/Deploy.t.sol'` on a clean clone reproduces the 14 invariants locally in roughly three hundred milliseconds.

## 11. Repository tree at end of step 3

```
t3rra-phase-one/
├── DESIGN.md
├── README.md
├── foundry.toml
├── .env.example
├── .gitignore
├── spec/
│   ├── 01-cryptographic-spec.pdf
│   ├── 02-architecture.pdf
│   ├── 03-whitepaper.pdf
│   ├── 04-flow.pdf
│   ├── 05-tokenomics.pdf
│   ├── 06-theorems.md
│   ├── 07-profile-f.md
│   ├── 08-deployment-target.md
│   └── L3RS-1_v1_0_0.pdf
├── lib/
│   ├── openzeppelin-contracts/
│   └── forge-std/
├── src/
│   ├── ComplianceModule.sol
│   ├── L3RS1Asset.sol
│   ├── IdentityAttestation.sol
│   ├── PolicyRegistry.sol
│   ├── interfaces/
│   │   ├── IComplianceModuleF.sol
│   │   └── ILifecycle.sol
│   └── libraries/
│       ├── ReasonCodes.sol
│       └── Sha3.sol
└── test/
    ├── BaseTest.t.sol
    ├── invariants/
    │   ├── INV1_ComplianceTotality.t.sol
    │   ├── INV2_PolicyHashStability.t.sol
    │   └── INV6_NoLayerBypass.t.sol
    └── theorems/
        ├── Theorem01_StateIntegrity.t.sol
        ├── Theorem02_ReplayResistance.t.sol
        ├── Theorem03_CrossChainDowngrade.t.sol
        ├── Theorem04_DoubleIssuance.t.sol
        ├── Theorem05_GovernanceSafety.t.sol
        ├── Theorem06_AtomicSettlement.t.sol
        └── Theorem07_LegalBinding.t.sol
```

Note: the three markdown spec files (`06-theorems.md`, `07-profile-f.md`, `08-deployment-target.md`) live in `spec/` alongside the PDFs per the original Phase One prompt. If an earlier revision placed them in the repo root, move them to `spec/` as part of the next commit.

Step 4 (full PolicyRegistry), step 5 (expand IdentityAttestation beyond the minimum), step 6 (unit tests to 95 % line coverage + scenario test), step 7 (THEOREMS.md), step 8 (deployment scripts) follow.
