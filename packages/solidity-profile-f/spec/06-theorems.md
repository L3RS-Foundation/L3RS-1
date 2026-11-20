# Theorem and invariant matrix — T3RRA corpus

This file catalogues every formal claim in the T3RRA cryptographic corpus and the L3RS-1 v1.0.0 standard, and maps each to its phase of the engineering build. It is the source of truth for what Phase One must test.

The corpus contains four classes of formal claim. Seven L3RS-1 theorems are stated in the L3RS-1 v1.0.0 standard §15, plus a Composability Theorem and a Certificate Integrity proposition. Seven T3RRA theorems are stated in the Cryptographic Specification Part II rev B. Ten L3RS-1 invariants are stated across §10, §12, §13, §14, §17 of the L3RS-1 standard. Six T3RRA system invariants are stated in the Architecture paper §7.

**Phase One implements the L3RS-1 Profile F (Hybrid Public-Private Architecture) reference implementation on Base.** All seven L3RS-1 theorems are in scope for Phase One. Most of the ten L3RS-1 invariants are in scope. None of the seven T3RRA theorems are in scope for Phase One — they apply to Layers 2 through 5 built in later engineering phases. Three of the six T3RRA system invariants are in scope (INV-1 full, INV-2 partial, INV-6 partial).

---

## Part A — The seven L3RS-1 theorems (Phase One in scope)

Extracted verbatim from L3RS-1 v1.0.0 Technical Annex, February 24, 2026, §15.

### Theorem 15.1 (Theorem 1): State Integrity

**Source:** L3RS-1 v1.0.0 §15.3.

**Formal statement:**

> No unauthorized state transition can occur.

**Proof sketch (from the standard):**

> State transitions are defined as: S_new = f(S_old, event). Where event must pass: ComplianceSuccess ∧ IdentitySuccess ∧ GovernanceSuccess. Since compliance rules are deterministic and blocking, identity validation rejects invalid identity, and governance override requires valid signature (and quorum if applicable), an adversary must break signature unforgeability or bypass compliance evaluation to alter state. Under assumptions, this is computationally infeasible.

**Plain-language restatement:** Every state transition is gated by three checks. Bypassing any check requires breaking a signature or the compliance module. Both are computationally infeasible.

**Phase One applicability:** **YES. Required.**

**Test property:** Foundry invariant test. For every fuzzed sequence of transfer attempts, the L3RS1Asset contract state transitions only if ComplianceSuccess ∧ IdentitySuccess ∧ GovernanceSuccess is satisfied. Any state change that occurs without all three returning true is a test failure. Include negative tests: attempt state transitions with invalid identity, failed compliance, and unauthorized governance — all must revert.

**Test file:** `test/theorems/Theorem01_StateIntegrity.t.sol`.

---

### Theorem 15.2 (Theorem 2): Replay Resistance

**Source:** L3RS-1 v1.0.0 §15.4.

**Formal statement:**

> A previously executed transaction cannot be replayed to produce duplicate state mutation.

**Proof sketch (from the standard):**

> Each transaction includes: TxID = H(sender ‖ receiver ‖ amount ‖ nonce ‖ timestamp). Nonce uniqueness ensures: nonce_new ≠ nonce_previous. Ledger history maintains record of TxID. Replay requires collision in H or reuse of nonce. Under collision resistance, replay is infeasible.

**Plain-language restatement:** Every transaction has a unique identifier built from its components. Replaying the same transaction is cryptographically infeasible.

**Phase One applicability:** **YES. Required.**

**Test property:** Foundry invariant test. Two transactions with identical (sender, receiver, amount) but distinct nonces produce distinct TxIDs. A submitted transaction cannot be resubmitted with the same nonce. The TxID registry rejects duplicates. Include negative tests: attempt to resubmit a successful transaction; attempt to resubmit after state change; attempt to forge a TxID.

**Test file:** `test/theorems/Theorem02_ReplayResistance.t.sol`.

---

### Theorem 15.3 (Theorem 3): Cross-Chain Downgrade Resistance

**Source:** L3RS-1 v1.0.0 §15.5.

**Formal statement:**

> Compliance and governance configuration cannot be downgraded during cross-chain transfer.

**Proof sketch (from the standard):**

> Cross-chain certificate: CID = H(I ‖ StateHash ‖ ComplianceHash ‖ GovHash ‖ Timestamp). Destination verifies: ComplianceHash_dest = ComplianceHash_origin. If adversary modifies compliance: ComplianceHash_dest ≠ ComplianceHash_origin. Verification fails. Under collision resistance, adversary cannot forge equivalent hash for modified compliance.

**Plain-language restatement:** An asset moved across chains must carry identical compliance and governance hashes. Weakening compliance during a bridge transfer fails verification.

**Phase One applicability:** **Partial.** The cross-chain bridge is a Phase Five deliverable. Phase One implements the origin-side structures: the CrossChainMetadata object X per L3RS-1 §13.9, the ComplianceHash and GovHash computations, and the CID construction per §2.12. Phase Five will implement the destination-side verification.

**Test property:** Unit test in Phase One. The CrossChainMetadata object is correctly serialized. ComplianceHash is the correct hash of the canonical ComplianceModule object per §13.11. GovHash is the correct hash of the canonical GovernanceModule object. CID is correctly computed. Any mutation to the compliance or governance module changes ComplianceHash or GovHash and therefore changes CID.

**Test file:** `test/theorems/Theorem03_CrossChainDowngrade.t.sol`.

---

### Theorem 15.4 (Theorem 4): Double Issuance Prevention

**Source:** L3RS-1 v1.0.0 §15.6.

**Formal statement:**

> Global supply remains constant under lock-and-mint or burn-and-mint transfer models.

**Proof sketch (from the standard):**

> Define: Supply_global = Σ Supply_chains. Under lock-and-mint: Supply_origin = Supply_origin − x, Supply_dest = Supply_dest + x. Under burn-and-mint: Supply_origin = Supply_origin − x, Supply_dest = Supply_dest + x. Net effect: Supply_global = constant. If mint occurs without corresponding lock/burn, certificate validation fails.

**Plain-language restatement:** Total supply across all chains is invariant. Minting on one chain requires locking or burning on another.

**Phase One applicability:** **Partial.** Phase One implements supply accounting on Base. The cross-chain mint/burn coupling is Phase Five. In Phase One, total supply on Base is tracked and mint/burn operations update it atomically.

**Test property:** Foundry invariant test on Phase One. Total supply increases only through valid mint operations that produce a mint record. Total supply decreases only through valid burn operations. No state path exists that mutates balances without mint or burn accounting.

**Test file:** `test/theorems/Theorem04_DoubleIssuance.t.sol`.

---

### Theorem 15.5 (Theorem 5): Governance Safety

**Source:** L3RS-1 v1.0.0 §15.7.

**Formal statement:**

> No minority subset of governance authorities can execute restricted override actions.

**Proof sketch (from the standard):**

> Override requires: k ≥ (2/3) N. If adversary controls k < threshold: override validation fails. To succeed, adversary must compromise threshold keys. Thus governance safety reduces to signature unforgeability and key security.

**Plain-language restatement:** Governance overrides require a two-thirds quorum of authorized keys. A minority cannot force an override.

**Phase One applicability:** **YES. Required.**

**Test property:** Foundry invariant test. For every fuzzed subset Q of governance authorities with |Q| < (2/3) N, override attempts produced by Q fail. For every subset Q with |Q| ≥ (2/3) N and valid signatures, overrides succeed. EMERGENCY_ROLLBACK specifically requires quorum per L3RS-1 §5.5 and is not possible without it.

**Test file:** `test/theorems/Theorem05_GovernanceSafety.t.sol`.

---

### Theorem 15.6 (Theorem 6): Atomic Settlement

**Source:** L3RS-1 v1.0.0 §15.8.

**Formal statement:**

> No partial state mutation occurs under settlement failure.

**Proof sketch (from the standard):**

> Settlement defined as: SettlementSuccess ⇐⇒ Compliance ∧ Identity ∧ Governance ∧ Fee ∧ StateCommit. If any component fails: SettlementSuccess = FALSE. State commit executed only after all validations. Therefore no partial state persists.

**Plain-language restatement:** A transfer either completes in full or has no effect. No intermediate state is ever observable.

**Phase One applicability:** **YES. Required.**

**Test property:** Foundry invariant test. For every transfer attempt, if any of the five validation components fails (compliance, identity, governance, fee, state-commit), no state variable is mutated. Verify pre-state equals post-state under every failure mode. Reentrancy guards are present on all external calls.

**Test file:** `test/theorems/Theorem06_AtomicSettlement.t.sol`.

---

### Theorem 15.7 (Theorem 7): Legal Binding Integrity

**Source:** L3RS-1 v1.0.0 §15.9.

**Formal statement:**

> Legal document reference cannot be altered without detection.

**Proof sketch (from the standard):**

> Legal mirror contains: LH = H(document ‖ jurisdiction ‖ version). Modification of document changes LH. Under collision resistance, adversary cannot produce alternate document with same LH. Thus legal binding is cryptographically anchored.

**Plain-language restatement:** The legal document hash is bound to the asset. Altering the underlying document changes the hash and is therefore detectable.

**Phase One applicability:** **YES. Required.**

**Test property:** Unit test. The LegalMirror object stores LH = H(document ‖ jurisdiction ‖ version) per L3RS-1 §12.3. Any modification to any of the three inputs changes LH. The LegalMirror object's authority signature (if present) verifies correctly against the authority public key. Legal amendments produce a new LH and are recorded with the amendment object per §12.7.

**Test file:** `test/theorems/Theorem07_LegalBinding.t.sol`.

---

## Part B — Supplementary L3RS-1 claims

### Theorem 15.8 (Composability Theorem)

**Source:** L3RS-1 v1.0.0 §15.10.

**Formal statement:**

> L3RS-1 invariants are composable across chains.

**Phase One applicability:** Out of scope. Depends on cross-chain deployment. Phase Five.

### Proposition 15.1 (Certificate Integrity)

**Source:** L3RS-1 v1.0.0 §15.11.

**Formal statement:**

> Assuming collision resistance of H and canonical serialization, it is computationally infeasible to alter any of (S, C, G, J, L) without changing CID.

**Phase One applicability:** **Partial.** Phase One verifies that canonical serialization per §13.11 produces correct hashes. The CID construction is verified as part of Theorem 15.3.

---

## Part C — The ten L3RS-1 invariants

Extracted from L3RS-1 v1.0.0 §15.11 (summary) with source sections cited.

### I1 — State Integrity
**Source:** L3RS-1 v1.0.0 §10.5.
**Phase One:** YES. Tested by Theorem 15.1.

### I2 — Compliance Integrity
**Source:** L3RS-1 v1.0.0 §10.6.
**Phase One:** YES. ComplianceModule enforcement at every state transition.

### I3 — Identity Integrity
**Source:** L3RS-1 v1.0.0 §10.7.
**Phase One:** YES. IdentityAttestation validation prior to transfer for ID ≥ 1.

### I4 — Governance Integrity
**Source:** L3RS-1 v1.0.0 §10.8.
**Phase One:** YES. Tested by Theorem 15.5.

### I5 — Downgrade Resistance
**Source:** L3RS-1 v1.0.0 §10.10.
**Phase One:** Partial. Origin-side structures only; destination-side in Phase Five.

### I6 — Legal Binding
**Source:** L3RS-1 v1.0.0 §12.10.
**Phase One:** YES. Tested by Theorem 15.7.

### I7 — Schema Integrity
**Source:** L3RS-1 v1.0.0 §13.16.
**Phase One:** YES. Canonical serialization per §13.11 produces correct hashes.

### I8 — Bounded Execution
**Source:** L3RS-1 v1.0.0 §14.15.
**Phase One:** YES. Gas-bounded execution for all contract functions.

### I10 — Profile Invariant
**Source:** L3RS-1 v1.0.0 §17.12.
**Phase One:** YES. Profile F implementation preserves all protocol invariants.

### I11 — Certificate Integrity
**Source:** L3RS-1 v1.0.0 §15.11 and Proposition 15.1.
**Phase One:** Partial. Origin-side CID construction only.

Note: L3RS-1 numbering skips I9. This is per the standard.

---

## Part D — The seven T3RRA theorems (Phase One out of scope)

Extracted verbatim from Cryptographic Specification Part II rev B, April 2026.

These theorems apply to Layers 2 through 5 of the T3RRA stack. None are in Phase One scope.

### Theorem 7.1 (Policy Soundness) — Cryptographic Spec §7.4. Layer 2. **Phase Two.**
### Theorem 7.2 (Unforgeability Preservation) — Cryptographic Spec §7.5. Layer 2. **Phase Two.**
### Theorem 7.3 (Policy Replay Resistance) — Cryptographic Spec §7.6. Layer 2. **Phase Two.**
### Theorem 8.1 (Strategy-Proofness Under Honest Compliance) — Cryptographic Spec §8.4. Layer 3. **Phase Three.**
### Theorem 8.2 (Continuity) — Cryptographic Spec §8.5. Layer 3. **Phase Three.**
### Theorem 9.1 (Tractability) — Cryptographic Spec §9.4. Layer 4. **Phase Four.**
### Theorem 10.1 (Certificate Unforgeability) — Cryptographic Spec §10.4. Layer 5. **Phase Five.**

Plus Theorem 5.1 (Forward Security under Refresh) from Crypto Spec §5.3, standard Ostrovsky–Yung result. Phase Two.

Full formal statements of all seven T3RRA theorems are catalogued in an appendix to this file and in the Cryptographic Specification directly. They are not repeated here to keep Phase One focus clear.

---

## Part E — The six T3RRA system invariants (Architecture paper §7)

Extracted verbatim from Architecture v1.0, April 2026, §7.

These govern the composition of the five T3RRA layers. Three apply to Phase One.

### INV-1 Compliance Totality
**Phase One:** **YES. Full.**
**Test property:** checkTransfer never reverts; always returns accept or reject with non-zero reasonCode on reject.
**Test file:** `test/invariants/INV1_ComplianceTotality.t.sol`.

### INV-2 Signing-Compliance Binding
**Phase One:** **Partial.** The C_hash precondition for Layer 2 PG[Σ] is exposed correctly.
**Test property:** ComplianceModule exposes policyHash() returning keccak256 of bytecode; hash changes only when bytecode changes.
**Test file:** `test/invariants/INV2_PolicyHashStability.t.sol`.

### INV-3 Match Admissibility
**Phase One:** No. Layer 3. Phase Three.

### INV-4 Route Admissibility
**Phase One:** No. Layer 4. Phase Four.

### INV-5 Certificate Continuity
**Phase One:** No. Layer 5. Phase Five.

### INV-6 No Layer Bypass
**Phase One:** **Partial.** L3RS1Asset refuses every state-changing operation that is not mediated by ComplianceModule.
**Test property:** Every state-changing function invokes ComplianceModule.checkTransfer as its first non-view operation. No code path exists that mutates state without first calling checkTransfer. Verified by structural analysis and negative tests.
**Test file:** `test/invariants/INV6_NoLayerBypass.t.sol`.

---

## Part F — Phase-by-phase mapping summary

Build Phase 1 — Layer 1 — L3RS-1 Profile F asset contracts on Base.

- Tests all seven L3RS-1 theorems (Theorems 15.1 through 15.7).
- Tests Proposition 15.1 Certificate Integrity (origin-side only).
- Tests L3RS-1 invariants I1 through I8, I10, I11 (partial where noted).
- Tests T3RRA system invariants INV-1 full, INV-2 partial, INV-6 partial.

Build Phase 2 — Layer 2 — PG[Σ] MPC signing protocol.

- Tests Theorems 7.1, 7.2, 7.3 and supplementary Theorem 5.1.
- Completes INV-2.

Build Phase 3 — Layer 3 — Compliance-gated matching engine.

- Tests Theorems 8.1 and 8.2.
- Completes INV-3.

Build Phase 4 — Layer 4 — Flow routing plus contextual bandit.

- Tests Theorem 9.1.
- Completes INV-4.

Build Phase 5 — Layer 5 — Cross-chain certificate and bridge committee.

- Tests Theorem 10.1.
- Completes INV-5.
- Completes L3RS-1 Theorem 15.3 (destination-side verification), Theorem 15.4 (cross-chain supply invariance), Proposition 15.1 (full).
- Completes L3RS-1 Invariants I5 and I11.
- Tests Composability Theorem 15.8.

---

## Implementation notes

Every theorem-test for Phase One must cite the L3RS-1 theorem number and the standard's section in a comment block at the top of the test file.

Every invariant test must cite the invariant identifier (I1–I11 for L3RS-1, INV-1–INV-6 for T3RRA) and the source section.

If any theorem or invariant appears to conflict with another document in the corpus, stop and flag the conflict. Do not paper over it. Known conflicts at time of writing: the L3RS-1 standard §2.4 names states ISSUED, ACTIVE, RESTRICTED, FROZEN, SUSPENDED, REDEEMED, BURNED. The T3RRA Architecture paper Figure 4 and Crypto Spec Figure 5 show Issued, Active, Locked, Frozen, Suspended, Restored, Burned. Phase One implements the L3RS-1 standard names as normative.

Phase One tests all seven L3RS-1 theorems fully or partially. This is the primary test deliverable and the external audit's primary scope. The T3RRA theorems are explicitly out of Phase One scope and attempting to test them in Phase One will produce incorrect tests.
