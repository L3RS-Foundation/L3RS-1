# L3RS-1 Profile F — surface specification for Phase One

This file defines the subset of L3RS-1 v1.0.0 that Phase One implements. Phase One conforms to **Profile F: Hybrid Public-Private Architecture** per L3RS-1 §17.7, with CROSSCHAIN conformance class per §11.2.

**Critical clarification.** The T3RRA corpus labels itself "L3RS-1 v1.0.0 · Profile F (Full) Conformant." The L3RS-1 standard §17.7 names Profile F as **Hybrid Public-Private Architecture**, not "Full." The "Full" parenthetical in the T3RRA documents appears to be either an older draft label or a misnomer. Phase One uses the standard's name: Profile F is Hybrid Public-Private Architecture.

---

## What Profile F is

From L3RS-1 v1.0.0 §17.7, verbatim:

> In hybrid deployments:
> - Issuance MAY occur on permissioned layer,
> - Liquidity MAY occur on public layer,
> - Cross-chain certificate SHALL preserve compliance and governance integrity,
> - Origin chain SHALL remain canonical legal authority.
> 
> Hybrid deployment SHALL NOT weaken downgrade resistance.

Profile F is the profile designed for institutional deployments that combine a permissioned issuance layer (where compliance and governance are administered) with a public liquidity layer (where tokens trade). This is the structural match for T3RRA's intended mandates: a regulated issuer operates the permissioned issuance, institutional and eligible investors hold and transfer on public chains, and the cross-chain certificate preserves compliance across both.

The Profile F implementation must satisfy every other invariant and requirement of L3RS-1 v1.0.0. Profile F does not reduce the standard's requirements; it specifies a deployment shape that satisfies them.

---

## The twelve-field asset object

Per L3RS-1 v1.0.0 §2.1, verbatim:

> An L3RS-1 Asset SHALL be defined as a deterministic state object:
> A = (I, T, J, L, ID, C, R, G, F, B, X, S)

All twelve fields are now specified from the standard. Each entry below cites the L3RS-1 section that defines it.

### I — Asset_ID

**Source:** L3RS-1 v1.0.0 §2.1 and §2.2.

**Formal definition:** `I = H(pk_issuer ‖ ts ‖ nonce)` where H is a collision-resistant hash function, pk_issuer is the issuer public key, ts is the timestamp of issuance, and nonce prevents replay.

**Invariance:** Asset_ID SHALL remain invariant across chains.

**Implementation in Phase One:** Immutable bytes32 value set at contract deployment. Computed using keccak256 with domain string `"L3RS-1-AID-v1"` per Cryptographic Specification §1.2.

### T — Asset_Type

**Source:** L3RS-1 v1.0.0 §2.1 and §2.3.

**Enumeration:** `T ∈ { CBDC, INDUSTRY_STABLE, REGULATED_SECURITY, UTILITY, GOVERNANCE, STORAGE_BACKED }`

**Immutability:** Asset_Type SHALL NOT change after issuance.

**Implementation in Phase One:** uint8 enum with six values. Fixed at asset initialization.

### J — Jurisdiction_Code

**Source:** L3RS-1 v1.0.0 §2.1, §12.4.

**Format:** ISO 3166-1 alpha-2 country code (e.g., "GB", "US", "GE").

**Constraint (§12.4):** J_asset = J_legal. Jurisdiction SHALL NOT be modified during cross-chain transfer.

**Implementation in Phase One:** bytes2 field encoding the alpha-2 code. Immutable post-issuance except via governance amendment.

### L — Legal_Mirror_Hash

**Source:** L3RS-1 v1.0.0 §2.1, §12.

**Structure:** `L = (J, LH, LV, TS, SIGN)` where J is jurisdiction code, LH = H(document_bytes ‖ jurisdiction ‖ version), LV is legal version, TS is timestamp, and SIGN is optional legal authority signature.

**Implementation in Phase One:** A LegalMirror struct per L3RS-1 §13.4, stored in contract state. LH is computed at issuance and updated only via governance-approved legal amendments per §12.6.

### ID — Identity_Requirement_Level

**Source:** L3RS-1 v1.0.0 §2.1, §3.2.

**Enumeration:** `ID ∈ {0, 1, 2, 3}`

- ID = 0 (Unbound): no identity requirement for ownership or transfer.
- ID = 1 (Verified): holder MUST have a verified identity attestation (KYC/KYB acceptable).
- ID = 2 (Sovereign-Validated): holder MUST have an attestation issued or validated by a sovereign authority (or sovereign-delegated authority).
- ID = 3 (Multi-Jurisdiction Validated): holder MUST satisfy two or more jurisdictional identity attestations.

**Rule:** If ID ≥ 1, identity validation SHALL be performed prior to settlement finality.

**Implementation in Phase One:** uint8 field. IdentityAttestation contract enforces the validation per §3.11.

### C — Compliance_Module

**Source:** L3RS-1 v1.0.0 §2.1, §4.

**Formal definition:** `C = {r1, r2, ..., rn}` as a total decision function `C : E → {0, 1}` where 1 = ALLOW and 0 = BLOCK.

Each rule: `ri = (RID, TYPE, SCOPE, TRIGGER, CONDITION, ACTION, PRIORITY)`

**Evaluation:** `C(e) = ⋀ ri(e)` — conjunction of rule predicates. Rules evaluated in ascending order of PRIORITY. First blocking rule terminates execution.

**Rule types** (§4.4, mandatory support):
TRANSFER_ELIGIBILITY, INVESTOR_CLASSIFICATION, HOLDING_PERIOD, GEOGRAPHIC_RESTRICTION, SANCTIONS_SCREENING, TRANSACTION_THRESHOLD, AML_TRIGGER, MARKET_RESTRICTION, REDEMPTION_ELIGIBILITY.

**Enforcement actions** (§4.7):
REJECT, FREEZE, RESTRICT, FLAG, REQUIRE_DISCLOSURE.

**Implementation in Phase One:** ComplianceModule.sol contract implementing the total decision function. Rules stored in a priority-ordered array. checkTransfer evaluates rules in order and returns on first BLOCK. Never reverts — always returns (allow, reasonCode).

### R — Transfer_Rule_Engine

**Source:** L3RS-1 v1.0.0 §2.1, §2.6, §2.7.

**Role:** The transfer rule engine executes the seven-step transfer sequence per §2.6: identity validation, compliance evaluation, governance override check, transfer rule validation, fee routing, balance update, cross-chain metadata update.

**Implementation in Phase One:** Built into L3RS1Asset.sol's transfer function. The sequence is enforced by code structure — no step can be skipped or reordered.

### G — Governance_Interface

**Source:** L3RS-1 v1.0.0 §2.1, §5.

**Structure:** Per L3RS-1 §13.6:
```
GovernanceModule {
    authorities: Address[],
    quorum_threshold: uint16,  // percentage in basis points, e.g. 67 for two-thirds
    override_types: string[]
}
```

**Quorum:** `Quorum = (2/3) × N` where N is the number of registered governance keys.

**Authorized override actions** (§5.3):
FREEZE_BALANCE, UNFREEZE_BALANCE, RESTRICT_TRANSFER, SEIZE_ASSET, FORCE_REDEMPTION, EMERGENCY_ROLLBACK.

**Implementation in Phase One:** A governance module stored in contract state. Override requires signatures from at least ⌈(2/3) × N⌉ authorities. EMERGENCY_ROLLBACK explicitly requires quorum per §5.5.

### F — Fee_Distribution_Module

**Source:** L3RS-1 v1.0.0 §2.1, §2.10, §6.

**Structure:** Per L3RS-1 §13.7:
```
FeeModule {
    base_rate: uint256,
    allocations: [(recipient, percentage), ...]
}
```

**Constraint:** Sum of percentages SHALL equal 10000 basis points.

**Allocation categories** (§2.10):
- ps = Sovereign allocation
- pv = Validation layer allocation
- pt = Storage allocation
- po = Operator allocation
- Constraint: ps + pv + pt + po = 1

**Timing:** Fee routing SHALL execute before state finalization.

**Implementation in Phase One:** Part of L3RS1Asset.sol's transfer function. Fees computed from transfer amount, allocated per the FeeModule's percentage vector, and distributed atomically before balance update.

### B — Reserve_Interface

**Source:** L3RS-1 v1.0.0 §2.1, §2.11, §7.

**Structure:** Per L3RS-1 §13.8:
```
ReserveInterface {
    custodian_id: string,
    backing_type: string,  // "FIAT", "COMMODITY", "SECURITIES", "MIXED"
    audit_hash: bytes32,
    attestation_frequency: string,  // "DAILY", "WEEKLY", "MONTHLY", "QUARTERLY"
    insolvency_priority: string
}
```

**Optionality:** May be null for non-backed assets.

**Failure behavior:** If reserve validation fails, asset SHALL transition to RESTRICTED.

**Implementation in Phase One:** Optional struct stored in contract state. Used for asset types that require backing (CBDC, INDUSTRY_STABLE, STORAGE_BACKED). May be omitted for UTILITY and GOVERNANCE types.

### X — CrossChain_Metadata

**Source:** L3RS-1 v1.0.0 §2.1, §2.12, §13.9.

**Structure:** Per L3RS-1 §13.9:
```
CrossChainMetadata {
    origin_chain_id: bytes32,
    compliance_hash: bytes32,
    governance_hash: bytes32,
    state_hash: bytes32,
    timestamp: uint64
}
```

**Cross-chain certificate** (§2.12): `X = H(I ‖ S ‖ C_hash ‖ timestamp)`

**Constraints:** Asset_ID SHALL remain invariant across all chains. Compliance state SHALL NOT downgrade during cross-chain operations.

**Implementation in Phase One:** Metadata struct stored in contract state. Origin-chain values are set. Destination-chain verification is Phase Five. Phase One produces correctly-formed CrossChainMetadata that Phase Five will consume.

### S — Current_State

**Source:** L3RS-1 v1.0.0 §2.1, §2.4, §2.5, §13.3.

**Enumeration (normative):** `S ∈ { ISSUED, ACTIVE, RESTRICTED, FROZEN, SUSPENDED, REDEEMED, BURNED }`

Note on naming: the T3RRA Architecture paper and Crypto Spec use the names Issued, Active, **Locked**, Frozen, Suspended, **Restored**, Burned. Phase One implements the L3RS-1 standard names (RESTRICTED and REDEEMED), which are normative. Update the T3RRA corpus in a future revision to align.

**State transition matrix** (§2.5):

| Current State | Trigger | Condition | Next State |
|---|---|---|---|
| ISSUED | Activation | Identity + Compliance Valid | ACTIVE |
| ACTIVE | Compliance Breach | Rule Triggered | RESTRICTED |
| ACTIVE | Governance Freeze | Authorized Override | FROZEN |
| RESTRICTED | Compliance Cleared | Validation Pass | ACTIVE |
| FROZEN | Override Release | Quorum Approval | ACTIVE |
| ACTIVE | Redemption | Valid Redemption Logic | REDEEMED |
| REDEEMED | Finalization | Settlement Complete | BURNED |

Transitions SHALL be deterministic and atomic.

**Implementation in Phase One:** State machine in L3RS1Asset.sol. Every transition calls ComplianceModule.checkTransfer and, where applicable, the GovernanceInterface. No transition is possible outside the matrix.

---

## Deterministic transfer execution

L3RS-1 v1.0.0 §2.6 mandates that transfers execute in the following exact order. Phase One's L3RS1Asset.transfer function must follow this order without exception.

1. Identity validation
2. Compliance evaluation
3. Governance override check
4. Transfer rule validation
5. Fee routing
6. Balance update
7. Cross-chain metadata update

Execution SHALL be atomic. Any step failing halts the entire transfer and leaves state unchanged. This is tested by Theorem 15.6 (Atomic Settlement).

---

## Identity binding (L3RS-1 §3)

**Identity Record structure (§3.3):**
```
IR = (HID, VA, JI, EXP, REV, ATTR, PROOF)
```

Where HID is the identity hash, VA is the verification authority, JI is the jurisdiction identity scope, EXP is expiry, REV is the revocation flag, ATTR is optional attribute commitments, PROOF is an optional zero-knowledge proof.

**Identity Hash (§3.4):** `HID = H(PII ‖ salt ‖ domain)`. PII SHALL NOT be published on-chain in plaintext.

**Identity status function (§3.6):**
`Status(IR) ∈ { VALID, EXPIRED, REVOKED, UNKNOWN }`

If ID ≥ 1, settlement MUST NOT proceed unless Status(IR) = VALID.

**Implementation in Phase One:** IdentityAttestation.sol stores HID (not PII) and exposes a `getStatus(address)` function returning the four-valued status. Integration with external KYC providers happens through the VA field, whose public keys are registered in the contract.

---

## Canonical serialization

**Source:** L3RS-1 v1.0.0 §13.11.

**Rules (verbatim):**

- Field ordering: fields MUST be serialized in the exact order defined by the canonical schema.
- Encoding: all strings MUST be UTF-8 encoded with no normalization-dependent ambiguity.
- Numeric representation: integers MUST be serialized as fixed-width unsigned big-endian where a fixed width is defined; otherwise as minimally-sized unsigned big-endian with explicit length prefixing.
- No ignored fields: unknown fields MUST be rejected in strict mode for any object used in hash computations.
- Whitespace neutrality: if JSON is used, canonical JSON MUST be applied.

**Hash computation** (§13.12): `H_Y = H(ser(Y))` for any object Y with hash H_Y.

**Implementation in Phase One:** A `CanonicalSerializer.sol` library implementing ser(·) for each of the canonical objects (Asset, LegalMirror, ComplianceModule, GovernanceModule, FeeModule, ReserveInterface, CrossChainMetadata). Unit tests verify that identical inputs produce identical byte outputs, and that inputs differing by any byte produce different outputs.

---

## ComplianceModule Solidity interface

```solidity
interface IComplianceModule {
    /// @notice Evaluate whether an event is permitted under the current policy.
    /// @dev Implements the total decision function C : E → {0, 1} per L3RS-1 §4.3.
    ///      Must be total: never reverts, always returns allow with or without a reason code.
    /// @param assetRef The asset this evaluation applies to.
    /// @param sender The originator address.
    /// @param receiver The beneficiary address.
    /// @param amount The transfer amount.
    /// @param context Arbitrary additional context (jurisdictions, timestamps, metadata).
    /// @return allow True if C(e) = ALLOW, false otherwise.
    /// @return reasonCode On block, a structured reason code; zero on allow.
    function evaluate(
        address assetRef,
        address sender,
        address receiver,
        uint256 amount,
        bytes calldata context
    ) external view returns (bool allow, bytes32 reasonCode);

    /// @notice Return the canonical ComplianceModule hash.
    /// @dev ComplianceHash = H(serialize(ComplianceModule)) per L3RS-1 §13.12.
    function complianceHash() external view returns (bytes32);

    /// @notice Return the rule set in priority order.
    /// @dev Per L3RS-1 §4.2. Each rule is (RID, TYPE, SCOPE, TRIGGER, CONDITION, ACTION, PRIORITY).
    function getRules() external view returns (Rule[] memory);

    /// @notice Return the amendment version of this module.
    function version() external view returns (uint256);
}
```

---

## Reason codes

The `reasonCode` returned by evaluate() maps to the enforcement action taken on block. Minimum set required by L3RS-1:

- `REASON_TRANSFER_INELIGIBLE` — TRANSFER_ELIGIBILITY rule triggered.
- `REASON_INVESTOR_CLASS` — INVESTOR_CLASSIFICATION rule triggered.
- `REASON_HOLDING_PERIOD` — HOLDING_PERIOD rule triggered per §4.9.
- `REASON_GEOGRAPHIC` — GEOGRAPHIC_RESTRICTION rule triggered.
- `REASON_SANCTIONS` — SANCTIONS_SCREENING rule triggered per §4.8.
- `REASON_THRESHOLD` — TRANSACTION_THRESHOLD rule triggered per §4.10.
- `REASON_AML` — AML_TRIGGER rule triggered.
- `REASON_MARKET` — MARKET_RESTRICTION rule triggered.
- `REASON_REDEMPTION` — REDEMPTION_ELIGIBILITY rule triggered.
- `REASON_ORACLE_UNAVAILABLE` — oracle dependency unresolved per §4.8 (sanctions list non-deterministic) or §14.10 (oracle timeout).

Each code is a bytes32 constant defined in a shared `ReasonCodes.sol` and used consistently across ComplianceModule, L3RS1Asset, and all tests.

---

## Conformance class

**Source:** L3RS-1 v1.0.0 §11.2.

Phase One targets the CROSSCHAIN conformance class, which per the standard implements CORE plus ENHANCED plus SOVEREIGN plus cross-chain capabilities:

- CORE (§11.2): Deterministic Asset Object, Identity Binding, Compliance Engine, Deterministic Settlement.
- ENHANCED: adds Governance Override Architecture, Fee Routing Architecture, Reserve Interface.
- SOVEREIGN: adds Quorum governance enforcement, Jurisdiction lock enforcement, Audit hash anchoring, Legal Mirror integration.
- CROSSCHAIN: adds Cross-chain certificate validation, Downgrade resistance enforcement, Double-issuance prevention, Finality verification prior to bridging.

Phase One builds the origin-chain portion of CROSSCHAIN. Phase Five completes it with the destination-chain bridge and certificate verification.

---

## Profile F constraints (L3RS-1 §17.7)

Phase One must satisfy, in addition to every base requirement:

- Cross-chain certificate preserves compliance and governance integrity (tested by Theorems 15.3 and 15.4 partially in Phase One, fully in Phase Five).
- Origin chain remains the canonical legal authority (enforced by J field immutability per §12.4).
- Hybrid deployment does not weaken downgrade resistance (tested by Theorem 15.3).

---

## Performance and determinism constraints (L3RS-1 §14)

Phase One must satisfy the Performance Integrity Invariant I8 per §14.15. Specific bounds from the standard:

- Compliance rule evaluation: O(n) where n = |C| (§14.3). No nested rule recursion.
- Identity verification: bounded time for signature validation; fixed proof size for ZKP (§14.4).
- Fee distribution: O(m) where m = |allocations| (§14.5). Bounded maximum size declared at issuance.
- Governance quorum evaluation: O(N) where N = |authorities| (§14.6). Maximum size declared at issuance.
- Cross-chain verification: single hash recomputation plus deterministic comparison plus signature verification (§14.7). No scanning of historical chain state.

Gas-bounded environments: no dynamic unbounded loops in compliance logic; governance validation within declared gas limits; cross-chain verification constant-time hash.

---

## Testing notes for Phase One

The Profile F implementation is verified by:

- Seven L3RS-1 theorem tests (Theorems 15.1 through 15.7) per `06-theorems.md` Part A.
- L3RS-1 invariant tests (I1 through I8, I10, I11 partial) per `06-theorems.md` Part C.
- Three applicable T3RRA system invariants (INV-1 full, INV-2 partial, INV-6 partial) per `06-theorems.md` Part E.
- Unit tests for every public function on every contract.
- The end-to-end scenario test exercising every lifecycle transition (ISSUED → ACTIVE → RESTRICTED → ACTIVE → FROZEN → ACTIVE → REDEEMED → BURNED) with ComplianceModule gating at each step.

The scenario test must also include at least one rejection for each of the ten reason codes defined above, and at least one governance override requiring quorum.

---

## Nothing is pending

Every field, every invariant, every theorem is now specified from the L3RS-1 v1.0.0 standard. Phase One is ready to proceed.
