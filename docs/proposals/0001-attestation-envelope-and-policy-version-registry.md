# L3RS-1 v1.1.0 Amendment Proposal: Attestation Envelope and Policy Version Registry

Proposed by Zurab Ashvil · November 20, 2026 · Draft for public comment

## Status of this proposal

This proposal is filed for public comment. It cannot be adopted in the present phase. Under `GOVERNANCE.md`, an amendment that changes a requirement of the standard needs the procedure of Section 11.8, which includes a vote by a governing body, and no such body is yet seated. Until one is, the Working Group publishes errata, clarifications and reference implementations only. Comments received now go to the Technical Steering Committee when it is seated.

**Relation to the Profile F reference contracts.** The repository publishes two contracts named `IdentityAttestation` and `PolicyRegistry` in `packages/solidity-profile-f`. They implement Sections 3 and 5 and Profile F of v1.0.0 as it stands. The objects proposed here are different objects with different fields, and they carry different names so that the two cannot be confused: the **Attestation Envelope** and the **Policy Version Registry**. Nothing in this proposal changes those contracts or requires them to change.

**Relation to the v1.0.0 errata.** Erratum E-3 in `specification/ERRATA.md` records that Section 13 gives no canonical object for the identity record and leaves the matter to the next version. Clause 13.18 below supplies that object.

## Summary

This proposal adds two objects to L3RS-1 as a minor version, 1.1.0: the **Attestation Envelope** and the **Policy Version Registry**. Both are backward-compatible additions. No existing clause is changed, no invariant is touched, and every conformant v1.0.0 implementation remains conformant.

| Item | Value |
| --- | --- |
| Proposed version | L3RS-1 v1.1.0 |
| Type of change | Minor: backward-compatible feature addition (Section 11.7) |
| New clauses | 3.14 Attestation Envelope; 4.16 Policy Version Registry; 13.18 Extension objects |
| Invariants affected | None. I1 to I11 are preserved |
| Proposer | Zurab Ashvil |
| Status | Draft for public comment; adoption requires a seated governing body |

**The Technical Steering Committee, once seated, is asked to decide three things.**

1. Whether the two objects belong in the standard.
2. Whether the proposed normative text is accepted, with or without changes.
3. Whether to confirm the four design positions recorded in the last section.

## Motivation

Version 1.0.0 defines an identity record and a compliance module. It leaves two things to each implementation, and both are needed whenever more than one institution relies on the same identity and the same rules.

- **A portable attestation.** Section 3.3 defines the identity record: a hash, a verification authority, a jurisdiction, an expiry, a revocation flag, and optional attributes and proof. It does not bind the record to a holder's account, does not carry the holder's investor tier or sanctions status, and has no signed envelope. Section 3.1 already speaks of an "attestation structure"; this proposal supplies it.
- **A versioned source of rules.** Section 4.2 defines the compliance module as a set of rules. The standard does not say how a rule set is published, versioned, activated or superseded, or how a decision records which version it was taken under. Section 4.8 requires sanctions registries to be versioned and hash-anchored; the same discipline is missing for the rules themselves.

No protocol depends on these objects today. The proposal is made so that the layer is defined by a neutral standard before implementations diverge, and so that the omission recorded in erratum E-3 is closed with a complete object and not a partial one.

## Compatibility

- **Additive only.** The proposal adds clauses 3.14, 4.16 and 13.18. It amends no existing clause.
- **Optional capabilities.** The conformance classes of Section 11.2 are unchanged. An implementation of any class MAY declare the capability `ATTESTATION_ENVELOPE`, `POLICY_VERSION_REGISTRY`, or both.
- **Invariants.** The identity invariant I3 still reads on the identity record, which every attestation contains. The compliance invariant I2 still reads on the compliance module, which the registry selects but does not alter.
- **Version field.** Assets issued under `L3RS-1.0.0` remain valid. An asset that uses either capability declares `L3RS-1.1.0`.

## Proposed text: 3.14 Attestation Envelope

*The text below is proposed for insertion after Section 3.13. It uses the notation of Section 3.*

### 3.14.1 Definition

An attestation envelope is a signed statement by a verification authority that a holder has been verified. It contains the identity record of Section 3.3 and binds it to a subject.

```
AE = (AID, IR, SUBJ, TIER, SR, ISSUED, REVPTR, SIG)
```

| Field | Meaning |
| --- | --- |
| `AID` | Attestation identifier, unique per verification authority |
| `IR` | The identity record of Section 3.3, unchanged |
| `SUBJ` | Subject reference: a commitment to the account or key the attestation is issued for |
| `TIER` | Investor tier of the subject (3.14.3) |
| `SR` | The sanctions registry snapshot of Section 4.8 against which the subject was screened at issuance |
| `ISSUED` | Issuance timestamp |
| `REVPTR` | Revocation pointer: the location and method, among those of Section 3.10, by which revocation is checked |
| `SIG` | Signature of the verification authority `IR.VA` over the canonical serialization of all other fields |

### 3.14.2 Privacy

An attestation envelope SHALL NOT contain personally identifiable information in plaintext. The requirement of Section 3.4 applies to every field. `SUBJ` SHALL be a commitment and SHALL NOT disclose the holder's identity.

### 3.14.3 Tier

The tier SHALL belong to the ordered enumeration:

```
RETAIL < PROFESSIONAL < INSTITUTIONAL < ISSUER
```

| Tier | Meaning |
| --- | --- |
| `RETAIL` | A natural or legal person not classified in a higher tier |
| `PROFESSIONAL` | A client classified as professional, accredited or qualified under the law of the attesting jurisdiction |
| `INSTITUTIONAL` | A regulated financial institution, or an entity the attesting jurisdiction treats as one |
| `ISSUER` | A licensed institution that issues assets or money liabilities under this standard or a protocol that imports it |

A compliance rule of type `INVESTOR_CLASSIFICATION` MAY compare tiers under this order. A deployment profile MAY refine a tier into sub-tiers, provided that each sub-tier maps to exactly one tier of this enumeration.

### 3.14.4 Issuance

A verification authority SHALL issue an attestation only after completing the verification that its own regulatory obligations require. It SHALL NOT issue an attestation for a subject listed in `SR`. `ISSUED` SHALL precede `IR.EXP`.

An attestation SHALL NOT be altered after issuance. A change of tier or expiry requires revocation and a new attestation. If the subject is later listed in a sanctions registry that the authority screens against, the authority SHALL revoke the attestation.

A verification authority SHALL NOT hold more than one unrevoked, unexpired attestation for the same subject.

### 3.14.5 Status

The status of an attestation is the status of its identity record under Section 3.6, with the revocation flag resolved through `REVPTR`:

```
Status(AE) in {VALID, EXPIRED, REVOKED, UNKNOWN}
```

`Status(AE) = VALID` only if `SIG` verifies under `IR.VA`, the current time is before `IR.EXP`, and revocation resolved through `REVPTR` is negative. If revocation cannot be resolved deterministically, the status is `UNKNOWN`, and `UNKNOWN` is blocking where `ID >= 1`.

An attestation is not evidence of current sanctions status. Where a sanctions rule applies, it SHALL be evaluated under Section 4.8 at each decision, against the registry in force at that decision.

Where more than one condition holds, `REVOKED` takes precedence over `EXPIRED`. An attestation whose verification authority is no longer recognized has status `UNKNOWN`.

### 3.14.6 Revocation

The issuing verification authority SHALL publish revocation by the method named in `REVPTR`. Revocation SHALL be irreversible. Status SHALL be evaluated at every compliance decision that depends on the attestation; a status evaluated for one decision SHALL NOT be reused for another.

Resolution through `REVPTR` is an external data reference. It SHALL be hash-anchored, versioned and evaluated in bounded time, as Section 14.10 requires. If it is not resolved within the declared bound, the status is `UNKNOWN`. Signature verification SHALL meet the bound of Section 14.4.

### 3.14.7 Relation to identity requirement levels

A valid attestation satisfies `ID = 1`. It satisfies `ID = 2` where `IR.VA` is a sovereign or sovereign-delegated authority. `ID = 3` is satisfied by two or more valid attestations under Section 3.9.

### 3.14.8 Reliance

A party other than the issuing authority MAY rely on an attestation for a compliance decision. This standard defines the attestation and its status. It does not allocate liability between the issuing authority and a relying party; that allocation belongs to the rules of the network or venue in which reliance occurs.

### 3.14.9 Conformance

An implementation that declares `ATTESTATION_ENVELOPE` SHALL issue, verify and revoke attestations as specified in this section, SHALL reject an attestation whose signature does not verify, and SHALL pass the attestation test vectors.

## Proposed text: 4.16 Policy Version Registry

*The text below is proposed for insertion after Section 4.15. It uses the notation of Section 4.*

### 4.16.1 Purpose

The policy version registry is the versioned, append-only record of the rule sets in force. It lets any party determine which compliance module applied to an event, and lets every decision record the version under which it was taken.

### 4.16.2 Policy version

```
PV = (PID, VER, SCOPE, PH, EFFECTIVE, PREV, AUTH)
```

| Field | Meaning |
| --- | --- |
| `PID` | Policy identifier, stable across versions |
| `VER` | Version, under semantic versioning |
| `SCOPE` | Jurisdictional or asset scope, as in Section 4.2 |
| `PH` | Policy hash: the hash of the canonical serialization of the policy content (4.16.3) |
| `EFFECTIVE` | The point from which the version applies, expressed in the deterministic ordering of Section 9.7 |
| `PREV` | Hash of the policy version this one supersedes; empty for the first version |
| `AUTH` | The signatures that authorize registration (4.16.4) |

### 4.16.3 Policy content

The policy content is `P = (C, EXT)`: a compliance module `C` as defined in Section 4.2, together with an optional extension namespace `EXT` of parameters under Section 13.17. A deployment profile defines the parameters it places in `EXT`. The registry treats them as opaque and binds them through `PH = H(ser(P))`.

`PH` is distinct from the compliance hash `CH = H(ser(C))` of Section 8.3, which this proposal does not change.

### 4.16.4 Authorization

Each `PID` has an authorization rule: a set of signers and a threshold. A registry SHALL accept a policy version only if `AUTH` satisfies the authorization rule in force for that `PID`. The rule MAY require signatures from more than one class of signer. A change to the authorization rule is itself a registered, authorized event.

### 4.16.5 Registration

A registry SHALL accept `PV` only if all of the following hold:

- `AUTH` satisfies the authorization rule;
- `VER` is strictly greater than the version of the current head for `PID`;
- `PREV` equals the hash of the current head;
- `EFFECTIVE` is later than the point of registration and later than the effective point of the current head.

A registered version SHALL NOT be altered or removed.

The last condition makes effective points strictly increasing along the chain, so that `Active` is single-valued. Without it, a version registered later with an earlier effective point would let an older version return to force.

### 4.16.6 Resolution

```
Active(PID, t) = the registered version of PID with the greatest EFFECTIVE not later than t
```

`Active` SHALL be a deterministic function of the registry's state. If it cannot be evaluated deterministically for an event, the compliance decision for that event SHALL be `BLOCK`.

### 4.16.7 Decision binding

Every compliance decision SHALL record `(PID, VER, ``P``H)` of the version under which it was evaluated. That version SHALL be `Active(PID, t)` at the point `t` of the event.

A decision validly taken under one version remains valid after that version is superseded. A decision SHALL NOT be applied to an event for which a different version is active.

### 4.16.8 Availability

Every registered version, with its content, SHALL be retrievable by each party that evaluates compliance under it and by the competent authority, for the retention period that applies to the records of the assets in scope.

### 4.16.9 Relation to other sections

Registration of a policy version is not a governance override under Section 5.

Where a policy version governs an asset, the asset's compliance module is the module `C` of the active version. The compliance hash `CH` of Section 8.3 follows from it. Activation of a version with a different `C` therefore changes `CH` and requires a new cross-chain certificate, as invariant I11 already demands.

Parameters in `EXT` are bound by `PH` in the registry and are not bound into the certificate. An asset governed by a policy with a non-empty `EXT` SHALL carry `(PID, VER, PH)` in the extension namespace of its cross-chain metadata. A destination that cannot resolve that version SHALL reject the transfer.

### 4.16.10 Conformance

An implementation that declares `POLICY_VERSION_REGISTRY` SHALL implement registration, resolution and decision binding as specified in this section, SHALL reject a registration that fails any condition of 4.16.5, and SHALL pass the policy-version-registry test vectors.

## Consequential changes

Three further additions follow from the two new clauses. None alters existing text.

### 13.18 Extension objects

*Proposed for insertion after Section 13.17, in the extension namespace that section provides.*

```
IdentityRecord {
    identity_hash: bytes32,
    verification_authority: string,
    jurisdiction_identity: string,
    expiry: uint64,
    revoked: bool,
    attribute_commitments: bytes32[],   // optional
    proof: Proof                        // optional; the proof object of Section 3.8
}

AttestationEnvelope {
    attestation_id: bytes32,
    identity_record: IdentityRecord,
    subject_ref: bytes32,
    tier: string,
    sanctions_registry: bytes32,
    issued_at: uint64,
    revocation_pointer: string,
    signature: Signature
}

PolicyVersion {
    policy_id: string,
    version: string,
    scope: string,
    policy_hash: bytes32,
    effective_at: uint64,
    previous: bytes32,
    authorization: Signature[]
}

Signature {
    signer: string,
    suite: string,
    value: bytes
}

PolicyRef {                             // carried by a compliance decision and,
    policy_id: string,                  // where 4.16.9 requires, by cross-chain metadata
    version: string,
    policy_hash: bytes32
}
```

Serialization and hashing follow Sections 13.10 to 13.12. Version 1.0.0 gives the identity record a formal model in Section 3.3 but no canonical object in Section 13. The first object above closes that gap.

### Conformance (Section 11)

The four conformance classes are unchanged. Two optional capability identifiers are added: `ATTESTATION_ENVELOPE` and `POLICY_VERSION_REGISTRY`. A certificate of conformance names the class and any capabilities declared.

### Invariants

| Invariant | Effect of this proposal |
| --- | --- |
| I2 Compliance integrity | Preserved. The decision function of Section 4.3 is unchanged; the registry determines which module is in force |
| I3 Identity integrity | Preserved. An attestation is valid only if its identity record is valid |
| I7 Schema integrity | Preserved. New objects sit in the extension namespace; existing field order is untouched |
| All others | Not engaged |

### Glossary and symbol index (Section 18)

The v1.0.0 glossary describes the identity record as an "identity attestation structure". To keep the two objects distinct, the entry is reworded and new entries are added.

| Symbol | Entry |
| --- | --- |
| `IR` | Identity Record: the cryptographically anchored record of a verified identity (reworded) |
| `AE` | Attestation Envelope: a signed statement by a verification authority that binds an identity record to a subject |
| `PV` | Policy Version: one registered, authorized version of a policy |
| `P` | Policy content: a compliance module with an optional parameter extension |
| `PH` | Policy Hash |

### Errata in v1.0.0, to correct in the same release

The three errata recorded in `specification/ERRATA.md` (E-1, mixed-numeral cross-references; E-2, the invariant summary; E-3, the identity record in the canonical schema) are corrected in the text of v1.1.0. E-1 and E-2 change no meaning. E-3 is closed by clause 13.18.

## Reference implementation and publication

A minor version is complete when text, code, vectors and citation are published together. None of the items below exists yet.

- [ ] **Specification.** Insert clauses 3.14, 4.16 and 13.18 into the source; update the version, the glossary and the symbol index; correct the three errata; build `L3RS-1_v1.1.0.pdf`.
- [ ] **Reference contracts.** Implement the Attestation Envelope and the Policy Version Registry as new contracts beside the Profile F contracts, with tests. The existing `IdentityAttestation` and `PolicyRegistry` contracts are not renamed or altered.
- [ ] **SDK types.** Add the objects of 13.18 to the TypeScript, Python, Go, Rust and Java packages.
- [ ] **Test vectors.** Add an attestation-envelope corpus and a policy-version-registry corpus, each with negative cases: bad signature, expired, revoked, unresolvable revocation, version not greater, wrong predecessor, effective point in the past, insufficient authorization.
- [ ] **Conformance harness.** Run both corpora in all five languages in continuous integration, as for the compliance corpus.
- [ ] **Release.** Tag `v1.1.0`; update the changelog and the citation file.
- [ ] **Zenodo.** Deposit v1.1.0 as a new version of the existing record.
- [ ] **Website.** Update the standard page to v1.1.0 and show the DOI and the license there.

## Disclosure of interest

The proposer is the author of L3RS-1 and chairs the L3RS Foundation. He is also the founder of Fiat-on-Chain Ltd. Its protocol, FoC-P, does not depend on the objects proposed here: its release candidate carries an attestation by hash and keeps investor tier and sanctions status in its own messages. A later version of that protocol could adopt these objects, and the proposer therefore has an interest. The Committee is asked to review the proposal on its merits as a general addition to the standard, and to record this disclosure with its decision.

## Procedure

Section 11.8 of the specification requires four things of an amendment: technical committee approval, a public notice period, a supermajority governance vote, and publication of the rationale. `GOVERNANCE.md` states how each is met in the Working Group phase and records that the vote cannot yet be held.

| Step | How this proposal meets it |
| --- | --- |
| Publication of the rationale | This document, in a public pull request |
| Public notice | The pull request stays open for comment for not less than 14 days, and in any case until a governing body is seated |
| Technical committee approval | By the Technical Steering Committee, once seated |
| Supermajority governance vote | By the Board of Governors, once seated |

## Positions taken on the four design questions

1. **Tier enumeration: fixed in the standard.** A portable attestation is only useful if every relying party reads the tier the same way. Four tiers are defined in 3.14.3, and a profile may refine them by sub-tiers that each map to one of the four.
2. **Sanctions: a screening reference, not a status.** A status fixed at issuance goes stale, and a stale "clear" is worse than none. The attestation records the registry snapshot the subject was screened against. The authority may not issue for a listed subject and must revoke on a later listing. Current status is always evaluated by the sanctions rule of Section 4.8.
3. **Cross-chain certificate: unchanged.** The certificate already binds the compliance module through the compliance hash, so a new policy version with different rules forces a new certificate under invariant I11. Parameters outside the module travel as a policy reference in the cross-chain metadata, and a destination that cannot resolve it rejects the transfer. Binding the policy hash into the certificate itself is left to a major version.
4. **Candidate status: a pre-release under semantic versioning.** After Committee approval the text is published first as `v1.1.0-rc.1`. A dependent specification may pin the candidate. No certificate of conformance is issued against a candidate, and `v1.1.0` is declared only after the procedure of Section 11.8 is complete.
