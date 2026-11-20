# Governance

## Current Status

L3RS-1 is currently stewarded by the **L3RS Working Group**.

The specification was originally authored by **Dr. Zurab Ashvil**.

Version 1.0.0 represents the initial public release of the standard.

---

## Governance Model (Current Phase)

During the Working Group phase:

- The original author acts as Steward.
- Amendments are proposed and reviewed publicly via GitHub Issues.
- All changes MUST preserve protocol invariants (𝓘₁–𝓘₁₁).
- Changes MUST follow semantic versioning.

The objective of this phase is stability, technical review, and ecosystem feedback.

---

## Amendment Process

All amendments SHALL:

1. Be submitted via GitHub Issue or Pull Request.
2. Clearly specify whether invariants are affected.
3. Include rationale and implementation implications.
4. Be documented in a formal release note if accepted.

Amendments that weaken protocol invariants SHALL NOT be accepted.

---

## Relationship to Section 11.8 of the Specification

Section 11.8 of L3RS-1 requires four things of an amendment to the standard: technical committee approval, a public notice period, a supermajority governance vote, and publication of the amendment rationale. These requirements apply in every phase.

During the Working Group phase:

- **Technical review** is carried out by the Steward and Working Group reviewers and is recorded on the pull request.
- **Public notice** is given by keeping the pull request open for public comment for not less than 14 days before it is accepted.
- **Rationale** is published in the pull request and in the release note.
- **No voting body yet exists.** An amendment that changes a requirement of the standard therefore cannot complete Section 11.8 in this phase. Until a governing body is seated, the Working Group publishes errata, clarifications and changes to the reference implementations, and does not publish a new minor or major version of the standard.

Errata to a published version are recorded in `specification/ERRATA.md`. A published version is not altered.

---

## Versioning

L3RS-1 follows semantic versioning:

- MAJOR — breaking changes or invariant modifications
- MINOR — backward-compatible structural additions
- PATCH — clarifications, corrections, non-normative updates

---

## Invariant Protection

All implementations and amendments MUST preserve:

𝓘₁–𝓘₁₁ as defined in the specification.

Invariant preservation is mandatory and non-negotiable.

---

## Transition Plan

The long-term intent is to transition governance to an independent legal foundation structure as adoption matures.

At that stage:

- Stewardship authority will transfer to a formal governing body.
- Amendment voting procedures may be formalized.
- Independent board oversight may be introduced.

Until such transition occurs, governance remains under the L3RS Working Group structure.

---

## Neutrality Statement

L3RS-1 is intended to remain:

- Ledger-agnostic
- Vendor-neutral
- Implementation-neutral
- Open and royalty-free

No single commercial entity shall control the evolution of the standard.
