# L3RS-1 v1.0.0 — Errata

This file records known defects in the published text of L3RS-1 v1.0.0. The published version is final (Standard Declaration, "Version Finality") and is not altered. Each erratum states how the text is to be read. None changes a requirement.

Errata are corrected in the text of the next published version.

## E-1. Section cross-references with a mixed numeral

Fourteen cross-references print a section number as a digit followed by Roman letters. Each stands for the section named below.

| Printed | Read as | Section title | Occurrences |
|---|---|---|---|
| Section 1I | Section 2 | Formal Asset Model | §11.2 |
| Section 1II | Section 3 | Identity Binding Architecture | §11.2 |
| Section 1V | Section 4 | Compliance Engine | §11.2, §20 |
| Section 5I | Section 6 | Fee Routing Architecture | §11.2 |
| Section 5II | Section 7 | Reserve and Asset Backing Verification | §11.2, §12 |
| Section 1X | Section 9 | Deterministic Settlement and Finality Guarantees | §11.2 |
| Section 10III | Section 13 | Canonical Data Schema Specification | §8, §10, §20 |
| Section 10IV | Section 14 | Performance and Determinism Constraints | §17 |
| Section 10V | Section 15 | Extended Mathematical Appendix and Formal Proofs | §16, §17 |

## E-2. Invariant summary

The invariant summary in Section 15 lists invariants I₁ to I₈ and I₁₁. Invariants I₉ (Section 16, deployment) and I₁₀ (Section 17, implementation profiles) are defined in the text and are part of the set I₁–I₁₁. The summary is to be read as including them.

## E-3. Identity record in the canonical schema

Section 3.3 defines the identity record `IR = (HID, VA, JI, EXP, REV, ATTR, PROOF)`. Section 13 gives canonical objects for the asset, its state and its modules, and gives none for the identity record. This is recorded as an omission. No reading is prescribed here; a canonical object for the identity record is a matter for the next version of the standard.
