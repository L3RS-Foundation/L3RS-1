# l3rs1-sdk (Rust)

L3RS-1 Layer-3 Regulated Asset Standard — Rust Reference Implementation

**Conformance class:** CROSSCHAIN — all invariants I₁–I₁₁ enforced.

## Install

```toml
[dependencies]
l3rs1-sdk = "1.0.1"
```

## Usage

```rust
use l3rs1::crypto::{construct_asset_id, construct_cid};
use l3rs1::modules::{apply_state_transition, evaluate_compliance};
use l3rs1::types::{AssetState, ComplianceDecision};

// Construct a deterministic Asset_ID (§2.2)
let asset_id = construct_asset_id(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    1740355200,
    "0000000000000001",
)?;

// Apply a state transition (§2.5)
let new_state = apply_state_transition(&AssetState::Issued, "ACTIVATION")?;
assert_eq!(new_state, AssetState::Active);
```

## Spec coverage

| Section | Description |
|---|---|
| §2 | Asset model, state machine, transfer execution |
| §3 | Identity binding, ZKP interface |
| §4 | Compliance engine, rule evaluation |
| §5 | Governance overrides, quorum |
| §6 | Fee routing, atomicity |
| §7 | Reserve interface |
| §8 | Cross-chain CID, downgrade resistance |
| §9 | Settlement, replay protection |
| §13 | Canonical serialization |

## Zero external runtime dependencies

All L3RS-1 implementations are pure function libraries with no I/O or transport.
Runtime dependencies: `sha2`, `hex`, `serde`, `serde_json`, `thiserror`.

## Links

- [L3RS Foundation](https://www.l3rs.foundation)
- [Specification](https://www.l3rs.foundation/standard)
- [GitHub](https://github.com/L3RS-Foundation/L3RS-1)
