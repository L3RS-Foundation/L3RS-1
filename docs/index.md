# L3RS-1 SDK — Developer Documentation

**Layer-3 Regulated Asset Standard · v1.0.0 · CROSSCHAIN Conformance**

The L3RS-1 SDK is a multi-language reference implementation of the [L3RS-1 specification](https://l3rs.foundation/specification). All implementations are pure deterministic libraries — no transport, no ledger coupling, zero runtime dependencies.

## Quick Start

| Language | Install | Docs |
|----------|---------|------|
| TypeScript | `npm install @l3rs/reference-impl` | [API Reference](typescript/) |
| Python | `pip install l3rs1-sdk` | [API Reference](python/) |
| Go | `go get github.com/L3RS-Foundation/L3RS-1/packages/go` | [API Reference](go/) |
| Rust | `cargo add l3rs1-sdk` | [API Reference](rust/) |
| Java | `foundation.l3rs1:l3rs1-sdk:1.0.1` | [API Reference](java/) |
| Solidity | `npm install @l3rs/contracts` | [API Reference](solidity/) |

## Conformance Class

All implementations target **CROSSCHAIN** — the highest conformance class, enforcing all invariants I₁–I₁₁ across §2–§13 of the specification.

## Canonical Test Vector

All six implementations must produce this output for the §2.2 Asset_ID construction:

```
Input:
  issuer_pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  timestamp:     1740355200
  nonce:         0000000000000001

Output (Asset_ID):
  593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a
```

## Architecture

Every implementation is a **pure function library** — no I/O, no network, no ledger coupling:

```
┌─────────────────────────────────────────┐
│         Your ledger / platform          │
├─────────────────────────────────────────┤
│         L3RS-1 SDK (this repo)          │
│  types · state machine · compliance     │
│  identity · governance · settlement     │
│  cross-chain CID · canonical hashing    │
├─────────────────────────────────────────┤
│      SHA-256 (stdlib in all langs)      │
└─────────────────────────────────────────┘
```

## Source

[github.com/L3RS-Foundation/L3RS-1](https://github.com/L3RS-Foundation/L3RS-1)
