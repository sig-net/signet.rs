# Testing Guide for signet-rs

`signet-rs` builds `no_std` transaction signing payloads for Bitcoin and EVM. This guide describes how the crate is tested and how to run and extend the suite.

## How tests are organized

All tests are **inline unit tests** — `#[cfg(test)] mod tests { ... }` blocks that live next to the code they exercise in `src/`. There is currently no separate integration-test suite: the `tests/` directory contains no `.rs` files, so `just test-integration` (`cargo test --test '*'`) matches nothing.

The heaviest coverage is in the two serializers — `src/bitcoin/bitcoin_transaction.rs` (transaction and sighash round-trips) and `src/evm/evm_transaction.rs` (EIP-1559 RLP encoding for signing and with-signature) — with focused tests across the Bitcoin primitive types (`src/bitcoin/types/`), PSBT serialization (`src/bitcoin/psbt/`), DER signature encoding (`src/bitcoin/utils.rs`), and EVM address / access-list handling (`src/evm/`).

## Running the tests

Use the `justfile` recipe that CI runs:

```bash
just test-unit          # cargo test --lib — the full unit-test suite
```

Or drive cargo directly:

```bash
cargo test --lib                     # all unit tests (default features: evm + bitcoin)
cargo test --lib bitcoin::           # only the bitcoin module's tests
cargo test --lib -- --nocapture      # show test stdout
cargo test --lib test_der_encoding   # a single test by name substring
```

### Feature combinations

The default build enables both `evm` and `bitcoin`. CI only builds the default set, so feature-gating mistakes can hide — test each combination when you touch feature-gated code or its tests:

```bash
cargo test --lib --no-default-features --features bitcoin
cargo test --lib --no-default-features --features evm
cargo test --lib --all-features
```

Also confirm the crate still compiles for the Substrate / wasm target after changing dependencies or imports:

```bash
just check-wasm         # cargo check --target wasm32-unknown-unknown
```

## How correctness is enforced

Encoding correctness is pinned by **differential (oracle) tests**: the crate's output is compared against battle-tested reference implementations pulled in as dev-dependencies — `alloy` / `alloy-rlp` for EVM (EIP-1559 RLP encoding and signatures), and `rust-bitcoin` plus `k256` for Bitcoin (sighash, DER / low-S signatures, scripts).

When adding or changing encoding logic, assert against these references rather than hand-written hex. This is how the suite catches subtle consensus bugs such as minimal DER per BIP-66, canonical RLP integers, BIP-143 SegWit preimages, and txid byte order.

## Writing new tests

Add tests inline in the module under test:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_like_the_reference() {
        // build with signet-rs, then compare against alloy / rust-bitcoin
    }
}
```

If the code or test is specific to a chain feature, gate it so single-feature builds stay green:

```rust
#[cfg(all(test, feature = "evm"))]
mod evm_tests { /* ... */ }
```

## Continuous integration

`.github/workflows/test.yml` gates every PR: `just fmt`, `just lint` (clippy with `-D clippy::all -D clippy::nursery`), a doc build with `RUSTDOCFLAGS="-D warnings"`, `just check`, `just check-wasm`, then `just test-unit` on stable and nightly. The unit-test job also installs the Foundry toolchain (the `alloy` dev-dependency enables its `node-bindings` feature). Run the same `just` recipes locally before pushing.
