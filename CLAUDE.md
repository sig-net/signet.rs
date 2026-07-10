# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this crate is

`signet-rs` is a minimal `no_std` library that **builds transaction signing payloads** for Bitcoin and EVM (EIP-1559 RLP preimages, Bitcoin legacy/SegWit sighash preimages, PSBTs) and re-encodes transactions once a signature exists. It does **not** hold keys or sign — `src/signer/` only defines request/response types for an external (MPC-style) signing service. Single crate, not a workspace. Derived from NEAR's `omni-transaction-rs`.

## no_std / wasm discipline (mandatory)

- `src/lib.rs` is `#![cfg_attr(not(test), no_std)]` with `extern crate alloc`. In `src/**` outside `#[cfg(test)]`, use `core::` and `alloc::` (`use alloc::vec::Vec;`) — never `std::`.
- Everything must compile for `wasm32-unknown-unknown` (the crate is `rlib`-only for Substrate). Run `just check-wasm` after changing dependencies, features, or imports.
- New dependencies must be `default-features = false` and `no_std`-compatible.

## Features & feature-gating

- `default = ["evm", "bitcoin"]`; `bitcoin` pulls `sha2`/`borsh`/`serde-big-array`/`bs58`; `evm` adds no deps; `std = ["schemars"]` is forward-looking (schemars is unused today).
- Code **and its tests** that touch a chain module must be gated — e.g. `#[cfg(feature = "bitcoin")]` on items, `#[cfg(all(test, feature = "evm"))]` on tests. CI builds only the default set, so a missing gate compiles locally but breaks single-feature builds. Verify with `/feature-matrix`, or: `cargo test --lib --no-default-features --features bitcoin` and `... --features evm`.

## Commands (justfile; CI runs these recipes)

- `just lint` → `cargo clippy --all-targets -- -D clippy::all -D clippy::nursery`. **`clippy::nursery` is denied** — much stricter than default clippy; expect to add `const fn`, `Self`, `#[must_use]`, etc. to pass. MSRV is 1.76 (`.clippy.toml`).
- `just fmt` → `cargo fmt --check`.
- `just doc` → `RUSTDOCFLAGS="-D warnings" cargo doc` (doc warnings fail CI).
- `just check` / `just check-wasm` — host / wasm32 compile.
- `just test-unit` → `cargo test --lib`. All tests are inline `#[cfg(test)]` modules and are the entire test surface; the `tests/` dir has **no** integration sources today, so `just test-integration` is a no-op and TESTING.md's integration/count details are stale. `/preflight` runs the full local CI gate.

## Signing correctness invariants (consensus rules — do not "simplify")

Changing these silently produces transactions that real nodes reject. All are pinned by **differential tests** against reference crates (`alloy` for EVM; `rust-bitcoin` + `k256` for Bitcoin) — validate new or changed encoding the same way, never against hand-written hex.

- Bitcoin ECDSA sigs: BIP-66 **minimal** DER (strip leading zero bytes) + low-S, then append the sighash byte (`src/bitcoin/utils.rs`).
- EVM RLP integers must be **canonical** (no leading zeros) or nodes reject with "rlp: non-canonical integer" (`src/evm/evm_transaction.rs`).
- Bitcoin SegWit (BIP-143) sighash preimage excludes the marker/flag bytes.
- `Txid` display order is byte-reversed from the internal order — keep the reversal.
- `from_json` deserializers must return `Result` (never panic) and accept hex-string numerics.

## Conventions

- Conventional commits with scope (`fix(bitcoin):`, `feat(evm):`, `docs:`); imperative subject ≤ 72 chars. Branch prefixes `fix/`, `docs/`, `chore/`, `ci/`; land on `main` via PR.
- **Every version bump must ship a release.** Whenever `version` in `Cargo.toml` is bumped, the matching release must go out (crates.io publish + git tag) — never leave a bumped version unreleased. release-plz automates this on merge to `main`; don't run `cargo publish` by hand.
