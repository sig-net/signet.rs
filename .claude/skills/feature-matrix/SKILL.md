---
name: feature-matrix
description: Build and unit-test signet-rs across every feature combination — default, `--no-default-features --features bitcoin`, `--features evm`, and `--all-features` — to catch feature-gating mistakes that CI's default-only build passes silently. Use whenever the user edits `[features]` in Cargo.toml, adds or changes a `#[cfg(feature = ...)]` gate, writes or moves a test that touches a chain module, or edits code under `src/bitcoin` or `src/evm` and wants the single-feature builds to still compile. Reach for it proactively after any feature-gated change, even when the user just says "make sure I didn't break the build".
---

CI builds only the default feature set (`evm` + `bitcoin`), so a missing or wrong `#[cfg(feature = ...)]` gate — in library code OR in a test — can compile for you and still break someone building a single feature. This skill runs every combination so those gaps show up before CI (or a downstream user) hits them. Run from the repo root.

Run all of these and report a full pass/fail matrix — don't stop at the first red one, because the whole point is to see *which* combinations break, not just the first:

1. default:       `cargo test --lib`
2. bitcoin only:  `cargo test --lib --no-default-features --features bitcoin`
3. evm only:      `cargo test --lib --no-default-features --features evm`
4. all features:  `cargo test --lib --all-features`
5. no features:   `cargo check --no-default-features` (compiles the crate with neither chain; runs no tests)

If your change touched dependencies, imports, or `no_std` boundaries, also confirm the gated builds stay wasm-clean:
`cargo check --target wasm32-unknown-unknown --no-default-features --features bitcoin` (and again with `--features evm`).

The failure this exists to catch is a test or item that names `EVM`/`BITCOIN` or reaches into a chain module without being gated. The fix is to gate it — e.g. `#[cfg(all(test, feature = "evm"))]` on the test (or `"bitcoin"`) — never to loosen the feature split just to make a single-feature build compile, since that defeats the crate's `no_std`/minimal-dependency goal.

End with the matrix: one ✅/❌ line per configuration, with failing output shown inline.
