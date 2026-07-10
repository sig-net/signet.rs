---
name: preflight
description: Run signet-rs's full local CI gate — cargo fmt check, clippy with `-D clippy::nursery`, doc build with `-D warnings`, host + wasm32 compile, and `cargo test --lib` — and report what passes or fails. Use whenever the user is about to push, commit, or open a PR, or asks to "run the checks", "make sure CI will pass", "lint and test", "verify the branch", or otherwise wants confidence the branch is green before CI sees it. Prefer it over ad-hoc cargo commands, since it reproduces the exact sequence GitHub Actions runs.
---

Reproduce signet-rs's CI gate locally so failures surface here instead of on GitHub. These steps mirror `.github/workflows/test.yml`, which drives the `just` recipes below. Run from the repo root, and prefer each `just` recipe — fall back to the raw `cargo` command only if `just` isn't installed.

Run the whole gate and collect every result — the goal is to hand the user one list of everything to fix, not to stop at the first problem. The one exception: steps 4–6 all compile the crate, so if `just check` (step 4) fails to compile, say so and skip 5 and 6 rather than repeating the same errors.

1. `just fmt`        — `cargo fmt --check`. If this fails, the fix is `cargo fmt` (without `--check`).
2. `just lint`       — `cargo clippy --all-targets -- -D clippy::all -D clippy::nursery`.
3. `just doc`        — `RUSTDOCFLAGS="-D warnings" cargo doc`.
4. `just check`      — `cargo check` (host).
5. `just check-wasm` — `cargo check --target wasm32-unknown-unknown`.
6. `just test-unit`  — `cargo test --lib`.

Why these, and what to watch for:
- `clippy::nursery` is denied, so lint hits are real signal — fix the code; only reach for `#[allow]` when it's a genuine false positive, and say so.
- Step 5 guards the `no_std`/wasm contract (the crate is `rlib`-only for Substrate). It needs the target installed: `rustup target add wasm32-unknown-unknown` (the repo's `rust-toolchain.toml` already requests it).
- Don't run `just test-integration` — there are no integration sources today, and it expects external tooling (Anvil, bitcoind), so it only adds noise.

Finish with a compact ✅/❌ line per step, the failing output inline for anything red, and — if all green — a clear statement that the branch passes the gate CI enforces.
