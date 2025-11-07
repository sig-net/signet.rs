# Documentation

This repository follows the standard Rust pattern of using the crate README as the crate-level
`rustdoc`. The key entry points are:

- **Hosted docs:** https://docs.rs/signet-rs
- **Crate page:** https://crates.io/crates/signet-rs
- **Source README:** reused automatically via `#![doc = include_str!("../README.md")]`

## Build locally

```bash
# Render docs for all features without pulling in dependency docs
cargo doc --all-features --no-deps --open

# Or use the just recipe (runs with warnings turned into errors)
just doc
```

## Tips

- Run `cargo doc --document-private-items` while iterating on internal modules.
- Use `#[cfg(doc)]` guards if you need doc-only helpers that should not compile in production.
