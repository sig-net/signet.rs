# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2](https://github.com/sig-net/signet.rs/compare/v1.0.1...v1.0.2) - 2026-07-10

### Fixed

- *(build)* gate EVM-only builder test behind evm feature
- *(bitcoin)* minimal DER, real P2WPKH script code, txid byte order
- *(evm)* canonical RLP signatures and safe JSON parsing

### Other

- modernize release-plz workflow (split jobs, current action)
- fall back to built-in GITHUB_TOKEN in release-plz workflow

## [1.0.1] - 2026-03-28

### Fixed

- Fix BIP-143 sighash bug: remove SegWit marker/flag from sighash preimage
- Fix legacy sighash to use non-witness serialization
- Fix `from_json` to handle contract creation (to: None)
- Fix `from_json` panics: return `Result` errors instead of panicking
- Fix `deserialize_address` silent truncation of values > 255
- Fix `deserialize_u64`/`deserialize_u128` to support hex strings in serde path

### Added

- `accessList` parsing in `from_json`

### Added

- Comprehensive test suite (70 → 100 unit tests) validated against Alloy and rust-bitcoin
- Doc comments across EVM types, signer module, and transaction builders

### Changed

- Fix clippy nursery lints
- Simplify CI matrix (15 → 11 jobs)

## [0.0.2] - 2025-11-07

### Changed

- Documented the builder APIs and README so rustdoc exposes the canonical guides.

## [0.0.1] - 2025-11-07

### Added

- Initial release of `signet-rs`, including the `no_std`-friendly transaction builders for Bitcoin and EVM chains, PSBT helpers, and signer data structures.
