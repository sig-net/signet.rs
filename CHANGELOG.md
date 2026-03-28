# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2025-11-07

### Fixed

- Fix BIP-143 sighash bug: remove SegWit marker/flag from sighash preimage
- Fix legacy sighash to use non-witness serialization
- Fix `from_json` to handle contract creation (to: None)
- Implement accessList parsing in `from_json`

### Changed

- Add comprehensive test suite (70 → 100 unit tests) validated against Alloy and rust-bitcoin
- Add doc comments across EVM types, signer module, and transaction builders
- Fix clippy nursery lints

## [0.0.2] - 2025-11-07

### Changed

- Documented the builder APIs and README so rustdoc exposes the canonical guides.

## [0.0.1] - 2025-11-07

### Added

- Initial release of `signet-rs`, including the `no_std`-friendly transaction builders for Bitcoin and EVM chains, PSBT helpers, and signer data structures.
