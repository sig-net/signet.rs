# Testing Guide for Signet-RS

This guide explains how to test the signet-rs library, which provides transaction builders for Bitcoin and EVM chains.

## Test Structure

The repository contains multiple levels of testing:

### 1. Unit Tests (59 tests)
Located within the source files themselves, these test individual components in isolation.

**Modules with unit tests:**
- `bitcoin/bitcoin_transaction.rs` - Bitcoin transaction serialization/deserialization
- `bitcoin/bitcoin_transaction_builder.rs` - Bitcoin transaction builder logic
- `bitcoin/types/` - Type-specific tests for Bitcoin primitives
- `bitcoin/utils.rs` - Bitcoin utility functions
- `evm/evm_transaction.rs` - EVM transaction serialization/deserialization
- `evm/evm_transaction_builder.rs` - EVM transaction builder logic
- `transaction_builder.rs` - High-level transaction builder tests

### 2. Integration Tests
Located in the `/tests` directory:
- `basic_test.rs` - Basic integration tests without external dependencies
- `bitcoin_integration_test.rs` - Bitcoin integration tests (requires external setup)
- `evm_integration_test.rs` - EVM integration tests (requires Anvil)

## Running Tests

### Quick Test Commands

```bash
# Run all unit tests (recommended for quick validation)
cargo test --lib

# Run specific unit test module
cargo test --lib bitcoin::bitcoin_transaction::tests

# Run basic integration tests (no external deps needed)
cargo test --test basic_test

# Run all available tests
cargo test

# Run tests in release mode (optimized)
cargo test --release

# Run tests with output displayed
cargo test -- --nocapture

# Run a specific test by name
cargo test test_bitcoin_transaction_builder
```

### Test Categories

#### 1. Core Library Tests (Always Available)
These tests validate the core functionality without any external dependencies:

```bash
# Run only library unit tests
cargo test --lib

# Expected output: 59 tests passing
```

#### 2. Basic Integration Tests (Always Available)
Simple integration tests that verify the main APIs:

```bash
# Run basic integration tests
cargo test --test basic_test

# Tests included:
# - test_bitcoin_transaction_builder
# - test_evm_transaction_builder
```

#### 3. Full Integration Tests (Requires Setup)

**Bitcoin Integration Tests:**
Requires bitcoin test infrastructure. Currently depends on `omni_testing_utilities`.

```bash
# Would need bitcoin testnet setup
cargo test --test bitcoin_integration_test
```

**EVM Integration Tests:**
Requires Anvil (local Ethereum node) to be installed:

```bash
# Install Anvil first
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Then run EVM tests
cargo test --test evm_integration_test
```

## Testing Specific Features

### Bitcoin-only Tests
```bash
cargo test --lib --features bitcoin --no-default-features
```

### EVM-only Tests
```bash
cargo test --lib --features evm --no-default-features
```

## Test Coverage Areas

### Bitcoin Module Testing
- Transaction serialization/deserialization
- Script building and validation
- Sighash calculation
- Type conversions (Version, LockTime, Amount, etc.)
- JSON parsing and encoding
- Witness data handling

### EVM Module Testing
- EIP-1559 transaction building
- RLP encoding/decoding
- Address parsing
- Access list handling
- Signature handling
- Gas fee calculations

## Writing New Tests

### Adding Unit Tests
Add tests within the module file using the `#[cfg(test)]` attribute:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_function() {
        // Test implementation
    }
}
```

### Adding Integration Tests
Create a new file in the `/tests` directory:

```rust
// tests/my_integration_test.rs
use signet_rs::{TransactionBuilder, TxBuilder};

#[test]
fn test_integration_scenario() {
    // Test implementation
}
```

## Continuous Integration

For CI/CD pipelines, use these commands:

```bash
# Basic CI test suite (no external deps)
cargo test --lib --test basic_test

# Full test suite (requires all dependencies)
cargo test --all

# With specific features
cargo test --all-features
```

## Troubleshooting

### Common Issues

1. **"No such file or directory" error in integration tests**
   - This usually means external dependencies (Anvil, Bitcoin testnet) are not set up
   - Run `cargo test --lib --test basic_test` for tests without external dependencies

2. **Compilation errors after changes**
   - Run `cargo clean` then `cargo build`
   - Check that all features compile: `cargo check --all-features`

3. **Test failures after modifying types**
   - Ensure serialization/deserialization tests are updated
   - Check that test vectors match the new format

## Performance Testing

Run benchmarks (if available):
```bash
cargo bench
```

Run tests with timing information:
```bash
cargo test -- --show-output --test-threads=1
```

## Summary

- **Quick validation**: `cargo test --lib --test basic_test` (61 total tests)
- **Full validation**: `cargo test` (requires external setup)
- **Bitcoin only**: `cargo test --lib --features bitcoin --no-default-features`
- **EVM only**: `cargo test --lib --features evm --no-default-features`

The library is well-tested with comprehensive unit tests covering all core functionality. Integration tests are available for more complex scenarios but require additional setup.