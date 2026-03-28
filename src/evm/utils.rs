//! Address parsing utilities for EVM transactions.
use hex;

use super::types::Address;

/// Parse a 40-character hex address (no `0x` prefix) into a fixed array, panic on invalid input.
///
/// # Panics
///
/// Panics if the hex string is not exactly 40 characters or contains invalid hex.
pub fn parse_eth_address(address: &str) -> Address {
    let address = hex::decode(address).expect("address should be hex");
    assert_eq!(address.len(), 20, "address should be 20 bytes long");
    let mut result = [0u8; 20];
    result.copy_from_slice(&address);
    result
}
