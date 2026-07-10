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

/// Parse an Ethereum address from a hex string, tolerating an optional `0x`
/// prefix and returning `None` instead of panicking on invalid input.
///
/// Returns `None` if the string is not valid hex or does not decode to exactly
/// 20 bytes.
pub fn parse_eth_address_checked(address: &str) -> Option<Address> {
    let address = address.strip_prefix("0x").unwrap_or(address);
    let bytes = hex::decode(address).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut result = [0u8; 20];
    result.copy_from_slice(&bytes);
    Some(result)
}
