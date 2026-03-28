//! Types used by the EVM transaction builder.
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Raw 20-byte Ethereum address (no checksum casing).
pub type Address = [u8; 20];

/// Access list entries represented as `(address, storage_keys)` tuples.
pub type AccessList = Vec<(Address, Vec<[u8; 32]>)>;

/// ECDSA signature components used to assemble a signed EIP-1559 transaction.
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    /// Recovery ID (0 or 1 for EIP-1559).
    pub v: u64,
    /// 32-byte big-endian R scalar.
    pub r: Vec<u8>,
    /// 32-byte big-endian S scalar.
    pub s: Vec<u8>,
}
