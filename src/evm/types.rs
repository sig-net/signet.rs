//! Types used by the EVM transaction builder.
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Raw 20-byte Ethereum address (no checksum casing).
pub type Address = [u8; 20];

/// Access list entries represented as `(address, storage_keys)` tuples.
pub type AccessList = Vec<(Address, Vec<[u8; 32]>)>;

/// EVM signature payload compatible with signing providers and RLP assembly.
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}
