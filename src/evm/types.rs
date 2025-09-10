//! Types used by the EVM transaction builder.
use serde::{Deserialize, Serialize};
use alloc::vec::Vec;

pub type Address = [u8; 20];

pub type AccessList = Vec<(Address, Vec<[u8; 32]>)>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}
