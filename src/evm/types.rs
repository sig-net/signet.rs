//! Types used by the EVM transaction builder.
#[cfg(feature = "std")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub type Address = [u8; 20];

pub type AccessList = Vec<(Address, Vec<[u8; 32]>)>;

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "std", derive(JsonSchema))]
pub struct Signature {
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}
