use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// The type of signature hash to compute.
///
/// Currently only [`All`](Self::All) is supported.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
pub enum EcdsaSighashType {
    /// 0x1: Sign all outputs.
    All = 0x01,
}
