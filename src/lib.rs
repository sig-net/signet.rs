#![doc = include_str!("../README.md")]
// Use no_std except during tests (which need std for test infrastructure)
#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(feature = "bitcoin")]
pub mod bitcoin;
mod constants;
#[cfg(feature = "evm")]
pub mod evm;
pub mod signer;
mod transaction_builder;
mod transaction_builders;

pub use transaction_builder::{TransactionBuilder, TxBuilder};
/// Builder alias for Bitcoin transactions — use via [`TransactionBuilder::new::<BITCOIN>()`].
#[cfg(feature = "bitcoin")]
pub use transaction_builders::BITCOIN;
/// Builder alias for EVM transactions — use via [`TransactionBuilder::new::<EVM>()`].
#[cfg(feature = "evm")]
pub use transaction_builders::EVM;
