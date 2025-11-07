//! Transaction builder for Bitcoin transactions

use alloc::vec::Vec;

use super::{
    bitcoin_transaction::BitcoinTransaction,
    types::{LockTime, TxIn, TxOut, Version},
};
use crate::transaction_builder::TxBuilder;

/// Fluent builder for assembling [`BitcoinTransaction`] values, mirroring the shape of a raw
/// Bitcoin transaction but allowing incremental construction in `no_std` contexts.
pub struct BitcoinTransactionBuilder {
    pub version: Option<Version>,
    pub lock_time: Option<LockTime>,
    pub inputs: Option<Vec<TxIn>>,
    pub outputs: Option<Vec<TxOut>>,
}

impl Default for BitcoinTransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TxBuilder<BitcoinTransaction> for BitcoinTransactionBuilder {
    /// Ensures all mandatory fields are set and returns the immutable transaction.
    fn build(&self) -> BitcoinTransaction {
        BitcoinTransaction {
            version: self.version.expect("Missing version"),
            lock_time: self.lock_time.expect("Missing lock time"),
            input: self.inputs.clone().expect("Missing inputs"),
            output: self.outputs.clone().expect("Missing outputs"),
        }
    }
}

impl BitcoinTransactionBuilder {
    /// Creates an empty builder; each field must be filled before calling [`build`](TxBuilder::build).
    pub const fn new() -> Self {
        Self {
            version: None,
            lock_time: None,
            inputs: None,
            outputs: None,
        }
    }

    /// Sets the transaction version (e.g. `Version::One` or `Version::Two`).
    pub const fn version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the absolute height or timestamp after which miners may include the transaction.
    pub const fn lock_time(mut self, lock_time: LockTime) -> Self {
        self.lock_time = Some(lock_time);
        self
    }

    /// Provides the full input list; use `Vec::new()` if the transaction intentionally has no inputs.
    pub fn inputs(mut self, inputs: Vec<TxIn>) -> Self {
        self.inputs = Some(inputs);
        self
    }

    /// Provides the full output list, preserving order-of-appearance.
    pub fn outputs(mut self, outputs: Vec<TxOut>) -> Self {
        self.outputs = Some(outputs);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build() {
        let block_height = 10000;
        let builder = BitcoinTransactionBuilder::new()
            .version(Version::One)
            .lock_time(LockTime::from_height(block_height).unwrap())
            .inputs(vec![])
            .outputs(vec![])
            .build();

        assert_eq!(builder.version, Version::One);
        assert_eq!(
            builder.lock_time,
            LockTime::from_height(block_height).unwrap()
        );
    }

    #[test]
    fn test_sighash() {
        let block_height = 10000;
        let _builder = BitcoinTransactionBuilder::new()
            .version(Version::One)
            .lock_time(LockTime::from_height(block_height).unwrap())
            .inputs(vec![])
            .outputs(vec![])
            .build();
    }
}
