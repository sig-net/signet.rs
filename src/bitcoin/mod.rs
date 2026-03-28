//! Transaction builder, encoders, types and utilities for Bitcoin.
mod bitcoin_transaction;
mod bitcoin_transaction_builder;
mod constants;
mod encoding;
pub mod psbt;
pub mod types;
pub mod utils;

/// Bitcoin transaction -- use [`BitcoinTransactionBuilder`] for ergonomic construction.
pub use bitcoin_transaction::BitcoinTransaction;
/// Fluent builder for [`BitcoinTransaction`] values.
pub use bitcoin_transaction_builder::BitcoinTransactionBuilder;
