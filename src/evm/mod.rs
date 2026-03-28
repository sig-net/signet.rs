//! Transaction builder, encoders, types and utilities for EVM.
mod evm_transaction;
mod evm_transaction_builder;
pub mod types;
pub mod utils;

/// EIP-1559 transaction — use [`EVMTransactionBuilder`] for ergonomic construction.
pub use evm_transaction::EVMTransaction;
/// Fluent builder for [`EVMTransaction`] values.
pub use evm_transaction_builder::EVMTransactionBuilder;
