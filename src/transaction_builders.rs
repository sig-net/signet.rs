//! Low level transaction builders for different blockchains.
#[cfg(feature = "bitcoin")]
use crate::bitcoin::BitcoinTransactionBuilder;

#[cfg(feature = "evm")]
use crate::evm::EVMTransactionBuilder;

#[cfg(feature = "evm")]
/// Convenience alias for the EVM transaction builder.
pub type EVM = EVMTransactionBuilder;

#[cfg(feature = "bitcoin")]
/// Convenience alias for the Bitcoin transaction builder.
pub type BITCOIN = BitcoinTransactionBuilder;
