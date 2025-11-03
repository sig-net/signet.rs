use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::bitcoin::encoding::{
    io::{Error as IoError, Write},
    utils::VarInt,
    Encodable,
};

use super::types::{Input, Output, Psbt};

/// PSBT magic bytes: "psbt" + 0xff separator
const PSBT_MAGIC: &[u8] = b"psbt\xff";

/// PSBT serialization errors
#[derive(Debug, Clone)]
pub enum PsbtSerializeError {
    /// IO error during serialization
    Io(String),
    /// Invalid PSBT format
    InvalidFormat(String),
}

impl fmt::Display for PsbtSerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PsbtSerializeError::Io(s) => write!(f, "IO error: {}", s),
            PsbtSerializeError::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
        }
    }
}

/// PSBT parsing errors
#[derive(Debug, Clone)]
pub enum PsbtParseError {
    /// Invalid magic bytes
    InvalidMagic,
    /// IO error during parsing
    Io(String),
    /// Invalid format
    InvalidFormat(String),
}

impl fmt::Display for PsbtParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PsbtParseError::InvalidMagic => write!(f, "Invalid PSBT magic bytes"),
            PsbtParseError::Io(s) => write!(f, "IO error: {}", s),
            PsbtParseError::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
        }
    }
}

impl From<IoError> for PsbtSerializeError {
    fn from(e: IoError) -> Self {
        PsbtSerializeError::Io(alloc::format!("{}", e))
    }
}

// PSBT key types (BIP-174)
// Global types
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;

// Input types
const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;

// Output types
const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;

impl Psbt {
    /// Serialize the PSBT to bytes according to BIP-174.
    pub fn serialize(&self) -> Result<Vec<u8>, PsbtSerializeError> {
        let mut buf = Vec::new();

        // Magic bytes
        buf.write_all(PSBT_MAGIC)?;

        // Global map
        self.serialize_global(&mut buf)?;

        // Input maps
        for input in &self.inputs {
            serialize_input(input, &mut buf)?;
        }

        // Output maps
        for output in &self.outputs {
            serialize_output(output, &mut buf)?;
        }

        Ok(buf)
    }

    /// Serialize the PSBT to hex string.
    pub fn to_hex(&self) -> Result<String, PsbtSerializeError> {
        let bytes = self.serialize()?;
        Ok(hex::encode(bytes))
    }

    fn serialize_global(&self, buf: &mut Vec<u8>) -> Result<(), PsbtSerializeError> {
        // Serialize unsigned transaction
        serialize_key_value(buf, PSBT_GLOBAL_UNSIGNED_TX, &[], &{
            let mut tx_buf = Vec::new();
            self.unsigned_tx.encode(&mut tx_buf)?;
            tx_buf
        })?;

        // Serialize xpubs (sorted by key for canonical ordering)
        {
            let mut xpub: Vec<_> = self.xpub.iter().collect();
            xpub.sort_by_key(|&(k, _)| k);
            for &(key, value) in &xpub {
                serialize_key_value(buf, 0x01, key, value)?;
            }
        }

        // Serialize proprietary fields (sorted by key for canonical ordering)
        {
            let mut proprietary: Vec<_> = self.proprietary.iter().collect();
            proprietary.sort_by_key(|&(k, _)| k);
            for &(key, value) in &proprietary {
                serialize_key_value(buf, 0xfc, key, value)?;
            }
        }

        // Serialize unknown fields (sorted by key for canonical ordering)
        {
            let mut unknown: Vec<_> = self.unknown.iter().collect();
            unknown.sort_by_key(|&(k, _)| k);
            for &(key, value) in &unknown {
                buf.write_all(key)?;
                buf.write_all(value)?;
            }
        }

        // End of global map
        buf.write_all(&[0x00])?;

        Ok(())
    }
}

fn serialize_input(input: &Input, buf: &mut Vec<u8>) -> Result<(), PsbtSerializeError> {
    // Non-witness UTXO
    if let Some(ref tx) = input.non_witness_utxo {
        let mut tx_buf = Vec::new();
        tx.encode(&mut tx_buf)?;
        serialize_key_value(buf, PSBT_IN_NON_WITNESS_UTXO, &[], &tx_buf)?;
    }

    // Witness UTXO
    if let Some(ref utxo) = input.witness_utxo {
        serialize_key_value(buf, PSBT_IN_WITNESS_UTXO, &[], utxo)?;
    }

    // Partial signatures (sorted by key for canonical ordering)
    {
        let mut partial_sigs: Vec<_> = input.partial_sigs.iter().collect();
        partial_sigs.sort_by_key(|&(k, _)| k);
        for &(key, value) in &partial_sigs {
            serialize_key_value(buf, PSBT_IN_PARTIAL_SIG, key, value)?;
        }
    }

    // Sighash type
    if let Some(sighash) = input.sighash_type {
        serialize_key_value(buf, PSBT_IN_SIGHASH_TYPE, &[], &sighash.to_le_bytes())?;
    }

    // Redeem script
    if let Some(ref script) = input.redeem_script {
        serialize_key_value(buf, PSBT_IN_REDEEM_SCRIPT, &[], script)?;
    }

    // Witness script
    if let Some(ref script) = input.witness_script {
        serialize_key_value(buf, PSBT_IN_WITNESS_SCRIPT, &[], script)?;
    }

    // BIP32 derivation (sorted by key for canonical ordering)
    {
        let mut bip32_derivation: Vec<_> = input.bip32_derivation.iter().collect();
        bip32_derivation.sort_by_key(|&(k, _)| k);
        for &(key, value) in &bip32_derivation {
            serialize_key_value(buf, PSBT_IN_BIP32_DERIVATION, key, value)?;
        }
    }

    // Final scriptSig
    if let Some(ref script) = input.final_script_sig {
        serialize_key_value(buf, PSBT_IN_FINAL_SCRIPTSIG, &[], script)?;
    }

    // Final scriptWitness
    if let Some(ref witness) = input.final_script_witness {
        let mut witness_buf = Vec::new();
        VarInt(witness.len() as u64).encode(&mut witness_buf)?;
        for item in witness {
            VarInt(item.len() as u64).encode(&mut witness_buf)?;
            witness_buf.write_all(item)?;
        }
        serialize_key_value(buf, PSBT_IN_FINAL_SCRIPTWITNESS, &[], &witness_buf)?;
    }

    // Proprietary fields (sorted by key for canonical ordering)
    {
        let mut proprietary: Vec<_> = input.proprietary.iter().collect();
        proprietary.sort_by_key(|&(k, _)| k);
        for &(key, value) in &proprietary {
            serialize_key_value(buf, 0xfc, key, value)?;
        }
    }

    // Unknown fields (sorted by key for canonical ordering)
    {
        let mut unknown: Vec<_> = input.unknown.iter().collect();
        unknown.sort_by_key(|&(k, _)| k);
        for &(key, value) in &unknown {
            buf.write_all(key)?;
            buf.write_all(value)?;
        }
    }

    // End of input map
    buf.write_all(&[0x00])?;

    Ok(())
}

fn serialize_output(output: &Output, buf: &mut Vec<u8>) -> Result<(), PsbtSerializeError> {
    // Redeem script
    if let Some(ref script) = output.redeem_script {
        serialize_key_value(buf, PSBT_OUT_REDEEM_SCRIPT, &[], script)?;
    }

    // Witness script
    if let Some(ref script) = output.witness_script {
        serialize_key_value(buf, PSBT_OUT_WITNESS_SCRIPT, &[], script)?;
    }

    // BIP32 derivation (sorted by key for canonical ordering)
    {
        let mut bip32_derivation: Vec<_> = output.bip32_derivation.iter().collect();
        bip32_derivation.sort_by_key(|&(k, _)| k);
        for &(key, value) in &bip32_derivation {
            serialize_key_value(buf, PSBT_OUT_BIP32_DERIVATION, key, value)?;
        }
    }

    // Proprietary fields (sorted by key for canonical ordering)
    {
        let mut proprietary: Vec<_> = output.proprietary.iter().collect();
        proprietary.sort_by_key(|&(k, _)| k);
        for &(key, value) in &proprietary {
            serialize_key_value(buf, 0xfc, key, value)?;
        }
    }

    // Unknown fields (sorted by key for canonical ordering)
    {
        let mut unknown: Vec<_> = output.unknown.iter().collect();
        unknown.sort_by_key(|&(k, _)| k);
        for &(key, value) in &unknown {
            buf.write_all(key)?;
            buf.write_all(value)?;
        }
    }

    // End of output map
    buf.write_all(&[0x00])?;

    Ok(())
}

fn serialize_key_value(
    buf: &mut Vec<u8>,
    key_type: u8,
    key_data: &[u8],
    value: &[u8],
) -> Result<(), PsbtSerializeError> {
    // Key length (1 byte type + key data)
    VarInt((1 + key_data.len()) as u64).encode(buf)?;

    // Key type
    buf.write_all(&[key_type])?;

    // Key data
    buf.write_all(key_data)?;

    // Value length
    VarInt(value.len() as u64).encode(buf)?;

    // Value data
    buf.write_all(value)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::types::*;
    use crate::{TransactionBuilder, TxBuilder, BITCOIN};
    use alloc::vec;

    #[test]
    fn test_psbt_serialization() {
        // Create a simple transaction
        let tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::Two)
            .inputs(vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash::all_zeros()), 0),
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }])
            .outputs(vec![TxOut {
                value: Amount::from_sat(500_000_000),
                script_pubkey: ScriptBuf::default(),
            }])
            .lock_time(LockTime::from_height(0).unwrap())
            .build();

        // Create PSBT
        let psbt = tx.to_psbt();

        // Serialize
        let serialized = psbt.serialize().unwrap();

        // Verify magic bytes
        assert_eq!(&serialized[0..5], PSBT_MAGIC);

        // Should be non-empty
        assert!(serialized.len() > 5);
    }

    #[test]
    fn test_psbt_to_hex() {
        let tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::One)
            .inputs(vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash::all_zeros()), 0),
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }])
            .outputs(vec![TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: ScriptBuf::default(),
            }])
            .lock_time(LockTime::from_height(0).unwrap())
            .build();

        let psbt = tx.to_psbt();
        let hex = psbt.to_hex().unwrap();

        // Should start with "psbt" in hex: 70736274ff
        assert!(hex.starts_with("70736274ff"));

        // Should be valid hex
        assert_eq!(hex.len() % 2, 0);
    }

    #[test]
    fn test_psbt_compare_to_rust_bitcoin_simple() {
        use bitcoin::absolute::LockTime as RustBitcoinLockTime;
        use bitcoin::psbt::Psbt as RustBitcoinPsbt;
        use bitcoin::transaction::{
            OutPoint as RustBitcoinOutPoint, TxIn as RustBitcoinTxIn, TxOut as RustBitcoinTxOut,
            Version as RustBitcoinVersion,
        };
        use bitcoin::Transaction as RustBitcoinTransaction;
        use bitcoin::{
            Amount as RustBitcoinAmount, ScriptBuf as RustBitcoinScriptBuf,
            Witness as RustBitcoinWitness,
        };

        // Create rust-bitcoin transaction
        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::TWO,
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: RustBitcoinOutPoint::null(),
                script_sig: RustBitcoinScriptBuf::default(),
                sequence: bitcoin::Sequence::MAX,
                witness: RustBitcoinWitness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: RustBitcoinAmount::from_sat(500_000_000),
                script_pubkey: RustBitcoinScriptBuf::default(),
            }],
        };

        // Create rust-bitcoin PSBT
        let rb_psbt = RustBitcoinPsbt::from_unsigned_tx(rb_tx.clone()).unwrap();

        // Serialize rust-bitcoin PSBT
        let rb_serialized = rb_psbt.serialize();

        // Create our transaction (matching rust-bitcoin)
        let our_tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::Two)
            .inputs(vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }])
            .outputs(vec![TxOut {
                value: Amount::from_sat(500_000_000),
                script_pubkey: ScriptBuf::default(),
            }])
            .lock_time(LockTime::from_height(0).unwrap())
            .build();

        // Create our PSBT
        let our_psbt = our_tx.to_psbt();
        let our_serialized = our_psbt.serialize().unwrap();

        assert_eq!(rb_serialized.len(), our_serialized.len());
        assert_eq!(rb_serialized, our_serialized);
    }

    #[test]
    fn test_psbt_compare_to_rust_bitcoin_multiple_outputs() {
        use bitcoin::absolute::LockTime as RustBitcoinLockTime;
        use bitcoin::psbt::Psbt as RustBitcoinPsbt;
        use bitcoin::transaction::{
            OutPoint as RustBitcoinOutPoint, TxIn as RustBitcoinTxIn, TxOut as RustBitcoinTxOut,
            Version as RustBitcoinVersion,
        };
        use bitcoin::Transaction as RustBitcoinTransaction;
        use bitcoin::{
            Amount as RustBitcoinAmount, ScriptBuf as RustBitcoinScriptBuf,
            Witness as RustBitcoinWitness,
        };

        // Create rust-bitcoin transaction with 2 outputs
        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::ONE,
            lock_time: RustBitcoinLockTime::from_height(100000).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: RustBitcoinOutPoint::null(),
                script_sig: RustBitcoinScriptBuf::default(),
                sequence: bitcoin::Sequence::MAX,
                witness: RustBitcoinWitness::default(),
            }],
            output: vec![
                RustBitcoinTxOut {
                    value: RustBitcoinAmount::from_sat(100_000_000),
                    script_pubkey: RustBitcoinScriptBuf::default(),
                },
                RustBitcoinTxOut {
                    value: RustBitcoinAmount::from_sat(200_000_000),
                    script_pubkey: RustBitcoinScriptBuf::default(),
                },
            ],
        };

        let rb_psbt = RustBitcoinPsbt::from_unsigned_tx(rb_tx.clone()).unwrap();
        let rb_serialized = rb_psbt.serialize();

        // Create our transaction (matching rust-bitcoin)
        let our_tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::One)
            .inputs(vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }])
            .outputs(vec![
                TxOut {
                    value: Amount::from_sat(100_000_000),
                    script_pubkey: ScriptBuf::default(),
                },
                TxOut {
                    value: Amount::from_sat(200_000_000),
                    script_pubkey: ScriptBuf::default(),
                },
            ])
            .lock_time(LockTime::from_height(100000).unwrap())
            .build();

        let our_psbt = our_tx.to_psbt();
        let our_serialized = our_psbt.serialize().unwrap();

        assert_eq!(rb_serialized.len(), our_serialized.len());
        assert_eq!(rb_serialized, our_serialized);
    }

    #[test]
    fn test_psbt_compare_to_rust_bitcoin_with_scripts() {
        use bitcoin::absolute::LockTime as RustBitcoinLockTime;
        use bitcoin::hashes::Hash as _;
        use bitcoin::psbt::Psbt as RustBitcoinPsbt;
        use bitcoin::transaction::{
            OutPoint as RustBitcoinOutPoint, TxIn as RustBitcoinTxIn, TxOut as RustBitcoinTxOut,
            Version as RustBitcoinVersion,
        };
        use bitcoin::Transaction as RustBitcoinTransaction;
        use bitcoin::{
            Amount as RustBitcoinAmount, ScriptBuf as RustBitcoinScriptBuf,
            Witness as RustBitcoinWitness,
        };

        // P2PKH script: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        let script_bytes =
            hex::decode("76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac").unwrap();

        // Create rust-bitcoin transaction with real script
        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::TWO,
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: RustBitcoinOutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x42; 32]),
                    vout: 1,
                },
                script_sig: RustBitcoinScriptBuf::default(),
                sequence: bitcoin::Sequence::from_consensus(0xfffffffe),
                witness: RustBitcoinWitness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: RustBitcoinAmount::from_sat(499_990_000),
                script_pubkey: RustBitcoinScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let rb_psbt = RustBitcoinPsbt::from_unsigned_tx(rb_tx.clone()).unwrap();
        let rb_serialized = rb_psbt.serialize();

        // Create our transaction (matching rust-bitcoin)
        let our_tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::Two)
            .inputs(vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash([0x42; 32])), 1),
                script_sig: ScriptBuf::default(),
                sequence: Sequence(0xfffffffe),
                witness: Witness::default(),
            }])
            .outputs(vec![TxOut {
                value: Amount::from_sat(499_990_000),
                script_pubkey: ScriptBuf(script_bytes),
            }])
            .lock_time(LockTime::from_height(0).unwrap())
            .build();

        let our_psbt = our_tx.to_psbt();
        let our_serialized = our_psbt.serialize().unwrap();

        assert_eq!(rb_serialized.len(), our_serialized.len());
        assert_eq!(rb_serialized, our_serialized);
    }

    #[test]
    fn test_psbt_with_witness_utxo_metadata() {
        use bitcoin::absolute::LockTime as RustBitcoinLockTime;
        use bitcoin::psbt::Psbt as RustBitcoinPsbt;
        use bitcoin::transaction::{
            OutPoint as RustBitcoinOutPoint, TxIn as RustBitcoinTxIn, TxOut as RustBitcoinTxOut,
            Version as RustBitcoinVersion,
        };
        use bitcoin::Transaction as RustBitcoinTransaction;
        use bitcoin::{
            Amount as RustBitcoinAmount, ScriptBuf as RustBitcoinScriptBuf,
            Witness as RustBitcoinWitness,
        };

        let script_bytes =
            hex::decode("76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac").unwrap();

        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::TWO,
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: RustBitcoinOutPoint::null(),
                script_sig: RustBitcoinScriptBuf::default(),
                sequence: bitcoin::Sequence::MAX,
                witness: RustBitcoinWitness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: RustBitcoinAmount::from_sat(499_990_000),
                script_pubkey: RustBitcoinScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let mut rb_psbt = RustBitcoinPsbt::from_unsigned_tx(rb_tx.clone()).unwrap();

        rb_psbt.inputs[0].witness_utxo = Some(RustBitcoinTxOut {
            value: RustBitcoinAmount::from_sat(500_000_000),
            script_pubkey: RustBitcoinScriptBuf::from_bytes(script_bytes.clone()),
        });
        rb_psbt.inputs[0].sighash_type = Some(bitcoin::sighash::EcdsaSighashType::All.into());

        let rb_serialized = rb_psbt.serialize();

        let our_tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::Two)
            .inputs(vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }])
            .outputs(vec![TxOut {
                value: Amount::from_sat(499_990_000),
                script_pubkey: ScriptBuf(script_bytes.clone()),
            }])
            .lock_time(LockTime::from_height(0).unwrap())
            .build();

        let mut our_psbt = our_tx.to_psbt();

        our_psbt
            .update_input_with_witness_utxo(0, script_bytes, 500_000_000)
            .unwrap();
        our_psbt.update_input_with_sighash_type(0, 1).unwrap();

        let our_serialized = our_psbt.serialize().unwrap();

        assert_eq!(rb_serialized.len(), our_serialized.len());
        assert_eq!(rb_serialized, our_serialized);
    }

    #[test]
    fn test_psbt_compare_to_rust_bitcoin_multiple_inputs() {
        use bitcoin::absolute::LockTime as RustBitcoinLockTime;
        use bitcoin::psbt::Psbt as RustBitcoinPsbt;
        use bitcoin::transaction::{
            OutPoint as RustBitcoinOutPoint, TxIn as RustBitcoinTxIn, TxOut as RustBitcoinTxOut,
            Version as RustBitcoinVersion,
        };
        use bitcoin::Transaction as RustBitcoinTransaction;
        use bitcoin::{
            Amount as RustBitcoinAmount, ScriptBuf as RustBitcoinScriptBuf,
            Witness as RustBitcoinWitness,
        };

        // Create rust-bitcoin transaction with 2 inputs
        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::TWO,
            lock_time: RustBitcoinLockTime::from_height(500000).unwrap(),
            input: vec![
                RustBitcoinTxIn {
                    previous_output: RustBitcoinOutPoint::null(),
                    script_sig: RustBitcoinScriptBuf::default(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: RustBitcoinWitness::default(),
                },
                RustBitcoinTxIn {
                    previous_output: RustBitcoinOutPoint::null(),
                    script_sig: RustBitcoinScriptBuf::default(),
                    sequence: bitcoin::Sequence::from_consensus(0xfffffffd),
                    witness: RustBitcoinWitness::default(),
                },
            ],
            output: vec![RustBitcoinTxOut {
                value: RustBitcoinAmount::from_sat(800_000_000),
                script_pubkey: RustBitcoinScriptBuf::default(),
            }],
        };

        let rb_psbt = RustBitcoinPsbt::from_unsigned_tx(rb_tx.clone()).unwrap();
        let rb_serialized = rb_psbt.serialize();

        // Create our transaction (matching rust-bitcoin)
        let our_tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::Two)
            .inputs(vec![
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::default(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::default(),
                    sequence: Sequence(0xfffffffd),
                    witness: Witness::default(),
                },
            ])
            .outputs(vec![TxOut {
                value: Amount::from_sat(800_000_000),
                script_pubkey: ScriptBuf::default(),
            }])
            .lock_time(LockTime::from_height(500000).unwrap())
            .build();

        let our_psbt = our_tx.to_psbt();
        let our_serialized = our_psbt.serialize().unwrap();

        assert_eq!(rb_serialized.len(), our_serialized.len());
        assert_eq!(rb_serialized, our_serialized);
    }
}
