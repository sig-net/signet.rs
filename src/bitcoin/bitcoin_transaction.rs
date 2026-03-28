use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    constants::{SEGWIT_FLAG, SEGWIT_MARKER},
    encoding::{
        decode::MAX_VEC_SIZE,
        io::{BufRead, Write},
        utils::VarInt,
        Decodable, Encodable, ToU64,
    },
    types::{
        EcdsaSighashType, Hash, LockTime, ScriptBuf, TransactionType, TxIn, TxOut, Txid, Version,
        Witness,
    },
};

/// A Bitcoin transaction with version, locktime, inputs, and outputs.
///
/// ###### Example:
///
/// You can create a Bitcoin transaction directly via struct literal or from JSON.
///
/// ```rust
/// use signet_rs::bitcoin::types::{
///     Amount, Hash, LockTime, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Version, Witness
/// };
/// use signet_rs::bitcoin::BitcoinTransaction;
///
/// // The first case would be as follows:
/// let omni_tx = BitcoinTransaction {
///     version: Version::One,
///     lock_time: LockTime::from_height(1000000).unwrap(),
///     input: vec![TxIn {
///         previous_output: OutPoint {
///             txid: Txid(Hash::all_zeros()),
///             vout: 0,
///         },
///         script_sig: ScriptBuf::default(),
///         sequence: Sequence::default(),
///         witness: Witness::default(),
///     }],
///    output: vec![TxOut {
///        value: Amount::from_sat(10000),
///         script_pubkey: ScriptBuf::default(),
///    }],
/// };
///
/// // If you prefer to do it from a JSON:
/// let json_value = r#"
/// {
///     "version": "1",
///     "lock_time": "0",
///     "input": [{
///         "previous_output": {
///             "txid": "bc25cc0dddd0a202c21e66521a692c0586330a9a9dcc38ccd9b4d2093037f31a",
///             "vout": 0
///         },
///         "script_sig": [],
///         "sequence": 4294967295,
///         "witness": []
///    }],
///     "output": [{
///         "value": 1,
///         "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ad"
///     },   
///     {
///         "value": 2649,
///         "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ac"
///    }]
/// }
/// "#;
/// let tx = signet_rs::bitcoin::BitcoinTransaction::from_json(json_value).unwrap();
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BitcoinTransaction {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    pub version: Version,
    /// Block height or timestamp. Transaction cannot be included in a block until this height/time.
    ///
    /// ### Relevant BIPs
    ///
    /// * [BIP-65 OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
    /// * [BIP-113 Median time-past as endpoint for lock-time calculations](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
    pub lock_time: LockTime,
    /// List of transaction inputs.
    pub input: Vec<TxIn>,
    /// List of transaction outputs.
    pub output: Vec<TxOut>,
}

// Function to compute sha256d (double SHA-256)
fn sha256d(data: &[u8]) -> Vec<u8> {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(hash1);
    hash2.to_vec()
}

impl BitcoinTransaction {
    /// Serialize the transaction to bytes (BIP-144 format if witness data is present).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let _ = self.encode(&mut buffer);

        buffer
    }

    fn encode_without_witness<W: Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, super::encoding::io::Error> {
        let mut len = 0;
        len += self.version.encode(w)?;
        len += self.input.encode(w)?;
        len += self.output.encode(w)?;
        len += self.lock_time.encode(w)?;
        Ok(len)
    }

    /// Compute the transaction ID (double-SHA256 of the non-witness serialization, per BIP-141).
    pub fn compute_txid(&self) -> Txid {
        let mut buffer = Vec::new();
        self.encode_without_witness(&mut buffer)
            .expect("txid encoding should never fail");

        let hash = sha256d(&buffer);
        Txid(Hash(
            hash.try_into().expect("sha256d always returns 32 bytes"),
        ))
    }

    /// Convert this transaction into a [`Psbt`](crate::bitcoin::psbt::Psbt) for incremental signing.
    pub fn to_psbt(&self) -> crate::bitcoin::psbt::Psbt {
        crate::bitcoin::psbt::Psbt::from_unsigned_tx(self.clone())
    }

    /// Encode a legacy transaction into a vector of bytes
    pub fn build_for_signing_legacy(&self, sighash_type: EcdsaSighashType) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Legacy sighash must use non-witness serialization regardless of
        // whether any inputs already have witness data attached.
        let _ = self.encode_without_witness(&mut buffer);

        // Sighash type
        buffer.extend_from_slice(&(sighash_type as u32).to_le_bytes());

        buffer
    }

    /// Attach a script sig to the transaction
    ///
    /// # Panics
    ///
    /// Panics if `tx_type` is a SegWit type (use [`build_with_witness`](Self::build_with_witness) instead).
    pub fn build_with_script_sig(
        &mut self,
        input_index: usize,
        script_sig: ScriptBuf,
        tx_type: TransactionType,
    ) -> Vec<u8> {
        match tx_type {
            TransactionType::P2PKH | TransactionType::P2SH => {
                self.input[input_index].script_sig = script_sig;
            }
            TransactionType::P2WPKH | TransactionType::P2WSH => {
                panic!("Use build_with_witness for SegWit transactions");
            }
        }

        let mut buffer = Vec::new();
        let _ = self.encode(&mut buffer);

        buffer
    }

    /// Encode the transaction for signing in SegWit format
    ///
    /// # Panics
    ///
    /// Panics if the transaction version is not [`Version::Two`].
    pub fn build_for_signing_segwit(
        &self,
        sighash_type: EcdsaSighashType,
        input_index: usize,
        script_code: &ScriptBuf,
        value: u64,
    ) -> Vec<u8> {
        if self.version != Version::Two {
            panic!("SegWit transactions must be version 2");
        }

        let mut buffer = Vec::new();

        self.encode_for_sighash_for_segwit(&mut buffer, input_index, script_code, value);

        // Sighash type
        buffer.extend_from_slice(&(sighash_type as u32).to_le_bytes());

        buffer
    }

    /// Function to attach a witness to the transaction
    ///
    /// # Panics
    ///
    /// Panics if `tx_type` is a legacy type (use [`build_with_script_sig`](Self::build_with_script_sig) instead).
    pub fn build_with_witness(
        &mut self,
        input_index: usize,
        witness: Vec<Vec<u8>>,
        tx_type: TransactionType,
    ) -> Vec<u8> {
        match tx_type {
            TransactionType::P2WPKH | TransactionType::P2WSH => {
                self.input[input_index].witness = Witness::from_slice(&witness);
            }
            TransactionType::P2PKH | TransactionType::P2SH => {
                panic!("Use build_with_script_sig for non-SegWit transactions");
            }
        }

        let mut buffer = Vec::new();

        let _ = self
            .encode(&mut buffer)
            .expect("Failed to encode transaction");

        buffer
    }

    fn encode_for_sighash_for_segwit(
        &self,
        buffer: &mut Vec<u8>,
        input_index: usize,
        script_code: &ScriptBuf,
        value: u64,
    ) {
        // Version
        self.version.encode(buffer).unwrap();

        // Note: BIP-143 sighash preimage must NOT include SegWit marker/flag.
        // Those bytes are only for network serialization (BIP-144).

        // Hash prevouts
        let mut prevouts = Vec::new();
        for input in &self.input {
            input.previous_output.encode(&mut prevouts).unwrap();
        }
        let prevouts_hash = sha256d(&prevouts);
        buffer.extend_from_slice(&prevouts_hash);

        // Hash sequences
        let mut sequences = Vec::new();
        for input in &self.input {
            input.sequence.encode(&mut sequences).unwrap();
        }
        let sequences_hash = sha256d(&sequences);
        buffer.extend_from_slice(&sequences_hash);

        // Outpoint
        self.input[input_index]
            .previous_output
            .encode(buffer)
            .unwrap();

        // Script code
        script_code.encode(buffer).unwrap();

        // Value
        buffer.extend_from_slice(&value.to_le_bytes());

        // Sequence
        self.input[input_index].sequence.encode(buffer).unwrap();

        // Hash outputs
        let mut outputs = Vec::new();
        for output in &self.output {
            output.encode(&mut outputs).unwrap();
        }
        let outputs_hash = sha256d(&outputs);
        buffer.extend_from_slice(&outputs_hash);

        // Locktime
        self.lock_time.encode(buffer).unwrap();
    }

    /// Returns whether or not to serialize transaction as specified in BIP-144.
    fn uses_segwit_serialization(&self) -> bool {
        if self.input.iter().any(|input| !input.witness.is_empty()) {
            return true;
        }
        // To avoid serialization ambiguity, no inputs means we use BIP141 serialization
        self.input.is_empty()
    }

    /// Deserialize a JSON object into a [`BitcoinTransaction`].
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let tx: Self = serde_json::from_str(json)?;
        Ok(tx)
    }
}

impl Encodable for Vec<TxIn> {
    fn encode<W: Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> core::result::Result<usize, super::encoding::io::Error> {
        let mut len = 0;
        len += VarInt(self.len().to_u64()).encode(w)?;
        for c in self.iter() {
            len += c.encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for Vec<TxIn> {
    fn decode<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> core::result::Result<Self, super::encoding::io::Error> {
        let len = VarInt::decode_from_finite_reader(r)?.0;
        // Do not allocate upfront more items than if the sequence of type
        // occupied roughly quarter a block. This should never be the case
        // for normal data, but even if that's not true - `push` will just
        // reallocate.
        // Note: OOM protection relies on reader eventually running out of
        // data to feed us.
        let max_capacity = MAX_VEC_SIZE / 4 / core::mem::size_of::<Self>();
        let mut ret = Self::with_capacity(core::cmp::min(len as usize, max_capacity));
        for _ in 0..len {
            ret.push(Decodable::decode_from_finite_reader(r)?);
        }
        Ok(ret)
    }
}

impl Encodable for Vec<TxOut> {
    fn encode<W: Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> core::result::Result<usize, super::encoding::io::Error> {
        let mut len = 0;
        len += VarInt(self.len().to_u64()).encode(w)?;
        for c in self.iter() {
            len += c.encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for Vec<TxOut> {
    fn decode<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> core::result::Result<Self, super::encoding::io::Error> {
        let len = VarInt::decode_from_finite_reader(r)?.0;
        // Do not allocate upfront more items than if the sequence of type
        // occupied roughly quarter a block. This should never be the case
        // for normal data, but even if that's not true - `push` will just
        // reallocate.
        // Note: OOM protection relies on reader eventually running out of
        // data to feed us.
        let max_capacity = MAX_VEC_SIZE / 4 / core::mem::size_of::<Vec<TxIn>>();
        let mut ret = Self::with_capacity(core::cmp::min(len as usize, max_capacity));
        for _ in 0..len {
            ret.push(Decodable::decode_from_finite_reader(r)?);
        }
        Ok(ret)
    }
}

impl Encodable for BitcoinTransaction {
    fn encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, super::encoding::io::Error> {
        let mut len = 0;
        len += self.version.encode(w)?;

        // Legacy transaction serialization format only includes inputs and outputs.
        if !self.uses_segwit_serialization() {
            len += self.input.encode(w)?;
            len += self.output.encode(w)?;
        } else {
            // BIP-141 (segwit) transaction serialization also includes marker, flag, and witness data.
            len += SEGWIT_MARKER.encode(w)?;
            len += SEGWIT_FLAG.encode(w)?;
            len += self.input.encode(w)?;
            len += self.output.encode(w)?;
            for input in &self.input {
                len += input.witness.encode(w)?;
            }
        }
        len += self.lock_time.encode(w)?;
        Ok(len)
    }
}
#[cfg(test)]
mod tests {
    // Omni imports
    use super::BitcoinTransaction as OmniBitcoinTransaction;
    use super::*;
    use crate::bitcoin::types::{
        Amount as OmniAmount, EcdsaSighashType as OmniSighashType, Hash as OmniHash,
        OutPoint as OmniOutPoint, ScriptBuf as OmniScriptBuf, Sequence as OmniSequence,
        Txid as OmniTxid, Witness as OmniWitness,
    };

    // Rust Bitcoin imports
    use bitcoin::absolute::LockTime as RustBitcoinLockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::transaction::Sequence as RustBitcoinSequence;
    use bitcoin::transaction::{
        OutPoint, TxIn as RustBitcoinTxIn, TxOut as RustBitcoinTxOut, Txid,
    };
    use bitcoin::transaction::{
        Transaction as RustBitcoinTransaction, Version as RustBitcoinVersion,
    };
    use bitcoin::Witness;
    use bitcoin::{Amount, ScriptBuf};

    #[test]
    fn test_build_for_signing_against_rust_bitcoin_for_version_1() {
        let height = 1000000;
        let version = 1;
        let mut tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(version),
            lock_time: RustBitcoinLockTime::from_height(height).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::all_zeros()),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::default(),
                witness: Witness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(10000),
                script_pubkey: ScriptBuf::default(),
            }],
        };

        let sighash_type: EcdsaSighashType = EcdsaSighashType::All;
        let sighasher = SighashCache::new(&mut tx);
        let mut buffer: Vec<u8> = Vec::new();
        sighasher
            .legacy_encode_signing_data_to(
                &mut buffer,
                0,
                &ScriptBuf::default(),
                sighash_type.to_u32(),
            )
            .is_sighash_single_bug()
            .unwrap();

        // Omni implementation
        let omni_tx = OmniBitcoinTransaction {
            version: Version::One,
            lock_time: LockTime::from_height(height).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash::all_zeros()),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::default(),
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(10000),
                script_pubkey: OmniScriptBuf::default(),
            }],
        };

        let serialized = omni_tx.build_for_signing_legacy(OmniSighashType::All);

        assert_eq!(buffer.len(), serialized.len());
        assert_eq!(buffer, serialized);
    }

    #[test]
    fn test_build_for_signing_for_against_rust_bitcoin_for_version_2() {
        let height = 1000000;
        let version = 2;
        let mut tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(version),
            lock_time: RustBitcoinLockTime::from_height(height).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::all_zeros()),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::default(),
                witness: Witness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(10000),
                script_pubkey: ScriptBuf::default(),
            }],
        };

        let sighash_type: EcdsaSighashType = EcdsaSighashType::All;
        let sighasher = SighashCache::new(&mut tx);
        let mut buffer: Vec<u8> = Vec::new();
        sighasher
            .legacy_encode_signing_data_to(
                &mut buffer,
                0,
                &ScriptBuf::default(),
                sighash_type.to_u32(),
            )
            .is_sighash_single_bug()
            .unwrap();

        // Omni implementation
        let omni_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(height).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash::all_zeros()),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::default(),
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(10000),
                script_pubkey: OmniScriptBuf::default(),
            }],
        };

        let serialized = omni_tx.build_for_signing_legacy(OmniSighashType::All);

        assert_eq!(buffer.len(), serialized.len());
        assert_eq!(buffer, serialized);
    }

    #[test]
    fn test_build_for_signing_against_rust_bitcoin_for_version_2_and_segwit() {
        let height = 1000000;
        let version = 2;
        let mut tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(version),
            lock_time: RustBitcoinLockTime::from_height(height).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::all_zeros()),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::default(),
                witness: Witness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(10000),
                script_pubkey: ScriptBuf::default(),
            }],
        };

        let sighash_type: EcdsaSighashType = EcdsaSighashType::All;
        let mut sighasher = SighashCache::new(&mut tx);
        let mut buffer: Vec<u8> = Vec::new();
        sighasher
            .segwit_v0_encode_signing_data_to(
                &mut buffer,
                0,
                &ScriptBuf::default(),
                Amount::from_sat(0),
                sighash_type,
            )
            .unwrap();

        // Omni implementation
        let omni_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(height).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash::all_zeros()),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::default(),
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(10000),
                script_pubkey: OmniScriptBuf::default(),
            }],
        };

        let serialized = omni_tx.build_for_signing_segwit(
            OmniSighashType::All,
            0,
            &OmniScriptBuf::default(),
            OmniAmount::from_sat(0).to_sat(),
        );

        assert_eq!(buffer.len(), serialized.len());
        assert_eq!(buffer, serialized);
    }

    #[test]
    fn test_from_json_bitcoin_transaction() {
        let json = r#"
        {
            "version": "1",
            "lock_time": "0",
            "input": [
                {
                    "previous_output": {
                        "txid": "bc25cc0dddd0a202c21e66521a692c0586330a9a9dcc38ccd9b4d2093037f31a",
                        "vout": 0
                    },
                    "script_sig": "",
                    "sequence": 4294967295,
                    "witness": []
                }
            ],
            "output": [
                {
                    "value": 1,
                    "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ad"
                },
                {
                    "value": 2649,
                    "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ac"
                }
            ]
        }
        "#;

        let _tx = OmniBitcoinTransaction::from_json(json).unwrap();
    }

    #[test]
    fn test_from_json_bitcoin_transaction_2() {
        let json = r#"
        {
            "version": "1",
            "lock_time": "0",
            "input": [
                {
                    "previous_output": {
                        "txid": "bc25cc0dddd0a202c21e66521a692c0586330a9a9dcc38ccd9b4d2093037f31a",
                        "vout": 0
                    },
                    "script_sig": [],
                    "sequence": 4294967295,
                    "witness": []
                }
            ],
            "output": [
                {
                    "value": 1,
                    "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ad"
                },
                {
                    "value": 2649,
                    "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ac"
                }
            ]
        }
        "#;

        let tx = OmniBitcoinTransaction::from_json(json).unwrap();

        assert_eq!(tx.version, Version::One);
        assert_eq!(tx.lock_time, LockTime::from_height(0).unwrap());
        // input
        assert_eq!(tx.input[0].script_sig, OmniScriptBuf::default());
        assert_eq!(tx.input[0].witness, OmniWitness::default());
        assert_eq!(tx.input[0].sequence, OmniSequence(4294967295));
        assert_eq!(
            tx.input[0].previous_output,
            OmniOutPoint {
                txid: OmniTxid(
                    OmniHash::from_hex(
                        "bc25cc0dddd0a202c21e66521a692c0586330a9a9dcc38ccd9b4d2093037f31a"
                    )
                    .unwrap()
                ),
                vout: 0
            }
        );
        assert_eq!(tx.input.len(), 1);
        // output
        assert_eq!(
            tx.output[0].script_pubkey,
            OmniScriptBuf::from_hex("76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ad").unwrap()
        );
        assert_eq!(
            tx.output[1].script_pubkey,
            OmniScriptBuf::from_hex("76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ac").unwrap()
        );
        assert_eq!(tx.output[0].value, OmniAmount::from_sat(1));
        assert_eq!(tx.output[1].value, OmniAmount::from_sat(2649));
        assert_eq!(tx.output.len(), 2);
    }

    #[test]
    fn test_from_json_bitcoin_transaction_3() {
        let json = r#"
        {
            "version": "2",
            "lock_time": "0",
            "input": [
                {
                    "previous_output": {
                        "txid": "bc25cc0dddd0a202c21e66521a692c0586330a9a9dcc38ccd9b4d2093037f31a",
                        "vout": 0
                    },
                    "script_sig": [],
                    "sequence": 4294967295,
                    "witness": []
                }
            ],
            "output": [
                {
                    "value": 1,
                    "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ad"
                },
                {
                    "value": 2649,
                    "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ac"
                }
            ]
        }
        "#;

        let tx = OmniBitcoinTransaction::from_json(json).unwrap();

        assert_eq!(tx.version, Version::Two);
        assert_eq!(tx.lock_time, LockTime::from_height(0).unwrap());
        // input
        assert_eq!(tx.input[0].script_sig, OmniScriptBuf::default());
        assert_eq!(tx.input[0].witness, OmniWitness::default());
        assert_eq!(tx.input[0].sequence, OmniSequence(4294967295));
        assert_eq!(
            tx.input[0].previous_output,
            OmniOutPoint {
                txid: OmniTxid(
                    OmniHash::from_hex(
                        "bc25cc0dddd0a202c21e66521a692c0586330a9a9dcc38ccd9b4d2093037f31a"
                    )
                    .unwrap()
                ),
                vout: 0
            }
        );
        assert_eq!(tx.input.len(), 1);
        // output
        assert_eq!(
            tx.output[0].script_pubkey,
            OmniScriptBuf::from_hex("76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ad").unwrap()
        );
        assert_eq!(
            tx.output[1].script_pubkey,
            OmniScriptBuf::from_hex("76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ac").unwrap()
        );
        assert_eq!(tx.output[0].value, OmniAmount::from_sat(1));
        assert_eq!(tx.output[1].value, OmniAmount::from_sat(2649));
        assert_eq!(tx.output.len(), 2);
    }

    #[test]
    fn test_from_json_bitcoin_transaction_4() {
        let json = r#"
            {
                "version": "2",
                "lock_time": "0",
                "input": [
                    {
                        "previous_output": {
                            "txid": "bc25cc0dddd0a202c21e66521a692c0586330a9a9dcc38ccd9b4d2093037f31a",
                            "vout": 0
                        },
                        "script_sig": [],
                        "sequence": 4294967295,
                        "witness": []
                    }
                ],
                "output": [
                    {
                        "value": 1,
                        "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ad"
                    },
                    {
                        "value": 2649,
                        "script_pubkey": "76a9148356ecd5f1761e60c144dc2f4de6bf7d8be7690688ac"
                    }
                ]
            }
        "#;

        let tx = OmniBitcoinTransaction::from_json(json).unwrap();

        assert_eq!(tx.version, Version::Two);
        assert_eq!(tx.lock_time, LockTime::from_height(0).unwrap());
    }

    #[test]
    fn test_txid_against_rust_bitcoin() {
        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::TWO,
            lock_time: RustBitcoinLockTime::from_height(100000).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::all_zeros()),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(500_000_000),
                script_pubkey: ScriptBuf::default(),
            }],
        };

        let rb_txid = rb_tx.compute_txid();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(100000).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash::all_zeros()),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(500_000_000),
                script_pubkey: OmniScriptBuf::default(),
            }],
        };

        let our_txid = our_tx.compute_txid();

        assert_eq!(*rb_txid.as_byte_array(), our_txid.as_byte_array());
        assert_eq!(rb_txid.to_string(), our_txid.to_string());
    }

    #[test]
    fn test_txid_segwit_transaction() {
        let script_bytes =
            hex::decode("76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac").unwrap();

        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::TWO,
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::from_slice(&[vec![0x01, 0x02, 0x03]]),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(499_990_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let rb_txid = rb_tx.compute_txid();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint::null(),
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::from_slice(&[vec![0x01, 0x02, 0x03]]),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(499_990_000),
                script_pubkey: OmniScriptBuf(script_bytes),
            }],
        };

        let our_txid = our_tx.compute_txid();

        assert_eq!(*rb_txid.as_byte_array(), our_txid.as_byte_array());
        assert_eq!(rb_txid.to_string(), our_txid.to_string());
    }

    #[test]
    fn test_from_json_bitcoin_transaction_5() {
        let json_data = r#"
        {
            "version": 1,
            "lock_time": 1,
            "input": [
                {
                    "previous_output": {
                        "txid": [59, 103, 22, 67, 189, 12, 138, 114, 42, 90, 207, 173, 211, 254, 197, 194, 92, 65, 224, 168, 146, 169, 213, 217, 184, 81, 123, 217, 19, 81, 69, 71],
                        "vout": 0
                    },
                    "script_sig": [],
                    "sequence": 4294967295,
                    "witness": []
                }
            ],
            "output": [
                {
                    "value": 500000000,
                    "script_pubkey": [118, 169, 20, 136, 240, 168, 35, 147, 140, 88, 207, 91, 23, 200, 235, 147, 198, 130, 128, 99, 91, 115, 78, 136, 172]
                },
                {
                    "value": 4499999000,
                    "script_pubkey": [118, 169, 20, 197, 64, 140, 145, 44, 231, 221, 181, 123, 174, 124, 22, 79, 148, 247, 47, 225, 189, 178, 180, 136, 172]
                }
            ]
        }
        "#;

        let result: Result<BitcoinTransaction, _> = serde_json::from_str(json_data);
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result.err());
    }

    // ========================================================================
    // SegWit Sighash Tests
    // ========================================================================

    #[test]
    fn test_segwit_sighash_with_real_script_and_value() {
        // P2PKH-style script code used for P2WPKH sighash:
        // OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        let script_hex = "76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac";
        let script_bytes = hex::decode(script_hex).unwrap();
        let value_sats: u64 = 100_000_000; // 1 BTC

        // Txid hex in display order (big-endian, as shown in block explorers).
        // OmniHash stores bytes in this display order and reverses on encode.
        // rust-bitcoin's from_byte_array takes the internal (little-endian) order,
        // so we reverse the bytes for rust-bitcoin.
        let txid_hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let txid_display_bytes = hex::decode(txid_hex).unwrap();
        let mut display_arr = [0u8; 32];
        display_arr.copy_from_slice(&txid_display_bytes);

        // For rust-bitcoin: internal byte order = reversed display bytes
        let mut internal_arr = display_arr;
        internal_arr.reverse();

        // rust-bitcoin reference
        let mut rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(500_000).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array(internal_arr)),
                    vout: 1,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(90_000_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let sighash_type = EcdsaSighashType::All;
        let mut rb_buf: Vec<u8> = Vec::new();
        SighashCache::new(&mut rb_tx)
            .segwit_v0_encode_signing_data_to(
                &mut rb_buf,
                0,
                &ScriptBuf::from_bytes(script_bytes.clone()),
                Amount::from_sat(value_sats),
                sighash_type,
            )
            .unwrap();

        // Our implementation
        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(500_000).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash(display_arr)),
                    vout: 1,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(90_000_000),
                script_pubkey: OmniScriptBuf(script_bytes.clone()),
            }],
        };

        let our_buf = our_tx.build_for_signing_segwit(
            OmniSighashType::All,
            0,
            &OmniScriptBuf(script_bytes),
            value_sats,
        );

        assert_eq!(rb_buf.len(), our_buf.len());
        assert_eq!(rb_buf, our_buf);
    }

    #[test]
    fn test_segwit_sighash_multiple_inputs() {
        let script_hex = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let script_bytes = hex::decode(script_hex).unwrap();

        let make_txid = |b: u8| -> [u8; 32] { [b; 32] };

        let rb_inputs: Vec<RustBitcoinTxIn> = (0u8..3)
            .map(|i| RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array(make_txid(i + 1))),
                    vout: i as u32,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::default(),
            })
            .collect();

        let mut rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: rb_inputs,
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let our_inputs: Vec<TxIn> = (0u8..3)
            .map(|i| TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash(make_txid(i + 1))),
                    vout: i as u32,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::default(),
            })
            .collect();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: our_inputs,
            output: vec![TxOut {
                value: OmniAmount::from_sat(50_000),
                script_pubkey: OmniScriptBuf(script_bytes.clone()),
            }],
        };

        let value = 100_000u64;
        let sighash_type = EcdsaSighashType::All;

        for input_index in 0..3 {
            let mut rb_buf: Vec<u8> = Vec::new();
            SighashCache::new(&mut rb_tx)
                .segwit_v0_encode_signing_data_to(
                    &mut rb_buf,
                    input_index,
                    &ScriptBuf::from_bytes(script_bytes.clone()),
                    Amount::from_sat(value),
                    sighash_type,
                )
                .unwrap();

            let our_buf = our_tx.build_for_signing_segwit(
                OmniSighashType::All,
                input_index,
                &OmniScriptBuf(script_bytes.clone()),
                value,
            );

            assert_eq!(rb_buf, our_buf, "Mismatch at input index {input_index}");
        }
    }

    #[test]
    fn test_segwit_sighash_multiple_outputs() {
        let script_hex = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let script_bytes = hex::decode(script_hex).unwrap();
        // P2WPKH output script: OP_0 <20-byte-hash>
        let p2wpkh_script = hex::decode("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
        // OP_RETURN data
        let op_return_script = hex::decode("6a0b68656c6c6f20776f726c64").unwrap();

        let mut rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(750_000).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0xaa; 32])),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![
                RustBitcoinTxOut {
                    value: Amount::from_sat(50_000_000),
                    script_pubkey: ScriptBuf::from_bytes(p2wpkh_script.clone()),
                },
                RustBitcoinTxOut {
                    value: Amount::from_sat(49_000_000),
                    script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
                },
                RustBitcoinTxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::from_bytes(op_return_script.clone()),
                },
            ],
        };

        let mut rb_buf: Vec<u8> = Vec::new();
        SighashCache::new(&mut rb_tx)
            .segwit_v0_encode_signing_data_to(
                &mut rb_buf,
                0,
                &ScriptBuf::from_bytes(script_bytes.clone()),
                Amount::from_sat(100_000_000),
                EcdsaSighashType::All,
            )
            .unwrap();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(750_000).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash([0xaa; 32])),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::default(),
            }],
            output: vec![
                TxOut {
                    value: OmniAmount::from_sat(50_000_000),
                    script_pubkey: OmniScriptBuf(p2wpkh_script),
                },
                TxOut {
                    value: OmniAmount::from_sat(49_000_000),
                    script_pubkey: OmniScriptBuf(script_bytes.clone()),
                },
                TxOut {
                    value: OmniAmount::from_sat(0),
                    script_pubkey: OmniScriptBuf(op_return_script),
                },
            ],
        };

        let our_buf = our_tx.build_for_signing_segwit(
            OmniSighashType::All,
            0,
            &OmniScriptBuf(script_bytes),
            100_000_000,
        );

        assert_eq!(rb_buf, our_buf);
    }

    #[test]
    fn test_segwit_sighash_large_value() {
        // 21 million BTC in satoshis
        let value_sats: u64 = 2_100_000_000_000_000;
        let script_hex = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let script_bytes = hex::decode(script_hex).unwrap();

        let mut rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0xff; 32])),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(value_sats),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let mut rb_buf: Vec<u8> = Vec::new();
        SighashCache::new(&mut rb_tx)
            .segwit_v0_encode_signing_data_to(
                &mut rb_buf,
                0,
                &ScriptBuf::from_bytes(script_bytes.clone()),
                Amount::from_sat(value_sats),
                EcdsaSighashType::All,
            )
            .unwrap();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash([0xff; 32])),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(value_sats),
                script_pubkey: OmniScriptBuf(script_bytes.clone()),
            }],
        };

        let our_buf = our_tx.build_for_signing_segwit(
            OmniSighashType::All,
            0,
            &OmniScriptBuf(script_bytes),
            value_sats,
        );

        assert_eq!(rb_buf, our_buf);
    }

    #[test]
    fn test_segwit_sighash_with_nondefault_sequence() {
        let script_hex = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let script_bytes = hex::decode(script_hex).unwrap();
        // RBF-enabled sequence
        let rbf_sequence = 0xFFFF_FFFDu32;

        let mut rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(100_000).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0xbb; 32])),
                    vout: 3,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence(rbf_sequence),
                witness: Witness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let mut rb_buf: Vec<u8> = Vec::new();
        SighashCache::new(&mut rb_tx)
            .segwit_v0_encode_signing_data_to(
                &mut rb_buf,
                0,
                &ScriptBuf::from_bytes(script_bytes.clone()),
                Amount::from_sat(2_000_000),
                EcdsaSighashType::All,
            )
            .unwrap();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(100_000).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash([0xbb; 32])),
                    vout: 3,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence(rbf_sequence),
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(1_000_000),
                script_pubkey: OmniScriptBuf(script_bytes.clone()),
            }],
        };

        let our_buf = our_tx.build_for_signing_segwit(
            OmniSighashType::All,
            0,
            &OmniScriptBuf(script_bytes),
            2_000_000,
        );

        assert_eq!(rb_buf, our_buf);
    }

    // ========================================================================
    // Transaction Serialization Tests
    // ========================================================================

    #[test]
    fn test_segwit_serialization_against_rust_bitcoin() {
        let script_bytes =
            hex::decode("76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac").unwrap();
        let witness_sig = vec![0x30; 71]; // mock DER sig
        let witness_pubkey = vec![0x02; 33]; // mock compressed pubkey

        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0xab; 32])),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::from_slice(&[witness_sig.clone(), witness_pubkey.clone()]),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let rb_serialized = bitcoin::consensus::serialize(&rb_tx);

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash([0xab; 32])),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::from_slice(&[witness_sig, witness_pubkey]),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(50_000),
                script_pubkey: OmniScriptBuf(script_bytes),
            }],
        };

        let our_serialized = our_tx.serialize();

        assert_eq!(rb_serialized, our_serialized);
    }

    #[test]
    fn test_segwit_serialization_multiple_witnesses() {
        let script_bytes = hex::decode("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba").unwrap();

        let wit1_sig = vec![0x30; 72];
        let wit1_pk = vec![0x03; 33];
        let wit2_sig = vec![0x30; 71];
        let wit2_pk = vec![0x02; 33];

        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(200_000).unwrap(),
            input: vec![
                RustBitcoinTxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_raw_hash(Hash::from_byte_array([0x11; 32])),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: RustBitcoinSequence::MAX,
                    witness: Witness::from_slice(&[wit1_sig.clone(), wit1_pk.clone()]),
                },
                RustBitcoinTxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_raw_hash(Hash::from_byte_array([0x22; 32])),
                        vout: 1,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: RustBitcoinSequence::MAX,
                    witness: Witness::from_slice(&[wit2_sig.clone(), wit2_pk.clone()]),
                },
            ],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(80_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let rb_serialized = bitcoin::consensus::serialize(&rb_tx);

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(200_000).unwrap(),
            input: vec![
                TxIn {
                    previous_output: OmniOutPoint {
                        txid: OmniTxid(OmniHash([0x11; 32])),
                        vout: 0,
                    },
                    script_sig: OmniScriptBuf::default(),
                    sequence: OmniSequence::MAX,
                    witness: OmniWitness::from_slice(&[wit1_sig, wit1_pk]),
                },
                TxIn {
                    previous_output: OmniOutPoint {
                        txid: OmniTxid(OmniHash([0x22; 32])),
                        vout: 1,
                    },
                    script_sig: OmniScriptBuf::default(),
                    sequence: OmniSequence::MAX,
                    witness: OmniWitness::from_slice(&[wit2_sig, wit2_pk]),
                },
            ],
            output: vec![TxOut {
                value: OmniAmount::from_sat(80_000),
                script_pubkey: OmniScriptBuf(script_bytes),
            }],
        };

        let our_serialized = our_tx.serialize();

        assert_eq!(rb_serialized, our_serialized);
    }

    #[test]
    fn test_segwit_serialization_mixed_witness_empty() {
        let script_bytes =
            hex::decode("76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac").unwrap();

        let wit_sig = vec![0x30; 70];
        let wit_pk = vec![0x02; 33];

        // First input has witness, second has empty witness
        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![
                RustBitcoinTxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_raw_hash(Hash::from_byte_array([0xcc; 32])),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: RustBitcoinSequence::MAX,
                    witness: Witness::from_slice(&[wit_sig.clone(), wit_pk.clone()]),
                },
                RustBitcoinTxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_raw_hash(Hash::from_byte_array([0xdd; 32])),
                        vout: 1,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: RustBitcoinSequence::MAX,
                    witness: Witness::default(),
                },
            ],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let rb_serialized = bitcoin::consensus::serialize(&rb_tx);

        // Verify segwit flag is present (byte at index 4 = 0x00 marker, index 5 = 0x01 flag)
        assert_eq!(rb_serialized[4], 0x00, "Missing segwit marker");
        assert_eq!(rb_serialized[5], 0x01, "Missing segwit flag");

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: vec![
                TxIn {
                    previous_output: OmniOutPoint {
                        txid: OmniTxid(OmniHash([0xcc; 32])),
                        vout: 0,
                    },
                    script_sig: OmniScriptBuf::default(),
                    sequence: OmniSequence::MAX,
                    witness: OmniWitness::from_slice(&[wit_sig, wit_pk]),
                },
                TxIn {
                    previous_output: OmniOutPoint {
                        txid: OmniTxid(OmniHash([0xdd; 32])),
                        vout: 1,
                    },
                    script_sig: OmniScriptBuf::default(),
                    sequence: OmniSequence::MAX,
                    witness: OmniWitness::default(),
                },
            ],
            output: vec![TxOut {
                value: OmniAmount::from_sat(30_000),
                script_pubkey: OmniScriptBuf(script_bytes),
            }],
        };

        let our_serialized = our_tx.serialize();

        assert_eq!(rb_serialized, our_serialized);
    }

    // ========================================================================
    // Txid Tests
    // ========================================================================

    #[test]
    fn test_txid_segwit_multiple_inputs() {
        let script_bytes =
            hex::decode("76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac").unwrap();
        let witness_data = vec![vec![0x30; 72], vec![0x02; 33]];

        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::TWO,
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![
                RustBitcoinTxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_raw_hash(Hash::from_byte_array([0x11; 32])),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: RustBitcoinSequence::MAX,
                    witness: Witness::from_slice(&witness_data),
                },
                RustBitcoinTxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_raw_hash(Hash::from_byte_array([0x22; 32])),
                        vout: 1,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: RustBitcoinSequence::MAX,
                    witness: Witness::from_slice(&witness_data),
                },
            ],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let rb_txid = rb_tx.compute_txid();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: vec![
                TxIn {
                    previous_output: OmniOutPoint {
                        txid: OmniTxid(OmniHash([0x11; 32])),
                        vout: 0,
                    },
                    script_sig: OmniScriptBuf::default(),
                    sequence: OmniSequence::MAX,
                    witness: OmniWitness::from_slice(&witness_data),
                },
                TxIn {
                    previous_output: OmniOutPoint {
                        txid: OmniTxid(OmniHash([0x22; 32])),
                        vout: 1,
                    },
                    script_sig: OmniScriptBuf::default(),
                    sequence: OmniSequence::MAX,
                    witness: OmniWitness::from_slice(&witness_data),
                },
            ],
            output: vec![TxOut {
                value: OmniAmount::from_sat(100_000),
                script_pubkey: OmniScriptBuf(script_bytes),
            }],
        };

        let our_txid = our_tx.compute_txid();

        assert_eq!(*rb_txid.as_byte_array(), our_txid.as_byte_array());
        assert_eq!(rb_txid.to_string(), our_txid.to_string());
    }

    #[test]
    fn test_txid_segwit_large_witness() {
        let script_bytes =
            hex::decode("76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac").unwrap();

        // Large witness stack with 6 items
        let large_witness: Vec<Vec<u8>> = vec![
            vec![0x00],      // OP_0 for CHECKMULTISIG bug
            vec![0x30; 72],  // sig 1
            vec![0x30; 71],  // sig 2
            vec![0x30; 70],  // sig 3
            vec![0x30; 73],  // sig 4
            vec![0x52; 105], // redeem script
        ];

        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::TWO,
            lock_time: RustBitcoinLockTime::from_height(300_000).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0xee; 32])),
                    vout: 2,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::from_slice(&large_witness),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(999_999),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let rb_txid = rb_tx.compute_txid();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(300_000).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash([0xee; 32])),
                    vout: 2,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::from_slice(&large_witness),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(999_999),
                script_pubkey: OmniScriptBuf(script_bytes),
            }],
        };

        let our_txid = our_tx.compute_txid();

        assert_eq!(*rb_txid.as_byte_array(), our_txid.as_byte_array());
        assert_eq!(rb_txid.to_string(), our_txid.to_string());
    }

    #[test]
    fn test_txid_with_real_scripts() {
        // P2WPKH output scripts: OP_0 <20-byte-hash>
        let output_script_1 = hex::decode("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
        let output_script_2 = hex::decode("0014deadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();

        let witness_data = vec![vec![0x30; 72], vec![0x02; 33]];

        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion::TWO,
            lock_time: RustBitcoinLockTime::from_height(400_000).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0x55; 32])),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::from_slice(&witness_data),
            }],
            output: vec![
                RustBitcoinTxOut {
                    value: Amount::from_sat(40_000_000),
                    script_pubkey: ScriptBuf::from_bytes(output_script_1.clone()),
                },
                RustBitcoinTxOut {
                    value: Amount::from_sat(9_000_000),
                    script_pubkey: ScriptBuf::from_bytes(output_script_2.clone()),
                },
            ],
        };

        let rb_txid = rb_tx.compute_txid();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(400_000).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash([0x55; 32])),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::from_slice(&witness_data),
            }],
            output: vec![
                TxOut {
                    value: OmniAmount::from_sat(40_000_000),
                    script_pubkey: OmniScriptBuf(output_script_1),
                },
                TxOut {
                    value: OmniAmount::from_sat(9_000_000),
                    script_pubkey: OmniScriptBuf(output_script_2),
                },
            ],
        };

        let our_txid = our_tx.compute_txid();

        assert_eq!(*rb_txid.as_byte_array(), our_txid.as_byte_array());
        assert_eq!(rb_txid.to_string(), our_txid.to_string());
    }

    // ========================================================================
    // Build With Witness Tests
    // ========================================================================

    #[test]
    fn test_build_with_witness_p2wpkh() {
        let script_bytes = hex::decode("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
        let witness_sig = vec![0x30; 72];
        let witness_pubkey = vec![0x02; 33];

        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0xaa; 32])),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::from_slice(&[witness_sig.clone(), witness_pubkey.clone()]),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let rb_serialized = bitcoin::consensus::serialize(&rb_tx);

        let mut our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash([0xaa; 32])),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(50_000),
                script_pubkey: OmniScriptBuf(script_bytes),
            }],
        };

        let our_serialized = our_tx.build_with_witness(
            0,
            vec![witness_sig, witness_pubkey],
            TransactionType::P2WPKH,
        );

        assert_eq!(rb_serialized, our_serialized);
    }

    #[test]
    fn test_build_with_witness_p2wsh() {
        let script_bytes =
            hex::decode("0020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd")
                .unwrap();

        // P2WSH witness: OP_0, sig1, sig2, redeem_script (multisig)
        let witness_items = vec![
            vec![0x00],     // OP_0 for CHECKMULTISIG bug
            vec![0x30; 72], // signature 1
            vec![0x30; 71], // signature 2
            vec![0x52; 71], // redeem script (mock)
        ];

        let rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0xbb; 32])),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::from_slice(&witness_items),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(75_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let rb_serialized = bitcoin::consensus::serialize(&rb_tx);

        let mut our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash([0xbb; 32])),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(75_000),
                script_pubkey: OmniScriptBuf(script_bytes),
            }],
        };

        let our_serialized = our_tx.build_with_witness(0, witness_items, TransactionType::P2WSH);

        assert_eq!(rb_serialized, our_serialized);
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_segwit_locktime_time_based() {
        // Time-based locktime: >= 500_000_000
        let locktime_time = 500_000_100u32;
        let script_hex = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let script_bytes = hex::decode(script_hex).unwrap();

        let mut rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_time(locktime_time).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0x44; 32])),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(5_000_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let mut rb_buf: Vec<u8> = Vec::new();
        SighashCache::new(&mut rb_tx)
            .segwit_v0_encode_signing_data_to(
                &mut rb_buf,
                0,
                &ScriptBuf::from_bytes(script_bytes.clone()),
                Amount::from_sat(10_000_000),
                EcdsaSighashType::All,
            )
            .unwrap();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_time(locktime_time).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash([0x44; 32])),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::ENABLE_RBF_NO_LOCKTIME,
                witness: OmniWitness::default(),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(5_000_000),
                script_pubkey: OmniScriptBuf(script_bytes.clone()),
            }],
        };

        let our_buf = our_tx.build_for_signing_segwit(
            OmniSighashType::All,
            0,
            &OmniScriptBuf(script_bytes),
            10_000_000,
        );

        assert_eq!(rb_buf, our_buf);
    }

    #[test]
    fn test_segwit_multiple_inputs_different_values() {
        let script_hex = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let script_bytes = hex::decode(script_hex).unwrap();

        let values = [50_000_000u64, 100_000_000, 200_000_000];

        let make_txid = |b: u8| -> [u8; 32] { [b; 32] };

        let rb_inputs: Vec<RustBitcoinTxIn> = (0u8..3)
            .map(|i| RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array(make_txid(i + 0x10))),
                    vout: i as u32,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::MAX,
                witness: Witness::default(),
            })
            .collect();

        let mut rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: rb_inputs,
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(340_000_000),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let our_inputs: Vec<TxIn> = (0u8..3)
            .map(|i| TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash(make_txid(i + 0x10))),
                    vout: i as u32,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::MAX,
                witness: OmniWitness::default(),
            })
            .collect();

        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: our_inputs,
            output: vec![TxOut {
                value: OmniAmount::from_sat(340_000_000),
                script_pubkey: OmniScriptBuf(script_bytes.clone()),
            }],
        };

        let sighash_type = EcdsaSighashType::All;
        let mut all_sighashes: Vec<Vec<u8>> = Vec::new();

        for (input_index, &value) in values.iter().enumerate() {
            let mut rb_buf: Vec<u8> = Vec::new();
            SighashCache::new(&mut rb_tx)
                .segwit_v0_encode_signing_data_to(
                    &mut rb_buf,
                    input_index,
                    &ScriptBuf::from_bytes(script_bytes.clone()),
                    Amount::from_sat(value),
                    sighash_type,
                )
                .unwrap();

            let our_buf = our_tx.build_for_signing_segwit(
                OmniSighashType::All,
                input_index,
                &OmniScriptBuf(script_bytes.clone()),
                value,
            );

            assert_eq!(rb_buf, our_buf, "Mismatch at input index {input_index}");
            all_sighashes.push(our_buf);
        }

        // Verify each sighash is unique (different values produce different sighashes)
        assert_ne!(all_sighashes[0], all_sighashes[1]);
        assert_ne!(all_sighashes[1], all_sighashes[2]);
        assert_ne!(all_sighashes[0], all_sighashes[2]);
    }

    // ========================================================================
    // Regression tests for bugs found during spec audit
    // ========================================================================

    #[test]
    fn test_segwit_sighash_with_prepopulated_witness() {
        // Regression: encode_for_sighash_for_segwit must NOT include SegWit
        // marker/flag bytes in the BIP-143 sighash preimage, even when some
        // inputs already have witness data attached (e.g., signing input 1
        // after input 0's witness was already set).
        let script_hex = "76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac";
        let script_bytes = hex::decode(script_hex).unwrap();
        let value_sats: u64 = 50_000_000;

        let txid_bytes =
            hex::decode("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
                .unwrap();
        let mut display_arr = [0u8; 32];
        display_arr.copy_from_slice(&txid_bytes);
        let mut internal_arr = display_arr;
        internal_arr.reverse();

        // Witness data that would already be on input 0
        let existing_witness = vec![
            vec![0x30; 70], // fake DER signature
            vec![0x02; 33], // fake compressed pubkey
        ];

        // rust-bitcoin: input 0 has witness, we sign input 1
        let mut rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(2),
            lock_time: RustBitcoinLockTime::from_height(0).unwrap(),
            input: vec![
                RustBitcoinTxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array(internal_arr),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: RustBitcoinSequence::MAX,
                    witness: Witness::from_slice(&existing_witness),
                },
                RustBitcoinTxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array(internal_arr),
                        vout: 1,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: RustBitcoinSequence::MAX,
                    witness: Witness::default(),
                },
            ],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(value_sats),
                script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
            }],
        };

        let mut rb_buf: Vec<u8> = Vec::new();
        let mut sighasher = SighashCache::new(&mut rb_tx);
        sighasher
            .segwit_v0_encode_signing_data_to(
                &mut rb_buf,
                1,
                &ScriptBuf::from_bytes(script_bytes.clone()),
                Amount::from_sat(value_sats),
                EcdsaSighashType::All,
            )
            .unwrap();

        // Our implementation: same tx with witness on input 0
        let our_tx = OmniBitcoinTransaction {
            version: Version::Two,
            lock_time: LockTime::from_height(0).unwrap(),
            input: vec![
                TxIn {
                    previous_output: OmniOutPoint {
                        txid: OmniTxid(OmniHash(display_arr)),
                        vout: 0,
                    },
                    script_sig: OmniScriptBuf::default(),
                    sequence: OmniSequence::MAX,
                    witness: OmniWitness::from_slice(&existing_witness),
                },
                TxIn {
                    previous_output: OmniOutPoint {
                        txid: OmniTxid(OmniHash(display_arr)),
                        vout: 1,
                    },
                    script_sig: OmniScriptBuf::default(),
                    sequence: OmniSequence::MAX,
                    witness: OmniWitness::default(),
                },
            ],
            output: vec![TxOut {
                value: OmniAmount::from_sat(value_sats),
                script_pubkey: OmniScriptBuf(script_bytes.clone()),
            }],
        };

        let our_buf = our_tx.build_for_signing_segwit(
            OmniSighashType::All,
            1,
            &OmniScriptBuf(script_bytes),
            value_sats,
        );

        assert_eq!(
            rb_buf, our_buf,
            "Sighash must match even when input 0 has witness data"
        );
    }

    #[test]
    fn test_legacy_sighash_with_witness_present() {
        // Regression: build_for_signing_legacy must use non-witness serialization
        // even when inputs have witness data attached.
        let height = 1000000;

        let witness_data = vec![vec![0x01, 0x02, 0x03]];

        let mut rb_tx = RustBitcoinTransaction {
            version: RustBitcoinVersion(1),
            lock_time: RustBitcoinLockTime::from_height(height).unwrap(),
            input: vec![RustBitcoinTxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::all_zeros()),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: RustBitcoinSequence::default(),
                witness: Witness::from_slice(&witness_data),
            }],
            output: vec![RustBitcoinTxOut {
                value: Amount::from_sat(10000),
                script_pubkey: ScriptBuf::default(),
            }],
        };

        let sighasher = SighashCache::new(&mut rb_tx);
        let mut rb_buf: Vec<u8> = Vec::new();
        sighasher
            .legacy_encode_signing_data_to(
                &mut rb_buf,
                0,
                &ScriptBuf::default(),
                EcdsaSighashType::All.to_u32(),
            )
            .is_sighash_single_bug()
            .unwrap();

        let our_tx = OmniBitcoinTransaction {
            version: Version::One,
            lock_time: LockTime::from_height(height).unwrap(),
            input: vec![TxIn {
                previous_output: OmniOutPoint {
                    txid: OmniTxid(OmniHash::all_zeros()),
                    vout: 0,
                },
                script_sig: OmniScriptBuf::default(),
                sequence: OmniSequence::default(),
                witness: OmniWitness::from_slice(&witness_data),
            }],
            output: vec![TxOut {
                value: OmniAmount::from_sat(10000),
                script_pubkey: OmniScriptBuf::default(),
            }],
        };

        let our_buf = our_tx.build_for_signing_legacy(OmniSighashType::All);

        assert_eq!(rb_buf, our_buf, "Legacy sighash must exclude witness data");
    }
}
