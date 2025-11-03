use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::bitcoin::encoding::{utils::VarInt, Encodable};
use crate::bitcoin::BitcoinTransaction;

/// Partially Signed Bitcoin Transaction (BIP-174).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Psbt {
    pub unsigned_tx: BitcoinTransaction,
    pub xpub: Vec<(Vec<u8>, Vec<u8>)>,
    pub proprietary: Vec<(Vec<u8>, Vec<u8>)>,
    pub unknown: Vec<(Vec<u8>, Vec<u8>)>,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

/// PSBT input metadata.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default,
)]
pub struct Input {
    pub non_witness_utxo: Option<BitcoinTransaction>,
    pub witness_utxo: Option<Vec<u8>>,
    pub partial_sigs: Vec<(Vec<u8>, Vec<u8>)>,
    pub sighash_type: Option<u32>,
    pub redeem_script: Option<Vec<u8>>,
    pub witness_script: Option<Vec<u8>>,
    pub bip32_derivation: Vec<(Vec<u8>, Vec<u8>)>,
    pub final_script_sig: Option<Vec<u8>>,
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    pub proprietary: Vec<(Vec<u8>, Vec<u8>)>,
    pub unknown: Vec<(Vec<u8>, Vec<u8>)>,
}

/// PSBT output metadata.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default,
)]
pub struct Output {
    pub redeem_script: Option<Vec<u8>>,
    pub witness_script: Option<Vec<u8>>,
    pub bip32_derivation: Vec<(Vec<u8>, Vec<u8>)>,
    pub proprietary: Vec<(Vec<u8>, Vec<u8>)>,
    pub unknown: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Psbt {
    pub fn from_unsigned_tx(tx: BitcoinTransaction) -> Self {
        Self {
            unsigned_tx: tx.clone(),
            xpub: Vec::new(),
            proprietary: Vec::new(),
            unknown: Vec::new(),
            inputs: alloc::vec![Input::default(); tx.input.len()],
            outputs: alloc::vec![Output::default(); tx.output.len()],
        }
    }

    pub fn update_input_with_witness_utxo(
        &mut self,
        input_index: usize,
        script_pubkey: Vec<u8>,
        value: u64,
    ) -> Result<(), &'static str> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or("Input index out of bounds")?;

        let mut utxo_bytes = Vec::new();
        utxo_bytes.extend_from_slice(&value.to_le_bytes());
        VarInt(script_pubkey.len() as u64)
            .encode(&mut utxo_bytes)
            .map_err(|_| "Failed to encode script length")?;
        utxo_bytes.extend_from_slice(&script_pubkey);

        input.witness_utxo = Some(utxo_bytes);
        Ok(())
    }

    pub fn update_input_with_non_witness_utxo(
        &mut self,
        input_index: usize,
        prev_tx: BitcoinTransaction,
    ) -> Result<(), &'static str> {
        self.inputs
            .get_mut(input_index)
            .ok_or("Input index out of bounds")?
            .non_witness_utxo = Some(prev_tx);
        Ok(())
    }

    pub fn update_input_with_sighash_type(
        &mut self,
        input_index: usize,
        sighash_type: u32,
    ) -> Result<(), &'static str> {
        self.inputs
            .get_mut(input_index)
            .ok_or("Input index out of bounds")?
            .sighash_type = Some(sighash_type);
        Ok(())
    }

    pub fn update_input_with_bip32_derivation(
        &mut self,
        input_index: usize,
        pubkey: Vec<u8>,
        derivation: Vec<u8>,
    ) -> Result<(), &'static str> {
        self.inputs
            .get_mut(input_index)
            .ok_or("Input index out of bounds")?
            .bip32_derivation
            .push((pubkey, derivation));
        Ok(())
    }

    pub fn update_output_with_bip32_derivation(
        &mut self,
        output_index: usize,
        pubkey: Vec<u8>,
        derivation: Vec<u8>,
    ) -> Result<(), &'static str> {
        self.outputs
            .get_mut(output_index)
            .ok_or("Output index out of bounds")?
            .bip32_derivation
            .push((pubkey, derivation));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::types::*;
    use crate::{TransactionBuilder, TxBuilder, BITCOIN};
    use alloc::vec;

    #[test]
    fn test_psbt_from_unsigned_tx() {
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

        let psbt = Psbt::from_unsigned_tx(tx.clone());

        assert_eq!(psbt.unsigned_tx, tx);
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 1);
        assert!(psbt.xpub.is_empty());
        assert!(psbt.proprietary.is_empty());
        assert!(psbt.unknown.is_empty());
    }

    #[test]
    fn test_psbt_to_psbt_method() {
        let tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::One)
            .inputs(vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash::all_zeros()), 0),
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
            .lock_time(LockTime::from_height(0).unwrap())
            .build();

        let psbt = tx.to_psbt();

        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 2);
    }
}
