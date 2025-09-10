//! EVM transaction
use super::types::{AccessList, Address, Signature};
use super::utils::parse_eth_address;
use crate::constants::EIP_1559_TYPE;
use rlp::RlpStream;
#[cfg(feature = "std")]
use schemars::JsonSchema;
use serde::de::{Error as DeError, Visitor};
use serde::Deserializer;
use serde::{Deserialize, Serialize};
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{string::ToString, vec, vec::Vec};
#[cfg(feature = "std")]
use std::{string::ToString, vec, vec::Vec};

///
/// ###### Example:
///
/// ```rust
/// use signet_rs::evm::utils::parse_eth_address;
/// use signet_rs::evm::EVMTransaction;
/// 
/// const MAX_FEE_PER_GAS: u128 = 20_000_000_000;
/// const MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;
/// const GAS_LIMIT: u128 = 21_000;
/// 
/// let nonce: u64 = 0;
/// let value = 10000000000000000u128; // 0.01 ETH
/// let data: Vec<u8> = vec![];
/// let chain_id = 1;
/// let to_address_str = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
/// let to_address = Some(parse_eth_address(to_address_str));
/// // Generate using EVMTransaction
/// let tx = EVMTransaction {
///     chain_id,
///     nonce,
///     to: to_address,
///     value,
///     input: data.clone(),
///     gas_limit: GAS_LIMIT,
///     max_fee_per_gas: MAX_FEE_PER_GAS,
///     max_priority_fee_per_gas: MAX_PRIORITY_FEE_PER_GAS,
///     access_list: vec![],
/// };
/// ```
///
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "std", derive(JsonSchema))]
#[cfg_attr(feature = "std", schemars(rename_all = "camelCase"))]
pub struct EVMTransaction {
    #[serde(deserialize_with = "deserialize_u64")]
    pub chain_id: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    pub nonce: u64,
    #[serde(deserialize_with = "deserialize_address")]
    pub to: Option<Address>,
    #[serde(deserialize_with = "deserialize_u128")]
    pub value: u128,
    pub input: Vec<u8>,
    #[serde(deserialize_with = "deserialize_u128")]
    pub gas_limit: u128,
    #[serde(deserialize_with = "deserialize_u128")]
    pub max_fee_per_gas: u128,
    #[serde(deserialize_with = "deserialize_u128")]
    pub max_priority_fee_per_gas: u128,
    pub access_list: AccessList,
}

impl EVMTransaction {
    pub fn build_for_signing(&self) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();

        rlp_stream.append(&EIP_1559_TYPE);

        rlp_stream.begin_unbounded_list();

        self.encode_fields(&mut rlp_stream);

        rlp_stream.finalize_unbounded_list();

        rlp_stream.out().to_vec()
    }

    pub fn build_with_signature(&self, signature: &Signature) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();

        rlp_stream.append(&EIP_1559_TYPE);

        rlp_stream.begin_unbounded_list();

        self.encode_fields(&mut rlp_stream);

        rlp_stream.append(&signature.v);
        rlp_stream.append(&signature.r);
        rlp_stream.append(&signature.s);

        rlp_stream.finalize_unbounded_list();

        rlp_stream.out().to_vec()
    }

    fn encode_fields(&self, rlp_stream: &mut RlpStream) {
        let to: Vec<u8> = self.to.map_or(vec![], |to| to.to_vec());
        let access_list = self.access_list.clone();

        rlp_stream.append(&self.chain_id);
        rlp_stream.append(&self.nonce);
        rlp_stream.append(&self.max_priority_fee_per_gas);
        rlp_stream.append(&self.max_fee_per_gas);
        rlp_stream.append(&self.gas_limit);
        rlp_stream.append(&to);
        rlp_stream.append(&self.value);
        rlp_stream.append(&self.input);

        // Write access list.
        {
            rlp_stream.begin_unbounded_list();
            for access in access_list {
                rlp_stream.begin_unbounded_list();
                rlp_stream.append(&access.0.to_vec());
                // Append list of storage keys.
                {
                    rlp_stream.begin_unbounded_list();
                    for storage_key in access.1 {
                        rlp_stream.append(&storage_key.to_vec());
                    }
                    rlp_stream.finalize_unbounded_list();
                }
                rlp_stream.finalize_unbounded_list();
            }
            rlp_stream.finalize_unbounded_list();
        }
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let v: serde_json::Value = serde_json::from_str(json)?;

        let to = v["to"].as_str().unwrap_or_default().to_string();

        let to_parsed = parse_eth_address(
            to.strip_prefix("0x")
                .unwrap_or("0000000000000000000000000000000000000000"),
        );

        let nonce_str = v["nonce"].as_str().expect("nonce should be provided");
        let nonce = parse_u64(nonce_str).expect("nonce should be a valid u64");

        let value_str = v["value"].as_str().expect("value should be provided");
        let value = parse_u128(value_str).expect("value should be a valid u128");

        let gas_limit_str = v["gasLimit"].as_str().expect("gasLimit should be provided");
        let gas_limit = parse_u128(gas_limit_str).expect("gasLimit should be a valid u128");

        let max_priority_fee_per_gas_str = v["maxPriorityFeePerGas"]
            .as_str()
            .expect("maxPriorityFeePerGas should be provided");
        let max_priority_fee_per_gas = parse_u128(max_priority_fee_per_gas_str)
            .expect("maxPriorityFeePerGas should be a valid u128");

        let max_fee_per_gas_str = v["maxFeePerGas"]
            .as_str()
            .expect("maxFeePerGas should be provided");
        let max_fee_per_gas =
            parse_u128(max_fee_per_gas_str).expect("maxFeePerGas should be a valid u128");

        let chain_id_str = v["chainId"].as_str().expect("chainId should be provided");
        let chain_id = parse_u64(chain_id_str).expect("chainId should be a valid u64");

        let input = v["input"].as_str().unwrap_or_default().to_string();
        let input =
            hex::decode(input.strip_prefix("0x").unwrap_or("")).expect("input should be hex");

        // TODO: Implement access list
        // let access_list = v["accessList"].as_str().unwrap_or_default().to_string();

        Ok(Self {
            chain_id,
            nonce,
            to: Some(to_parsed),
            value,
            input,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list: vec![],
        })
    }
}

fn parse_u64(value: &str) -> Result<u64, core::num::ParseIntError> {
    value.strip_prefix("0x").map_or_else(
        || value.parse::<u64>(),
        |hex_str| u64::from_str_radix(hex_str, 16),
    )
}

fn parse_u128(value: &str) -> Result<u128, core::num::ParseIntError> {
    value.strip_prefix("0x").map_or_else(
        || value.parse::<u128>(),
        |hex_str| u128::from_str_radix(hex_str, 16),
    )
}

fn deserialize_address<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{Error as DeError, Unexpected};
    use serde_json::Value;

    let value = Value::deserialize(deserializer)?;

    if value.is_null() {
        return Ok(None);
    }

    // Handle array cases
    if let Some(arr) = value.as_array() {
        if arr.len() != 20 {
            return Err(DeError::invalid_length(arr.len(), &"20-byte address"));
        }

        let mut out = [0u8; 20];

        // Case: [133, 138, ...]
        if arr.iter().all(|v| v.is_u64()) {
            for (i, v) in arr.iter().enumerate() {
                let n = v
                    .as_u64()
                    .ok_or_else(|| DeError::invalid_type(Unexpected::Other("not a u64"), &"u8"))?;
                out[i] = n as u8;
            }
            return Ok(Some(out));
        }

        // Case: ["133", "138", ...]
        if arr.iter().all(|v| v.is_string()) {
            for (i, v) in arr.iter().enumerate() {
                let s = v
                    .as_str()
                    .ok_or_else(|| {
                        DeError::invalid_type(Unexpected::Other("not a string"), &"string")
                    })?
                    .trim();

                let byte = s.parse::<u8>().map_err(|_| {
                    DeError::invalid_value(Unexpected::Str(s), &"a string representing a u8")
                })?;

                out[i] = byte;
            }
            return Ok(Some(out));
        }

        return Err(DeError::invalid_type(
            Unexpected::Other("invalid address format"),
            &"array of u8 or array of numeric strings",
        ));
    }

    Err(DeError::invalid_type(
        Unexpected::Other("unexpected format for address"),
        &"null or array of 20 bytes",
    ))
}

pub fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct U64FlexibleVisitor;

    impl<'de> Visitor<'de> for U64FlexibleVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a u64 or a string representing a u64")
        }

        fn visit_u64<E: DeError>(self, v: u64) -> Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_str<E: DeError>(self, s: &str) -> Result<Self::Value, E> {
            s.parse::<u64>()
                .map_err(|_| {
                    #[cfg(not(feature = "std"))]
                    use alloc::format;
                    DeError::custom(format!("invalid u64 string: {}", s))
                })
        }
    }

    deserializer.deserialize_any(U64FlexibleVisitor)
}

pub fn deserialize_u128<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    struct U128FlexibleVisitor;

    impl<'de> Visitor<'de> for U128FlexibleVisitor {
        type Value = u128;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a u128 or a string representing a u128")
        }

        fn visit_u64<E: DeError>(self, value: u64) -> Result<Self::Value, E> {
            Ok(value as u128)
        }

        fn visit_u128<E: DeError>(self, value: u128) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
            value
                .parse::<u128>()
                .map_err(|_| {
                    #[cfg(not(feature = "std"))]
                    use alloc::format;
                    DeError::custom(format!("invalid u128 string: {}", value))
                })
        }
    }

    deserializer.deserialize_any(U128FlexibleVisitor)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize, Debug)]
    pub struct SignCallbackArgs {
        pub nonce: u64,
        pub tx_type: u8,
        pub ethereum_tx: EVMTransaction,
    }

    use alloy::{
        consensus::{SignableTransaction, TxEip1559},
        network::TransactionBuilder,
        primitives::{address, hex, Address, Bytes, U256},
        rpc::types::{AccessList, TransactionRequest},
    };
    use alloy_primitives::{b256, Signature};

    use crate::evm::types::Signature as OmniSignature;
    use crate::evm::{evm_transaction::EVMTransaction, utils::parse_eth_address};
    const MAX_FEE_PER_GAS: u128 = 20_000_000_000;
    const MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;
    const GAS_LIMIT: u128 = 21_000;

    #[test]
    fn test_build_for_signing_for_evm_against_alloy() {
        let nonce: u64 = 0;
        let to: Address = address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let value = 10000000000000000u128; // 0.01 ETH
        let data: Vec<u8> = vec![];
        let chain_id = 1;
        let to_address_str = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let to_address = Some(parse_eth_address(to_address_str));

        // Generate using EVMTransaction
        let tx = EVMTransaction {
            chain_id,
            nonce,
            to: to_address,
            value,
            input: data.clone(),
            gas_limit: GAS_LIMIT,
            max_fee_per_gas: MAX_FEE_PER_GAS,
            max_priority_fee_per_gas: MAX_PRIORITY_FEE_PER_GAS,
            access_list: vec![],
        };

        let rlp_bytes = tx.build_for_signing();

        // Now let's compare with the Alloy RLP encoding
        let alloy_tx = TransactionRequest::default()
            .with_chain_id(chain_id)
            .with_nonce(nonce)
            .with_to(to)
            .with_value(U256::from(value))
            .with_max_priority_fee_per_gas(MAX_PRIORITY_FEE_PER_GAS)
            .with_max_fee_per_gas(MAX_FEE_PER_GAS)
            .with_gas_limit(GAS_LIMIT)
            .with_input(data);

        let alloy_rlp_bytes: alloy::consensus::TypedTransaction = alloy_tx
            .build_unsigned()
            .expect("Failed to build unsigned transaction");

        let rlp_encoded = alloy_rlp_bytes.eip1559().unwrap();

        // Prepare the buffer and encode
        let mut buf = vec![];
        rlp_encoded.encode_for_signing(&mut buf);

        assert!(buf == rlp_bytes);
    }

    #[test]
    fn test_build_for_signing_with_data_for_evm_against_alloy() {
        let input: Bytes = hex!("a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000").into();
        let nonce: u64 = 0;
        let to: Address = address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let value = 10000000000000000u128; // 0.01 ETH
        let chain_id = 1;
        let to_address_str = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let to_address = Some(parse_eth_address(to_address_str));

        // Generate using EVMTransaction
        let tx = EVMTransaction {
            chain_id,
            nonce,
            to: to_address,
            value,
            input: input.to_vec(),
            gas_limit: GAS_LIMIT,
            max_fee_per_gas: MAX_FEE_PER_GAS,
            max_priority_fee_per_gas: MAX_PRIORITY_FEE_PER_GAS,
            access_list: vec![],
        };

        let rlp_bytes = tx.build_for_signing();

        // Now let's compare with the Alloy RLP encoding
        let alloy_tx = TransactionRequest::default()
            .with_chain_id(chain_id)
            .with_nonce(nonce)
            .with_to(to)
            .with_value(U256::from(value))
            .with_max_priority_fee_per_gas(MAX_PRIORITY_FEE_PER_GAS)
            .with_max_fee_per_gas(MAX_FEE_PER_GAS)
            .with_gas_limit(GAS_LIMIT)
            .access_list(AccessList::default())
            .with_input(input);

        let alloy_rlp_bytes: alloy::consensus::TypedTransaction = alloy_tx
            .build_unsigned()
            .expect("Failed to build unsigned transaction");

        let rlp_encoded = alloy_rlp_bytes.eip1559().unwrap();

        // Prepare the buffer and encode
        let mut buf = vec![];
        rlp_encoded.encode_for_signing(&mut buf);

        assert!(buf == rlp_bytes);
    }

    #[test]
    fn test_build_with_signature_for_evm_against_alloy() {
        let chain_id = 1;
        let nonce = 0x42;
        let gas_limit = 44386;

        let to_str = "6069a6c32cf691f5982febae4faf8a6f3ab2f0f6";
        let to = address!("6069a6c32cf691f5982febae4faf8a6f3ab2f0f6").into();
        let to_address = Some(parse_eth_address(to_str));
        let value_as_128 = 0_u128;
        let value = U256::from(value_as_128);

        let max_fee_per_gas = 0x4a817c800;
        let max_priority_fee_per_gas = 0x3b9aca00;
        let input: Bytes = hex!("a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000").into();

        let tx: TxEip1559 = TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            to,
            value,
            input: input.clone(),
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list: AccessList::default(),
        };

        let mut tx_encoded = vec![];
        tx.encode_for_signing(&mut tx_encoded);

        // Generate using EVMTransaction
        let tx_omni = EVMTransaction {
            chain_id,
            nonce,
            to: to_address,
            value: value_as_128,
            input: input.to_vec(),
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list: vec![],
        };

        let rlp_bytes_for_omni_tx = tx_omni.build_for_signing();

        assert_eq!(tx_encoded.len(), rlp_bytes_for_omni_tx.len());

        let sig = Signature::from_scalars_and_parity(
            b256!("840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565"),
            b256!("25e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1"),
            false,
        )
        .unwrap();

        let mut tx_encoded_with_signature: Vec<u8> = vec![];
        tx.encode_with_signature(&sig, &mut tx_encoded_with_signature, false);

        let signature: OmniSignature = OmniSignature {
            v: sig.v().to_u64(),
            r: sig.r().to_be_bytes::<32>().to_vec(),
            s: sig.s().to_be_bytes::<32>().to_vec(),
        };

        let omni_encoded_with_signature = tx_omni.build_with_signature(&signature);

        assert_eq!(
            tx_encoded_with_signature.len(),
            omni_encoded_with_signature.len()
        );
        assert_eq!(tx_encoded_with_signature, omni_encoded_with_signature);
    }

    #[test]
    fn test_build_for_signing_for_evm_against_allow_using_json_input() {
        let tx1 = r#"
        {
            "to": "0x525521d79134822a342d330bd91DA67976569aF1",
            "nonce": "1",
            "value": "0x038d7ea4c68000",
            "maxPriorityFeePerGas": "0x1",
            "maxFeePerGas": "0x1",
            "gasLimit":"21000",
            "chainId":"11155111"
        }"#;

        let evm_tx1 = EVMTransaction::from_json(tx1).unwrap();

        assert_eq!(evm_tx1.chain_id, 11155111);
        assert_eq!(evm_tx1.nonce, 1);
        assert_eq!(
            evm_tx1.to,
            Some(
                address!("525521d79134822a342d330bd91DA67976569aF1")
                    .0
                    .into()
            )
        );
        assert_eq!(evm_tx1.value, 0x038d7ea4c68000);
        assert_eq!(evm_tx1.max_fee_per_gas, 0x1);
        assert_eq!(evm_tx1.max_priority_fee_per_gas, 0x1);
        assert_eq!(evm_tx1.gas_limit, 21000);

        let tx2 = r#"
        {
            "to": "0x525521d79134822a342d330bd91DA67976569aF1",
            "nonce": "1",
            "input": "0x6a627842000000000000000000000000525521d79134822a342d330bd91DA67976569aF1",
            "value": "0",
            "maxPriorityFeePerGas": "0x1",
            "maxFeePerGas": "0x1",
            "gasLimit":"21000",
            "chainId":"11155111"
        }"#;

        let evm_tx2 = EVMTransaction::from_json(tx2).unwrap();

        assert_eq!(evm_tx2.chain_id, 11155111);
        assert_eq!(evm_tx2.nonce, 1);
        assert_eq!(
            evm_tx2.to,
            Some(
                address!("525521d79134822a342d330bd91DA67976569aF1")
                    .0
                    .into()
            )
        );
        assert_eq!(evm_tx2.value, 0);
        assert_eq!(
            evm_tx2.input,
            hex!("6a627842000000000000000000000000525521d79134822a342d330bd91DA67976569aF1")
                .to_vec()
        );
    }

    #[test]
    fn test_deserialize_to_as_array_of_strings() {
        let json = r#"
    {
        "nonce": 0,
        "tx_type": 4,
        "ethereum_tx": {
            "to": ["133", "138", "138", "255", "241", "27", "252", "203", "97", "230", "157", "168", "126", "186", "30", "204", "204", "52", "198", "64"],
            "input": [1, 2, 3],
            "nonce": "0",
            "value": "0",
            "chain_id": "421614",
            "gas_limit": "44386",
            "access_list": [],
            "max_fee_per_gas": "20000000000",
            "max_priority_fee_per_gas": "1000000000"
        }
    }
    "#;

        let result: Result<SignCallbackArgs, _> = serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "Expected to deserialize but got error: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_deserialize_to_example_with_zeros() {
        let json = r#"
    {
        "nonce": 0,
        "tx_type": 4,
        "ethereum_tx": {
            "to": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "input": [1, 2, 3],
            "nonce": "0",
            "value": "0",
            "chain_id": "421614",
            "gas_limit": "44386",
            "access_list": [],
            "max_fee_per_gas": "20000000000",
            "max_priority_fee_per_gas": "1000000000"
        }
    }"#;

        let result: Result<SignCallbackArgs, _> = serde_json::from_str(json);
        if let Err(e) = &result {
            println!("[TEST ERROR] Deserialization failed: {:?}", e);
        }
        assert!(
            result.is_ok(),
            "Expected deserialization to work with array of zeros"
        );
    }

    #[test]
    fn test_deserialize_to_works_with_array_of_numbers() {
        let json = r#"
    {
        "nonce": 0,
        "tx_type": 4,
        "ethereum_tx": {
            "to": [133, 138, 138, 255, 241, 27, 252, 203, 97, 230, 157, 168, 126, 186, 30, 204, 204, 52, 198, 64],
            "input": [1, 2, 3],
            "nonce": "0",
            "value": "0",
            "chain_id": "421614",
            "gas_limit": "44386",
            "access_list": [],
            "max_fee_per_gas": "20000000000",
            "max_priority_fee_per_gas": "1000000000"
        }
    }
    "#;

        let result: Result<SignCallbackArgs, _> = serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "Expected deserialization to work with array of numbers"
        );
    }
}
