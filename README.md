# Signet.rs

> **Note**: This is a fork of [near/omni-transaction-rs](https://github.com/near/omni-transaction-rs), originally developed by NEAR Protocol.

A Rust library for constructing and signing transactions across multiple blockchain networks.

## Supported Chains

- Ethereum
- Bitcoin

## Installation

```toml
[dependencies]
signet-rs = "0.2.4"
```

## Examples

### Ethereum Transaction

```rust
let to_address_str = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
let to_address = parse_eth_address(to_address_str);
let max_gas_fee: u128 = 20_000_000_000;
let max_priority_fee_per_gas: u128 = 1_000_000_000;
let gas_limit: u128 = 21_000;
let chain_id: u64 = 1;
let nonce: u64 = 0;
let data: Vec<u8> = vec![];
let value: u128 = 10000000000000000; // 0.01 ETH

let evm_tx = TransactionBuilder::new::<EVM>()
    .nonce(nonce)
    .to(to_address)
    .value(value)
    .input(data.clone())
    .max_priority_fee_per_gas(max_priority_fee_per_gas)
    .max_fee_per_gas(max_gas_fee)
    .gas_limit(gas_limit)
    .chain_id(chain_id)
    .build();

// Now you have access to build_for_signing that returns the encoded payload
let rlp_encoded = evm_tx.build_for_signing();
```

### Bitcoin Transaction

```rust
let txid_str = "2ece6cd71fee90ff613cee8f30a52c3ecc58685acf9b817b9c467b7ff199871c";
let hash = Hash::from_hex(txid_str).unwrap();
let txid = Txid(hash);
let vout = 0;

let txin: TxIn = TxIn {
    previous_output: OutPoint::new(txid, vout as u32),
    script_sig: ScriptBuf::default(), // For a p2pkh script_sig is initially empty.
    sequence: Sequence::MAX,
    witness: Witness::default(),
};

let sender_script_pubkey_hex = "76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac";
let sender_script_pubkey = ScriptBuf(sender_script_pubkey_hex.as_bytes().to_vec());

let receiver_script_pubkey_hex = "76a914406cf8a18b97a230d15ed82f0d251560a05bda0688ac";
let receiver_script_pubkey = ScriptBuf(receiver_script_pubkey_hex.as_bytes().to_vec());

// The spend output is locked to a key controlled by the receiver.
let spend_txout: TxOut = TxOut {
    value: Amount::from_sat(500_000_000),
    script_pubkey: receiver_script_pubkey,
};

let change_txout = TxOut {
    value: Amount::from_sat(100_000_000),
    script_pubkey: sender_script_pubkey,
};

let bitcoin_tx = TransactionBuilder::new::<BITCOIN>()
    .version(Version::One)
    .inputs(vec![txin])
    .outputs(vec![spend_txout, change_txout])
    .lock_time(LockTime::from_height(0).unwrap())
    .build();

// Prepare the transaction for signing
let encoded_tx = bitcoin_tx.build_for_signing_legacy(EcdsaSighashType::All);
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE-APACHE](LICENSE-APACHE) file for details.

### Original Work Attribution

This project is based on [omni-transaction-rs](https://github.com/near/omni-transaction-rs), originally created by NEAR Protocol and contributors.

Copyright 2024 Proximity Labs Limited

Licensed under the Apache License, Version 2.0
