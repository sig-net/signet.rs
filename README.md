# signet-rs

> Minimal, `no_std` transaction builders for Bitcoin and EVM networks, ready for contracts, embedded clients, and signing services.

[Crates.io](https://crates.io/crates/signet-rs) • [Documentation](https://docs.rs/signet-rs) • [Testing Guide](TESTING.md)

## Documentation

- API reference: <https://docs.rs/signet-rs>
- Build locally: `cargo doc --all-features --no-deps --open`
- Doc notes: see `docs/README.md`

## Installation

```toml
[dependencies]
signet-rs = "0.0.3"
```

## Features

- ✅ EVM transaction builder with native EIP-1559 encoding and flexible access-list support.
- ✅ Bitcoin transaction builder with legacy + SegWit signing payloads, PSBT helpers, and DER utilities.
- ✅ `no_std` by default with opt-in `std` feature for integrations such as `schemars`.

## Quick Start

### EVM transaction

```rust
use signet_rs::evm::utils::parse_eth_address;
use signet_rs::{TransactionBuilder, TxBuilder, EVM};

let to_address_str = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
let to_address = parse_eth_address(to_address_str);
let max_gas_fee: u128 = 20_000_000_000;
let max_priority_fee_per_gas: u128 = 1_000_000_000;
let gas_limit: u128 = 21_000;
let chain_id: u64 = 1;
let nonce: u64 = 0;
let data: Vec<u8> = vec![];
let value: u128 = 10_000_000_000_000_000; // 0.01 ETH

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

let rlp_encoded = evm_tx.build_for_signing();
```

### Bitcoin transaction

```rust
use signet_rs::bitcoin::types::{
    Amount, Hash, LockTime, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Version, Witness,
    EcdsaSighashType,
};
use signet_rs::{TransactionBuilder, TxBuilder, BITCOIN};

let txid_str = "2ece6cd71fee90ff613cee8f30a52c3ecc58685acf9b817b9c467b7ff199871c";
let hash = Hash::from_hex(txid_str).unwrap();
let txid = Txid(hash);
let vout = 0;

let txin: TxIn = TxIn {
    previous_output: OutPoint::new(txid, vout as u32),
    script_sig: ScriptBuf::default(), // P2PKH script_sig is initially empty.
    sequence: Sequence::MAX,
    witness: Witness::default(),
};

let sender_script_pubkey = ScriptBuf::from_hex(
    "76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac"
).unwrap();

let receiver_script_pubkey = ScriptBuf::from_hex(
    "76a914406cf8a18b97a230d15ed82f0d251560a05bda0688ac"
).unwrap();

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

let encoded_tx = bitcoin_tx.build_for_signing_legacy(EcdsaSighashType::All);
```

## Testing

See [TESTING.md](TESTING.md) for the unit, integration, and feature-flag test matrix plus the exact `cargo` commands we run in CI.

## License

Licensed under the [Apache License 2.0](LICENSE-APACHE). Portions derive from [omni-transaction-rs](https://github.com/near/omni-transaction-rs) by NEAR Protocol and contributors.

Copyright 2024 Proximity Labs Limited
