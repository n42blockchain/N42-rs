// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sends signed value transfers to a node's JSON-RPC, for watching them
//! travel a mixed fleet: submitted to one client, sealed by the other.
//!
//!   send_tx --rpc http://127.0.0.1:18545 --key <hex> --to <address> --count 3 [--chain-id 1143]
//!
//! Prints each transaction's hash; `eth_getTransactionReceipt` on any member
//! then says which block, and whose, sealed it.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde_json::{json, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rpc = "http://127.0.0.1:18545".to_string();
    let mut key = None;
    let mut to = None;
    let mut count = 1u64;
    let mut chain_id = 1143u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rpc" => rpc = args.next().ok_or("--rpc needs a URL")?,
            "--key" => key = Some(args.next().ok_or("--key needs hex")?),
            "--to" => to = Some(args.next().ok_or("--to needs an address")?),
            "--count" => count = args.next().ok_or("--count needs a number")?.parse()?,
            "--chain-id" => chain_id = args.next().ok_or("--chain-id needs a number")?.parse()?,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    let signer: PrivateKeySigner = key.ok_or("--key is required")?.parse()?;
    let to: Address = to.ok_or("--to is required")?.parse()?;
    let client = reqwest::blocking::Client::new();
    let call = |method: &str, params: Vec<Value>| -> Result<Value, Box<dyn std::error::Error>> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let response: Value = client.post(&rpc).json(&body).send()?.json()?;
        if let Some(error) = response.get("error") {
            return Err(format!("{method}: {error}").into());
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    };
    let nonce_hex = call("eth_getTransactionCount", vec![json!(signer.address()), json!("pending")])?;
    let mut nonce = u64::from_str_radix(nonce_hex.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
    for _ in 0..count {
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 5_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(to),
            value: U256::from(1_000_000_000_000_000u64),
            ..Default::default()
        };
        let signature = signer.sign_hash_sync(&tx.signature_hash())?;
        let envelope: TxEnvelope = tx.into_signed(signature).into();
        let raw = alloy_primitives::hex::encode_prefixed(envelope.encoded_2718());
        let hash = call("eth_sendRawTransaction", vec![json!(raw)])?;
        println!("{} nonce {nonce}", hash.as_str().unwrap_or("?"));
        nonce += 1;
    }
    Ok(())
}
