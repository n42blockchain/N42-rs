//! Public vectors produced independently by the wallet (PQClean) and Go client.
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, Bytes, U256};
use n42_tx_types::{FalconTx, N42PooledTxEnvelope, N42TxEnvelope, N42TxType};
use reth_codecs::Compact;
use reth_primitives_traits::SignerRecoverable;

fn vector(json: &str) -> (FalconTx, Vec<u8>) {
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    let raw = hex::decode(v["rawTransaction"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let tx = FalconTx::decode_2718_exact(&raw).unwrap();
    let sender: Address = v["sender"].as_str().unwrap().parse().unwrap();
    let digest: B256 = v["signingHash"].as_str().unwrap().parse().unwrap();
    assert_eq!(tx.tx().signing_hash(), digest);
    assert_eq!(tx.verify().unwrap(), sender);
    assert_eq!(tx.encoded_2718(), raw);
    (tx, raw)
}

#[test]
fn wallet_and_go_signatures_roundtrip_storage_pool_and_json() {
    for json in [
        include_str!("testdata/falcon512_wallet_v1.json"),
        include_str!("testdata/falcon512_go_v1.json"),
    ] {
        let (tx, raw) = vector(json);
        let env = N42TxEnvelope::decode_2718_exact(&raw).unwrap();
        assert!(matches!(env, N42TxEnvelope::Falcon(_)));
        assert_eq!(env.recover_signer().unwrap(), tx.sender());
        let mut compact = Vec::new();
        let len = env.to_compact(&mut compact);
        let (stored, rest) = N42TxEnvelope::from_compact(&compact, len);
        assert!(rest.is_empty());
        assert_eq!(stored, env);
        assert_eq!(stored.recover_signer().unwrap(), tx.sender());
        let pooled = N42PooledTxEnvelope::decode_2718_exact(&raw).unwrap();
        assert_eq!(pooled.encoded_2718(), raw);
        assert_eq!(pooled.recover_signer().unwrap(), tx.sender());
        let encoded = serde_json::to_string(&env).unwrap();
        let decoded: N42TxEnvelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, env);
        let mut kind = Vec::new();
        let id = N42TxType::Falcon.to_compact(&mut kind);
        assert_eq!(N42TxType::from_compact(&kind, id).0, N42TxType::Falcon);
    }
}

#[test]
fn signature_binds_payment_and_rejects_other_modes() {
    let (valid, raw) = vector(include_str!("testdata/falcon512_wallet_v1.json"));
    for case in 0..8 {
        let mut tx = valid.tx().clone();
        match case {
            0 => tx.chain_id += 1,
            1 => tx.nonce += 1,
            2 => tx.value += U256::from(1),
            3 => tx.to = Address::with_last_byte(1),
            4 => tx.pubkey_mode = 1,
            5 => tx.alg_type = 1,
            6 => tx.pubkey = Bytes::from(vec![0; 897]),
            _ => tx.max_fee_per_gas += 1,
        }
        assert!(FalconTx::new(tx, valid.signature().clone()).verify().is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(FalconTx::decode_2718_exact(&trailing).is_err());
    for len in [0, 32, 665, 667, 690] {
        assert!(
            FalconTx::new(valid.tx().clone(), Bytes::from(vec![0; len]))
                .verify()
                .is_err()
        );
    }
    let mut bad = raw;
    *bad.last_mut().unwrap() ^= 1;
    assert!(FalconTx::decode_2718_exact(&bad).unwrap().verify().is_err());
}

#[test]
fn evm_mapping_and_rpc_receipt_preserve_the_extended_type() {
    use alloy_consensus::Typed2718;
    use alloy_evm::FromRecoveredTx;
    let (tx, _) = vector(include_str!("testdata/falcon512_wallet_v1.json"));
    let env = N42TxEnvelope::from(tx.clone());
    let evm = revm::context::TxEnv::from_recovered_tx(&env, tx.verify().unwrap());
    assert_eq!(evm.tx_type, 2);
    assert_eq!(evm.caller, tx.sender());
    assert_eq!(evm.value, tx.tx().value);
    assert_eq!(evm.chain_id, Some(tx.tx().chain_id));
    let receipt = n42_tx_types::N42RpcReceipt::from_receipt(
        N42TxType::Falcon,
        alloy_consensus::Receipt {
            status: true.into(),
            cumulative_gas_used: 21000,
            logs: Vec::new(),
        },
    );
    assert_eq!(receipt.ty(), 5);
    let json = serde_json::to_value(&receipt).unwrap();
    assert_eq!(json["type"], "0x5");
    let restored: n42_tx_types::N42RpcReceipt = serde_json::from_value(json).unwrap();
    assert_eq!(restored.ty(), 5);
}
