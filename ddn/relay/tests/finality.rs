use alloy_primitives::B256;
use serde_json::{Value, json};

async fn verify(target: B256, responses: Vec<(&'static str, Value)>) -> eyre::Result<()> {
    let mut responses = responses.into_iter();
    let result = n42_decision_relay::verify_committed_ancestry(target, |method, params| {
        let (expected_method, value) = responses.next().expect("unexpected RPC call or fallback");
        assert_eq!(method, expected_method);
        if method == "eth_getBlockByNumber" {
            assert_eq!(params, json!(["finalized", false]));
        } else {
            assert_eq!(params[1], false);
        }
        std::future::ready(Ok(value))
    })
    .await;
    assert!(responses.next().is_none(), "unconsumed expected RPC calls");
    result
}

#[tokio::test]
async fn accepts_finalized_head_and_its_ancestor() {
    let parent = B256::repeat_byte(1);
    let head = B256::repeat_byte(2);
    verify(
        parent,
        vec![
            ("eth_getBlockByNumber", json!({"hash":head,"number":"0x2"})),
            (
                "eth_getBlockByHash",
                json!({"hash":head,"parentHash":parent}),
            ),
        ],
    )
    .await
    .unwrap();
    verify(
        head,
        vec![("eth_getBlockByNumber", json!({"hash":head,"number":"0x2"}))],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn rejects_missing_or_malformed_finality_without_fallback() {
    for block in [
        Value::Null,
        json!({"hash":B256::ZERO,"number":"0x0"}),
        json!({"hash":B256::repeat_byte(2),"number":"latest"}),
        json!({"hash":"0x01","number":"0x1"}),
    ] {
        assert!(
            verify(B256::repeat_byte(1), vec![("eth_getBlockByNumber", block)])
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn rejects_wrong_hash_and_broken_ancestry() {
    let head = B256::repeat_byte(2);
    for block in [
        Value::Null,
        json!({"hash":B256::repeat_byte(3),"parentHash":B256::repeat_byte(1)}),
        json!({"hash":head,"parentHash":head}),
        json!({"hash":head,"parentHash":B256::ZERO}),
    ] {
        assert!(
            verify(
                B256::repeat_byte(1),
                vec![
                    ("eth_getBlockByNumber", json!({"hash":head,"number":"0x2"})),
                    ("eth_getBlockByHash", block),
                ]
            )
            .await
            .is_err()
        );
    }
}

#[tokio::test]
async fn propagates_transport_failure_without_fallback() {
    let mut calls = 0;
    let result =
        n42_decision_relay::verify_committed_ancestry(B256::repeat_byte(1), |method, _| {
            calls += 1;
            assert_eq!(method, "eth_getBlockByNumber");
            std::future::ready(Err(eyre::eyre!("RPC offline")))
        })
        .await;
    assert!(result.is_err());
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn bounds_a_cyclic_rpc_ancestry() {
    let first = B256::repeat_byte(2);
    let second = B256::repeat_byte(3);
    let mut calls = 0;
    let result =
        n42_decision_relay::verify_committed_ancestry(B256::repeat_byte(1), |method, params| {
            calls += 1;
            let block = if method == "eth_getBlockByNumber" {
                json!({"hash":first,"number":"0x2"})
            } else {
                let hash: B256 = params[0].as_str().unwrap().parse().unwrap();
                json!({"hash":hash,"parentHash":if hash == first { second } else { first }})
            };
            std::future::ready(Ok(block))
        })
        .await;
    assert!(result.unwrap_err().to_string().contains("window"));
    assert_eq!(calls, 4097);
}
