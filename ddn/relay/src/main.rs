use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use eyre::{Result, bail, ensure};
use n42_decision_relay::{
    DecisionTemplate, Evaluation, HubExpectation, QuantizedAnswer, QuestionSchema, QuoteFields,
    ResultFields, answer_hash, call_jev, committed_ancestor, confirmed_proposal, encode_answers,
    encode_fulfill, finalized_block, parse_proposal_log, read_request, rpc, sign_quote,
    sign_result, store_first_response, validate_evaluation, validate_public_proposal,
    validate_response, verify_hub_state,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env, fs,
    io::Write,
    path::PathBuf,
    process::Command,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuoteJob {
    chain_id: u64,
    hub: Address,
    requester: Address,
    refund_to: Address,
    consumer: Address,
    template_id: u64,
    input_hash: B256,
    deadline: u64,
    signer_version: u64,
    fee: String,
    quote_expiry: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvaluationJob {
    chain_id: u64,
    hub: Address,
    template_id: u64,
    template_path: PathBuf,
    request_id: String,
    signer_version: u64,
    input_hash: B256,
    template: DecisionTemplate,
    evaluation: Evaluation,
    rpc_url: String,
    request_tx_hash: B256,
    router: Address,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WatchConfig {
    chain_id: u64,
    hub: Address,
    router: Address,
    rpc_url: String,
    template_id: u64,
    template_path: PathBuf,
    template: DecisionTemplate,
    signer_version: u64,
    start_block: u64,
    archive_dir: PathBuf,
    cursor_path: PathBuf,
}

fn signer() -> Result<PrivateKeySigner> {
    let key = env::var("N42_DECISION_SIGNING_KEY")?;
    let signer = PrivateKeySigner::from_str(&key)?;
    Ok(signer)
}

fn json_file<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + 2);
    out.push_str("0x");
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn hex_quantity(value: &Value) -> Result<U256> {
    let text = value
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing hex quantity"))?;
    Ok(U256::from_str_radix(text.trim_start_matches("0x"), 16)?)
}

async fn submit_result(job: &EvaluationJob, result_path: &str) -> Result<()> {
    let result: Value = json_file(result_path)?;
    let answers: Vec<QuantizedAnswer> = serde_json::from_value(result["answers"].clone())?;
    let request_id = U256::from_str(&job.request_id)?;
    ensure!(
        result["chainId"].as_u64() == Some(job.chain_id)
            && result["hub"]
                .as_str()
                .and_then(|s| s.parse::<Address>().ok())
                == Some(job.hub)
            && result["requestId"].as_str() == Some(job.request_id.as_str()),
        "result belongs to another chain, hub, or request"
    );
    let evidence_hash: B256 = result["evidenceHash"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("evidence hash missing"))?
        .parse()?;
    let model_hash: B256 = result["modelHash"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("model hash missing"))?
        .parse()?;
    ensure!(
        model_hash == keccak256(job.template.model.as_bytes()),
        "model hash changed"
    );
    ensure!(
        result["answerHash"].as_str() == Some(&format!("{:#x}", answer_hash(&answers))),
        "answer hash changed"
    );
    let evidence_path = result["evidenceFile"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("evidence file missing"))?;
    let evidence_bytes = fs::read(evidence_path)?;
    ensure!(
        keccak256(&evidence_bytes) == evidence_hash,
        "evidence archive hash changed"
    );
    let evidence: Value = serde_json::from_slice(&evidence_bytes)?;
    ensure!(
        evidence["request"] == serde_json::to_value(&job.evaluation)?,
        "evidence request changed"
    );
    ensure!(
        validate_response(&job.template, &evidence["response"])? == answers,
        "evidence answers changed"
    );
    let sig = alloy_primitives::hex::decode(
        result["signature"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("signature missing"))?
            .trim_start_matches("0x"),
    )?;
    ensure!(sig.len() == 65, "bad attestation signature");
    let data = encode_fulfill(request_id, &answers, evidence_hash, model_hash, &sig);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let rpc_url = &job.rpc_url;
    let actual_chain_id = hex_quantity(&rpc(&client, rpc_url, "eth_chainId", json!([])).await?)?;
    ensure!(
        actual_chain_id == U256::from(job.chain_id),
        "wrong RPC chain"
    );
    let tx_key = env::var("N42_TX_SIGNING_KEY")?;
    let tx_signer = PrivateKeySigner::from_str(&tx_key)?;
    let sender = tx_signer.address();
    let nonce: u64 = hex_quantity(
        &rpc(
            &client,
            rpc_url,
            "eth_getTransactionCount",
            json!([sender, "pending"]),
        )
        .await?,
    )?
    .try_into()?;
    let gas_price: u128 =
        hex_quantity(&rpc(&client, rpc_url, "eth_gasPrice", json!([])).await?)?.try_into()?;
    ensure!(
        gas_price > 0 && gas_price <= u128::MAX / 2,
        "invalid gas price"
    );
    let estimated: u64 = hex_quantity(
        &rpc(
            &client,
            rpc_url,
            "eth_estimateGas",
            json!([{
                "from":sender,"to":job.hub,"data":hex(&data),"value":"0x0"
            }]),
        )
        .await?,
    )?
    .try_into()?;
    let tx = TxEip1559 {
        chain_id: job.chain_id,
        nonce,
        gas_limit: estimated.saturating_mul(12) / 10 + 10_000,
        max_fee_per_gas: gas_price * 2,
        max_priority_fee_per_gas: gas_price / 4,
        to: TxKind::Call(job.hub),
        value: U256::ZERO,
        input: Bytes::from(data),
        access_list: Default::default(),
    };
    let signature = tx_signer.sign_hash_sync(&tx.signature_hash())?;
    let mut raw = Vec::new();
    tx.into_signed(signature).encode_2718(&mut raw);
    let sent = rpc(
        &client,
        rpc_url,
        "eth_sendRawTransaction",
        json!([hex(&raw)]),
    )
    .await?;
    let tx_hash: B256 = sent
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing transaction hash"))?
        .parse()?;
    for _ in 0..40 {
        let receipt = rpc(
            &client,
            rpc_url,
            "eth_getTransactionReceipt",
            json!([tx_hash]),
        )
        .await?;
        if receipt.is_object() {
            ensure!(receipt["status"] == "0x1", "fulfillment transaction failed");
            let block_hash: B256 = receipt["blockHash"]
                .as_str()
                .ok_or_else(|| eyre::eyre!("missing result block"))?
                .parse()?;
            for _ in 0..40 {
                if committed_ancestor(&client, rpc_url, block_hash)
                    .await
                    .is_ok()
                {
                    println!(
                        "{}",
                        json!({"txHash":tx_hash,"blockHash":block_hash,"committed":true})
                    );
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            bail!("fulfillment included but no committed ancestry within 120 seconds: {tx_hash}");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    bail!("fulfillment submitted but no receipt within 120 seconds: {tx_hash}")
}

fn persist_cursor(path: &PathBuf, next: u64) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("next");
    let mut file = fs::File::create(&temporary)?;
    write!(file, "{next}")?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

async fn watch(config: WatchConfig) -> Result<()> {
    fs::create_dir_all(&config.archive_dir)?;
    let document: Value = serde_json::from_slice(&fs::read(&config.template_path)?)?;
    let questions = document["questions"].clone();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let actual_chain =
        hex_quantity(&rpc(&client, &config.rpc_url, "eth_chainId", json!([])).await?)?;
    ensure!(
        actual_chain == U256::from(config.chain_id),
        "watcher RPC chain mismatch"
    );
    loop {
        let next = match fs::read_to_string(&config.cursor_path) {
            Ok(value) => value.trim().parse::<u64>()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => config.start_block,
            Err(error) => return Err(error.into()),
        };
        let block = finalized_block(&client, &config.rpc_url).await?;
        let highest: u64 = hex_quantity(&block["number"])?.try_into()?;
        if next > highest {
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        }
        let topic = keccak256("ProposalSubmitted(bytes32,uint256,bytes)");
        let logs = rpc(
            &client,
            &config.rpc_url,
            "eth_getLogs",
            json!([{
                "address":config.router,"fromBlock":format!("0x{next:x}"),
                "toBlock":format!("0x{next:x}"),"topics":[topic]
            }]),
        )
        .await?;
        for log in logs
            .as_array()
            .ok_or_else(|| eyre::eyre!("logs response not an array"))?
        {
            let Some(proposal) = parse_proposal_log(log, config.router)? else {
                continue;
            };
            let request =
                read_request(&client, &config.rpc_url, config.hub, proposal.request_id).await?;
            if request.status != 0 {
                continue;
            }
            let job = EvaluationJob {
                chain_id: config.chain_id,
                hub: config.hub,
                template_id: config.template_id,
                template_path: config.template_path.clone(),
                request_id: proposal.request_id.to_string(),
                signer_version: config.signer_version,
                input_hash: keccak256(proposal.state.as_bytes()),
                template: config.template.clone(),
                evaluation: Evaluation {
                    model: config.template.model.clone(),
                    state: proposal.state,
                    questions: questions.clone(),
                },
                rpc_url: config.rpc_url.clone(),
                request_tx_hash: proposal.transaction_hash,
                router: config.router,
            };
            let basename = format!("{}-{}-{}", job.chain_id, job.hub, proposal.request_id);
            let job_path = config.archive_dir.join(format!("{basename}.job.json"));
            let job_value = serde_json::to_value(&job)?;
            ensure!(
                store_first_response(&job_path, &job_value)? == job_value,
                "archived job mismatch"
            );
            let output = Command::new(env::current_exe()?)
                .arg("evaluate")
                .arg(&job_path)
                .arg(&config.archive_dir)
                .output()?;
            ensure!(
                output.status.success(),
                "evaluation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let result: Value = serde_json::from_slice(&output.stdout)?;
            let result_path = config.archive_dir.join(format!("{basename}.result.json"));
            ensure!(
                store_first_response(&result_path, &result)? == result,
                "archived result mismatch"
            );
            let output = Command::new(env::current_exe()?)
                .arg("submit")
                .arg(&job_path)
                .arg(&result_path)
                .output()?;
            if !output.status.success() {
                let current =
                    read_request(&client, &config.rpc_url, config.hub, proposal.request_id).await?;
                ensure!(
                    current.status != 0,
                    "submission failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        persist_cursor(&config.cursor_path, next + 1)?;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        bail!(
            "usage: n42-decision-relay quote <quote.json> | evaluate <job.json> <archive-dir> | submit <job.json> <result.json> | watch <watch.json>"
        );
    }
    match args[1].as_str() {
        "quote" if args.len() == 3 => {
            let job: QuoteJob = json_file(&args[2])?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            ensure!(
                job.chain_id > 0
                    && job.hub != Address::ZERO
                    && job.requester != Address::ZERO
                    && job.refund_to != Address::ZERO
                    && job.input_hash != B256::ZERO
                    && job.signer_version > 0,
                "invalid quote fields"
            );
            ensure!(
                job.deadline > now
                    && job.deadline <= now + 86_400
                    && job.quote_expiry >= now
                    && job.quote_expiry <= job.deadline,
                "invalid quote lifetime"
            );
            let fields = QuoteFields {
                chain_id: job.chain_id,
                hub: job.hub,
                requester: job.requester,
                refund_to: job.refund_to,
                consumer: job.consumer,
                template_id: job.template_id,
                input_hash: job.input_hash,
                deadline: job.deadline,
                signer_version: job.signer_version,
                fee: U256::from_str(&job.fee)?,
                quote_expiry: job.quote_expiry,
            };
            let signature = sign_quote(&fields, &signer()?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "quote": serde_json::from_slice::<Value>(&fs::read(&args[2])?)?,
                    "signature": hex(&signature),
                }))?
            );
        }
        "evaluate" if args.len() == 4 => {
            let job: EvaluationJob = json_file(&args[2])?;
            let document_bytes = fs::read(&job.template_path)?;
            let document: Value = serde_json::from_slice(&document_bytes)?;
            ensure!(
                document["model"].as_str() == Some(job.template.model.as_str())
                    && document["questions"] == job.evaluation.questions,
                "evaluation differs from frozen template document"
            );
            for (i, schema) in job.template.questions.iter().enumerate() {
                let key = format!("q{i}");
                match schema {
                    QuestionSchema::Choice { options } => {
                        let order = document["optionOrder"][&key]
                            .as_array()
                            .ok_or_else(|| eyre::eyre!("template option order missing"))?;
                        ensure!(
                            order.len() == options.len()
                                && order
                                    .iter()
                                    .zip(options)
                                    .all(|(actual, expected)| actual.as_str() == Some(expected)),
                            "template option order changed"
                        );
                    }
                    QuestionSchema::Score { levels } => {
                        let actual = document["questions"][&key]["criteria"]
                            .as_array()
                            .ok_or_else(|| eyre::eyre!("score levels missing"))?;
                        ensure!(
                            actual.len() == levels.len()
                                && actual
                                    .iter()
                                    .zip(levels)
                                    .all(|(actual, expected)| actual.as_str() == Some(expected)),
                            "score levels changed"
                        );
                    }
                    QuestionSchema::Noul => {}
                }
            }
            let document_hash = keccak256(&document_bytes);
            validate_evaluation(&job.template, &job.evaluation)?;
            validate_public_proposal(&job.evaluation.state)?;
            ensure!(
                keccak256(job.evaluation.state.as_bytes()) == job.input_hash,
                "state/input hash mismatch"
            );
            let request_id = U256::from_str(&job.request_id)?;
            let rpc_client = reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()?;
            let chain =
                hex_quantity(&rpc(&rpc_client, &job.rpc_url, "eth_chainId", json!([])).await?)?;
            ensure!(chain == U256::from(job.chain_id), "wrong RPC chain");
            let state = confirmed_proposal(
                &rpc_client,
                &job.rpc_url,
                job.request_tx_hash,
                job.router,
                request_id,
                job.input_hash,
            )
            .await?;
            ensure!(
                state == job.evaluation.state.as_bytes(),
                "confirmed event state differs from evaluation"
            );
            verify_hub_state(
                &rpc_client,
                &job.rpc_url,
                &HubExpectation {
                    hub: job.hub,
                    request_id,
                    router: job.router,
                    template_id: job.template_id,
                    input_hash: job.input_hash,
                    signer_version: job.signer_version,
                    model_hash: keccak256(job.template.model.as_bytes()),
                    document_hash,
                },
            )
            .await?;
            let dir = PathBuf::from(&args[3]);
            fs::create_dir_all(&dir)?;
            let path = dir.join(format!("{}-{}-{}.json", job.chain_id, job.hub, request_id));
            let response: Value = if path.exists() {
                serde_json::from_slice(&fs::read(&path)?)?
            } else {
                let api_key = env::var("TYPESAFE_API_KEY")?;
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(20))
                    .build()?;
                let endpoint = env::var("TYPESAFE_API_URL")
                    .unwrap_or_else(|_| "https://api.typesafe.ai/v1/systemone".into());
                ensure!(
                    endpoint.starts_with("https://")
                        || endpoint.starts_with("http://127.0.0.1:")
                        || endpoint.starts_with("http://[::1]:"),
                    "insecure Jev endpoint"
                );
                let received =
                    call_jev(&client, &endpoint, &api_key, &job.template, &job.evaluation).await?;
                store_first_response(&path, &received)?
            };
            let answers = validate_response(&job.template, &response)?;
            let evidence = json!({"request":job.evaluation,"response":response});
            let evidence_path = dir.join(format!(
                "{}-{}-{}.evidence.json",
                job.chain_id, job.hub, request_id
            ));
            ensure!(
                store_first_response(&evidence_path, &evidence)? == evidence,
                "evidence archive mismatch"
            );
            let evidence_hash = keccak256(fs::read(&evidence_path)?);
            let model_hash = keccak256(job.template.model.as_bytes());
            let fields = ResultFields {
                chain_id: job.chain_id,
                hub: job.hub,
                request_id,
                answer_hash: answer_hash(&answers),
                evidence_hash,
                model_hash,
                signer_version: job.signer_version,
            };
            let signature = sign_result(&fields, &signer()?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "requestId": request_id.to_string(), "chainId": job.chain_id,
                    "hub": job.hub, "answerHash": fields.answer_hash,
                    "answersAbi": hex(&encode_answers(&answers)), "answers": answers,
                    "evidenceHash": evidence_hash, "modelHash": model_hash,
                    "signature": hex(&signature), "evidenceFile": evidence_path,
                }))?
            );
        }
        "submit" if args.len() == 4 => {
            let job: EvaluationJob = json_file(&args[2])?;
            submit_result(&job, &args[3]).await?;
        }
        "watch" if args.len() == 3 => {
            let config: WatchConfig = json_file(&args[2])?;
            watch(config).await?;
        }
        _ => bail!("invalid subcommand or arguments"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_survives_restart_without_partial_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/cursor");
        persist_cursor(&path, 101).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "101");
        persist_cursor(&path, 102).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "102");
    }
}
