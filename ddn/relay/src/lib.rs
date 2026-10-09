use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolStruct, SolValue, eip712_domain, sol};
use eyre::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs, io::Write, path::Path, time::Duration};

pub const PPM: u32 = 1_000_000;

sol! {
    struct ResultAttestation {
        uint256 requestId;
        bytes32 answerHash;
        bytes32 evidenceHash;
        bytes32 modelHash;
        uint64 signerVersion;
    }
    struct Quote {
        address requester;
        address refundTo;
        address consumer;
        uint64 templateId;
        bytes32 inputHash;
        uint64 deadline;
        uint64 signerVersion;
        uint256 fee;
        uint64 quoteExpiry;
    }
    struct Answer {
        uint8 kind;
        uint8 selected;
        uint32 valuePpm;
        uint32 confidencePpm;
        uint32[] probabilitiesPpm;
    }
    function fulfill(uint256 requestId, Answer[] answers, bytes32 evidenceHash, bytes32 modelHash, bytes signature);
    struct RequestView {
        address requester;
        address refundTo;
        address consumer;
        uint64 templateId;
        uint64 deadline;
        uint64 signerVersion;
        bytes32 inputHash;
        bytes32 answerHash;
        bytes32 evidenceHash;
        uint256 fee;
        uint8 status;
        bytes answers;
    }
    struct TemplateView {
        bytes32 documentHash;
        bytes32 modelHash;
        bool active;
        uint8[] kinds;
        uint8[] sizes;
        uint32[] minProbabilityPpm;
        uint32[] minConfidencePpm;
        uint8[] reviewOption;
    }
    function getRequest(uint256 requestId) external view returns (RequestView request);
    function getTemplate(uint64 templateId) external view returns (TemplateView templateInfo);
}

#[derive(Clone, Copy, Debug)]
pub struct QuoteFields {
    pub chain_id: u64,
    pub hub: Address,
    pub requester: Address,
    pub refund_to: Address,
    pub consumer: Address,
    pub template_id: u64,
    pub input_hash: B256,
    pub deadline: u64,
    pub signer_version: u64,
    pub fee: U256,
    pub quote_expiry: u64,
}

pub fn quote_digest(fields: &QuoteFields) -> B256 {
    let domain = eip712_domain! {
        name: "N42Decision",
        version: "1",
        chain_id: fields.chain_id,
        verifying_contract: fields.hub,
    };
    Quote {
        requester: fields.requester,
        refundTo: fields.refund_to,
        consumer: fields.consumer,
        templateId: fields.template_id,
        inputHash: fields.input_hash,
        deadline: fields.deadline,
        signerVersion: fields.signer_version,
        fee: fields.fee,
        quoteExpiry: fields.quote_expiry,
    }
    .eip712_signing_hash(&domain)
}

pub fn sign_quote(fields: &QuoteFields, signer: &PrivateKeySigner) -> Result<[u8; 65]> {
    Ok(signer.sign_hash_sync(&quote_digest(fields))?.as_bytes())
}

pub fn encode_answers(answers: &[QuantizedAnswer]) -> Vec<u8> {
    let converted: Vec<Answer> = answers
        .iter()
        .map(|answer| Answer {
            kind: answer.kind,
            selected: answer.selected,
            valuePpm: answer.value_ppm,
            confidencePpm: answer.confidence_ppm,
            probabilitiesPpm: answer.probabilities_ppm.clone(),
        })
        .collect();
    converted.abi_encode()
}

pub fn answer_hash(answers: &[QuantizedAnswer]) -> B256 {
    keccak256(encode_answers(answers))
}

pub fn encode_fulfill(
    request_id: U256,
    answers: &[QuantizedAnswer],
    evidence_hash: B256,
    model_hash: B256,
    signature: &[u8],
) -> Vec<u8> {
    use alloy_sol_types::SolCall;
    fulfillCall {
        requestId: request_id,
        answers: answers
            .iter()
            .map(|a| Answer {
                kind: a.kind,
                selected: a.selected,
                valuePpm: a.value_ppm,
                confidencePpm: a.confidence_ppm,
                probabilitiesPpm: a.probabilities_ppm.clone(),
            })
            .collect(),
        evidenceHash: evidence_hash,
        modelHash: model_hash,
        signature: signature.to_vec().into(),
    }
    .abi_encode()
}

#[derive(Clone, Copy, Debug)]
pub struct ResultFields {
    pub chain_id: u64,
    pub hub: Address,
    pub request_id: U256,
    pub answer_hash: B256,
    pub evidence_hash: B256,
    pub model_hash: B256,
    pub signer_version: u64,
}

pub fn result_digest(fields: &ResultFields) -> B256 {
    let domain = eip712_domain! {
        name: "N42Decision",
        version: "1",
        chain_id: fields.chain_id,
        verifying_contract: fields.hub,
    };
    ResultAttestation {
        requestId: fields.request_id,
        answerHash: fields.answer_hash,
        evidenceHash: fields.evidence_hash,
        modelHash: fields.model_hash,
        signerVersion: fields.signer_version,
    }
    .eip712_signing_hash(&domain)
}

pub fn sign_result(fields: &ResultFields, signer: &PrivateKeySigner) -> Result<[u8; 65]> {
    Ok(signer.sign_hash_sync(&result_digest(fields))?.as_bytes())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum QuestionSchema {
    Choice { options: Vec<String> },
    Score { levels: Vec<String> },
    Noul,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecisionTemplate {
    pub model: String,
    pub questions: Vec<QuestionSchema>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evaluation {
    pub model: String,
    pub state: String,
    pub questions: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicProposal {
    pub title: String,
    pub body: String,
    pub proposal_key: B256,
}

pub fn validate_public_proposal(state: &str) -> Result<PublicProposal> {
    let proposal: PublicProposal = serde_json::from_str(state)?;
    ensure!(
        !proposal.title.trim().is_empty() && !proposal.body.trim().is_empty(),
        "empty proposal"
    );
    ensure!(proposal.proposal_key != B256::ZERO, "empty proposal key");
    ensure!(
        state.len() <= 4096 && serde_json::to_string(&proposal)? == state,
        "noncanonical proposal state"
    );
    Ok(proposal)
}

/// Check the frozen template against the actual Jev request before sending it.
pub fn validate_evaluation(template: &DecisionTemplate, evaluation: &Evaluation) -> Result<()> {
    ensure!(evaluation.model == template.model, "model changed");
    ensure!(
        !evaluation.state.is_empty() && evaluation.state.len() <= 65_536,
        "invalid state length"
    );
    ensure!(
        (1..=8).contains(&template.questions.len()),
        "invalid template size"
    );
    let questions = evaluation
        .questions
        .as_object()
        .ok_or_else(|| eyre::eyre!("questions must be an object"))?;
    ensure!(
        questions.len() == template.questions.len(),
        "question count changed"
    );
    for (i, schema) in template.questions.iter().enumerate() {
        let question = questions
            .get(&format!("q{i}"))
            .ok_or_else(|| eyre::eyre!("missing question q{i}"))?;
        let kind = question.get("type").and_then(Value::as_str).unwrap_or("");
        ensure!(
            question
                .get("instructions")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty()),
            "missing instructions"
        );
        match schema {
            QuestionSchema::Choice { options } => {
                ensure!(
                    kind == "choice" && (2..=16).contains(&options.len()),
                    "choice type or size changed"
                );
                let criteria = question
                    .get("criteria")
                    .and_then(Value::as_object)
                    .ok_or_else(|| eyre::eyre!("missing criteria"))?;
                ensure!(
                    criteria.len() == options.len()
                        && options.iter().all(|name| criteria
                            .get(name)
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty())),
                    "choice criteria changed"
                );
            }
            QuestionSchema::Score { levels } => {
                ensure!(
                    kind == "score" && (2..=10).contains(&levels.len()),
                    "score type or size changed"
                );
                let criteria = question
                    .get("criteria")
                    .and_then(Value::as_array)
                    .ok_or_else(|| eyre::eyre!("missing score criteria"))?;
                ensure!(
                    criteria.len() == levels.len()
                        && criteria
                            .iter()
                            .all(|v| v.as_str().is_some_and(|s| !s.is_empty())),
                    "score criteria changed"
                );
            }
            QuestionSchema::Noul => ensure!(kind == "noul", "noul type changed"),
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct QuantizedAnswer {
    pub kind: u8,
    pub selected: u8,
    pub value_ppm: u32,
    pub confidence_ppm: u32,
    pub probabilities_ppm: Vec<u32>,
}

fn ppm(value: &Value) -> Result<u32> {
    let number = value
        .as_f64()
        .ok_or_else(|| eyre::eyre!("expected number"))?;
    ensure!(
        number.is_finite() && (0.0..=1.0).contains(&number),
        "probability outside 0..1"
    );
    Ok(decimal_millionths(value)? as u32)
}

fn decimal_millionths(value: &Value) -> Result<u64> {
    let number = value
        .as_number()
        .ok_or_else(|| eyre::eyre!("expected decimal number"))?;
    let representation = number.to_string();
    let (mantissa, exponent) = match representation.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i32>()?),
        None => (representation.as_str(), 0),
    };
    ensure!(!mantissa.starts_with('-'), "negative number");
    let decimals = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len() as i32);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let integer = digits.parse::<u128>()?;
    let shift = exponent - decimals + 6;
    ensure!(shift <= 38, "decimal exponent outside range");
    let scaled = if shift < -38 {
        0
    } else if shift >= 0 {
        integer
            .checked_mul(
                10u128
                    .checked_pow(shift as u32)
                    .ok_or_else(|| eyre::eyre!("decimal overflow"))?,
            )
            .ok_or_else(|| eyre::eyre!("decimal overflow"))?
    } else {
        integer / 10u128.pow((-shift) as u32)
    };
    Ok(u64::try_from(scaled)?)
}

fn distribution(value: &Value, names: &[String]) -> Result<Vec<u32>> {
    let map = value
        .as_object()
        .ok_or_else(|| eyre::eyre!("distribution must be an object"))?;
    ensure!(map.len() == names.len(), "wrong distribution cardinality");
    ensure!(
        names.iter().collect::<std::collections::HashSet<_>>().len() == names.len(),
        "duplicate option name"
    );
    let mut raw_sum = 0.0;
    let mut quantized = Vec::with_capacity(names.len());
    for name in names {
        let raw = map
            .get(name)
            .ok_or_else(|| eyre::eyre!("missing option {name}"))?;
        raw_sum += raw
            .as_f64()
            .ok_or_else(|| eyre::eyre!("option must be a number"))?;
        quantized.push(ppm(raw)?);
    }
    ensure!(
        (raw_sum - 1.0).abs() <= 0.000001,
        "probabilities do not sum to one"
    );
    let sum: u64 = quantized.iter().map(|v| u64::from(*v)).sum();
    ensure!(
        sum <= u64::from(PPM) && sum + names.len() as u64 >= u64::from(PPM),
        "quantized distribution rejected by contract"
    );
    Ok(quantized)
}

/// Validate exact model/question shape before anything is signed or submitted.
pub fn validate_response(
    template: &DecisionTemplate,
    value: &Value,
) -> Result<Vec<QuantizedAnswer>> {
    ensure!(
        !template.questions.is_empty() && template.questions.len() <= 8,
        "invalid template size"
    );
    ensure!(
        value.get("model").and_then(Value::as_str) == Some(template.model.as_str()),
        "model changed"
    );
    let answers = value
        .get("answers")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre::eyre!("missing answers"))?;
    ensure!(
        answers.len() == template.questions.len(),
        "wrong answer count"
    );
    let mut out = Vec::with_capacity(answers.len());
    for (i, schema) in template.questions.iter().enumerate() {
        let item = answers
            .get(&format!("q{i}"))
            .ok_or_else(|| eyre::eyre!("missing q{i}"))?;
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
        let next = match schema {
            QuestionSchema::Choice { options } => {
                ensure!(
                    kind == "choice" && (2..=16).contains(&options.len()),
                    "invalid choice schema or type"
                );
                let selected = item
                    .get("choice")
                    .and_then(Value::as_str)
                    .and_then(|name| options.iter().position(|candidate| candidate == name))
                    .ok_or_else(|| eyre::eyre!("unknown choice"))?;
                let probabilities = distribution(&item["probabilities"], options)?;
                ensure!(
                    probabilities[selected] == *probabilities.iter().max().unwrap(),
                    "selected option is not maximal"
                );
                QuantizedAnswer {
                    kind: 1,
                    selected: selected as u8,
                    value_ppm: 0,
                    confidence_ppm: ppm(&item["confidence"])?,
                    probabilities_ppm: probabilities,
                }
            }
            QuestionSchema::Score { levels } => {
                ensure!(
                    kind == "score" && (2..=10).contains(&levels.len()),
                    "invalid score schema or type"
                );
                let names: Vec<String> = (0..levels.len()).map(|n| n.to_string()).collect();
                let probabilities = distribution(&item["probabilities"], &names)?;
                let score = item
                    .get("score")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| eyre::eyre!("missing score"))?;
                ensure!(
                    score.is_finite() && score >= 0.0 && score <= (levels.len() - 1) as f64,
                    "score outside rubric"
                );
                let legend = item
                    .get("legend")
                    .and_then(Value::as_object)
                    .ok_or_else(|| eyre::eyre!("missing score legend"))?;
                ensure!(
                    legend.len() == levels.len()
                        && levels.iter().enumerate().all(|(n, level)| legend
                            .get(&n.to_string())
                            .and_then(Value::as_str)
                            == Some(level)),
                    "score legend changed"
                );
                QuantizedAnswer {
                    kind: 2,
                    selected: 0,
                    value_ppm: u32::try_from(decimal_millionths(&item["score"])?)?,
                    confidence_ppm: ppm(&item["confidence"])?,
                    probabilities_ppm: probabilities,
                }
            }
            QuestionSchema::Noul => {
                ensure!(kind == "noul", "invalid noul type");
                ensure!(
                    item.get("confidence").is_none() && item.get("probabilities").is_none(),
                    "noul has no distribution or confidence"
                );
                QuantizedAnswer {
                    kind: 3,
                    selected: 0,
                    value_ppm: ppm(&item["noul"])?,
                    confidence_ppm: 0,
                    probabilities_ppm: Vec::new(),
                }
            }
        };
        out.push(next);
    }
    Ok(out)
}

/// Persist the first valid response atomically; retries reuse the same bytes.
pub fn store_first_response(path: &Path, response: &Value) -> Result<Value> {
    let bytes = serde_json::to_vec(response)?;
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("missing response directory"))?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(&bytes)?;
    temp.as_file().sync_all()?;
    match fs::hard_link(temp.path(), path) {
        Ok(()) => Ok(response.clone()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(path)?;
            if existing.is_empty() {
                bail!("response file is empty");
            }
            Ok(serde_json::from_slice(&existing)?)
        }
        Err(error) => Err(error.into()),
    }
}

/// HTTP wrapper around the official Jev endpoint. Only rate-limit/overload
/// responses are retried; a malformed request or bad API key must surface.
pub async fn call_jev(
    client: &reqwest::Client,
    endpoint: &str,
    api_key: &str,
    template: &DecisionTemplate,
    evaluation: &Evaluation,
) -> Result<Value> {
    validate_evaluation(template, evaluation)?;
    ensure!(!api_key.is_empty(), "missing TypeSafe API key");
    for attempt in 0..3 {
        let response = client
            .post(endpoint)
            .bearer_auth(api_key)
            .json(evaluation)
            .send()
            .await?;
        let status = response.status();
        if status.is_success() {
            let bytes = response.bytes().await?;
            ensure!(bytes.len() <= 1_048_576, "Jev response too large");
            let body: Value = serde_json::from_slice(&bytes)?;
            validate_response(template, &body)?;
            return Ok(body);
        }
        if (status.as_u16() == 429 || status.as_u16() == 529) && attempt < 2 {
            tokio::time::sleep(Duration::from_millis(250 * (1 << attempt))).await;
            continue;
        }
        bail!("Jev HTTP {status}");
    }
    unreachable!()
}

pub async fn rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value> {
    let body: Value = client
        .post(url)
        .json(&serde_json::json!({
            "jsonrpc":"2.0", "id":1, "method":method, "params":params,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        body.get("error").is_none(),
        "RPC {method} failed: {}",
        body["error"]
    );
    body.get("result")
        .cloned()
        .ok_or_else(|| eyre::eyre!("RPC {method} missing result"))
}

pub struct HubExpectation {
    pub hub: Address,
    pub request_id: U256,
    pub router: Address,
    pub template_id: u64,
    pub input_hash: B256,
    pub signer_version: u64,
    pub model_hash: B256,
    pub document_hash: B256,
}

pub async fn read_request(
    client: &reqwest::Client,
    rpc_url: &str,
    hub: Address,
    request_id: U256,
) -> Result<RequestView> {
    use alloy_sol_types::SolCall;
    let request_call = getRequestCall {
        requestId: request_id,
    }
    .abi_encode();
    let request_hex = format!("0x{}", alloy_primitives::hex::encode(request_call));
    let request_result = rpc(
        client,
        rpc_url,
        "eth_call",
        serde_json::json!([{"to":hub,"data":request_hex},"latest"]),
    )
    .await?;
    let request_bytes = alloy_primitives::hex::decode(
        request_result
            .as_str()
            .ok_or_else(|| eyre::eyre!("missing request bytes"))?
            .trim_start_matches("0x"),
    )?;
    Ok(getRequestCall::abi_decode_returns(&request_bytes)?)
}

pub async fn verify_hub_state(
    client: &reqwest::Client,
    rpc_url: &str,
    expected: &HubExpectation,
) -> Result<()> {
    use alloy_sol_types::SolCall;
    let request = read_request(client, rpc_url, expected.hub, expected.request_id).await?;
    ensure!(
        request.requester == expected.router && request.consumer == expected.router,
        "request router mismatch"
    );
    ensure!(
        request.templateId == expected.template_id && request.inputHash == expected.input_hash,
        "request template or input mismatch"
    );
    ensure!(
        request.signerVersion == expected.signer_version && request.status == 0,
        "request not pending under expected signer"
    );
    let template_call = getTemplateCall {
        templateId: expected.template_id,
    }
    .abi_encode();
    let template_hex = format!("0x{}", alloy_primitives::hex::encode(template_call));
    let template_result = rpc(
        client,
        rpc_url,
        "eth_call",
        serde_json::json!([{"to":expected.hub,"data":template_hex},"latest"]),
    )
    .await?;
    let template_bytes = alloy_primitives::hex::decode(
        template_result
            .as_str()
            .ok_or_else(|| eyre::eyre!("missing template bytes"))?
            .trim_start_matches("0x"),
    )?;
    let template = getTemplateCall::abi_decode_returns(&template_bytes)?;
    ensure!(
        template.documentHash == expected.document_hash
            && template.modelHash == expected.model_hash,
        "template document or model hash mismatch"
    );
    Ok(())
}

fn abi_event_bytes(data: &str) -> Result<Vec<u8>> {
    let bytes = alloy_primitives::hex::decode(data.trim_start_matches("0x"))?;
    ensure!(
        bytes.len() >= 64 && bytes.len() % 32 == 0,
        "invalid event data"
    );
    ensure!(
        bytes[..31].iter().all(|b| *b == 0) && bytes[31] == 32,
        "invalid event offset"
    );
    let len = U256::from_be_slice(&bytes[32..64]);
    ensure!(len <= U256::from(4096), "event state too large");
    let len = len.to::<usize>();
    ensure!(bytes.len() >= 64 + len, "truncated event state");
    Ok(bytes[64..64 + len].to_vec())
}

pub struct ProposalLog {
    pub request_id: U256,
    pub state: String,
    pub transaction_hash: B256,
}

pub fn parse_proposal_log(log: &Value, router: Address) -> Result<Option<ProposalLog>> {
    let log_address: Address = log["address"].as_str().unwrap_or("").parse()?;
    if log_address != router {
        return Ok(None);
    }
    let topics = log["topics"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("missing topics"))?;
    let event_topic = keccak256("ProposalSubmitted(bytes32,uint256,bytes)");
    if topics.len() != 3
        || topics[0].as_str().and_then(|s| s.parse::<B256>().ok()) != Some(event_topic)
    {
        return Ok(None);
    }
    let event_key: B256 = topics[1].as_str().unwrap_or("").parse()?;
    let request_id = U256::from_str_radix(
        topics[2].as_str().unwrap_or("").trim_start_matches("0x"),
        16,
    )?;
    let bytes = abi_event_bytes(
        log["data"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("missing event data"))?,
    )?;
    let state = String::from_utf8(bytes)?;
    ensure!(
        validate_public_proposal(&state)?.proposal_key == event_key,
        "event proposal key mismatch"
    );
    let transaction_hash: B256 = log["transactionHash"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing transaction hash"))?
        .parse()?;
    Ok(Some(ProposalLog {
        request_id,
        state,
        transaction_hash,
    }))
}

/// Read a proposal from its receipt and ensure its block is an ancestor of
/// the finalized settlement block reported by the operator's execution layer.
pub async fn confirmed_proposal(
    client: &reqwest::Client,
    rpc_url: &str,
    tx_hash: B256,
    router: Address,
    request_id: U256,
    expected_input_hash: B256,
) -> Result<Vec<u8>> {
    let receipt = rpc(
        client,
        rpc_url,
        "eth_getTransactionReceipt",
        serde_json::json!([tx_hash]),
    )
    .await?;
    ensure!(
        receipt.is_object() && receipt["status"] == "0x1",
        "transaction failed or missing"
    );
    let receipt_hash: B256 = receipt["blockHash"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing block hash"))?
        .parse()?;
    let event_topic = keccak256("ProposalSubmitted(bytes32,uint256,bytes)");
    let mut state = None;
    for log in receipt["logs"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("missing logs"))?
    {
        let log_address: Address = log["address"].as_str().unwrap_or("").parse()?;
        if log_address != router {
            continue;
        }
        let topics = log["topics"]
            .as_array()
            .ok_or_else(|| eyre::eyre!("missing topics"))?;
        if topics.len() != 3
            || topics[0].as_str().and_then(|s| s.parse::<B256>().ok()) != Some(event_topic)
        {
            continue;
        }
        let id = U256::from_str_radix(
            topics[2].as_str().unwrap_or("").trim_start_matches("0x"),
            16,
        )?;
        if id != request_id {
            continue;
        }
        let bytes = abi_event_bytes(
            log["data"]
                .as_str()
                .ok_or_else(|| eyre::eyre!("missing event data"))?,
        )?;
        let proposal = validate_public_proposal(std::str::from_utf8(&bytes)?)?;
        let event_key: B256 = topics[1].as_str().unwrap_or("").parse()?;
        ensure!(
            event_key == proposal.proposal_key,
            "event proposal key mismatch"
        );
        ensure!(
            keccak256(&bytes) == expected_input_hash,
            "event/input hash mismatch"
        );
        ensure!(state.replace(bytes).is_none(), "duplicate proposal event");
    }
    let state = state.ok_or_else(|| eyre::eyre!("proposal event absent"))?;
    committed_ancestor(client, rpc_url, receipt_hash).await?;
    Ok(state)
}

/// Use the execution layer's certified and persisted settlement tag.
/// Missing finality is an error: never fall back to latest or safe.
pub async fn finalized_block(client: &reqwest::Client, rpc_url: &str) -> Result<Value> {
    let block = rpc(
        client,
        rpc_url,
        "eth_getBlockByNumber",
        serde_json::json!(["finalized", false]),
    )
    .await?;
    validate_finalized_block(&block)?;
    Ok(block)
}

fn validate_finalized_block(block: &Value) -> Result<B256> {
    let hash: B256 = block["hash"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing finalized hash"))?
        .parse()?;
    ensure!(hash != B256::ZERO, "zero finalized hash");
    let number = block["number"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing finalized number"))?;
    ensure!(
        number.starts_with("0x") && u64::from_str_radix(&number[2..], 16).is_ok(),
        "invalid finalized number"
    );
    Ok(hash)
}

pub async fn committed_ancestor(
    client: &reqwest::Client,
    rpc_url: &str,
    block_hash: B256,
) -> Result<()> {
    verify_committed_ancestry(block_hash, |method, params| {
        rpc(client, rpc_url, method, params)
    })
    .await
}

/// Verify settlement ancestry using an injectable RPC transport.
/// The transport must query the operator's trusted execution layer.
pub async fn verify_committed_ancestry<F, Fut>(block_hash: B256, mut query: F) -> Result<()>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let finalized = query(
        "eth_getBlockByNumber",
        serde_json::json!(["finalized", false]),
    )
    .await?;
    let mut head = validate_finalized_block(&finalized)?;
    for _ in 0..4096 {
        ensure!(head != B256::ZERO, "zero ancestor hash");
        if head == block_hash {
            return Ok(());
        }
        let block = query("eth_getBlockByHash", serde_json::json!([head, false])).await?;
        ensure!(block.is_object(), "committed ancestor missing");
        ensure!(
            block["hash"].as_str().and_then(|h| h.parse::<B256>().ok()) == Some(head),
            "ancestor hash mismatch"
        );
        let parent: B256 = block["parentHash"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("missing parent"))?
            .parse()?;
        ensure!(
            parent != head && parent != B256::ZERO,
            "receipt outside committed ancestry"
        );
        head = parent;
    }
    bail!("receipt outside committed ancestry window")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn template() -> DecisionTemplate {
        DecisionTemplate {
            model: "jev-1.13.0".into(),
            questions: vec![
                QuestionSchema::Choice {
                    options: vec!["technical".into(), "community".into()],
                },
                QuestionSchema::Noul,
            ],
        }
    }

    #[test]
    fn rejects_wrong_model_and_missing_question() {
        let mut answer = json!({"model":"jev-latest","answers":{"q0":{"type":"choice","choice":"technical","probabilities":{"technical":0.7,"community":0.3},"confidence":0.6},"q1":{"type":"noul","noul":0.8}}});
        assert!(validate_response(&template(), &answer).is_err());
        answer["model"] = json!("jev-1.13.0");
        answer["answers"].as_object_mut().unwrap().remove("q1");
        assert!(validate_response(&template(), &answer).is_err());
    }

    #[test]
    fn quantizes_and_rejects_bad_distribution() {
        let good = json!({"model":"jev-1.13.0","answers":{"q0":{"type":"choice","choice":"technical","probabilities":{"technical":0.7,"community":0.3},"confidence":0.6},"q1":{"type":"noul","noul":0.8}}});
        let actual = validate_response(&template(), &good).unwrap();
        assert_eq!(actual[0].probabilities_ppm, vec![700_000, 300_000]);
        assert_eq!(actual[0].selected, 0);
        assert_eq!(actual[1].value_ppm, 800_000);
        let mut bad = good;
        bad["answers"]["q0"]["probabilities"]["community"] = json!(0.8);
        assert!(validate_response(&template(), &bad).is_err());
    }

    #[test]
    fn first_valid_response_wins_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let stored = json!({"model":"jev-1.13.0","answers":{"q0":{"type":"choice","choice":"technical","probabilities":{"technical":0.7,"community":0.3},"confidence":0.6},"q1":{"type":"noul","noul":0.8}}});
        let path = dir.path().join("response.json");
        let a = store_first_response(&path, &stored).unwrap();
        let b = store_first_response(&path, &json!({"different":true})).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, stored);
    }

    #[test]
    fn attestation_signature_is_domain_bound() {
        use alloy_primitives::{Address, B256, U256};
        use alloy_signer_local::PrivateKeySigner;
        let signer = PrivateKeySigner::from_slice(&[1u8; 32]).unwrap();
        let fields = ResultFields {
            chain_id: 94,
            hub: Address::repeat_byte(0x11),
            request_id: U256::from(7),
            answer_hash: B256::repeat_byte(0x22),
            evidence_hash: B256::repeat_byte(0x33),
            model_hash: B256::repeat_byte(0x44),
            signer_version: 1,
        };
        let signature = sign_result(&fields, &signer).unwrap();
        let digest = result_digest(&fields);
        let recovered = alloy_primitives::Signature::from_raw(&signature)
            .unwrap()
            .recover_address_from_prehash(&digest)
            .unwrap();
        assert_eq!(recovered, signer.address());
        assert_ne!(
            digest,
            result_digest(&ResultFields {
                chain_id: 95,
                ..fields
            })
        );
    }

    #[test]
    fn quote_cannot_move_refund_or_hub() {
        use alloy_primitives::{Address, B256, U256};
        use alloy_signer_local::PrivateKeySigner;
        let signer = PrivateKeySigner::from_slice(&[2u8; 32]).unwrap();
        let fields = QuoteFields {
            chain_id: 94,
            hub: Address::repeat_byte(1),
            requester: Address::repeat_byte(2),
            refund_to: Address::repeat_byte(3),
            consumer: Address::repeat_byte(4),
            template_id: 1,
            input_hash: B256::repeat_byte(5),
            deadline: 123,
            signer_version: 1,
            fee: U256::from(1000),
            quote_expiry: 100,
        };
        let signature = sign_quote(&fields, &signer).unwrap();
        let recovered = alloy_primitives::Signature::from_raw(&signature)
            .unwrap()
            .recover_address_from_prehash(&quote_digest(&fields))
            .unwrap();
        assert_eq!(recovered, signer.address());
        assert_ne!(
            quote_digest(&fields),
            quote_digest(&QuoteFields {
                refund_to: Address::repeat_byte(6),
                ..fields
            })
        );
        assert_ne!(
            quote_digest(&fields),
            quote_digest(&QuoteFields {
                hub: Address::repeat_byte(6),
                ..fields
            })
        );
    }

    #[test]
    fn abi_answer_hash_matches_encoded_payload() {
        use alloy_primitives::keccak256;
        let answers = vec![QuantizedAnswer {
            kind: 1,
            selected: 0,
            value_ppm: 0,
            confidence_ppm: 800_000,
            probabilities_ppm: vec![800_000, 200_000],
        }];
        let bytes = encode_answers(&answers);
        assert!(!bytes.is_empty());
        assert_eq!(answer_hash(&answers), keccak256(&bytes));
    }

    #[test]
    fn decimal_quantization_uses_exact_json_decimal() {
        assert_eq!(ppm(&json!(0.29)).unwrap(), 290_000);
        assert_eq!(ppm(&json!(0.0000009)).unwrap(), 0);
        assert_eq!(ppm(&json!(0.9999999)).unwrap(), 999_999);
        assert_eq!(ppm(&json!(1e-150)).unwrap(), 0);
        assert_eq!(decimal_millionths(&json!(1.05)).unwrap(), 1_050_000);
    }

    #[test]
    fn event_bytes_require_bounded_abi_payload() {
        let mut data = vec![0u8; 96];
        data[31] = 32;
        data[63] = 3;
        data[64..67].copy_from_slice(b"abc");
        assert_eq!(
            abi_event_bytes(&format!("0x{}", alloy_primitives::hex::encode(&data))).unwrap(),
            b"abc"
        );
        data[31] = 0;
        assert!(abi_event_bytes(&format!("0x{}", alloy_primitives::hex::encode(&data))).is_err());
    }

    #[test]
    fn proposal_log_binds_indexed_key_and_state() {
        let router = Address::repeat_byte(0x11);
        let key = B256::repeat_byte(0x33);
        let state = format!(r#"{{"title":"A","body":"B","proposalKey":"{key}"}}"#);
        let mut encoded = vec![0u8; 64 + state.len().div_ceil(32) * 32];
        encoded[31] = 32;
        encoded[63] = state.len() as u8;
        encoded[64..64 + state.len()].copy_from_slice(state.as_bytes());
        let mut log = json!({
            "address":router,
            "topics":[keccak256("ProposalSubmitted(bytes32,uint256,bytes)"),key,format!("0x{:064x}",7)],
            "data":format!("0x{}",alloy_primitives::hex::encode(encoded)),
            "transactionHash":B256::repeat_byte(0x44),
        });
        let parsed = parse_proposal_log(&log, router).unwrap().unwrap();
        assert_eq!(parsed.request_id, U256::from(7));
        assert_eq!(parsed.state, state);
        log["topics"][1] = json!(B256::repeat_byte(0x55));
        assert!(parse_proposal_log(&log, router).is_err());
    }

    #[test]
    fn sdk_proposal_hash_and_duplicate_keys() {
        let state = r#"{"title":"公开提案","body":"材料","proposalKey":"0x3333333333333333333333333333333333333333333333333333333333333333"}"#;
        assert!(validate_public_proposal(state).is_ok());
        assert_eq!(
            keccak256(state.as_bytes()).to_string(),
            "0xdbc9509175d68eb73e5ca525c222f4c8b48c154c124bc1eeaaa744a486a486e9"
        );
        let duplicate = state.replace("\"body\":\"材料\",", "\"body\":\"材料\",\"body\":\"其他\",");
        assert!(validate_public_proposal(&duplicate).is_err());
    }

    #[test]
    fn fulfill_calldata_uses_contract_signature() {
        let answers = vec![QuantizedAnswer {
            kind: 3,
            selected: 0,
            value_ppm: 800_000,
            confidence_ppm: 0,
            probabilities_ppm: vec![],
        }];
        let data = encode_fulfill(
            U256::from(1),
            &answers,
            B256::repeat_byte(2),
            B256::repeat_byte(3),
            &[4u8; 65],
        );
        let selector = keccak256(
            "fulfill(uint256,(uint8,uint8,uint32,uint32,uint32[])[],bytes32,bytes32,bytes)",
        );
        assert_eq!(&data[..4], &selector[..4]);
        assert!(data.len() > 4 + 32 * 5);
    }

    #[test]
    fn hub_view_abi_round_trips_dynamic_request_and_template() {
        use alloy_sol_types::SolCall;
        let request = RequestView {
            requester: Address::repeat_byte(1),
            refundTo: Address::repeat_byte(2),
            consumer: Address::repeat_byte(3),
            templateId: 7,
            deadline: 123,
            signerVersion: 1,
            inputHash: B256::repeat_byte(4),
            answerHash: B256::ZERO,
            evidenceHash: B256::ZERO,
            fee: U256::from(100),
            status: 0,
            answers: vec![1, 2, 3].into(),
        };
        let decoded = getRequestCall::abi_decode_returns(&request.abi_encode()).unwrap();
        assert_eq!(decoded.inputHash, request.inputHash);
        assert_eq!(decoded.answers.as_ref(), &[1, 2, 3]);
        let template = TemplateView {
            documentHash: B256::repeat_byte(5),
            modelHash: B256::repeat_byte(6),
            active: true,
            kinds: vec![1, 3],
            sizes: vec![4, 0],
            minProbabilityPpm: vec![900_000, 800_000],
            minConfidencePpm: vec![700_000, 0],
            reviewOption: vec![3, 255],
        };
        let decoded = getTemplateCall::abi_decode_returns(&template.abi_encode()).unwrap();
        assert_eq!(decoded.documentHash, template.documentHash);
        assert_eq!(decoded.kinds, vec![1, 3]);
    }

    #[test]
    fn concurrent_archive_writers_observe_one_response() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("response.json");
        let handles: Vec<_> = (0..4)
            .map(|n| {
                let path = path.clone();
                std::thread::spawn(move || {
                    store_first_response(&path, &json!({"value":n})).unwrap()
                })
            })
            .collect();
        let observed: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(observed.iter().all(|v| v == &observed[0]));
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap(),
            observed[0]
        );
    }

    #[test]
    fn request_body_rejects_question_shape_drift() {
        let eval = Evaluation {
            model: "jev-1.13.0".into(),
            state: "public proposal".into(),
            questions: json!({"q0":{"type":"choice","instructions":"classify","criteria":{"technical":"Code","community":"People"}},"q1":{"type":"noul","instructions":"is complete?"}}),
        };
        assert!(validate_evaluation(&template(), &eval).is_ok());
        let mut drift = eval;
        drift.questions["q0"]["criteria"]
            .as_object_mut()
            .unwrap()
            .remove("technical");
        assert!(validate_evaluation(&template(), &drift).is_err());
    }
}
