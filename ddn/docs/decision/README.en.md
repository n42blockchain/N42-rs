# N42 Distributed Decision Network: Testnet Guide

This guide covers the decision flow currently implemented in this repository:
`DecisionHub`, the public-proposal `ProposalRouter`, the `n42-decision-relay`,
the TypeScript SDK, and the example DApp. For the broader DDN design and roadmap,
see the [implementation and acceptance notes](../../README.md).

## Scope and status

This is a limited testnet prototype for routing **public proposals** into a
technical, community, or funding review queue. The AI classification does not
approve a proposal or authorize a payment. Funding decisions remain in the
application's governance process.

The relay checks the N42 committed-chain view and the exact proposal bytes, calls
the configured Jev endpoint, validates the structured response, saves the first
valid response as evidence, and signs an on-chain attestation. The contract
validates the signature, request binding, answer shape, and configured thresholds.
It does not prove that Jev produced the answer or that the answer is correct.
The operator's full N42 node is the source of committed-chain information used by
the relay.

This release does not provide private-input handling, general provider discovery,
multi-provider aggregation, account quotas, automated quote pricing, or independent
proof of model inference. The watcher is a single sequential worker without a
multi-instance lease. Do not treat this prototype as a production DDN service.

## Components

- `contracts/decision/DecisionHub.sol` registers decision templates, verifies
  signed quotes and result attestations, holds request fees, enforces answer
  thresholds, and tracks request status.
- `contracts/decision/examples/ProposalRouter.sol` binds a public proposal key,
  input hash, and request ID. A ready classification can be routed by any caller;
  a result requiring review can only be resolved by the configured reviewer.
- `relay/` provides `quote`, `evaluate`, `submit`, and `watch`
  commands.
- `sdk/decision-ts` encodes proposal input, computes Keccak-256 hashes, checks
  quotes, and exposes contract ABIs.
- `examples/decision-dapp` provides the browser example.

## Prerequisites

- Rust and Cargo for the relay.
- Foundry (`forge`) for Solidity compilation and contract tests.
- Node.js for the TypeScript SDK tests.
- An N42 testnet RPC endpoint that exposes `eth_getBlockByNumber("finalized", false)` and the standard
  Ethereum JSON-RPC methods used by the relay.
- A browser wallet connected to the same testnet for the example DApp.
- A TypeSafe API key for live Jev evaluation.

From the `ddn/` directory, the local checks are:

```sh
forge build
forge test --match-path 'contracts/decision/test/*'
nice -n 19 cargo test --locked -j 1 -p n42-decision-relay
npm test --prefix sdk/decision-ts
```

These checks validate local code only. They do not deploy contracts or prove a
live Jev request works against a particular RPC endpoint.

## Deploy the contracts

1. Choose a signing address for the relay. Deploy `DecisionHub` with that address
   as `initialSigner`; the deployer becomes the Hub owner.
2. Register the first template with the Hub owner account. Template IDs start at
   `1`. For the included template, hash the **exact file bytes** of
   `examples/decision-dapp/template.json` with Keccak-256 for `documentHash`.
   Set `modelHash` to Keccak-256 of the UTF-8 bytes of `jev-1.13.0`.
3. Register the included template with these arrays, in the same order as its
   questions:

   ```text
   kinds             [1, 3]        # Choice, Noul
   sizes             [4, 0]
   minProbabilityPpm [900000, 800000]
   minConfidencePpm  [700000, 0]
   reviewOption      [3, 255]      # Choice index 3 means needs_more_information
   ```

4. Deploy `ProposalRouter(hubAddress, templateId, reviewerAddress)`.
5. Configure a funded testnet transaction account for the relay. Keep the Hub
   owner key, decision-signing key, and transaction key separate. Never put
   private keys or the TypeSafe API key in the browser app or repository.

The quote signer address must match the Hub's active signer version. When rotating
the signer, update the relay's `signerVersion` configuration to the new on-chain
version. Revoked signers cannot fulfill requests signed under that version.

## Run the example DApp

Serve the `ddn/` directory so the app can load the local SDK module:

```sh
python3 -m http.server 8080
```

Open `http://127.0.0.1:8080/examples/decision-dapp/` and enter the deployed
Router and Hub addresses and the template ID. Connect a wallet on the matching
N42 testnet.

1. Enter a proposal title and public body, then select **Generate input hash**.
   The app displays the exact JSON state and its hash. The proposal body is public
   and is emitted in the `ProposalSubmitted` event; do not enter secrets or
   personal data.
2. Send the displayed hash, the user's wallet address, and the intended template
   to the quote operator. The returned quote must bind the Router as both
   `requester` and `consumer`, the user's wallet as `refundTo`, the same template
   and input hash, and a valid deadline and fee.
3. Paste the signed quote and submit. Review the fee and deadline in the wallet
   confirmation. The page reports the request ID from the Router event.
4. Use **Check status** to inspect the request. When the result is `Ready`, any
   account may call **Route result**. A `Review` result requires the configured
   reviewer to call `resolveReview` with a category from `0` to `2`.

The page loads viem from `esm.sh`; the browser therefore needs network access to
that CDN. A production deployment should pin or self-host its browser dependency.

## Operate the relay

Set secrets through a secret manager or a protected service environment. The
relay reads `N42_DECISION_SIGNING_KEY` for quotes and result attestations,
`N42_TX_SIGNING_KEY` for on-chain fulfillment transactions, and
`TYPESAFE_API_KEY` for live evaluation. The API endpoint defaults to
`https://api.typesafe.ai/v1/systemone`. For testing, `TYPESAFE_API_URL` accepts
HTTPS or a loopback HTTP mock endpoint only.

### Issue a quote

Create a `quote.json` containing the fields below. `fee` is a decimal string in
wei. The deadline must be in the future and no more than one day away;
`quoteExpiry` must not exceed the deadline. Addresses, chain ID, and hash below
are placeholders. Generate fresh timestamps when creating the file:

```json
{
  "chainId": 94,
  "hub": "0x1111111111111111111111111111111111111111",
  "requester": "0x2222222222222222222222222222222222222222",
  "refundTo": "0x3333333333333333333333333333333333333333",
  "consumer": "0x2222222222222222222222222222222222222222",
  "templateId": 1,
  "inputHash": "0x<64 hex characters from the DApp>",
  "deadline": 0,
  "signerVersion": 1,
  "fee": "1000000000000000",
  "quoteExpiry": 0
}
```

Replace the placeholder values, and set `deadline` and `quoteExpiry` to current
Unix time plus the chosen validity intervals. Sign the quote with the Hub's active
decision-signing key:

```sh
N42_DECISION_SIGNING_KEY=<secret> cargo run -p n42-decision-relay -- quote quote.json
```

Return the emitted `quote` and `signature` to the DApp user. The signing command
does not submit a transaction or charge the user.

### Evaluate and fulfill a request

After a proposal is submitted, create a `job.json` from that transaction's
`ProposalSubmitted` event. Use the exact `state` bytes and `inputHash` generated by
the DApp, plus the transaction hash and request ID from the same submission. The
job contains:

```text
chainId, hub, templateId, templatePath, router, rpcUrl,
requestTxHash, requestId, signerVersion, inputHash,
template, evaluation
```

`template` must match the registered model and question schema. `evaluation`
contains the same model, exact proposal state string, and questions. For a live
request, save the result and evidence archive, then submit the fulfillment:

```sh
TYPESAFE_API_KEY=<secret> N42_DECISION_SIGNING_KEY=<secret> \
  cargo run -p n42-decision-relay -- evaluate job.json ./decision-archive \
  > result.json

N42_TX_SIGNING_KEY=<funded-testnet-key> \
  cargo run -p n42-decision-relay -- submit job.json result.json
```

Before calling Jev, `evaluate` checks the RPC chain ID, the submitted event and
exact state bytes, the request and template on the Hub, and that the request
transaction's block is an ancestor of the node's latest committed block. It
validates the structured answer, writes the first response and evidence to the
archive, and signs their hashes. Keep the archive intact: `submit` re-reads it and
rejects a changed result or evidence file. Re-running evaluation for the same
request reuses the first archived response rather than requesting another answer.

### Run the watcher

For continuous processing, prepare a `watch.json`:

```json
{
  "chainId": 94,
  "hub": "0x1111111111111111111111111111111111111111",
  "router": "0x2222222222222222222222222222222222222222",
  "rpcUrl": "http://127.0.0.1:8545",
  "templateId": 1,
  "templatePath": "examples/decision-dapp/template.json",
  "template": {
    "model": "jev-1.13.0",
    "questions": [
      {"type": "choice", "options": ["technical", "community", "funding", "needs_more_information"]},
      {"type": "noul"}
    ]
  },
  "signerVersion": 1,
  "startBlock": 100,
  "archiveDir": "./decision-archive",
  "cursorPath": "./decision-archive/cursor"
}
```

Set `startBlock` to the Router deployment block. Start one watcher process:

```sh
TYPESAFE_API_KEY=<secret> N42_DECISION_SIGNING_KEY=<secret> \
N42_TX_SIGNING_KEY=<funded-testnet-key> \
  cargo run -p n42-decision-relay -- watch watch.json
```

The watcher polls the latest committed block, processes Router events in block
order, and persists the next block number in `cursorPath`. It writes each job and
result into `archiveDir`; if it stops, fix the RPC, API, key, gas, or template
error and restart it with the same archive and cursor. Do not run multiple watcher
instances against the same configuration: the current implementation has no
distributed lease. Quote issuance and per-account quotas remain application or
operator responsibilities; the watcher handles only proposals that already have
a valid quote and an on-chain request.

## Request lifecycle and recovery

```text
Pending -> Ready -> Consumed
         -> Review
Pending -> Expired
```

- `Ready`: any caller may invoke `ProposalRouter.route`; the Router consumes the
  result from the Hub.
- `Review`: only the configured reviewer can call `resolveReview` on the Router.
  This template routes low-confidence or `needs_more_information` answers here.
- `Expired`: anyone may expire a pending request after its deadline or signer
  revocation. The fee becomes a refund credit for `refundTo`; that same address
  must call `withdrawRefund`.
- A fulfilled request's fee moves to the Hub service balance. Only the Hub owner
  can withdraw service fees.

The example classification selects a review queue only. In particular, a
`funding` label is not approval to spend treasury funds.

## Operational and security limits

- Proposal text and request metadata are public on the chain. Do not use this flow
  for private or sensitive input.
- A valid signature proves that the configured gateway key attested to an answer
  and evidence hash. It does not prove model identity, inference execution,
  evidence completeness, or answer correctness.
- The relay relies on the operator's full node for committed ancestry; the current
  version does not verify that claim through an independent light client.
- Protect and rotate the signer and transaction keys independently. Pause new
  requests or revoke a signer if its key is compromised, then update the relay to
  the active signer version.
- Monitor the relay process, RPC availability, API failures, transaction balance,
  cursor, and archive backups. The watcher exits on a processing error; supervise
  it with a service manager and inspect the error before restarting.
- Before any production use, complete contract review, key-management review,
  live testnet deployment, end-to-end tests, and operational recovery testing.

## Source map

- [Implementation and acceptance](../../README.md)
- [Hub contract](../../contracts/decision/DecisionHub.sol)
- [Proposal router](../../contracts/decision/examples/ProposalRouter.sol)
- [Relay source](../../relay/src/main.rs)
- [TypeScript SDK](../../sdk/decision-ts/index.mjs)
- [Example DApp](../../examples/decision-dapp/index.html)
