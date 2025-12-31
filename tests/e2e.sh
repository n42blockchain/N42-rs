#!/bin/bash

RPC_ADDR=http://127.0.0.1:8545

N42=./target/release/n42
MOBILE_SDK_TEST=./target/release/examples/mobile-sdk-test

if [ ! -x $N42 ] || [ ! -x $MOBILE_SDK_TEST ]; then
	echo "binaries for n42 and mobile-sdk-test not found: $N42, $MOBILE_SDK_TEST"
	exit
fi

RUST_LOG=debug $N42 node --chain n42-devnet \
--dev.consensus-signer-private-key \
0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
--ws --http \
--http.api "eth,net,web3,txpool,debug,trace" \
--ws.api "eth,net,web3,txpool,debug,trace" \
--http.addr 0.0.0.0 --ws.addr 0.0.0.0 \
--dev.block-time 4s \
--disable-discovery \
>/dev/null 2>&1 &
N42_PID=$!

sleep 10 # wait for n42 to initialize

# install the contracts(deposit & exit)
cd tests/typescript/ && npm install &&
	PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 npx hardhat jest --network localdevnet && cd -

$MOBILE_SDK_TEST generate-credentials --number-of-validators 2 >v2.json
$MOBILE_SDK_TEST deposit-for-validators --deposit-private-key \
       	0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
	< v2.json

$MOBILE_SDK_TEST validate-for-validators < v2.json &
MOBILE_SDK_TEST_PID=$!
trap "kill $N42_PID $MOBILE_SDK_TEST_PID" EXIT

VALIDATOR_ADDR=`jq -r '.[0].withdrawal_address' <v2.json`

LIMIT=640
for (( i=1; i<=LIMIT; i++ )); do
BALANCE=`curl -X POST \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$VALIDATOR_ADDR\",\"latest\"],\"id\":1}" \
  $RPC_ADDR | jq -r '.result'`
echo $BALANCE
if (( "$BALANCE" > 300000 * 1000000000 )); then
	break
else
	sleep 4
fi
done

TOTAL_EFFECTIVE_BALANCE=`curl -X POST \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"consensusBeaconExt_get_total_effective_balance\",\"params\":[],\"id\":1}" \
  $RPC_ADDR | jq -r '.result'`
echo $TOTAL_EFFECTIVE_BALANCE
if (( "$TOTAL_EFFECTIVE_BALANCE" != 64000000000 )); then
	echo "error: total effective balance is incorrect"
	exit 1
fi

VALIDATOR_PUBLIC_KEY=`jq -r '.[0].validator_public_key' v2.json`
VALIDATOR_INFO=`curl -X POST \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"consensusBeaconExt_get_beacon_validator_by_pubkey\",\"params\":[\"$VALIDATOR_PUBLIC_KEY\"],\"id\":1}" \
  $RPC_ADDR`
ACTIVATION_TIMESTAMP=`echo $VALIDATOR_INFO | jq -r '.result.activation_timestamp'`
if (( "$ACTIVATION_TIMESTAMP" == 0 )); then
	echo "error: activation_timestamp is zero"
	exit 1
fi

$MOBILE_SDK_TEST exit-for-validators < v2.json
