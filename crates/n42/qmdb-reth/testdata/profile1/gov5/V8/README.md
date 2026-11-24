# V8 - profile-1 genesis vectors (gov5, partial)

Produced by gov5 branch feat/profile1 at 015bd9f6 (n42blockchain/N42-gov5).

Contents now:
- allowed-keys.json: the CLOSED key lists (standard AM12, P4) for config,
  config.hotstuff, config.hotstuff.committeePool and each validators[] entry,
  generated from params.Profile1AllowedKeys (gov5 test TestProfile1AllowedKeysFile
  keeps internal/testdata/profile1/allowed_keys.json equal to the code). Any other
  key refuses the genesis. blobSchedule is the only optional config key.
- refused/*.json: one case per file: {"case", "expectedError", "genesis"}.
  A client MUST refuse to start on "genesis"; "expectedError" is gov5's error
  substring (informative; other clients name the field their own way).
  Same files (bare genesis + refused/expected_errors.json) in gov5
  internal/testdata/profile1/refused, checked by TestProfile1RefusedGenesisVectors.

NOT here yet (owner decision AM17): genesis.json and hash.txt. The refused cases
are built from gov5's provisional standard-genesis fixture
(internal/testdata/profile1/standard_genesis.json: tenure 8, 6000/30000 ms,
interval 500 ms, epoch 200, gas 480M); those values are not final. Each case
changes exactly one thing, so its refusal does not depend on them.

Test validator keys (gov5 fixture, reused when genesis.json is cut):
BLS secret i (i = 0..3) = 0x00 || sha256("n42-profile1-test-validator-<i>")[1:]
(top byte zeroed so it is below the BLS12-381 group order), public key = the
48-byte compressed G1 point, address = last 20 bytes of keccak256(pubkey).
