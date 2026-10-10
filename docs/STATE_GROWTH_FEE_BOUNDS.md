# State growth and fee bounds: what bounds N42 today, against exponential EIP-1559 (2026-10-10)

Prompted by "The Economic Security of Exponential EIP-1559" (Berger, Felten, Fritsch,
arXiv 2610.10333, 2026-10-07). Research note, no code and no measurement. Numbers marked
(inferred) are arithmetic on the cited inputs, not measurements.

## 1. What N42 runs today

- **Base-fee rule.** Standard EIP-1559 as reth implements it: elasticity 2, change denominator 8
  (a full block raises the base fee 12.5%, an empty one lowers it 12.5%). No N42 fork of the
  rule was found in `crates/chainspec/src/spec.rs`. `scripts/fleet7-bench.sh` (lines 19, 42-44)
  states the 12.5% figure and the 480M limit / 240M target.
- **`baseFeeUpdateFraction`** appears in `n42_fleet7.json`, `n42_fleet7_bench.json` and
  `n42_devnet.json` only inside `blobSchedule` (3338477 Cancun, 5007716 Prague/Osaka). That is
  the exponential rule of EIP-4844 and applies to the blob fee only, not to the gas base fee.
- **Genesis `baseFeePerGas`:** `n42_devnet.json` 0x3b9aca00 (1 gwei). Absent from `n42_fleet7.json`
  and `n42_fleet7_bench.json` (reth default applies; the bench starts near ~800 wei, per the
  comment at `scripts/fleet7-bench.sh` line 51).
- **Gas limit:** `n42_fleet7.json` and `n42_devnet.json` 0x1c9c380 = 30,000,000;
  `n42_fleet7_bench.json` 0x1c9c3800 = 480,000,000. `period` is 3 (fleet7, devnet) and 1
  (bench); the bench paces at 350 ms via `F7_BLOCK_INTERVAL_MS` (CLAUDE.md).
- **Bench-only base-fee decay.** `scripts/fleet7-bench.sh` (lines ~344-385, `DECAY_SEC=30`, `read_basefee`)
  runs empty blocks until the base fee falls to a target before flooding, and the flood uses a
  fee cap of 1e14 wei (`GASPRICE`) so full blocks do not price it out. It is a test-harness
  step; nothing in the chain or genesis does this. Consequence: bench fees are near zero by
  construction, so the bench says nothing about the fee cost of state growth.
- **State-creation gas.** No genesis file sets `amsterdamTime`; Amsterdam is switched on only by
  `F7_AMSTERDAM=1` in the bench script (lines 177, 203). Without it, a transfer that creates its
  recipient costs the plain 21,000 gas (inferred from the Cancun/Prague rules). With Amsterdam,
  EIP-8037 applies: a creating transfer used 204,600 gas and needs ~207k limit (memory note
  `amsterdam-eip8037-gas`, measured 2026-09-01; no repo doc records it, only
  `docs/FLEET7_HANDOFF.md` line 159 mentions EIP-8037 as a known gap).
- **Accounts per block (measured).** The bench creates ~14,000 new accounts per full block (~9%) and a
  full 163k-tx block touches ~147,000 (`docs/BLOCK_SHAPE_SURVEY.md`, lines 8-9, 80-83).

## 2. Does the paper's guarantee apply

From the arXiv abstract (the intro and the formal theorem were not available to me, so the
classic-vs-exponential comparison below is from general knowledge, not the page):
the paper asks for parameters that guarantee a lower bound on total fees whenever usage in a window
exceeds a threshold, characterises the revenue-minimising usage distribution for the pure
exponential rule (Ethereum's blob fee), constructs a near-minimising distribution for a variant
(Robinhood Chain, Arbitrum), and ties the bound to goals such as limiting state growth.

- Classic rule: base fee changes by at most 1/8 per block, proportionally to the deviation from
  target, linearly in that deviation. Alternating full and empty blocks leave the fee about flat
  (+12.5% then -12.5% is ~-1.6% net), so an adversary using 100% of the limit every other block
  averages 50% of the limit, exactly at target, while paying roughly the current base fee
  and never driving it up. That is the known weakness; the paper's point is that the exponential rule
  closes it by making the fee a function of cumulative excess usage.
- **N42 runs the classic (linear-step) rule for gas.** The exponential rule exists in the repo only for
  blobs. So the paper's tight minimum-payment bound does not apply to gas on N42; only the
  per-block 12.5% step limit and the one-block-at-a-time argument do (inferred).
- Even with an exponential rule, a bound is in fees (wei), not bytes. Whether it deters state
  growth depends on the gas price of state creation (section 3).

## 3. Back-of-envelope state growth bound

Assumptions: every block is full of transactions that each create one new account (the cheapest
state-growth transaction; real cost may be lower with contract storage). Bytes per account: the
QMDB leaf value is gov5's `StateAccount.MarshalV2` (at most ~1+10+33+32 = 76 bytes; real
value length 72 in `crates/n42/twig-core/src/simd.rs` line 813) plus key and tree overhead that I could not find
documented. **Placeholder: 100 bytes/account (labelled, not measured).** Measured QMDB bytes/account
would replace it.

| chain config | gas/block | gas per new account | blocks/day | accounts/block | accounts/day | GB/day at 100 B |
| --- | --- | --- | --- | --- | --- | --- |
| fleet7, 3 s, pre-Amsterdam | 30M | 21,000 | 28,800 | 1,428 | 41.1M | 4.1 |
| fleet7, 3 s, Amsterdam | 30M | ~205,000 | 28,800 | 146 | 4.2M | 0.42 |
| bench, 350 ms, pre-Amsterdam | 480M | 21,000 | 246,857 | 22,857 | 5.64B | 564 |
| bench, 350 ms, Amsterdam | 480M | ~205,000 | 246,857 | 2,341 | 578M | 57.8 |

All rows inferred. The bench rows are a ceiling the hardware does not reach (the bench measured ~14k
new accounts per block, ~9% of a full block, and a 0.4+ s cycle); they show the protocol bound, not
what the fleet can do. A bound in dollars needs the base fee: at the bench floor (~800 wei) a
21,000-gas account costs ~1.7e-5 gwei-scale, effectively free (inferred).

## 4. Experiment design (not run)

Loads, each over 1, 7 and 30 simulated days (compress with block interval 1 s on a fresh
`fleet7-bench.sh` datadir; one day is 86,400 blocks, so 30 days needs the 350 ms bench or a long
run; state the compression factor):
- **Uniform:** `examples/tx_flood` at a constant creating rate, e.g. 50% of the gas limit.
- **Burst:** 100% of the limit for 10% of the time, idle otherwise (same average).
- **Intermittent:** full/empty alternation block by block (the classic weakness), same 50% average.

Run each with a realistic gas price (not the 1e14 cap), and with the decay step disabled so the base
fee evolves as it would on a live chain. Pick Amsterdam on and off as a second axis.

Record per run: total fees paid and average price per created account; QMDB net growth
(bytes on disk and live entries, `n42-qmdb-export` count); write amplification (bytes
written per byte of net growth, from the persistence timers `save_blocks_*`); fresh-node sync
time and snapshot size (`n42-init-snapshot export`, `LATE_VALIDATOR`/`LATE_SNAPSHOT` in
`scripts/devnet-fleet.sh`).

The current rule is insufficient if: the intermittent load creates the same accounts per day as the
uniform load while paying clearly less per account (fee per account falls toward the base-fee floor
instead of rising); or if the cost of an account at the floor price stays below an agreed state-cost target
(a budget in GB/year chosen by the operators); or sync time of a fresh node exceeds the chosen limit.

## 5. Recommendation

1. Do not change the update rule yet: nothing here shows a state-growth problem, only that N42 has
   no minimum-payment bound for gas.
2. First get a measured bytes-per-account figure and the Amsterdam decision (EIP-8037 is a 10x
   state-creation price the chain gets as baggage; it is the only existing price on creation).
3. Run the section 4 intermittent-vs-uniform experiment; it needs no code beyond scripts.
4. If the intermittent load wins by a wide margin, prefer a state-creation quota or a gas price
   on creation (EIP-8037-style) over a rule change, because the paper's bound is in fees and
   depends on how the price relates to the bytes; a quota bounds bytes directly.
5. If an exponential gas rule is still wanted, take the paper's parameter guidance (full text needed).
