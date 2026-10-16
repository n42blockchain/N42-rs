# The build-ahead limit and the vote pace on X16

Read-only analysis of loop351 stage cb (BREAKTHROUGH_DESIGN 10.151): the X16 legs `bench-loop351D2S12P30T64X11T16Rl{b,a}`
(drain 4.580 / 4.515M/s) and the X15 controls `...R{a,b}` (4.365 / 4.373M/s), 600M set, 30 ms pacing, E=1. Window
T0 .. T0+88 s. Sources and joins as in docs/VOTE_BOUND_GAPS.md (its `parse.py`, `ana.py`, `cls.py`, `L.py`), plus
`sd.py` (start-delay classes from `sealed_at_ms`, `chain started` and `proposal sent`) and `sim2.py` / `sim3.py` (the
VOTE_BOUND replay extended with the serial root, the N-2 fields gate and three build-ahead rules); all kept outside the repo.

## 1. The answer in brief

* Mean gap 43.6 / 44.3 = `sealed_at` 34.6 + start delay 9.0 / 9.7. **84% of builds start 1.7 ms after the parent's seal;
  the 15% that do not are the one-ahead rule and carry 7.2 / 7.7 ms of the 9.0 / 9.7 mean.** A gated build waits for
  prop(N-1), and prop(N-1) is tick-bound in 87% of them: prop(N-2) came 11.6 ms after seal(N-1) (late itself, vote-bound),
  then prop(N-1) waits out the 30 ms tick. Gated delay 46.8 p50 / 48.7 mean.
* The vote pace is not L/4 = 32 ms. A vote is released by the **answer** of N-4 (seal -> answer L = 178 / 180 ms, not
  seal -> state ready 130), and the proposal follows 10.4 p50 / 12.7 mean after it: (L + c)/4 = 47.6 / 48.2 ms with no
  lead. The seal's lead over its proposal (27 ms mean) is what brings the real gap under that.
* The closed loop: prop(N) >= seal(N-4) + L + c, and the build may run at most k blocks ahead, so
  **gap >= (L + c + sealed_at + 1.7) / (5 + k)** = 226.8 / (5 + k): k = 0 today (drop) 45.4, k = 1 (`N42_BUILD_AHEAD_AT_SEAL=1`)
  37.8, k = 2 (two-ahead) 32.4. The same term explains the elastic start delay: under k = 0 a 1 ms seal cut buys 0.2 ms of gap.
* Two-ahead turns the start delay into overlap; the gap then sits on the **seal pace 36.3 and the serial QMDB root
  (36.7 + 1 ms between roots = 37.7)**, replayed at 39.8 / 40.4. **`N42_BUILD_AHEAD_AT_SEAL=1` alone (a knob: k = 1, still
  one ahead) replays at 41.5 / 42.2, -3.1 / -3.5 ms**, and is the first thing to run.

## 2. What binds each proposal, X16 against X14 (prop(N) = max(seal N, commit N-1, prop N-1 + 30) + slack)

| leg | seal: blocks / time | vote (commit N-1): blocks / time | tick: blocks / time | gaps > 80 ms (vote / seal) | lead prop - seal mean |
| --- | --- | --- | --- | --- | --- |
| Rlb (X16) | 8% / 9% | 41% / 54% | 51% / 37% | 114 / 3 | 26.9 |
| Rla (X16) | 8% / 9% | 40% / 53% | 52% / 37% | 120 / 9 | 27.9 |
| Ra / Rb (X15) | 15% / 18-19% | 40% / 50% | 45% / 31% | 95 / 31, 91 / 32 | 25.3 / 24.5 |
| Ma (X14, VOTE_BOUND) | 25% / 27% | 37% / 46% | 38% / 27% | 84 / 11 | |

The seal no longer binds proposals (8%); the vote does, over half the time. Vote-bound chain on Rlb, p50 (mean) ms:
answer(N-4) -> 4th follower vote on N-1 1.0 (2.2; 72% within 3 ms, 27% 6.5 ms later = the vote-log sync) -> prepare QC
2.0 (2.7) -> commit 2.9 (3.6) -> proposal 2.5 (4.2): prop(N) - answer(N-4) = 10.4 (12.7), Rla 10.3 (13.4). Followers are
not the bound (check 0.2 ms, the four votes inside 1 ms).

## 3. The start delay's anatomy (builds in the window)

| leg | builds | at parent seal (< 4 ms): share, delay mean, share of mean | gated, start after prop(N-1): share, delay p50 / mean, share of mean | prop(N-1) of gated: tick / vote | other |
| --- | --- | --- | --- | --- | --- |
| Rlb | 1,996 | 84%, 1.7, 1.41 | 15%, 46.8 / 48.7, **7.17** | 256 / 38 | 1%, 0.46 |
| Rla | 1,986 | 83%, 1.7, 1.38 | 15%, 48.1 / 50.5, **7.71** | 258 / 45 | 1%, 0.65 |
| Ra | 1,925 | 86%, 1.7, 1.44 | 13%, 47.3 / 50.6, 6.79 | 205 / 53 | 1%, 0.32 |
| Rb | 1,922 | 86%, 1.7, 1.44 | 13%, 45.1 / 47.2, 5.94 | 218 / 24 | 1%, 0.42 |

`proposal sent` agrees: `build_start_trigger` seal 1,690 / send 304 (Rlb). No gated build starts at prop(N-2): under the
default (`AheadGate::Send`, `defer_refused` off) `chain_start_decision` returns `Refuse` and the start is dropped, so the
build waits for the request after prop(N-1) -- one tick later than the bound itself requires. `N42_BUILD_AHEAD_AT_SEAL=1`
(`Defer`) starts it at N-1's take, i.e. prop(N-2) + ~0.8: the gated wait falls from ~48 to ~12 ms.

## 4. L after X15 / X16 (means, ms; X14 = Ma of VOTE_BOUND_GAPS on the 400M set)

| part | X14 Ma | X15 Ra / Rb | X16 Rlb / Rla | X16 - X14 |
| --- | --- | --- | --- | --- |
| seal -> bundle (shards ready) | 14.8 | 8.7 / 8.2 | 9.2 / 9.0 | **-5.7** (shards ready first) |
| bundle -> root start (waits for the previous root) | 13.2 | 27.0 / 28.8 | 24.0 / 24.8 | **+11.2** |
| root | 34.0 | 38.7 / 40.1 | 36.7 / 37.2 | +3.0 (state growth) |
| root end -> merge start | 2.5 | 3.0 / 2.4 | 2.1 / 2.1 | -0.4 |
| merge (state; reverts 0) | 54.8 | 57.5 / 55.5 | 58.1 / 59.0 | +3.7 |
| **seal -> state ready** | 119.5 | 134.8 / 135.2 | **130.2 / 132.3** | +11.8 |
| state ready -> handed | 18.6 | 16.1 / 16.4 | 15.2 / 14.7 | -3.6 |
| handed -> canonical | 5.8 | 4.4 / 3.9 | 4.8 / 4.8 | -1.0 |
| canonical -> answer | 28.1 | 27.1 / 26.0 | 27.6 / 27.8 | -0.4 |
| **L = seal -> answer** | 171.9 | 182.4 / 181.5 | **177.8 / 179.5** | +6.8 |

What moved: the faster seal moved the root's queue, not L's end. The roots are serial (utilisation 36.7 / 43.6 = 0.84), so a
bundle ready 5.7 ms sooner waits 11 ms longer for the previous root. L's tail after state ready (47.6 ms) is unchanged.

## 5. Could the leader build two ahead?

| constraint | where | forbids two-ahead? |
| --- | --- | --- |
| one chained build, "never two ahead" | `h2-el-rpc/src/engine.rs` `ChainState.slot`, `chain_start_decision` (`Send`: `Refuse`/`Defer` while the slot holds the sealed build) | yes, by policy; `AheadGate::Seal` already implements the second place (`ChainState::next`, `abandon_branch`, `drain_orphan`; `engine::ahead_gate_tests`) |
| deferred depth 2 (`MAX_DEFERRED_EXECUTION_DEPTH`, carried depth 2) | N's seal waits for N-2's fields (`parent_fields`), seal + 71.8 ms | no: it counts block numbers, not proposals; it is the seal-side floor (2 x pace >= 72 -> pace >= ~36), the same with any build-ahead rule. Depth 3 is a chain-spec and follower-check change |
| followers' vote rule (`holds_far_ahead`, `N42_FAR_AHEAD_BLOCKS=1`, `DEFERRED_IN_FLIGHT=2`) | `h2-node/src/service.rs`, `h2-execution/src/driver.rs` | no: followers see proposals in order and gate on their import height; the build ahead is leader-local |
| leader memory | `N42_BUILT_KEEP` default 3 ("in flight, ahead, finishing"), `N42_LEADER_LAYERS=6`, `OWN_HOLD_BLOCKS` 16 | not forbidden, but blocks sealed-and-unanswered = L / gap rises 4.0 -> 4.7: `BUILT_KEEP` 4-5 or hand-off evictions turn into 136 ms direct re-imports; 10.60 saw +7.7 GB EL peak with AT_SEAL |

A block built on an unproposed parent needs only what today's chained build uses: the parent's sealed header hash (at
seal), its output shards (seal + 9) and, for its own seal, N-1's fields (seal(N-1) + 72, already the rule). If N-1 fails
its QC (timeout, TC, tenure end -- one orphan per tenure today, two then), `abandon_branch` drains the slot and the build
behind it (`CHAIN_DRAIN` up to 3 s), and the queue returns the own transactions as for any uncommitted own block. Stage w
(10.104) broke exactly here on X7: `own_not_committed=3`, BODYGATE stop, a child started at the seal landing on a replaced
parent. That path has to be re-audited against the frame/plan-ahead/hand-off code before a leg.

## 6. The gap if the build never waits for the proposal (replay, mean gap ms; replay base reads +1.0 / +1.4 high)

| rule | Rlb | Rla | gated | lead |
| --- | --- | --- | --- | --- |
| today (drop, k = 0) | 44.6 | 45.7 | 15% | 27 |
| `N42_BUILD_AHEAD_AT_SEAL=1` (k = 1) | **41.5** | **42.2** | 42-47% (at prop N-2) | 38-40 |
| same, `sealed_at` +2 (elastic) | 41.7 | 42.4 | | |
| two-ahead (`N42_BUILD_AHEAD_GATE=seal` + AT_SEAL, k = 2) | **39.8** | **40.4** | 8-10% | 48-50 |
| two-ahead, `sealed_at` +3 | 40.2 | 40.7 | | |
| free build (no limit) | 39.7 | 40.3 | 0% | 49-52 |
| free, without the serial root / fields gate | 36.3 | 36.2 | 0% | 72-82 |
| five-block window, `sealed_at` +5 as measured in 10.149 | 41.0 | 41.6 | 2-3% | 9-10 |
| `sealed_at` -8 (X15_BUILD_NEXT cuts) under today's rule | 43.7 | 44.6 | 20-22% | |
| AT_SEAL + root -8 (dirty twigs + pre-gate hashes) | 39.1 | 39.8 | | |
| two-ahead + root -8 + `sealed_at` -8 + answer at insert | 34.4 | 35.1 | | |

The two numbers asked for: **seal pace 36.3 / 36.2 ms** (34.6 + 1.7), with the root as its partner floor at 37.7 / 38.2;
**vote pace 47.6 / 48.2 ms** at zero lead, 32.4 / 32.7 once two blocks may be built ahead. Free building reaches 39.7, not
36.3, because of the serial root: with two-ahead the root becomes the floor, and the root cuts in flight count in full.
Caveat: the replay predicted the five-block window as a gain, and 10.149 measured -3.5%; it misses costs that grow with
blocks in flight (pruner, lanes lock, memory), so its build-ahead numbers are upper bounds on the gain.

## 7. The vote side (question 3)

The vote loop binds today, not the seal. To make it non-binding at a 40 ms gap under k = 0 it needs
L <= 5 x 40 - 12.7 - 34.6 - 1.7 = 151, i.e. **L -27** (answer at insert -20 is not enough alone; replay "drop, L -27" 41.1).
Under k = 1 the budget is L <= 191 (met, 13 ms spare; at a 36 ms gap L <= 167, -11: AAI covers it); under k = 2, L <= 231.
The five-block window buys the same denominator as AT_SEAL (6) but on the followers' side, with `N42_PARENT_OUTPUTS_KEPT=6`
and the +5 ms seal that lost 10.149; making it cheap first needs the cause split (one leg F2 at `KEPT=5`, read `sealed_at`,
`view_journal_searches`, `open_layers`). AT_SEAL gets the denominator without touching the followers, so the window waits.

## 8. Options, ranked

| rank | option | mean gap (replay) | risk | size | proof counters (`sd.py`, `cls.py`, `L.py` on the legs) |
| --- | --- | --- | --- | --- | --- |
| 1 | `N42_BUILD_AHEAD_AT_SEAL=1` on X16 | -3.1..-3.5 (to ~40.5-41 measured) | low: knob, one ahead kept; 0 correctness counters in loop307/312; memory +7.7 GB there | knob | gated-after-prop(N-1) 15% -> ~0, gated delay ~48 -> ~12, lead 27 -> ~38, vote-bound time 54% -> < 40%, `sealed_at` mean <= +2, EL peak RSS, `own block at this height was not the one committed` 0 |
| 2 | root cuts in flight (`N42_ROOT_UPPER_DIRTY=1 N42_ROOT_OPS_BEFORE_GATE=1`) stacked on 1 | -2.4 more (39.1 / 39.8) | as stage cc | knob | root mean 36.7 -> <= 29, bundle -> root start 24 -> <= 12, `parent_fields_us` mean <= 2 |
| 3 | answer at insert (`N42_ANSWER_AT_INSERT=1`) on 1 | -1.2 (40.3 / 40.9) | medium: 10.116 lost with MS beside it; alone not yet on X16 | knob | canonical -> answer 27.6 -> <= 8, L 178 -> <= 158 |
| 4 | two-ahead (`N42_BUILD_AHEAD_GATE=seal` + AT_SEAL + `N42_BUILT_KEEP=5`) | -4.8..-5.3 alone; with 2 + seal cuts + 3: 34.4-35.1 | high: stage w broke (`own_not_committed=3`, BODYGATE); the orphan path re-audited first; two orphans per tenure | small code audit + knobs | lead -> ~48, gated < 10%, `previous build on the same parent was not committed`, BODYGATE 0, hand-off evictions / direct imports 0, drain waits |
| 5 | five-block window | -3.6 replay, -3.5% measured (10.149) | medium: seal +5 | knobs + diagnosis | `sealed_at` unchanged against control is the gate |
| -- | seal-side cuts (`N42_PLAN_BODY_WAIT_MS`, work stealing) under today's rule | -0.9 for -8 | | | worth their full value only after 1 / 4 |

Order: 1 (two legs against two X16 controls, drain-rate scored), then 2 and 3 on top; 4 only once the gap reads ~40 with
1-3 and the root, not the vote, binds.
