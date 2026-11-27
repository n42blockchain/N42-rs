# AM33 draft: consecutive absent leaders (plan item E3) — for review by gov5, n42-26, n42-rs

Status: DRAFT, not adopted. Raised by gate 5d (2026-11-25): six consecutive absent leaders (views 57..62)
cost one 464 s gap (TC backoff 24/48/96/96/96/96 s at the gate's base 24 s / max 96 s). Liveness only;
safety was never at risk.

## Today's rule

SYNC §10.2: the view timeout is `min(base · 2^c, max)`, where `c` counts consecutive TCs since the last QC
(n42-rs `h2-consensus/src/protocol/pacemaker.rs`). With rotate-on-timeout (A22) each TC hands the view to the
next leader, but the exponent keeps growing across *different* dead leaders, so k consecutive absent leaders
cost `base + 2·base + max·(k−2)` once `2^c·base` hits `max`.

Exponential growth exists for one case: the network (or block execution) needs longer than `base` for any
leader to form a QC, so every view would time out forever at a fixed timeout. A run of absent leaders is a
different case: the next live leader forms a QC within `base`, and growth only delays it.

## Options

**O1 — grow once per f+1 TCs (recommended).** `timeout = min(base · 2^floor(c / (f+1)), max)` with
`f = floor((n−1)/3)`. A run of f+1 consecutive TCs without a QC means at least one leader in it was
honest and live (at most f are faulty) and still failed, which is the signature of the timing case; only
then does the timeout double.
- 5d (n = 100, f = 33): six absent leaders cost 6 · 24 = 144 s instead of 464 s. A worst-case run of 33
  absent leaders costs 33 · 24 s = 13.2 min, against roughly 52 min today.
- n = 4 (f = 1): 24, 24, 48, 48, 96, … instead of 24, 48, 96.
- Recovery from a real timing problem is slower by a factor of f+1 in the number of TCs before the
  timeout grows enough.
- Change: one line per client in the pacemaker, plus vectors for the sequence (gov5 fixture set). There
  is no wire or genesis change. Timeouts are local, so mixed clients only need the same rule for the
  M3 gates to be predictable; safety does not depend on it.

**O2 — leader order that interleaves operators.** This bounds the run length instead of its cost: with an
operator id per validator and a schedule that never puts two validators of one operator back to back, an
operator outage of m members produces m runs of length 1.
- It needs a genesis field (operator per validator), a new leader-schedule rule and vectors.
- It is a consensus-rule change activated at a fork. It does not help when the absent members span
  operators.

**O3 — skip leaders that recently timed out (reputation).** Rejected. Every member would need the same
view of who timed out, which is new agreed state, and a wrong skip costs liveness for an honest leader.

## Recommendation

Adopt O1 in v1.2, as an amendment to SYNC §10.2 with a vector set (sequences for n = 4, 7, 100, including
the AM32 epoch-boundary clamp case). Keep O2 as a design note for when operators become a genesis concept.
Gate: a mixed rerun of 5d with six consecutive absent leaders shows the gap ≤ 7 · base.

## Questions for the other clients

1. gov5: is `c` counted the same way as in n42-rs (reset only on a QC; a TC does not reset it)? AM32 says yes.
2. n42-26: same question; and does its pacemaker adapt `base` from observed latency? n42-rs does
   (`effective_base = max(base, 2·p95)`, capped at max). That is local, but it changes the numbers above.
3. All three: any objection to `f+1` as the group size, against a fixed constant such as 3?

## Review round 1 (2026-11-26)

gov5:
- `c` is counted per local view timeout. It resets on (a) a commit (the commit QC / Decide) and (b) a QC-based
  view jump while catching up. It ALSO resets on (c) a TC-based view jump taken from SyncInfo.
- Its pacemaker adapts `base` like n42-rs: `max(base, 2·p95 commit latency)`, capped at `max`.
- Group size: proposes `g = min(f+1, 3)`. With `f+1` alone, a real timing problem at n = 100 needs 34 TCs
  (~13.6 min) before the first doubling, and the adaptive base already covers a steadily slow network.
- O2 kept as a design note; O3 rejected.

n42-rs (checked in code):
- `RoundState::commit` resets `c` on the commit QC (`h2-consensus/src/protocol/round.rs`).
- The QC-based view jump resets it too (`state_machine.rs`, "QC-based view jump"). A TC never resets it.
  So n42-rs already has gov5's (a) and (b) and not (c).

Revised rule (proposed, pending n42-26):
- `timeout = min(base_eff · 2^floor(c / g), max)` with `g = min(f+1, 3)`, where `base_eff` is the local
  adaptive base.
- `c` increments on each local view timeout. It resets to 0 on a commit QC (two-phase HotStuff-2: "QC" in
  §10.2 means the commit QC / Decide) and on a QC-based view jump. A TC, including one embedded in SyncInfo,
  never resets it (gov5 drops (c)).
- Gate 5d's six absent leaders: 24·3 + 48·3 = 216 s, against 464 s today.
- gov5 produces the sequence vectors (n = 4, 7, 100, including the AM32 clamp) once n42-26 agrees.
