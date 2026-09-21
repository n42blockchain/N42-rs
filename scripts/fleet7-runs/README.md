# fleet7 runners (plan v4 campaign)

The runners that produced every number in `docs/FLEET7_PLAN_V4.md` and section 9 of `docs/FLEET7_PATH_AUDIT.md`,
kept as they ran. They are working files, not tools: each one's header says what it asked, what would falsify it, and
which legs it ran; `results/loopNNN.out` is what it printed. They live in `target/fleet-runs/` while a campaign is on
(paths inside them say so) and are copied here at a checkpoint.

What a runner does, in order: checks the working tree carries the code it measures; runs the touched crates' tests and
clippy; builds release binaries into `target/deferred`; only then waits for a quiet box and claims it
(`/data/blockchain/wr-logs/BOX-CLAIM-PROTOCOL.md`); runs its legs through `scripts/fleet7-bench.sh`, each under a
timeout, with a memory sampler beside it; scrapes metrics, compares the seven nodes' chains
(`scripts/fleet7-verify.py`), prints the windows and a line of counters; stops after 75 minutes of claim; releases the
box and kills its fleet on any exit.

| Runner | Question | Plan section |
| --- | --- | --- |
| run-loop170..181 | graft representation, direct receipts, pools, ceilings table | audit doc section 9 |
| run-loop182..189 | decay = memory squeeze; steps 1-2; fee cap; persistence; defect 10; step 2 dropped; the cycle dissected | 2b-2i |
| run-loop190 | `check_includable` in one pass; `N42_BODY_ONCE` | 2j |
| run-loop191 | `N42_COMMIT_FCU_ASYNC` | 2j |
| run-loop192 | cancelled before its claim (superseded) | -- |
| run-loop193 | `N42_BUILD_CHAIN` | 2k |
| run-loop194 | the chain's refusals fixed; the pool's size | 2l |
| run-loop195 | `N42_COMPACT_BODY`, first build | 2m |
| run-loop196 | compact body, second build; warm-up leg first | 2n |
| run-loop197 | flood workers 64 / 128 / 192: more supply is a slower chain | 2o |
| run-loop198 | per-thread-name CPU of every node (`threadcpu.py`) | 2o |

Tools: `dissect190.py <bench-dir>...` rebuilds a leg's window-1 cycle from the seven nodes' logs (segments A-F that sum
to the cycle, and the followers' vote road); `threadcpu.py <seconds>` samples per-thread-name CPU of the fleet's
processes; `decay.py` reads per-window phase medians; `heap-read.py` parses a jemalloc heap profile.

Two rules the campaign paid for: a runner's counters over a whole leg mislead (judge window 1 by the dissection), and a
round's first leg is not comparable with the rest (what the build left in the page cache decides it) -- run a warm-up
leg first and alternate the configurations.
