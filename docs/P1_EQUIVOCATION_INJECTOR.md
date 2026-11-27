# Equivocation injector (test only), for a mixed equivocation round

Plan item D2 (`docs/PLAN_P1_REMAINING_2026_11.md`): a mixed equivocation round needs a member
that deliberately signs two conflicting values in one view, with its real key, so that every
client's E15 detection (`docs/MIXED_PRODUCTION_STANDARD.md` E15, AM28) can be checked against
a real fault. The n42-rs HotStuff-2 validator (`h2_validator`) can now be that member.

## What it does

With the injector on, every message of the chosen kind the member sends in a chosen view
goes out as the engine signed it, followed by its **twin**: the same message naming another
block, signed again with the member's BLS key in the chain's signing domain. The twin's block is

    twin = keccak256("n42-test-equivocate/1" || block_hash)

so a record's `hash2` can be matched against the `hash1` it conflicts with, and the twin never
names a real block. Kinds:

| `<kind>` | What goes out twice | Sent to | Who can prove it |
| --- | --- | --- | --- |
| `vote` | Round-1 vote | the view's leader, the same way the real vote goes (consensus topic) | the leader of that view |
| `commit_vote` | Round-2 commit vote | as above | the leader of that view |
| `proposal` | proposal (only in views this member leads) | every peer, on the consensus topic | every follower |

The standard transport has no per-peer consensus send (`/n42/vote/1` is n42-rs only and not
standard, E16), so the twin proposal goes to every peer, after the real one; it does not split
the fleet into two halves. The twin proposal has no body: followers record the pair, never
vote for the twin, and nothing can import or commit it.

The member's own state does not change: no vote-log entry, no tracker, no collector. It keeps
voting honestly for the real block.

## Switches and guards

All three are required, or the validator does not start:

1. `N42_TEST_EQUIVOCATE=<kind>:<when>`: `<kind>` is `vote`, `commit_vote` or `proposal`;
   `<when>` is a view number (`vote:40`) or `every-<n>`, meaning every view divisible by n
   (`proposal:every-1` is every view the member leads).
2. The CLI flag `--test-equivocate`. Setting either one without the other is an error at
   startup, so a member that is only half configured cannot run as an honest member without
   anyone noticing.
3. The chain id must be one of 1143 (dev), 1144 (the profile-1 chain the mixed rounds run;
   no public network uses it), 1337 or 31337. Any other id is refused, including 94, 95,
   1142 and Ethereum's.

At startup it writes a `!!!` banner to stderr (`TEST EQUIVOCATION INJECTOR ON: ... this
validator WILL sign conflicting messages`) and logs an `ERROR` line from `n42.h2.node`.

Code: `crates/n42/h2-node/src/test_equivocate.rs` (configuration and guards),
`H2Service::with_test_equivocation` / `inject_equivocation` (`crates/n42/h2-node/src/service.rs`),
`ConsensusEngine::sign_equivocating_twin` (`crates/n42/h2-consensus/src/protocol/test_equivocation.rs`).

## Running it in a mixed round

Choose one **Rust** member as the equivocator. All other members, including gov5 and n42-26,
stay honest. Use a fleet of at least four members (f >= 1), so that the honest members reach
a quorum without the equivocator.

Add both switches to that member's `h2_validator` command line:

    N42_TEST_EQUIVOCATE=vote:every-1 h2_validator --chain <genesis> --index <i> ... --test-equivocate

With `scripts/devnet-fleet.sh` (plain members only, not the LATE/ABSENT member):

    EQUIVOCATE_VALIDATOR=2 EQUIVOCATE=commit_vote:every-1 scripts/devnet-fleet.sh <tag> <secs> [--gov5]

To get evidence of every kind, run one round per kind. `every-1` puts each honest member in
the position to prove a vote or commit vote whenever it leads, and gives a proposal pair in
every view the equivocator leads. A single view (`vote:40`) gives exactly one record, on one
member, and is easier to read.

Liveness: the twin goes out after the real message, but a peer may receive the twin first.
For a vote or commit vote, that peer then records the twin as the first message and drops
the real one, so the leader is left without the equivocator's vote. The quorum still forms
from the honest members. For a proposal, a follower that receives the twin first does not
vote for the real block in that view, which can cost a view timeout. If a round shows view
timeouts, use `every-<n>` with n larger than the set size.

## What each peer should log and serve

**The equivocator (n42-rs)**, for each twin it sends:

- `ERROR n42.h2.node: TEST EQUIVOCATION: sending a second signed message for this view kind=… view=… first=… second=… target=…`
- on stderr: `TEST EQUIVOCATION kind=<kind> view=<v> first=<hash> second=<twin>`
- the metric `n42_test_equivocations_injected_total{kind}` (with `--metrics`).

It records no evidence against itself.

**An honest n42-rs member** that receives a pair it can prove (it is the leader for a vote or
commit vote, or any follower for a proposal):

- `WARN n42::cl::voting: equivocation detected view=… validator=<i> kind=… hash1=… hash2=…`
- `WARN n42.h2.node: equivocation recorded kind=… view=… validator=<i> hash1=… hash2=…`
- one line in `<datadir>/equivocations.jsonl` per (kind, view, validator);
- `n42_equivocations_total` goes up by one per record (`--metrics`);
- `n42_equivocations` (`--rpc.http`) returns the record in AM28 form:
  `curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"n42_equivocations","params":[]}' http://<rpc.http>/`.
  Check that `validatorIndex` is the equivocator, `hash2` is
  `keccak256("n42-test-equivocate/1" || hash1)`, and `first` / `second` verify against
  `publicKey` (`EquivocationEvidence::verify`).

**gov5 and n42-26 members**: the same AM28 record over `n42_equivocations` and the
`n42_equivocations_total` metric, for each kind they implement. Status as of 2026-11-26
(`docs/MIXED_PRODUCTION_STATUS.md` E15, M3d): gov5 detects `vote` and `commit_vote`
(feat/p1-j2-e15). Its proposal-equivocation detection (M3d) is still open, so a gov5 follower
is not expected to record a `proposal` pair yet. That gap is what the `proposal` round
measures.

**Every member**, whichever kind is injected:

- **safety**: no two members commit different blocks at one height. Compare
  `eth_getBlockByNumber` hashes, or the validators' `COMMIT view=… block=…` lines, across
  members. No member commits a twin hash.
- **liveness**: the chain keeps committing through and after the injected views.
- the equivocator is not halted or disconnected. Profile 1 keeps evidence only and does not
  slash (O5).

## A detection gap found while building this (n42-rs, fixed on this branch)

A leader moves to the next view as soon as its CommitQC forms. Every commit vote that arrived
after that point was dropped as stale before the equivocation tracker saw it. That covers the
commit votes of members outside the quorum, and the second vote of a pair whose first vote
was counted. As a result, n42-rs never recorded a `commit_vote` pair in the four-member test
until this was changed. The leader now keeps, for the last 8 views it led, the verified
commit-vote tracker and the late commit votes as they arrived, without verifying them. It
checks signatures only when two commit votes from one voter conflict, so an honest late
commit vote costs one map insert. gov5 and n42-26 may have the same blind spot, and a mixed
`commit_vote` round shows whether they do. If a gov5 or n42-26 leader records nothing while
the n42-rs leaders do, look here first.

## Tests

- `cargo test -p n42-h2-consensus --lib test_equivocation`: a leader proves a double vote and a
  double commit vote (including the late commit vote, in both arrival orders), a follower
  proves a double proposal, and every pair verifies.
- `cargo test -p n42-h2-node --lib test_equivocate`: parsing, both switches, chain-id guard.
- `cargo test -p n42-h2-node --test equivocation_injector`: four `H2Service`s over a real
  gossip mesh on chain 1143, with member 3 equivocating each kind in every view. Every honest
  member persists self-verifying evidence naming member 3. No view commits two blocks, no twin
  is committed, and every honest member commits at least four more views after the first
  injection. The test also checks that the injector is refused on chain 94.
