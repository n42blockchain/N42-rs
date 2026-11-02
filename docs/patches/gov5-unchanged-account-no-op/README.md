# gov5 patch: unchanged accounts write no state-root leaf (audit R3-E2)

`0001-fix-state-leave-accounts-a-block-did-not-change-out-.patch` is one gov5
commit (`bc048ef1`, branch `fix/unchanged-account-no-op` in the local worktree
`/data/n42-build/gov5-wt-e2`, **not pushed**) on top of gov5 `origin/main`
`ec04b3758fa0328e94a55522d6f62cd105166230`. It is waiting on the user's decision.

What it does: it adds `unchangedAccountNoOpTime` to gov5's chain config (nil means
the old rule). From that time on, `IntraBlockState.computeRootViaComputer` leaves
out of the root any account the block touched but did not change. HotStuff's
`Finalize` and replay-v2 set the rule from the block's time. Why: see
`docs/audit/2026-10-5m/R3_E2.md`.

To apply it:

```bash
cd <gov5 checkout at ec04b375 or later>
git am <n42-rs>/docs/patches/gov5-unchanged-account-no-op/0001-*.patch
go test ./modules/state/ -run 'TestUnchangedAccountNoOp|TestIsUnchangedAccountNoOp'
```

Activation: set `"unchangedAccountNoOpTime": <unix time>` in the genesis config of
every member of the chain, gov5 and n42-rs alike. n42-rs ignores the field
because it already follows the rule. An existing chain needs its gov5 nodes on
the patched binary before that time. For a base rebuilt with replay-v2, set the
time in the chain config the base is rebuilt under, at or before the base's
first block, then use the same time in the genesis the fleet runs.
