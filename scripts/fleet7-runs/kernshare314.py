#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Kernel share of a perf record when kernel symbols are hidden (kptr_restrict=1, no sudo): reads `perf script`
callchains and groups kernel-leaf samples by the outermost kernel frame (the entry point into the kernel) and by the
first user frame (who asked for it). usage: kernshare314.py <perf.data>"""
import subprocess, sys, re, collections
p = subprocess.Popen(['perf', 'script', '--no-inline', '-i', sys.argv[1], '-F', 'comm,ip,sym'], stdout=subprocess.PIPE, text=True, errors='replace')
KERN = re.compile(r'^\s+ffffffff[0-9a-f]{8}\b')
def fam(c):
    c = re.sub(r'[-_:]?\d+$', '', c.strip()) or '?'
    return c
tot = 0; kern = 0
byfam = collections.Counter(); kfam = collections.Counter()
entry = collections.Counter(); entry_user = collections.defaultdict(collections.Counter); leaf = collections.Counter(); leaf_user = collections.defaultdict(collections.Counter)
def flush(comm, frames):
    global tot, kern
    if not frames: return
    tot += 1; f = fam(comm); byfam[f] += 1
    if not KERN.match(frames[0]): return
    kern += 1; kfam[f] += 1
    ks = [x for x in frames if KERN.match(x)]; us = [x for x in frames if not KERN.match(x)]
    e = ks[-1].split()[0]; l = frames[0].split()[0]
    u = us[0].strip().split(None, 1)[1][:80] if us and len(us[0].split()) > 1 else '(none)'
    entry[e] += 1; entry_user[e][u] += 1; leaf[l] += 1; leaf_user[l][u] += 1
comm = None; frames = []
for line in p.stdout:
    if not line.strip():
        flush(comm, frames); comm = None; frames = []; continue
    if not line.startswith('\t') and not line.startswith(' '):
        flush(comm, frames); frames = []; comm = line.strip(); continue
    frames.append(line.rstrip())
flush(comm, frames)
print(f'{sys.argv[1]}: {tot} samples, kernel-leaf {kern} = {100*kern/tot:.1f}%')
print('share of samples by thread family (all / kernel-leaf):')
for f, n in byfam.most_common(12): print(f'  {f:22s} {100*n/tot:5.1f}%  kernel {100*kfam[f]/n:5.1f}% of the family  ({100*kfam[f]/tot:.1f}% of all samples)')
print('kernel entry frames (outermost kernel frame), share of ALL samples; first user frames:')
for e, n in entry.most_common(6):
    print(f'  {e}  {100*n/tot:5.2f}%  ' + '; '.join(f'{u[:60]} {100*c/n:.0f}%' for u, c in entry_user[e].most_common(4)))
print('kernel leaf addresses, share of ALL samples; first user frames:')
for e, n in leaf.most_common(8):
    print(f'  {e}  {100*n/tot:5.2f}%  ' + '; '.join(f'{u[:60]} {100*c/n:.0f}%' for u, c in leaf_user[e].most_common(3)))
