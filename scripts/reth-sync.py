#!/usr/bin/env python3
"""Three-way merge of the vendored reth crates from one upstream revision to another.

    scripts/reth-sync.py <base-rev> <new-rev> [<dir>...]

For every file upstream changed between <base-rev> and <new-rev> under each
vendored directory, merges upstream's change onto this repo's copy with
`git merge-file` (base = upstream at <base-rev>, ours = this repo, theirs =
upstream at <new-rev>). Conflicts are left as markers and listed. Files only
upstream added are copied; files upstream deleted are deleted when this repo
had not touched them, and listed otherwise. Without directories, every
`path = "..."` in the reth patch table of Cargo.toml is synced.

Upstream is read from the checkout at ../reth, which must have <new-rev>.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

RETH = pathlib.Path(__file__).resolve().parents[1].parent / "reth"


def show(rev, path):
    r = subprocess.run(["git", "-C", RETH, "show", f"{rev}:{path}"], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def patched_dirs():
    text = pathlib.Path("Cargo.toml").read_text()
    table = text.split("[patch.'https://github.com/paradigmxyz/reth.git']", 1)[1].split("\n[", 1)[0]
    return re.findall(r'path\s*=\s*"([^"]+)"', table)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    base_rev, new_rev, dirs = sys.argv[1], sys.argv[2], sys.argv[3:] or patched_dirs()
    merged, added, deleted, kept, conflicts = [], [], [], [], []
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="reth-sync-"))
    for d in dirs:
        changed = subprocess.run(
            ["git", "-C", RETH, "diff", "--name-only", base_rev, new_rev, "--", d],
            capture_output=True, text=True, check=True,
        ).stdout.split()
        for f in changed:
            base, new = show(base_rev, f), show(new_rev, f)
            ours_path = pathlib.Path(f)
            ours = ours_path.read_bytes() if ours_path.exists() else None
            if new is None:
                if ours is None:
                    continue
                if ours == base:
                    ours_path.unlink()
                    deleted.append(f)
                else:
                    kept.append(f"{f} (deleted upstream, changed here)")
                continue
            if ours is None:
                if base is None:
                    ours_path.parent.mkdir(parents=True, exist_ok=True)
                    ours_path.write_bytes(new)
                    added.append(f)
                else:
                    kept.append(f"{f} (deleted here, changed upstream)")
                continue
            if base is None:
                base = b""
            if ours == base:
                ours_path.write_bytes(new)
                merged.append(f"{f} (fast-forward)")
                continue
            if ours == new:
                continue
            (tmp / "base").write_bytes(base)
            (tmp / "ours").write_bytes(ours)
            (tmp / "theirs").write_bytes(new)
            r = subprocess.run(
                ["git", "merge-file", "-p", "-L", "n42", "-L", base_rev[:9], "-L", new_rev,
                 tmp / "ours", tmp / "base", tmp / "theirs"],
                capture_output=True,
            )
            ours_path.write_bytes(r.stdout)
            (conflicts if r.returncode > 0 else merged).append(f"{f} ({r.returncode} conflicts)" if r.returncode > 0 else f)
    for title, items in (("merged", merged), ("added", added), ("deleted", deleted),
                         ("kept, look at these", kept), ("CONFLICTS", conflicts)):
        print(f"{title}: {len(items)}")
        for item in items:
            print(f"  {item}")


if __name__ == "__main__":
    main()
