"""Regression for active Reth patch discovery during upstream synchronization."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('reth_sync', Path(__file__).with_name('reth-sync.py'))
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class PatchDiscoveryTest(unittest.TestCase):
    def test_only_active_paths_are_synced_once(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                Path('Cargo.toml').write_text('''[patch.'https://github.com/paradigmxyz/reth.git']
# reth-evm = { path = "crates/evm" }
reth-provider = { path = "crates/provider" }
reth-provider-alias = { path = "crates/provider" }
reth-consensus = { git = "https://example.com/consensus" }
[patch.crates-io]
other = { path = "other" }
''')
                self.assertEqual(sync.patched_dirs(), ['crates/provider'])
            finally:
                os.chdir(original)

    def test_no_reth_patch_table_is_empty(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                Path('Cargo.toml').write_text('[workspace]\nmembers = []\n')
                self.assertEqual(sync.patched_dirs(), [])
            finally:
                os.chdir(original)


if __name__ == '__main__':
    unittest.main()
