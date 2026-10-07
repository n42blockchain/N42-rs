"""Regression tests for refusing misleading or stale fleet measurements."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[2]


class FleetGuards(unittest.TestCase):
    def test_verification_round_rejects_bypasses_before_launch(self):
        for mode, gateways in [('shard', ''), ('leader', ''), ('all', '0x01')]:
            with self.subTest(mode=mode, gateways=gateways), tempfile.TemporaryDirectory() as tmp:
                env = dict(os.environ, F7_ROOT=tmp, F7_REQUIRE_TX_VERIFY='1',
                           F7_SKIP_STALE_CHECK='1', N42_INGEST_VERIFY=mode,
                           N42_FRAME_GATEWAYS=gateways)
                result = subprocess.run(['bash', str(REPO / 'scripts/fleet7-bench.sh')],
                                        env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('F7_REQUIRE_TX_VERIFY=1 needs', result.stdout + result.stderr)
                self.assertFalse((Path(tmp) / 'node0').exists())

    def test_each_binary_and_shared_source_is_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'src' / 'checkout'
            (root / 'crates/tx/src').mkdir(parents=True)
            (root / 'bin').mkdir()
            (root / 'crates/n42/h2-node/examples').mkdir(parents=True)
            (root / 'built/examples').mkdir(parents=True)
            source = root / 'crates/tx/src/lib.rs'
            source.write_text('// transaction verifier\n')
            old = time.time() - 100
            os.utime(source, (old, old))
            binaries = [root / 'built/n42', root / 'built/examples/h2_validator',
                        root / 'built/examples/tx_flood']
            for binary in binaries:
                binary.write_text('#!/bin/sh\nexit 0\n')
                binary.chmod(0o755)
            # The checkout itself lives below /src/, which must not make
            # an unrelated example count as shared production source.
            (root / 'crates/n42/h2-node/examples/unrelated.rs').write_text('// example\n')
            env = dict(os.environ, AUDIT_FIXTURE=str(root), F7_SKIP_STALE_CHECK='0')
            command = ['bash', '-c', 'source "$1/scripts/fleet7-env.sh"; '
                       'REPO=$AUDIT_FIXTURE; F7_BIN=$REPO/built; f7_check_binary_fresh',
                       'guard', str(REPO)]
            self.assertEqual(subprocess.run(command, env=env, capture_output=True).returncode, 0)
            for binary in binaries:
                with self.subTest(binary=binary.name):
                    os.utime(binary, (old - 100, old - 100))
                    result = subprocess.run(command, env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(str(binary), result.stderr)
                    os.utime(binary, None)
            binaries[-1].unlink()
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('missing executable', result.stderr)


if __name__ == '__main__':
    unittest.main()
