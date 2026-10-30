"""Reproduce pinned upstream KZG tests in Foundry; never starts an N42 node."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time

COMMIT = 'a8a647d83366f1bb7d2ea683236c01fc7b53b374'


def run(output, forge):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='n42-kzg-reference-') as directory:
        root = Path(directory)
        subprocess.run(['git', 'clone', '--quiet', 'https://github.com/markolazic01/blober.git', str(root)], check=True)
        subprocess.run(['git', 'checkout', '--quiet', COMMIT], cwd=root, check=True)
        subprocess.run(['git', 'submodule', 'update', '--init', '--recursive'], cwd=root, check=True)
        started = time.monotonic()
        with (output / 'reference-tests.log').open('w') as log:
            subprocess.run([forge, 'test'], cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
        source = root / 'benchmarks/test/Compare.t.sol'
        text = source.read_text()
        start = text.index('uint256[16] internal SWEEP')
        end = text.index(';', start) + 1
        text = text[:start] + 'uint256[100] internal SWEEP = [uint256(1), ' + ', '.join(map(str, range(2,101))) + '];' + text[end:]
        # Actual ABI encoding lengths, including offsets and padded dynamic bytes.
        extra = '''
    function test_calldata_lengths() public {
        string memory csv = "n,shared_bytes,general_bytes,single_blob_bytes\\n";
        for (uint256 n = 1; n <= 100; ++n) {
            uint256 shared = abi.encodeCall(BatchedVerifier.verifyBatchedMultiBlob,
                (_sliceBytes32(mbBlobHashes,n), mbZ, _sliceBytes32(mbY,n),
                 _sliceBytes(mbCommitmentsUncompressed,n), _sliceBytes(mbProofsUncompressed,n))).length;
            bytes32[] memory zs = new bytes32[](n);
            for (uint256 j; j<n; ++j) zs[j] = mbZ;
            uint256 general = abi.encodeCall(BatchedVerifier.verifyBatchedGeneral,
                (_sliceBytes32(mbBlobHashes,n), zs, _sliceBytes32(mbY,n),
                 _sliceBytes(mbCommitmentsUncompressed,n), _sliceBytes(mbProofsUncompressed,n))).length;
            uint256 single = abi.encodeCall(BatchedVerifier.verifyBatchedMultiPoint,
                (mpBlobHash, _sliceBytes32(mpZ,n), _sliceBytes32(mpY,n),
                 mpCommitmentUncompressed, _sliceBytes(mpProofsUncompressed,n))).length;
            csv = string.concat(csv, vm.toString(n), ",", vm.toString(shared), ",", vm.toString(general), ",", vm.toString(single), "\\n");
        }
        vm.writeFile("benchmarks/data/calldata_lengths.csv", csv);
    }
'''
        text = text[:text.rindex('}')] + extra + '}\n'
        source.write_text(text)
        env = dict(os.environ, FOUNDRY_PROFILE='benchmark')
        with (output / 'sweep.log').open('w') as log:
            subprocess.run([forge, 'test', '-vv'], cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        for name in ['synthetic_gas_multi_blob_one_point.csv', 'synthetic_gas_multi_blob_multi_point.csv',
                     'synthetic_gas_multi_point_one_blob.csv', 'calldata_lengths.csv']:
            shutil.copyfile(root / 'benchmarks/data' / name, output / name)
        patch = subprocess.check_output(['git', 'diff', '--', 'benchmarks/test/Compare.t.sol'], cwd=root)
        (output / 'reference-sweep.patch').write_bytes(patch)
        (output / 'manifest.json').write_text(json.dumps({
            'upstream': 'https://github.com/markolazic01/blober', 'commit': COMMIT,
            'environment': 'Foundry reference EVM, not N42 execution',
            'forge_version': subprocess.check_output([forge, '--version'], text=True),
            'wall_seconds_including_compilation': time.monotonic() - started,
            'n42_cpu_benchmark': None, 'n42_setup_equivalence': None,
            'error_batch_localization_cost': None,
        }, indent=2) + '\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--forge', default='forge')
    args = parser.parse_args()
    run(args.output.resolve(), args.forge)
