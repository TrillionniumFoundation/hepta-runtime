"""Build and capture the fixed original after independent native capture."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
REFERENCE_INPUTS = {'tests/hia_native/filesystem_parity/build_original.py': {'bytes': 5257, 'sha256': 'e084459b40ebe481a52ab7a507495d962c8d6d8e6476e5fe45900d6123b4c4f8'}, 'tests/hia_native/filesystem_parity/cases.py': {'bytes': 12031, 'sha256': 'f2d3efb4e3da4a800206c018908bd5999a6d14b31dc8a7dd81a502413111dedb'}, 'tests/hia_native/filesystem_parity/oracle/Cargo.lock': {'bytes': 597, 'sha256': 'e7acd632c5eeaeb67f4f856bde6e477991f579e4bab51e81a0afd315f501b2cf'}, 'tests/hia_native/filesystem_parity/oracle/Cargo.toml': {'bytes': 176, 'sha256': '07f7c97663b67b7086f9ded2a89ad1d5febe54849f4a5449f12e6622cb5789ff'}, 'tests/hia_native/filesystem_parity/oracle/SOURCE-FILES.json': {'bytes': 774, 'sha256': '679dbefd1cc0fd15da6f3f2daf31171ba630689f4f2adcb752fb83f698dbece8'}, 'tests/hia_native/filesystem_parity/oracle/original-runtime.lock': {'bytes': 90148, 'sha256': '7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43'}, 'tests/hia_native/filesystem_parity/oracle/original_parity_ops.rs': {'bytes': 11952, 'sha256': '0e608303d16c22b95dc99bae2e6bb00ba0571872f52d15a7fe8e2f021286ccc1'}, 'tests/hia_native/filesystem_parity/oracle/src/driver.rs': {'bytes': 4316, 'sha256': 'f093a78aa751f1f7702fe7e06bd11ef6e777dc687c04e00389d0c16122cc0d7c'}, 'tests/hia_native/filesystem_parity/oracle/verify_sources.py': {'bytes': 2398, 'sha256': '6aa7438a71bd1913b7fa347d1a05b424c05ec33d1601c2306dab5faf0536a776'}, 'tests/hia_native/filesystem_parity/replay_original.py': {'bytes': 18199, 'sha256': 'f46faf9747aa13c4ea5b1188c3a19fe1d8d1afb5befab3fc4d129da1506b3950'}, 'tests/hia_native/filesystem_parity/strict_reference.py': {'bytes': 50568, 'sha256': '0e245abf82475988d91d4e3979fac733ed4d2a32ea631a6ac58cd8fbfda9a159'}}


def pin(path):
    with path.open('rb') as stream:
        return {'bytes': path.stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def dump(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser()
    for name in ('source-root', 'native-capture', 'output', 'cross-root'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--source-manifest-sha256')
    args = parser.parse_args()
    args.source_root = args.source_root.absolute()
    args.output = args.output.absolute()
    source_table = args.source_root/'SOURCE-FILES.json' if args.source_manifest_sha256 else None
    if source_table is not None:
        assert pin(source_table)['sha256'] == args.source_manifest_sha256
        table = json.loads(source_table.read_bytes())
        assert {name: table[name] for name in REFERENCE_INPUTS} == REFERENCE_INPUTS
    else:
        table = REFERENCE_INPUTS
    recipe_pin = pin(Path(__file__))
    def recheck():
        for relative, identity in table.items():
            name = Path(relative)
            assert not name.is_absolute() and '..' not in name.parts
            path = args.source_root/name
            assert path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1
            assert pin(path) == identity, relative
    recheck()
    native_path = args.native_capture/'NATIVE.json'
    native_pin = pin(native_path)
    native = json.loads(native_path.read_bytes())
    assert native['schema'] == 'hepta.runtime.filesystem-parity-native-only-capture.v1'
    assert native['status'] == 'PASS' and native['cases'] == 123 and native['actual_elf_processes'] == 8
    assert native['original_outputs_read'] is False and native['new_rust_processes'] == 0
    prior_umask = os.umask(0o077)
    args.output.mkdir(mode=0o700)
    dump(args.output/'remote-process.json', {'pid': os.getpid(), 'cgroup': Path('/proc/self/cgroup').read_text(), 'argv': sys.argv})
    started = time.monotonic()
    processes = []
    def run(name, command):
        begin = time.monotonic()
        stdout, stderr = args.output/(name+'.stdout'), args.output/(name+'.stderr')
        with stdout.open('xb') as out, stderr.open('xb') as err:
            child = subprocess.Popen(command, cwd=args.output, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
            timed_out = False
            try:
                code = child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGKILL)
                code = child.wait()
        row = dict(name=name, command=command, cwd=str(args.output), pid=child.pid,
                   timeout_seconds=180, timed_out=timed_out, exit_code=code,
                   elapsed_seconds=time.monotonic()-begin,
                   stdout=dict(path=stdout.name, **pin(stdout)), stderr=dict(path=stderr.name, **pin(stderr)))
        processes.append(row)
        assert not timed_out and code == 0, row
        return json.loads(stdout.read_bytes())
    try:
        tests = args.source_root/'tests/hia_native/filesystem_parity'
        oracle = tests/'oracle'
        oracle_table = json.loads((oracle/'SOURCE-FILES.json').read_bytes())
        original_source = args.output/'source'
        original_source.mkdir()
        for relative in (*oracle_table, 'SOURCE-FILES.json'):
            name = Path(relative)
            assert not name.is_absolute() and '..' not in name.parts
            source = oracle/name
            target = original_source/name
            assert source.is_file() and not source.is_symlink()
            if relative in oracle_table:
                assert pin(source) == oracle_table[relative]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for source_name, target_name in (('build_original.py', 'build_original_v2.py'),
                                         ('cases.py', 'cases.py'), ('replay_original.py', 'replay_original.py')):
            shutil.copyfile(tests/source_name, args.output/target_name)
        copied = {str(path.relative_to(args.output)): pin(path) for path in original_source.rglob('*') if path.is_file()}
        copied.update({name: pin(args.output/name) for name in ('build_original_v2.py', 'cases.py', 'replay_original.py')})
        build = run('fresh-original-build', [sys.executable, '-B', str(args.output/'build_original_v2.py'),
                    '--source', str(original_source), '--output', str(args.output/'build')])
        capture = run('original-capture', [sys.executable, '-B', str(args.output/'replay_original.py'),
                      '--build', str(args.output/'build'), '--cases', str(args.output/'cases.py'),
                      '--output', str(args.output/'captures-v1'), '--cross-root', str(args.cross_root)])
        evidence_path = args.output/'ORIGINAL-EVIDENCE.json'
        evidence = run('original-admission', [sys.executable, '-B', str(tests/'strict_reference.py'),
                       '--reference', str(args.output), '--capture', str(args.output/'captures-v1'),
                       '--output', str(evidence_path)])
        recheck()
        assert pin(native_path) == native_pin
        assert pin(Path(__file__)) == recipe_pin
        assert {relative: pin(args.output/relative) for relative in copied} == copied
        result = dict(schema='hepta.runtime.filesystem-parity-original-recipe.v2', status='PASS',
                      native_capture=dict(path=str(native_path), **native_pin), native_captured_before_original=True,
                      source_manifest=dict(path=str(source_table), **pin(source_table)) if source_table else None,
                      required_source_files=REFERENCE_INPUTS, recipe=dict(path=str(Path(__file__)), **recipe_pin),
                      source_files_unchanged=True,
                      original_source_files=copied, original_build=build, original_capture=capture,
                      original_evidence_summary=evidence, original_evidence=dict(path=evidence_path.name, **pin(evidence_path)),
                      actual_python_processes=len(processes), actual_rust_processes=build['actual_processes']+capture['replay_processes'],
                      fixed_rust_version='1.95.0', fresh_locked_original_builds=1, original_cases=capture['cases'],
                      new_native_calls=0, original_comparison_pending=True, public_filesystem_handlers_complete=False,
                      whole_runtime_replaced=False, elapsed_seconds=time.monotonic()-started)
        dump(args.output/'RESULT.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)
    except BaseException:
        dump(args.output/'FAILURE.json', dict(traceback=traceback.format_exc(), elapsed_seconds=time.monotonic()-started))
        raise
    finally:
        dump(args.output/'processes.json', processes)
        os.umask(prior_umask)


if __name__ == '__main__':
    main()
