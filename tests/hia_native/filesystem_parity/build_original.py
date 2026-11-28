"""Fresh pinned 1.95 build of the complete unchanged local Linux operations."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode = True
TOOL = Path.home()/'.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin'


def pin(path):
    with path.open('rb') as stream:
        return {'bytes': path.stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def dump(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False); stream.write('\n')


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    dump(args.output/'remote-process.json', {'pid': os.getpid(), 'cgroup': Path('/proc/self/cgroup').read_text(), 'argv': sys.argv})
    started = time.monotonic(); table = json.loads((args.source/'SOURCE-FILES.json').read_bytes())
    assert {name: pin(args.source/name) for name in table} == table
    # Compile and import only a fresh, fully enumerated copy of the pinned files.
    # Transport bookkeeping in the delivery directory is never a source input.
    verified = args.output/'verified-source'; verified.mkdir()
    for name in [*table, 'SOURCE-FILES.json']:
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        target = verified/relative; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.source/relative, target)
    assert {str(p.relative_to(verified)) for p in verified.rglob('*') if p.is_file()} == set(table)|{'SOURCE-FILES.json'}
    assert {name: pin(verified/name) for name in table} == table
    spec = importlib.util.spec_from_file_location('_filesystem_parity_original', verified/'verify_sources.py')
    original = importlib.util.module_from_spec(spec); spec.loader.exec_module(original)
    crate = args.output/'crate'; proof = original.materialize(verified, crate)
    dump(args.output/'SOURCE.json', proof)
    env = dict(os.environ, RUSTC=str(TOOL/'rustc'), CARGO_TARGET_DIR=str(args.output/'target'), CARGO_BUILD_JOBS='2')
    processes = []
    def run(name, command):
        begin = time.monotonic(); timed_out = False
        with (args.output/(name+'.stdout')).open('xb') as out, (args.output/(name+'.stderr')).open('xb') as err:
            process = subprocess.Popen(command, cwd=crate, env=env, stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, start_new_session=True)
            try: process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out = True; os.killpg(process.pid, signal.SIGKILL); process.wait()
        row = {'name': name, 'command': command, 'cwd': str(crate), 'pid': process.pid,
            'exit_code': process.returncode, 'timeout_seconds': 180, 'timed_out': timed_out,
            'elapsed_seconds': time.monotonic()-begin,
            'controlled_env': {name: env[name] for name in ('RUSTC', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS')},
            'stdin': None, 'stdout': pin(args.output/(name+'.stdout')), 'stderr': pin(args.output/(name+'.stderr'))}
        processes.append(row)
        (args.output/'processes.json').write_text(json.dumps(processes, sort_keys=True, indent=2)+'\n')
        assert not timed_out and process.returncode == 0, (name, row)
        return (args.output/(name+'.stdout')).read_bytes()
    version = run('rustc-version', [str(TOOL/'rustc'), '-Vv'])
    assert version.startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n')
    run('cargo-version', [str(TOOL/'cargo'), '-Vv'])
    frozen = {name: pin(crate/name) for name in ('Cargo.toml', 'Cargo.lock', 'src/main.rs')}
    run('locked-build', [str(TOOL/'cargo'), 'build', '--release', '--locked', '--manifest-path', str(crate/'Cargo.toml')])
    assert {name: pin(crate/name) for name in frozen} == frozen
    assert {name: pin(args.source/name) for name in table} == table
    assert {name: pin(verified/name) for name in table} == table
    info = json.loads((args.output/'target/.rustc_info.json').read_bytes())
    assert any(v.get('stdout', '').encode() == version for v in info['outputs'].values())
    binary = args.output/'target/release/hepta-filesystem-parity-original'
    result = {'schema': 'hepta.runtime.filesystem-parity-original-build.v1', 'status': 'PASS',
        'source': pin(args.output/'SOURCE.json'), 'source_table': pin(args.source/'SOURCE-FILES.json'),
        'source_files': table, 'materialized': frozen, 'binary': {'path': str(binary), **pin(binary)},
        'target_rustc_info': pin(args.output/'target/.rustc_info.json'), 'processes': pin(args.output/'processes.json'),
        'driver': pin(Path(__file__)), 'actual_processes': 3, 'fresh_locked_original_builds': 1,
        'actual_semantic_cases': 0, 'new_native_calls': 0, 'source_unchanged': True,
        'elapsed_seconds': time.monotonic()-started}
    dump(args.output/'RESULT.json', result); print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__': main()
