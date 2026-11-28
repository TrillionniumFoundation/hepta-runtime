"""Targeted physical refusal controls and complete relocation; runs no Rust/HIA."""
from pathlib import Path
from collections import Counter
import argparse
import copy
import importlib.util
import json
import os
import shutil
import struct
import sys
import time
sys.dont_write_bytecode = True


def dump(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False); stream.write('\n')


def main():
    p = argparse.ArgumentParser()
    for name in ('reader', 'source', 'capture', 'output'): p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args(); a.output.mkdir(mode=0o700); started = time.monotonic()
    spec = importlib.util.spec_from_file_location('_guard_strict', a.reader)
    reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
    baseline = reader.reference_evidence(a.source, a.capture); controls = []; groups = Counter()
    baseline_hash = reader.sha(reader.canonical(baseline)); dump(a.output/'BASELINE.json', baseline)
    def reject(group, name, callback):
        try: callback()
        except (ValueError, AssertionError, OSError) as error:
            controls.append({'group': group, 'name': name, 'status': 'REJECTED', 'error_type': type(error).__name__, 'error': str(error)[:512]})
            groups[group] += 1
        else: raise AssertionError('not rejected: '+name)
    for name, raw in [('duplicate-key', b'{"x":1,"x":2}'), ('NaN', b'{"x":NaN}'),
                      ('positive-infinity', b'{"x":Infinity}'), ('negative-infinity', b'{"x":-Infinity}'), ('float-overflow', b'{"x":1e9999}')]:
        reject('typed-json', name, lambda raw=raw: reader.strict_json(raw))
    process_rows = reader.strict_json((a.capture/'processes.json').read_bytes()); actual = process_rows[3]
    old_capture = Path(actual['controlled_env']['CARGO_TARGET_DIR']).parent
    execution = reader.strict_json((a.capture/'SOURCE.json').read_bytes())['execution']
    old_fixture = Path(execution['fixture_root'])
    def mutate_process(change):
        row = copy.deepcopy(actual); change(row); reader.process(row, actual['command'], Path(actual['cwd']), old_capture, execution)
    receipt_changes = [
        ('missing-deadline', lambda row: row.pop('timeout_seconds')),
        ('changed-deadline', lambda row: row.update(timeout_seconds=300)),
        ('missing-timeout-state', lambda row: row.pop('timed_out')),
        ('actual-timeout', lambda row: row.update(timed_out=True)),
        ('start-error', lambda row: row.update(start_error='synthetic refusal')),
        ('boolean-exit', lambda row: row.update(exit_code=False)),
        ('nonzero-exit', lambda row: row.update(exit_code=1)),
        ('boolean-pid', lambda row: row.update(pid=True)),
        ('unfixed-rustc', lambda row: row['controlled_env'].update(RUSTC=str(Path(execution['rustc']).parent/'not-the-selected-rustc'))),
        ('wrong-cwd', lambda row: row.update(cwd='/tmp')),
        ('missing-locked', lambda row: row['command'].remove('--locked')),
        ('zero-elapsed', lambda row: row.update(elapsed_seconds=0))]
    for name, change in receipt_changes: reject('process-receipts', name, lambda change=change: mutate_process(change))
    parser = reader.load(a.source/'run.py', '_guard_capture_parser_control')
    factory = reader.load(a.source/'cases.py', '_guard_case_control')
    cases = factory.iter_cases(old_fixture); stdout = (a.capture/'original.stdout').read_bytes()
    stderr = (a.capture/'original.stderr').read_bytes(); trace = (a.capture/'original.strace').read_bytes()
    observations = parser.parse_output(stdout, cases); first = observations[0]['record']
    first_raw = stdout[:8]+struct.pack('<Q', 1)+stdout[first['offset']:first['offset']+first['bytes']]
    def word(raw, offset, value):
        changed = bytearray(raw); struct.pack_into('<Q', changed, offset, value); return bytes(changed)
    for name, raw in [('wrong-magic', b'X'+first_raw[1:]), ('wrong-count', word(first_raw, 8, 2)),
                      ('trailing-byte', first_raw+b'X'), ('impossible-status', word(first_raw, 32, 7)),
                      ('descriptor-leak', word(first_raw, 80, 5)), ('errno-without-presence', word(first_raw, 48, 13))]:
        reject('complete-output-frames', name, lambda raw=raw: parser.parse_output(raw, cases[:1]))
    def check_trace(raw):
        return reader.trace_evidence(raw, cases, stdout, stderr, old_fixture,
            old_capture/'target/release/hepta-directory-guard-original', observations)
    def replaced(raw, old, new):
        assert old in raw; return raw.replace(old, new, 1)
    truncated = next(line for line in trace.splitlines(keepends=True) if b'"...' in line)
    short_truncated = replaced(truncated, b'\\x71', b'')
    trace_changes = [
        ('filesystem-mutation', replaced(trace, b' readlink(', b' unlink(')),
        ('unparsed-trailing-line', trace+b'not a syscall\n'),
        ('unfinished-trace', trace[:-1]),
        ('marker-case-order', replaced(trace, b'\\x31\\x60\\xea', b'\\x31\\x61\\xea')),
        ('stdout-byte-mismatch', replaced(trace, b'\\x48\\x46\\x44\\x47\\x4f\\x30\\x30\\x31', b'\\x58\\x46\\x44\\x47\\x4f\\x30\\x30\\x31')),
        ('close-unowned-descriptor', replaced(trace, b' close(3)', b' close(9)')),
        ('descriptor-probe-write-mode', replaced(trace, b'O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY', b'O_WRONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY')),
        ('undeclared-truncation-length', replaced(trace, truncated, short_truncated))]
    for name, raw in trace_changes: reject('actual-trace-and-markers', name, lambda raw=raw: check_trace(raw))
    owned = a.output/'relocation-a'; roots = {'source': owned/'source', 'capture': owned/'capture'}
    for name, digest in baseline['artifact_sha256'].items():
        namespace, relative = name.split('/', 1); src = {'source': a.source, 'capture': a.capture}[namespace]/relative
        dst = roots[namespace]/relative; dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True); shutil.copy2(src, dst)
        assert reader.pin(dst) == {'bytes': baseline['artifact_bytes'][name], 'sha256': digest}
    assert not (roots['capture']/'fixtures').exists()
    relocated = reader.reference_evidence(roots['source'], roots['capture']); reader.same(relocated, baseline, 'first physical relocation differs')
    owned.rename(a.output/'relocation-b'); owned = a.output/'relocation-b'; roots = {'source': owned/'source', 'capture': owned/'capture'}
    moved = reader.reference_evidence(roots['source'], roots['capture']); reader.same(moved, baseline, 'second physical relocation differs')
    def admit(): return reader.reference_evidence(roots['source'], roots['capture'])
    def change_byte(group, name, namespace, relative):
        path = roots[namespace]/relative
        with path.open('r+b') as stream:
            stream.seek(-1, os.SEEK_END); offset = stream.tell(); old = stream.read(1); stream.seek(offset); stream.write(bytes([old[0]^1]))
        try: reject(group, name, admit)
        finally:
            with path.open('r+b') as stream: stream.seek(offset); stream.write(old)
    change_byte('frozen-source-and-paths', 'changed-original-guard-source', 'source', 'original/config.rs')
    change_byte('frozen-source-and-paths', 'changed-materialized-main', 'capture', 'crate/src/main.rs')
    change_byte('frozen-source-and-paths', 'changed-materialized-lock', 'capture', 'crate/Cargo.lock')
    path = roots['capture']/'rustc-version.stdout'; backup = path.with_name('rustc-version.retained')
    path.rename(backup); path.symlink_to(backup.name)
    try: reject('frozen-source-and-paths', 'internal-symlink-artifact', admit)
    finally: path.unlink(); backup.rename(path)
    link = a.output/'linked-source'; link.symlink_to(roots['source'], target_is_directory=True)
    try: reject('frozen-source-and-paths', 'symlink-source-root', lambda: reader.reference_evidence(link, roots['capture']))
    finally: link.unlink()
    for name, relative in [('input-tail', 'input.bin'), ('output-tail', 'original.stdout'), ('stderr-marker-tail', 'original.stderr'),
                           ('trace-tail', 'original.strace'), ('gzip-tail', 'original.stdout.gz')]:
        change_byte('complete-physical-streams', name, 'capture', relative)
    def changed_json(relative, change):
        path = roots['capture']/relative; result_path = roots['capture']/'RESULT.json'
        old, old_result = path.read_bytes(), result_path.read_bytes()
        value = reader.strict_json(old); change(value); path.write_bytes(reader.canonical(value))
        if relative != 'RESULT.json':
            report = reader.strict_json(old_result); actual_pin = reader.pin(path)
            if relative == 'target/.rustc_info.json': report['target_rustc_info'] = actual_pin
            else:
                report['artifact_sha256'][relative] = actual_pin['sha256']; report['artifact_bytes'][relative] = actual_pin['bytes']
            result_path.write_bytes(reader.canonical(report))
        try: admit()
        finally: path.write_bytes(old); result_path.write_bytes(old_result)
    physical_controls = [
        ('public-sdk-claim', 'RESULT.json', lambda value: value.update(public_sdk_executed=True)),
        ('wrong-case-count', 'RESULT.json', lambda value: value.update(cases=91)),
        ('repinned-missing-deadline', 'processes.json', lambda value: value[3].pop('timeout_seconds')),
        ('repinned-target-compiler', 'target/.rustc_info.json', lambda value: value.update(outputs={})),
        ('repinned-host-capability', 'HOST.json', lambda value: value.update(status=value['status'].replace('CapEff:\t0000000000000000', 'CapEff:\t0000000000000001')))]
    physical_controls += [
        ('repinned-toolchain-invocation', 'SOURCE.json', lambda value: value['execution'].update(rustc='/invalid/selected-rustc')),
        ('repinned-fixture-mode', 'SOURCE.json', lambda value: value['execution'].update(fixture_mode='foreign')),
        ('repinned-producer-without-source', 'remote-process.json', lambda value: value['argv'].remove('--root'))]
    for name, relative, change in physical_controls:
        reject('repinned-metadata', name, lambda relative=relative, change=change: changed_json(relative, change))
    change_byte('portable-toolchain', 'changed-actual-strace-binary', 'capture', 'toolchain/strace.bin')
    reader.same(admit(), baseline, 'restored evidence differs')
    reader.same(reader.reference_evidence(a.source, a.capture), baseline, 'original evidence modified')
    assert dict(groups) == {'typed-json': 5, 'process-receipts': 12, 'complete-output-frames': 6, 'actual-trace-and-markers': 8,
        'frozen-source-and-paths': 5, 'complete-physical-streams': 5, 'repinned-metadata': 8, 'portable-toolchain': 1}
    result = {'schema': 'hepta.runtime.directory-move-guard-reference-evidence-controls.v1', 'status': 'PASS',
        'groups': len(groups), 'refusal_controls': len(controls), 'group_counts': dict(groups), 'controls': controls,
        'physical_relocations': 2, 'relocation_objects_equal': True, 'original_evidence_unchanged': True, 'relocated_live_fixtures': 0,
        'baseline_canonical_sha256': baseline_hash, 'bound_artifacts': len(baseline['artifact_sha256']),
        'bound_artifact_bytes': sum(baseline['artifact_bytes'].values()), 'elapsed_seconds': time.monotonic()-started,
        'source_sha256': {str(path): reader.pin(path) for path in (Path(__file__).absolute(), a.reader.absolute())},
        'new_rust_processes': 0, 'new_native_calls': 0, 'filesystem_operations_under_test_executed': False}
    dump(a.output/'RESULT.json', result)
    print(json.dumps({key: value for key, value in result.items() if key not in ('controls', 'source_sha256')}, sort_keys=True))


if __name__ == '__main__': main()
