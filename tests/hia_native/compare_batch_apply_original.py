"""Fresh original batch owner and complete Rust Debug-domain qualification."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time
CHUNK = 1 << 20

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for value in iter(lambda: stream.read(CHUNK), b''):
            h.update(value)
    return h.hexdigest()

def raw_gzip(path):
    h = hashlib.sha256()
    size = 0
    lines = 0
    with gzip.open(path, 'rb') as stream:
        for value in iter(lambda: stream.read(CHUNK), b''):
            h.update(value)
            size += len(value)
            lines += value.count(b'\n')
    return {'sha256': h.hexdigest(), 'bytes': size, 'lines': lines}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.manifest.resolve().parent
    manifest = json.loads(args.manifest.read_bytes())
    assert manifest['schema'] == 'hepta.runtime.batch-apply-original-input.v1'
    assert manifest['kind'] == 'batch_apply' and manifest['cases'] == 14412
    args.output.mkdir(exist_ok=False)
    global _CREATED_OUTPUT
    _CREATED_OUTPUT = args.output
    before = {name: {'bytes': (root / name).stat().st_size, 'sha256': sha(root / name)} for name in manifest['files']}
    assert before == manifest['files']
    oracle = root / manifest['oracle']
    requests = root / manifest['requests']
    expected = root / manifest['expected']
    req_record = raw_gzip(requests)
    out_record = raw_gzip(expected)
    for record, prefix in [(req_record, 'requests'), (out_record, 'native_output')]:
        assert record['sha256'] == manifest[prefix + '_sha256'] and record['bytes'] == manifest[prefix + '_bytes']
    version = subprocess.run([str(args.rustc), '-Vv'], check=True, capture_output=True, timeout=10).stdout
    assert version.startswith(b'rustc 1.95.0 '), version
    environment = os.environ.copy()
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET'):
        environment.pop(key, None)
    original = (root / manifest['original_text_editing']).read_text()
    line_hash = (root / manifest['original_line_hash']).read_text()

    def section(raw, start, end):
        return raw[raw.index(start):raw.index(end)]
    blocks = {'batch_operation': section(original, '#[derive(Debug, Clone)]\nstruct BatchOperation', '// Unresolved batch operation'), 'operation_type_and_range': section(original, '#[derive(Debug, Clone, PartialEq)]\nenum OperationType', '#[derive(Debug, Clone)]\nenum UnresolvedLineRange'), 'editable_and_incoming': section(original, 'const LF_ENDING:', 'fn sanitize_incoming_content'), 'guards_and_apply': section(original, 'fn is_structural_noise', "// Parse an operation's `start`"), 'batch_guards': section(original, '\t// Check for conflicts between operations', '\n\tlet edited = apply_batch_operations'), 'line_ids': section(line_hash, 'fn fnv1a_8', '/// Verify a composite id')}
    source_text = oracle.read_text()
    original_blocks = json.loads((root / manifest['original_blocks']).read_bytes())
    assert {name: {'bytes': len(value.encode()), 'sha256': hashlib.sha256(value.encode()).hexdigest()} for name, value in blocks.items()} == original_blocks
    assert all((source_text.count(value) == 1 for value in blocks.values()))
    formatted = subprocess.run([str(args.rustc.with_name('rustfmt')), '--check', '--edition=2024', '--config', 'hard_tabs=true,max_width=100', str(oracle)], capture_output=True, timeout=10)
    (args.output / 'format.stdout').write_bytes(formatted.stdout)
    (args.output / 'format.stderr').write_bytes(formatted.stderr)
    assert formatted.returncode == 0, formatted.stdout.decode(errors='replace')
    binary = args.output / 'original-oracle'
    command = [str(args.rustc), '-O', '--edition=2024', str(oracle), '-o', str(binary)]
    compile_timeout = 60
    compile_run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=compile_timeout, env=environment)
    (args.output / 'compile.stdout').write_bytes(compile_run.stdout)
    (args.output / 'compile.stderr').write_bytes(compile_run.stderr)
    assert compile_run.returncode == 0, compile_run.stderr.decode(errors='replace')
    failures = []
    timed_out = threading.Event()
    sent = {'bytes': 0}
    request_hash = hashlib.sha256()
    start = time.monotonic()
    with (args.output / 'original.stderr').open('xb') as stderr:
        process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)

        def timeout():
            timed_out.set()
            process.kill()
        replay_timeout = 180
        timer = threading.Timer(replay_timeout, timeout)
        timer.start()

        def feed():
            try:
                with gzip.open(requests, 'rb') as stream:
                    for value in iter(lambda: stream.read(CHUNK), b''):
                        process.stdin.write(value)
                        request_hash.update(value)
                        sent['bytes'] += len(value)
                process.stdin.close()
            except BaseException as error:
                failures.append(repr(error))
                process.kill()
        writer = threading.Thread(target=feed)
        writer.start()
        output_hash = hashlib.sha256()
        size = 0
        lines = 0
        try:
            with gzip.open(expected, 'rb') as wanted, (args.output / 'original-output.gz').open('xb') as raw, gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0) as retained:
                for value in iter(lambda: process.stdout.read(CHUNK), b''):
                    assert wanted.read(len(value)) == value, ('original result differs', size)
                    retained.write(value)
                    output_hash.update(value)
                    size += len(value)
                    lines += value.count(b'\n')
                assert wanted.read(1) == b'', 'original output was truncated'
            writer.join(timeout=5)
            assert not writer.is_alive(), 'input writer did not finish'
            code = process.wait(timeout=5)
            assert code == 0 and (not timed_out.is_set()) and (not failures), (code, failures)
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            writer.join(timeout=5)
            process.stdout.close()
            if not process.stdin.closed:
                process.stdin.close()
    assert request_hash.hexdigest() == manifest['requests_sha256'] and sent['bytes'] == manifest['requests_bytes']
    assert output_hash.hexdigest() == manifest['native_output_sha256'] and size == manifest['native_output_bytes']
    summary_raw = (args.output / 'original.stderr').read_bytes()
    if manifest['kind'] == 'batch_apply':
        summary = json.loads(summary_raw)
        assert summary == {'status': 'PASS', 'rust_oracle_cases': manifest['cases'], 'output_bytes': size}
    else:
        assert summary_raw == b'' and lines == manifest['cases']
        summary = {'status': 'PASS', 'rust_oracle_cases': lines, 'output_bytes': size}
    debug_source = root / 'rust_debug_properties.rs'
    debug_binary = args.output / 'original-debug-properties'
    debug_command = [str(args.rustc), '-O', '--edition=2024', str(debug_source), '-o', str(debug_binary)]
    debug_compile = subprocess.run(debug_command, capture_output=True, timeout=60, env=environment)
    (args.output / 'debug-compile.stdout').write_bytes(debug_compile.stdout)
    (args.output / 'debug-compile.stderr').write_bytes(debug_compile.stderr)
    assert debug_compile.returncode == 0, debug_compile.stderr
    debug_run = subprocess.run([str(debug_binary)], capture_output=True, timeout=30, env=environment)
    (args.output / 'debug-original.stdout').write_bytes(debug_run.stdout)
    (args.output / 'debug-original.stderr').write_bytes(debug_run.stderr)
    assert debug_run.returncode == 0 and debug_run.stderr == b''
    debug = json.loads(debug_run.stdout)
    assert debug == json.loads((root / 'rust_debug_properties.json').read_bytes())
    assert debug['unicode'] == [17, 0, 0] and debug['scalars'] == 1112064 and debug['formatting_calls'] == 4448256
    flags = bytearray(0x110000)
    previous = -1
    for first, last, value in debug['ranges']:
        assert first == previous + 1 and first <= last <= 0x10ffff and value in (0, 15, 16)
        flags[first:last + 1] = bytes([value]) * (last - first + 1)
        previous = last
    assert previous == 0x10ffff and bytes(flags) == (root / 'native-debug-properties.bin').read_bytes()
    assert hashlib.sha256(flags).hexdigest() == '9f9925503f7b96a2f76aa3b14aace30332213a411d1df27f7dd11f083be40de0'
    after = {name: {'bytes': (root / name).stat().st_size, 'sha256': sha(root / name)} for name in manifest['files']}
    assert after == before
    result = {'schema': 'hepta.runtime.batch-apply-original-comparison.v1', 'status': 'PASS', 'kind': manifest['kind'], 'compile_command': command, 'compiler_version': version.decode(), 'compiler_sha256': sha(args.rustc), 'oracle_sha256': sha(oracle), 'binary_sha256': sha(binary), 'manifest_sha256': sha(args.manifest), 'driver_sha256': sha(Path(__file__)), 'native_source_sha256': manifest['source_sha256'], 'native_image_sha256': manifest['image_sha256'], 'requests_sha256': request_hash.hexdigest(), 'requests_bytes': sent['bytes'], 'output_sha256': output_hash.hexdigest(), 'output_bytes': size, 'cases': manifest['cases'], 'original_summary': summary, 'input_files': before, 'input_files_unchanged': True, 'elapsed_seconds': time.monotonic() - start, 'timeout_seconds': replay_timeout, 'timed_out': False}
    result['debug_reference'] = {'source_sha256': sha(debug_source), 'binary_sha256': sha(debug_binary),
        'compile_command': debug_command, 'output_sha256': hashlib.sha256(debug_run.stdout).hexdigest(),
        'native_flags_sha256': hashlib.sha256(flags).hexdigest(), 'codepoints': 1114112,
        'valid_scalars': 1112064, 'surrogates': 2048, 'target_format_comparisons': 4448256,
        'prefix_format_comparisons': 4448256, 'unicode': [17, 0, 0]}
    result['original_stderr_sha256'] = hashlib.sha256(summary_raw).hexdigest()
    result['original_stderr_bytes'] = len(summary_raw)
    result['original_runtime_calls'] = manifest['cases']
    result['original_rust_executions'] = 2
    result['native_calls_added'] = 0
    result['editable_source_sha256'] = manifest['editable_source_sha256']
    result['editable_image_sha256'] = manifest['editable_image_sha256']
    result['native_evidence_sha256'] = manifest['native_evidence_sha256']
    (args.output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))
_CREATED_OUTPUT = None
if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        if _CREATED_OUTPUT is not None:
            (_CREATED_OUTPUT / 'result.json').write_text(json.dumps({'schema': 'hepta.runtime.batch-apply-original-comparison.v1', 'status': 'FAIL', 'error': repr(error)}, indent=2, sort_keys=True) + '\n')
        raise
