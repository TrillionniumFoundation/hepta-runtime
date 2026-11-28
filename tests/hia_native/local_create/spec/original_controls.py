"""Refuse incomplete or altered fresh target-Rust full Local comparisons."""
import copy
import gzip
from pathlib import Path
import struct
import zlib


def run(output, report, rustc, q, source_root):
    output, source_root = Path(output), Path(source_root)
    c = q.driver('controls.py'); counts = {name: 0 for name in q.ORIGINAL_CONTROL_COUNTS}
    with c.no_execution(): actual = q.original_capture(output, report, rustc, source_root=source_root)
    counts['actual_captures'] += 1
    sources = q.source_evidence(source_root)
    native = q.native_evidence(output, report, source_root=source_root)
    source_files = dict(sources['files'])
    for name, identity in native['build_and_state']['source_inputs']['files'].items():
        if name in source_files: q.exact(source_files[name], identity, 'state/semantic source identity differs')
        source_files[name] = identity
    with c.snapshot(output, actual['artifact_sha256'], source_root, source_files) as (root, relocated):
        with c.no_execution(), c.forbid_producer_reads(output):
            q.exact(q.original_capture(relocated, report, rustc, source_root=root), actual,
                    'relocated complete original comparison differs')
        counts['actual_captures'] += 1

    def refuses(root, copied, changed, category):
        try:
            with c.no_execution(): q.original_capture(copied, changed, rustc, source_root=root)
        except (ValueError, KeyError, TypeError, AssertionError, OSError, zlib.error):
            counts[category] += 1
        else: raise AssertionError('altered full Local original evidence was admitted: ' + category)

    for change in ('missing', 'duplicate', 'exit', 'boolean-exit', 'timeout', 'start', 'command', 'stdout', 'phase', 'environment'):
        with c.snapshot(output, actual['artifact_sha256'], source_root) as (root, copied):
            changed = copy.deepcopy(report); row = next(row for row in changed['checks'] if row['name'] == q.PROCESS_NAMES[-1])
            if change == 'missing': changed['checks'].remove(row)
            elif change == 'duplicate': changed['checks'].append(copy.deepcopy(row))
            elif change == 'exit': row['exit_code'] = 1
            elif change == 'boolean-exit': row['exit_code'] = False
            elif change == 'timeout': row['timed_out'] = True
            elif change == 'start': row['start_error'] = 'synthetic missing original process'
            elif change == 'command': row['command'].remove('-I')
            elif change == 'stdout':
                path = copied / (q.PROCESS_NAMES[-1] + '.stdout'); c.replace(path, path.read_bytes()[:-1])
            elif change == 'phase': row['phase'] = 'native_components'
            else: row['environment_binding']['selected']['CARGO_ENCODED_RUSTFLAGS'] = '-Copt-level=0'
            refuses(root, copied, changed, 'process_refusals')

    for name in (q.REFERENCE + '/src/main.rs', q.REFERENCE + '/Cargo.lock',
                 q.REFERENCE + '/src/original_delta.rs', q.DRIVERS + '/source-extraction.json'):
        with c.snapshot(output, actual['artifact_sha256'], source_root, source_files) as (root, copied):
            path = root / name; c.replace(path, path.read_bytes() + b'\n')
            refuses(root, copied, report, 'source_refusals')

    changes = ('stale-target', 'reference-source', 'cargo-bytes', 'rustc-identity', 'cargo-identity',
               'compiler-after', 'build-environment', 'executable', 'metadata-feature', 'native-typed-receipt')
    for change in changes:
        with c.snapshot(output, actual['artifact_sha256'], source_root) as (root, copied):
            changed = copy.deepcopy(report); folder = copied / q.FOLDER / 'reference'
            path = folder / 'reference-build.json'; receipt = q.decode(path.read_bytes())
            if change == 'stale-target': receipt['fresh_target_directory'] = False
            elif change == 'reference-source':
                target = folder / 'source/src/original_remote.rs'; c.replace(target, target.read_bytes() + b'\n')
            elif change == 'cargo-bytes':
                target = folder / 'source/Cargo.lock'; c.replace(target, target.read_bytes().replace(b'1.53.3', b'1.53.1'))
            elif change in ('rustc-identity', 'cargo-identity'):
                receipt['compiler_before']['rustc' if change.startswith('rustc') else 'cargo']['sha256'] = '0' * 64
            elif change == 'compiler-after': receipt['compiler_after']['rustc']['sha256'] = '0' * 64
            elif change == 'build-environment': receipt['environment_binding']['selected']['CARGO_ENCODED_RUSTFLAGS'] = '-Copt-level=0'
            elif change == 'executable':
                target = copied / receipt['executable']['path']; raw = bytearray(target.read_bytes()); raw[-1] ^= 1; c.replace(target, raw)
            elif change == 'metadata-feature':
                target = copied / (q.PROCESS_NAMES[2] + '.stdout'); metadata = q.decode(target.read_bytes())
                packages = {package['id']: package['name'] for package in metadata['packages']}
                node = next(node for node in metadata['resolve']['nodes'] if packages[node['id']] == 'tokio')
                assert 'fs' in node['features']; node['features'].remove('fs')
                raw = q.compact(metadata) + b'\n'; c.replace(target, raw)
                row = next(row for row in changed['checks'] if row['name'] == q.PROCESS_NAMES[2])
                row.update(stdout_bytes=len(raw), stdout_sha256=q.sha(raw))
            else:
                row = next(row for row in changed['checks'] if row['name'] == 'test_local_create_spec_state.py')
                row['exit_code'] = 1
            c.replace_json(path, receipt, q); refuses(root, copied, changed, 'reference_refusals')

    for change in ('input', 'file', 'stdout', 'drop-after-result', 'missing-worker', 'cache-value'):
        with c.snapshot(output, actual['artifact_sha256'], source_root) as (root, copied):
            held = change in ('drop-after-result', 'missing-worker')
            domain = copied / q.FOLDER / 'original' / ('held' if held else 'ordinary')
            name = 'canonical_sync_cancel' if held else 'ascii'; folder = domain / name
            summary = q.decode((domain / 'summary.json').read_bytes()); row = q.decode((folder / 'result.json').read_bytes())
            if not held:
                if change == 'file':
                    item = next(item for item in row['final_filesystem'] if item['kind'] == 'file')
                    target = folder / ('final-file-' + q.sha(bytes.fromhex(item['path_hex'])) + '.bin.gz')
                    raw = bytearray(gzip.decompress(target.read_bytes())); raw[-1] ^= 1
                    c.replace(target, gzip.compress(raw, mtime=0)); item['content'] = q.pin(raw)
                else:
                    stream = 'stdin' if change == 'input' else 'stdout' if change == 'stdout' else 'stderr'
                    target = folder / (stream + '.bin.gz'); raw = bytearray(gzip.decompress(target.read_bytes()))
                    if change == 'cache-value':
                        assert raw[:8] == b'HLCSCS01'; key_size, value_size = struct.unpack_from('<QQ', raw, 48)
                        assert value_size > 0; raw[48 + 16 + key_size] ^= 1
                    else: raw[-1] ^= 1
                    c.replace(target, gzip.compress(raw, mtime=0)); row[stream] = q.pin(raw)
                summary['rows'][next(index for index, item in enumerate(summary['rows']) if item['name'] == name)] = row
            else:
                trace = folder / 'trace'; result = q.decode((trace / 'result.json').read_bytes())
                if change == 'missing-worker':
                    child = next(pid for pid in result['owned_pids'] if pid != result['root_pid'])
                    result['owned_pids'].remove(child); result['exit_codes'].pop(str(child)); row['actual_owned_pids'] = result['owned_pids']
                else:
                    events = [q.decode(line) for line in (trace / 'events.jsonl').read_bytes().splitlines()]
                    drop = next(event for event in events if event['kind'] == 'marker_entry' and event.get('event') == 7)
                    joined = next(event for event in events if event['kind'] == 'marker_entry' and event.get('event') == 12)
                    events.remove(drop); events.insert(events.index(joined) + 1, drop)
                    mapping = {event['index']: index for index, event in enumerate(events)}
                    for index, event in enumerate(events):
                        event['index'] = index; event['elapsed_seconds'] = result['elapsed_seconds'] * index / (len(events) + 1)
                        for field in ('event_index', 'held_event'):
                            if field in event: event[field] = mapping[event[field]]
                    c.replace(trace / 'events.jsonl', b''.join(q.compact(event) + b'\n' for event in events))
                c.replace_json(trace / 'result.json', result, q); row['leaf_trace'] = q.pin((trace / 'result.json').read_bytes())
                summary['checks'][next(index for index, item in enumerate(summary['checks']) if item['name'] == name)] = row
            c.replace_json(folder / 'result.json', row, q); c.replace_json(domain / 'summary.json', summary, q)
            refuses(root, copied, report, 'stream_refusals')

    q.exact(counts, q.ORIGINAL_CONTROL_COUNTS, 'full Local original controls skipped a declared domain')
    q.exact(q.source_evidence(source_root), sources, 'full Local source changed during readonly original controls')
    with c.no_execution(): q.exact(q.original_capture(output, report, rustc, source_root=source_root), actual,
                                  'original controls altered their producer')
    summary = dict(schema='hepta.runtime.local-create-spec-original-controls.v1', status='PASS', counts=counts,
        source_inputs=sources, original_evidence_sha256=q.sha(q.compact(actual)),
        new_native_or_rust_processes=0, synthetic_receipt_controls=True, scope=q.SCOPE)
    (output / q.FOLDER / 'original-controls.json').write_bytes(q.compact(summary) + b'\n')
    return summary
