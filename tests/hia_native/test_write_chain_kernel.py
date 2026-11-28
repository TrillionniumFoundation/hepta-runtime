"""Actual Local caller kernel/error/cancellation comparison against Rust 1.95."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from write_chain_supervisor import supervise
from test_write_chain_files import equal_streams, json_bytes


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    result = []
    base = [dict(op=1, before_hex=b'previous\r\n'.hex()),
            dict(op=2, before_hex=b'external\n'.hex()), dict(op=2)]
    def case(name, **details):
        result.append(dict(name=name, steps=base, **details))
    case('ordinary')
    for tag, kind, errors in [
        (1, 'path_statx', [4, 5, 13, 38, 95]),
        (1, 'fd_statx', [4, 5, 13, 38]),
        (1, 'open', [4, 13]), (1, 'read', [4, 5]), (1, 'close', [4, 5]),
        (2, 'path_statx', [4, 5, 13, 38]), (2, 'open', [4, 13]),
        (2, 'write', [4, 5, 28]), (2, 'close', [4, 5]),
        (2, 'chmod', [4, 13]), (2, 'rename', [4, 13]),
    ]:
        for error in errors:
            case('fault-' + str(tag) + '-' + kind + '-' + str(error),
                 faults=[dict(tag=tag, kind=kind, errno=error)])
    case('write-zero', faults=[dict(tag=2, kind='write', zero=True)])
    for kind in ['chmod', 'rename']:
        case(kind + '-cleanup-error', faults=[dict(tag=2, kind=kind, errno=13),
                                             dict(tag=2, kind='unlink', errno=13)])
    case('actual-file-size-limit', file_size_limit=3)
    for probe_error in [1, 5, 38]:
        result.append(dict(name='shared-statx-unavailable-' + str(probe_error),
            steps=[dict(op=1, before_hex=b'first'.hex()), dict(op=1, before_hex=b'saved'.hex()),
                   dict(op=2, before_hex=b'new'.hex()), dict(op=2)],
            faults=[dict(tag=1, kind='path_statx', errno=5),
                    dict(tag=1, kind='statx_probe', errno=probe_error)]))
    for kind in ['path_statx', 'open', 'write', 'close', 'chmod', 'rename']:
        case('cancel-undo-' + kind, cancel=dict(tag=2, kind=kind, release_after_tag=3))
    case('cancel-cleanup', faults=[dict(tag=2, kind='chmod', errno=13)],
         cancel=dict(tag=2, kind='unlink', release_after_tag=3))
    case('cancel-inherited-mask', blocked_cancel=True,
         cancel=dict(tag=2, kind='write', release_after_tag=3))
    for kind in ['open', 'read', 'close']:
        case('cancel-save-' + kind, cancel=dict(tag=1, kind=kind, release_after_tag=2))
    case('cancel-sync-exists', cancel=dict(tag=1, kind='path_statx', synchronous=True))
    case('cancel-sync-key-after-read', cancel=dict(tag=1, kind='readlink', path='target', synchronous=True))
    case('cancel-sync-lock-key', cancel=dict(tag=2, kind='readlink', path='target', synchronous=True))
    case('cancel-sync-key-after-rename', cancel=dict(tag=2, kind='readlink', path='target', nth=3, synchronous=True))
    return result


def run(native, original, destination, selection=None):
    native = Path(native).resolve(strict=True)
    original = Path(original).resolve(strict=True) if original is not None else None
    destination = Path(destination); destination.mkdir()
    domain = cases()
    if selection is not None: domain = [case for case in domain if case['name'] in selection]
    assert domain
    (destination / 'cases.json').write_bytes(json_bytes(domain))
    source_names = ['test_write_chain_kernel.py', 'write_chain_supervisor.py', 'test_write_chain_files.py']
    source_inputs = {name: sha((HERE / name).read_bytes()) for name in source_names}
    started = time.monotonic()
    report = dict(schema='hepta.runtime.write-chain-kernel-comparison.v1', status='RUNNING',
        native_sha256=sha(native.read_bytes()), original_sha256=sha(original.read_bytes()) if original else None,
        original_status='PENDING',
        sources=source_inputs, declared_cases=len(domain), cases=0, observations=[],
        native_processes=0, original_processes=0, native_requests=0, original_requests=0,
        exact_trace_comparisons=0, cancellation_partial_order_comparisons=0)
    try:
        for index, config in enumerate(domain):
            entry = destination / ('%03d-' % index + config['name']); entry.mkdir()
            fixture = entry / 'fixture'; fixture.mkdir()
            observed = []
            for label, binary in [('native', native)] + ([('original', original)] if original else []):
                if label == 'original': shutil.rmtree(fixture); fixture.mkdir()
                record = supervise(binary, fixture, config, entry / label)
                observed.append(record)
                assert record['status'] == 'PASS', (config['name'], label, record['failure'])
                assert record['actual_requests'] == len(config['steps'])
                if 'cancel' in config:
                    if config['cancel'].get('synchronous'):
                        assert record['cancel_ack']['no_early_response'] is True
                    else:
                        assert record['cancel_ack']['code'] == 0xfffffff7
                        assert record['cancel_ack']['effect_still_held'] is True
                        held = [row for row in record['events'] if row.get('control', {}).get('type') == 'cancel']
                        tag = config['cancel']['release_after_tag']
                        assert len(held) == 1 and held[0]['release_reason'] == 'completed-response-' + str(tag)
                        assert held[0]['cancellation_ack_before_effect_release'] is True
                report[label + '_processes'] += 1
                report[label + '_requests'] += record['actual_requests']
            n = observed[0]
            compared = {}
            summary, r = None, None
            assert (entry / 'native/stderr.bin').read_bytes() == b''
            if original:
                r = observed[1]
                for name in ('requests.bin', 'normalized.bin', 'filesystem.bin.gz'):
                    compared[name] = equal_streams(entry / 'native' / name, entry / 'original' / name, name.endswith('.gz'))
                assert n['final_files'] == r['final_files']
                summary = json.loads((entry / 'original/stderr.bin').read_bytes())
                assert summary['status'] == 'PASS' and summary['responses'] == len(config['steps'])
                assert summary['original_owner_calls'] == len(config['steps'])
                if 'cancel' not in config:
                    assert n['normalized_events'] == r['normalized_events'], (config['name'], 'exact owner syscall trace differs')
                    report['exact_trace_comparisons'] += 1
                else:
                    # Both actual sides independently proved the causal holds
                    # above. Concurrent cleanup is not a deterministic schedule.
                    report['cancellation_partial_order_comparisons'] += 1
            if config['name'] == 'actual-file-size-limit':
                assert (fixture / '.octofs_tmp_target.tmp').read_bytes() == b'pre'
                assert [row['count'] for row in n['events'] if row['kind'] == 'write'] == [10, 7]
            report['observations'].append(dict(name=config['name'], compared=compared,
                native_result_sha256=sha((entry / 'native/result.json').read_bytes()),
                original_result_sha256=sha((entry / 'original/result.json').read_bytes()) if original else None,
                original_summary=summary, native_effects=n['actual_kernel_effects'],
                original_effects=r['actual_kernel_effects'] if r else 0, injected_completions=n['injected_completions']))
            report['cases'] += 1
            (destination / 'progress.json').write_bytes(json_bytes(report))
        assert source_inputs == {name: sha((HERE / name).read_bytes()) for name in source_names}
        assert sha(native.read_bytes()) == report['native_sha256']
        if original:
            assert sha(original.read_bytes()) == report['original_sha256']
            report['original_status'] = 'PASS'
        report['status'] = 'PASS' if original else 'NATIVE_PASS'
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error))
    report['elapsed_seconds'] = time.monotonic() - started
    (destination / 'result.json').write_bytes(json_bytes(report))
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--original', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--case', action='append')
    args = parser.parse_args()
    report = run(args.native, args.original, args.output, args.case)
    print(json.dumps({key: value for key, value in report.items() if key != 'observations'}, sort_keys=True))
    if report['status'] not in ('PASS', 'NATIVE_PASS'): raise SystemExit(1)


if __name__ == '__main__':
    main()
