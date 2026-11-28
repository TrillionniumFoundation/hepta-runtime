"""Real simultaneous history callers: held guard, cancellation and statx cache."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from write_chain_supervisor import supervise
from test_write_chain_files import equal_streams, json_bytes


def sha(raw): return hashlib.sha256(raw).hexdigest()


def cases():
    output = []
    for aliases in [False, True]:
        steps = [dict(op=1, before_hex=('level-%d\r\n' % i).encode().hex()) for i in range(4)]
        steps.append(dict(op=2, before_hex=b'latest'.hex()))
        for path in ([b'./target', b'sub/../target', b'././target'] if aliases else [b'target'] * 3):
            steps.append(dict(op=2, path_hex=path.hex()))
        steps.append(dict(op=2))
        output.append(dict(name='four-serialized-' + ('aliases' if aliases else 'same-path'), steps=steps,
            parallel=dict(mode='serialized', after=4, end=8,
                hold=dict(tag=5, kind='path_statx', path='target')),
            final_target_hex=b'level-0\r\n'.hex()))
    steps = [dict(op=1, before_hex=('snapshot-%d\n' % i).encode().hex()) for i in range(3)]
    steps += [dict(op=2, before_hex=b'latest'.hex()), dict(op=2, path_hex=b'./target'.hex()),
              dict(op=2), dict(op=2), dict(op=2)]
    output.append(dict(name='cancel-other-admitted-caller', steps=steps,
        parallel=dict(mode='queued-cancel', after=3, end=6, cancel_tag=5,
            hold=dict(tag=4, kind='path_statx', path='target')),
        final_target_hex=b'snapshot-0\n'.hex()))
    output.append(dict(name='late-first-statx-success-restores-present', steps=[
        dict(op=1, before_hex=b'A-original'.hex()),
        dict(op=1, path_hex=b'other'.hex(), before_hex=b'B-initial'.hex()),
        dict(op=1, path_hex=b'other'.hex(), before_hex=b'B-saved'.hex()),
        dict(op=2, before_hex=b'A-new'.hex()),
        dict(op=2, path_hex=b'other'.hex(), before_hex=b'B-new'.hex()),
        dict(op=2), dict(op=2, path_hex=b'other'.hex()), dict(op=2, path_hex=b'other'.hex())],
        faults=[dict(tag=2, kind='path_statx', path='other', errno=5),
                dict(tag=2, kind='statx_probe', errno=1)],
        parallel=dict(mode='cache-race', after=0, end=2,
            hold=dict(tag=1, kind='path_statx', path='target')),
        final_target_hex=b'A-original'.hex()))
    return output


def by_tag(record):
    rows = sorted(record['frames'], key=lambda row: row['tag'])
    assert [row['tag'] for row in rows] == list(range(1, len(rows) + 1))
    return b''.join(struct.pack('<QI', row['tag'], row['code']) + bytes.fromhex(row['output_hex']) for row in rows)


def run(native, original, destination):
    native = Path(native).resolve(strict=True)
    original = Path(original).resolve(strict=True) if original is not None else None
    destination = Path(destination); destination.mkdir()
    domain = cases(); (destination / 'cases.json').write_bytes(json_bytes(domain))
    sources = {name: sha((HERE / name).read_bytes()) for name in
        ('test_write_chain_concurrency.py', 'write_chain_supervisor.py', 'test_write_chain_files.py')}
    report = dict(schema='hepta.runtime.write-chain-concurrency.v1', status='RUNNING',
        declared_cases=len(domain), cases=0, native_processes=0, original_processes=0,
        native_requests=0, original_requests=0, observations=[], sources=sources,
        native_sha256=sha(native.read_bytes()), original_sha256=sha(original.read_bytes()) if original else None,
        original_status='PENDING',
        comparison_domain='complete tagged results, complete final files, actual causal hold/release assertions',
        concurrent_response_order_claimed=False, public_session_dispatch_qualified=False)
    started = time.monotonic()
    try:
        for index, config in enumerate(domain):
            entry = destination / ('%02d-' % index + config['name']); entry.mkdir()
            fixture = entry / 'fixture'; fixture.mkdir(); (fixture / 'sub').mkdir()
            sides = []
            for label, binary in [('native', native)] + ([('original', original)] if original else []):
                if label == 'original':
                    shutil.rmtree(fixture); fixture.mkdir(); (fixture / 'sub').mkdir()
                observed = supervise(binary, fixture, config, entry / label)
                sides.append(observed)
                assert observed['status'] == 'PASS', (config['name'], label, observed['failure'])
                assert observed['actual_requests'] == len(config['steps'])
                assert (fixture / 'target').read_bytes() == bytes.fromhex(config['final_target_hex'])
                parallel = config['parallel']
                held = [row for row in observed['events'] if row.get('control', {}).get('type') == 'hold']
                assert len(held) == 1
                if parallel['mode'] == 'serialized':
                    assert held[0]['release_reason'] == 'all-other-callers-reached-held-lock'
                    assert held[0]['queued_key_completions'] >= 3
                elif parallel['mode'] == 'queued-cancel':
                    assert held[0]['release_reason'] == 'canceled-waiter-removed-before-guard-release'
                    assert held[0]['queued_cancel_sent'] == held[0]['queued_cancel_ack'] == parallel['cancel_tag']
                    assert observed['cancel_ack']['effect_still_held'] is True
                    assert observed['cancel_ack']['queued_request_completed_before_guard_release'] is True
                else:
                    assert held[0]['release_reason'] == 'other-cache-transition-complete'
                    assert held[0]['other_request_completed_before_release'] == 2
                    # Thread B made the cache unavailable while A's first
                    # success was still held. A's later success stores Present;
                    # subsequent independent metadata really uses statx again.
                    assert any(row['kind'] == 'path_statx' and row['admission_epoch'] == 3 for row in observed['events'])
                    assert any(row['kind'] == 'fd_stat' and row['admission_epoch'] == 2 for row in observed['events'])
                report[label + '_processes'] += 1
                report[label + '_requests'] += observed['actual_requests']
            n = sides[0]
            files, requests, original_summary = None, None, None
            assert (entry / 'native/stderr.bin').read_bytes() == b''
            if original:
                r = sides[1]
                assert by_tag(n) == by_tag(r), (config['name'], 'complete tagged original results differ')
                assert n['final_files'] == r['final_files']
                files = equal_streams(entry / 'native/filesystem.bin.gz', entry / 'original/filesystem.bin.gz', True)
                requests = equal_streams(entry / 'native/requests.bin', entry / 'original/requests.bin')
                original_summary = json.loads((entry / 'original/stderr.bin').read_bytes())
                assert original_summary['status'] == 'PASS'
                assert original_summary['responses'] == original_summary['original_owner_calls'] == len(config['steps'])
            report['observations'].append(dict(name=config['name'], original_summary=original_summary,
                tagged_response_bytes=len(by_tag(n)), tagged_response_sha256=sha(by_tag(n)),
                filesystem=files, requests=requests,
                native_result_sha256=sha((entry / 'native/result.json').read_bytes()),
                original_result_sha256=sha((entry / 'original/result.json').read_bytes()) if original else None,
                native_kernel_effects=n['actual_kernel_effects'], original_kernel_effects=r['actual_kernel_effects'] if original else 0))
            report['cases'] += 1
            (destination / 'progress.json').write_bytes(json_bytes(report))
        assert sources == {name: sha((HERE / name).read_bytes()) for name in sources}
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
    args = parser.parse_args()
    report = run(args.native, args.original, args.output)
    print(json.dumps({key: value for key, value in report.items() if key != 'observations'}, sort_keys=True))
    if report['status'] not in ('PASS', 'NATIVE_PASS'): raise SystemExit(1)


if __name__ == '__main__': main()
