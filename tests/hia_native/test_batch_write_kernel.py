"""Actual Local batch body filesystem faults and cancellation, with full traces."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from batch_write_supervisor import supervise
from batch_write_trace_common import equal_streams, json_bytes

sha = lambda data: hashlib.sha256(data).hexdigest()


def cases():
    steps = [dict(before_hex=b'previous\r\n'.hex(), operations=[dict(operation='insert', start=0, content='first')]),
             dict(operations=[dict(operation='insert', start=0, content='second')]),
             dict(operations=[dict(operation='insert', start=0, content='last')])]
    result = []
    def case(name, **details): result.append(dict(name=name, steps=steps, **details))
    case('ordinary')
    # first exists(), first read, fresh history exists/read, and atomic metadata
    # are separate original calls. The occurrence is explicitly part of the domain.
    for kind, occurrences, errors in [
        ('path_statx', (1, 2, 3), (4, 5, 13, 38, 95)),
        ('fd_statx', (1, 2), (4, 5, 13, 38)),
        ('open', (1, 2, 3), (4, 13)),
        ('read', (1, 2, 3, 4), (4, 5)),
        ('close', (1, 2, 3), (4, 5)),
        ('write', (1,), (4, 5, 28)),
        ('chmod', (1,), (4, 13)),
        ('rename', (1,), (4, 13)),
    ]:
        for nth in occurrences:
            for error in errors:
                case(f'fault-{kind}-{nth}-{error}', faults=[dict(tag=1, kind=kind, nth=nth, errno=error)])
    case('write-zero', faults=[dict(tag=1, kind='write', zero=True)])
    for kind in ('chmod', 'rename'):
        case(kind+'-cleanup-error', faults=[dict(tag=1, kind=kind, errno=13),
                                            dict(tag=1, kind='unlink', errno=13)])
    case('actual-file-size-limit', file_size_limit=3)
    for error in (1, 5, 38):
        case('shared-statx-unavailable-'+str(error),
             faults=[dict(tag=1, kind='path_statx', errno=5),
                     dict(tag=1, kind='statx_probe', errno=error)])
    for kind, occurrences in [('path_statx', (3,)), ('open', (1, 2, 3)),
                              ('read', (1, 3)), ('write', (1,)), ('close', (1, 2, 3)),
                              ('chmod', (1,)), ('rename', (1,))]:
        for nth in occurrences:
            case(f'cancel-{kind}-{nth}', cancel=dict(tag=1, kind=kind, nth=nth, release_after_tag=2))
    case('cancel-cleanup', faults=[dict(tag=1, kind='chmod', errno=13)],
         cancel=dict(tag=1, kind='unlink', release_after_tag=2))
    case('cancel-inherited-mask', blocked_cancel=True,
         cancel=dict(tag=1, kind='write', release_after_tag=2))
    for nth in (1, 2):
        case(f'cancel-sync-exists-{nth}',
             cancel=dict(tag=1, kind='path_statx', nth=nth, synchronous=True))
    for nth in (1, 2, 3):
        case(f'cancel-sync-canonical-key-{nth}',
             cancel=dict(tag=1, kind='readlink', path='target', nth=nth, synchronous=True))
    return result


def run(native, original, destination, selection=None):
    native = Path(native).resolve(strict=True)
    original = Path(original).resolve(strict=True) if original is not None else None
    destination = Path(destination); destination.mkdir()
    domain = cases()
    if selection is not None: domain = [case for case in domain if case['name'] in selection]
    assert domain
    (destination/'cases.json').write_bytes(json_bytes(domain))
    names = ('test_batch_write_kernel.py', 'batch_write_supervisor.py', 'batch_write_trace_common.py')
    sources = {name: sha((HERE/name).read_bytes()) for name in names}
    started = time.monotonic()
    report = dict(schema='hepta.runtime.batch-write-kernel-comparison.v1', status='RUNNING',
        native_sha256=sha(native.read_bytes()), original_sha256=sha(original.read_bytes()) if original else None,
        original_status='PENDING', sources=sources, declared_cases=len(domain), cases=0,
        native_processes=0, original_processes=0, native_requests=0, original_requests=0,
        exact_trace_comparisons=0, cancellation_partial_order_comparisons=0, observations=[])
    try:
        for index, config in enumerate(domain):
            entry = destination / (f'{index:03d}-'+config['name']); entry.mkdir()
            fixture = entry/'fixture'; fixture.mkdir()
            observed = []
            for label, binary in [('native', native)] + ([('original', original)] if original else []):
                if label == 'original': shutil.rmtree(fixture); fixture.mkdir()
                record = supervise(binary, fixture, config, entry/label)
                observed.append(record)
                assert record['status']=='PASS', (config['name'], label, record['failure'])
                assert record['actual_requests']==len(config['steps'])
                if 'cancel' in config:
                    if config['cancel'].get('synchronous'):
                        assert record['cancel_ack']['no_early_response'] is True
                    else:
                        assert record['cancel_ack']['code']==0xfffffff7
                        assert record['cancel_ack']['effect_still_held'] is True
                        held = [row for row in record['events'] if row.get('control',{}).get('type')=='cancel']
                        assert len(held)==1 and held[0]['cancellation_ack_before_effect_release'] is True
                        assert held[0]['release_reason']=='completed-response-'+str(config['cancel']['release_after_tag'])
                report[label+'_processes'] += 1; report[label+'_requests'] += record['actual_requests']
            n = observed[0]; r = observed[1] if original else None
            assert (entry/'native/stderr.bin').read_bytes()==b''
            compared, summary = {}, None
            if original:
                for name in ('requests.bin', 'normalized.bin', 'filesystem.bin.gz'):
                    compared[name] = equal_streams(entry/'native'/name, entry/'original'/name, name.endswith('.gz'))
                assert n['final_files']==r['final_files']
                summary=json.loads((entry/'original/stderr.bin').read_bytes())
                assert summary['status']=='PASS' and summary['responses']==len(config['steps'])
                assert summary['original_owner_calls']==len(config['steps'])
                if 'cancel' not in config:
                    assert n['normalized_events']==r['normalized_events'], (config['name'], 'exact original syscall trace differs')
                    report['exact_trace_comparisons'] += 1
                else: report['cancellation_partial_order_comparisons'] += 1
            report['observations'].append(dict(name=config['name'], compared=compared,
                native_result_sha256=sha((entry/'native/result.json').read_bytes()),
                original_result_sha256=sha((entry/'original/result.json').read_bytes()) if original else None,
                original_summary=summary, native_effects=n['actual_kernel_effects'],
                original_effects=r['actual_kernel_effects'] if r else 0, injected_completions=n['injected_completions']))
            report['cases'] += 1
            (destination/'progress.json').write_bytes(json_bytes(report))
        assert sources=={name:sha((HERE/name).read_bytes()) for name in names}
        assert sha(native.read_bytes())==report['native_sha256']
        if original:
            assert sha(original.read_bytes())==report['original_sha256']
            report['original_status']='PASS'
        report['status']='PASS' if original else 'NATIVE_PASS'
    except BaseException as error:
        report.update(status='FAIL',failure=repr(error))
    report['elapsed_seconds']=time.monotonic()-started
    (destination/'result.json').write_bytes(json_bytes(report))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--original',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--case',action='append')
    args=parser.parse_args()
    report=run(args.native,args.original,args.output,args.case)
    print(json.dumps({k:v for k,v in report.items() if k!='observations'},sort_keys=True))
    if report['status'] not in ('PASS','NATIVE_PASS'):raise SystemExit(1)
