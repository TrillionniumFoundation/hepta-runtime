# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Capture current native audit effects, then compare fresh original processes.

The frozen harnesses retain every kernel receipt and complete output. Only the
same explicitly documented original projections are compared. Native capture
alone does not claim original equivalence; the independent recipe must replay
all cases against the current capture under the unchanged outer deadline.
"""
from pathlib import Path
import argparse
import importlib
import json
import struct
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'audit_harness'
sys.path[:0] = [str(HARNESS), str(HERE)]
from test_result_storage_fs import SHA, inventory, pin, require, retire_fixture

# The original filesystem corpus deliberately contains raw Unix names represented
# by surrogateescape. Escaped JSON preserves those bytes without a UTF-8 recode.
ENCODE = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()

# owner, case count, entered requests, real processes, intentionally killed
DOMAINS = {
    'prepare': ('prepare', 121, 278, 121, 0),
    'prepare_faults': ('prepare', 32, 64, 32, 0),
    'audit_directory': ('audit_directory', 155, 483, 155, 0),
    'audit_directory_faults': ('audit_directory', 23, 138, 23, 0),
    'audit_read': ('audit_read', 182, 503, 182, 0),
    'audit_read_faults': ('audit_read', 53, 159, 53, 0),
    'audit_write': ('audit_write', 215, 709, 215, 0),
    'audit_write_faults': ('audit_write', 61, 179, 61, 0),
    'audit_write_edges': ('audit_write', 15, 43, 22, 7),
    'audit_remove': ('audit_remove', 208, 446, 208, 0),
    'audit_remove_faults': ('audit_remove', 27, 79, 27, 0),
    'audit_remove_edges': ('audit_remove', 2, 6, 4, 2),
    'audit_entries': ('audit_entries', 105, 210, 105, 0),
    'audit_entries_faults': ('audit_entries', 36, 107, 36, 0),
    'audit_entries_edges': ('audit_entries', 5, 15, 10, 5),
    'audit_lock': ('audit_lock', 37, 258, 37, 0),
}
SCOPE = {name: False for name in ('whole_runtime_replaced', 'production_activated',
    'old_stack_removal_qualified', 'result_storage_closed', 'public_request_dispatch_qualified',
    'audit_storage_closed', 'archive_anchoring_closed', 'initialization_mutex_contention_qualified',
    'initialization_mutex_poisoning_qualified')}


def source_files():
    files = {Path(__file__).name: pin(Path(__file__)),
        'test_result_storage_fs.py': pin(HERE / 'test_result_storage_fs.py')}
    files.update({'audit_harness/' + path.name: pin(path) for path in sorted(HARNESS.glob('*.py'))})
    return files


def definitions(domain):
    owner, count, requests, processes, killed = DOMAINS[domain]
    if domain == 'audit_lock':
        module = importlib.import_module('test_audit_lock')
        result = [{'name': name, 'kind': kind, 'data': data} for name, kind, data in module.definitions()]
        # Application request counts are validated from the actual process, since
        # the observer issues a variable number of queue probes.
        require(len(result) == count, 'complete lock scenario set differs')
    else:
        name = owner + ('_fault_cases' if domain.endswith(('_faults', '_edges')) else '_cases')
        module = importlib.import_module(name)
        result = list(module.edge_cases() if domain.endswith('_edges') else module.cases())
        actual_requests = 0
        for row in result:
            actions = row['actions'] if owner == 'audit_directory' else row['operations']
            actual_requests += sum(isinstance(step, str) or 'request' in step
                or (owner == 'prepare' and 'mutation' not in step) for step in actions)
            actual_requests += len(row.get('recovery', []))
        require(len(result) == count and actual_requests == requests
            and len(result) + sum('recovery' in row for row in result) == processes
            and sum('recovery' in row for row in result) == killed, 'complete audit domain changed')
    require(len({row['name'] for row in result}) == len(result), 'case names repeat')
    return result


def execute(domain, executable, row, folder):
    owner = DOMAINS[domain][0]
    if owner == 'audit_lock':
        module = importlib.import_module('test_audit_lock')
        observed = module.run(executable, folder, row['kind'], row['data'])
        comparison = {key: observed[key] for key in ('application_frames', 'milestones', 'application_requests')}
        require(observed['reaped'] and observed['observed_task_count'] == 5
            and observed['worker_threads'] == 4 and observed['all_submitted_requests_completed'],
            'real thread lifecycle did not complete')
        # All application frames are compared; variable observation probes and
        # cross-thread arrival order remain separately retained, as originally.
        outputs = [bytes.fromhex(observed['application_frames'][str(i)])
            for i in range(1, observed['application_requests'] + 1)]
    elif owner in ('prepare', 'audit_directory'):
        module = importlib.import_module('test_' + owner)
        returned = module.run(executable, row, folder)
        comparison, outputs = returned[:2]
        if owner == 'prepare':
            comparison = dict(comparison, verified_created_anchors=len(returned[2]['verified_created_anchors']))
    elif domain.endswith('_edges'):
        module = importlib.import_module('test_' + domain)
        observed, outputs = module.run(executable, row, folder)
        fields = ['before', 'after', 'responses', 'selected_kernel_holding']
        if 'recovery' in row:
            fields += ['recovery_after', 'recovery_responses']
        comparison = {key: observed[key] for key in fields}
    else:
        module = importlib.import_module('test_' + owner)
        wire = b''.join(struct.pack('<Q', len(bytes.fromhex(raw))) + bytes.fromhex(raw)
            for raw in row['operations'])
        observed, outputs = module.run_one(executable, folder / 'fixture', folder, row, wire)
        (folder / 'stdin.bin').write_bytes(wire)
        fields = ['before', 'after', 'observations']
        if domain.endswith('_faults'):
            fields.append('selected_kernel_holding')
        comparison = {key: observed[key] for key in fields}
    if isinstance(outputs, bytes):
        outputs = [outputs]
    framed = b''.join(struct.pack('<Q', len(raw)) + raw for raw in outputs)
    semantic = ENCODE(comparison)
    (folder / 'semantic-comparison.json').write_bytes(semantic)
    (folder / 'complete-projected-output.bin').write_bytes(framed)
    if owner != 'audit_lock':
        retirement = retire_fixture(folder / 'fixture')
        (folder / 'fixture-retirement.json').write_bytes(ENCODE(retirement))
        require(not retirement['remaining_fixture'], 'observed fixture was not retired')
    return semantic, framed


def admit_capture(folder, domain):
    folder = Path(folder);report = json.loads((folder / 'result.json').read_bytes())
    require(report['status'] == 'PASS' and report['phase'] == 'native' and report['domain'] == domain
        and report['new_original_processes'] == 0 and report['source_files'] == source_files(),
        'native audit capture is incomplete or changed')
    rows = definitions(domain)
    require(report['definitions'] == pin(folder / 'definitions.json')
        and (folder / 'definitions.json').read_bytes() == ENCODE(rows)
        and len(report['cases']) == len(rows), 'native audit scenario set differs')
    for index, (record, row) in enumerate(zip(report['cases'], rows, strict=True)):
        require(record['index'] == index and record['name'] == row['name'] and record['completed'] is True,
            'native audit case order differs')
        case = folder / f'{index:04d}'
        require(record['artifacts'] == inventory(case)
            and record['semantic'] == pin(case / 'semantic-comparison.json')
            and record['complete_output'] == pin(case / 'complete-projected-output.bin'),
            'complete native audit observations differ')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True, choices=tuple(DOMAINS))
    parser.add_argument('--phase', required=True, choices=('native', 'original'))
    parser.add_argument('--executable', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--native-capture', type=Path)
    args = parser.parse_args();out = args.output.resolve();out.mkdir(mode=0o700, parents=True)
    executable = args.executable.resolve(strict=True);sources = source_files();image = pin(executable)
    started = time.monotonic()
    report = {'schema': 'hepta.audit-readiness.filesystem-execution.v1', 'status': 'RUNNING',
        'phase': args.phase, 'domain': args.domain, 'source_files': sources, 'executable': image,
        'cases': [], 'new_original_processes': 0, 'new_native_processes': 0,
        'semantic_reference_comparison_complete': False, **SCOPE}
    save = lambda: (out / 'result.json').write_bytes(ENCODE(report))
    save()
    try:
        require((args.phase == 'original') == (args.native_capture is not None), 'original needs current native capture')
        native = admit_capture(args.native_capture, args.domain) if args.native_capture else None
        rows = definitions(args.domain)
        (out / 'definitions.json').write_bytes(ENCODE(rows));report['definitions'] = pin(out / 'definitions.json')
        application_requests = 0
        for index, row in enumerate(rows):
            case = out / f'{index:04d}'
            semantic, complete = execute(args.domain, executable, row, case)
            if args.domain == 'audit_lock':
                application_requests += json.loads(semantic)['application_requests']
            if native:
                captured = args.native_capture / f'{index:04d}'
                require(semantic == (captured / 'semantic-comparison.json').read_bytes(),
                    'complete original/native audit observation differs: ' + row['name'])
                require(complete == (captured / 'complete-projected-output.bin').read_bytes(),
                    'complete original/native audit output differs: ' + row['name'])
            report['cases'].append({'index': index, 'name': row['name'], 'completed': True,
                'semantic': pin(case / 'semantic-comparison.json'),
                'complete_output': pin(case / 'complete-projected-output.bin'), 'artifacts': inventory(case)})
            if index % 16 == 0:
                save()
        require(source_files() == sources and pin(executable) == image, 'audit inputs changed during execution')
        if native:
            require(native == admit_capture(args.native_capture, args.domain), 'native audit capture changed during replay')
        _, count, requests, processes, killed = DOMAINS[args.domain]
        if args.domain == 'audit_lock':
            require(application_requests == requests, 'complete lock application request count differs')
        report.update(status='PASS', case_count=count, requests=requests, processes=processes,
            deliberately_killed_requests=killed, new_original_processes=processes if native else 0,
            new_native_processes=0 if native else processes, source_unchanged=True,
            semantic_reference_comparison_complete=bool(native), elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), elapsed_seconds=time.monotonic() - started)
        (out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:
        save()
    print(json.dumps({key: report[key] for key in ('schema', 'status', 'phase', 'domain', 'case_count',
        'requests', 'processes', 'deliberately_killed_requests', 'new_original_processes',
        'new_native_processes', 'semantic_reference_comparison_complete', 'elapsed_seconds')}, sort_keys=True))


if __name__ == '__main__':
    main()
