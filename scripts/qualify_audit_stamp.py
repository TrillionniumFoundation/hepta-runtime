# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Portable phased real Stamp qualification with fixed process bounds."""
from pathlib import Path
import argparse
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_stamp_qualification as q
import hia_native_stamp_reference as reference


def native_command(build, output):
    return [sys.executable, '-I', '-B', str(ROOT / 'tests/hia_native/run_stamp_native.py'),
        '--build', str(build), '--output', str(output / 'native')]


def original_command(build, output, domain, rustc, cargo):
    native = output / 'native';seal = native / 'result.json'
    return [sys.executable, '-I', '-B', str(ROOT / 'tests/hia_native/compare_stamp_original.py'),
        '--repo', str(ROOT), '--build', str(build), '--native', str(native),
        '--output', str(output / 'original' / domain), '--domain', domain,
        '--native-evidence', str(seal), '--native-evidence-sha256', q.pin(seal)['sha256'],
        '--rustc', str(rustc), '--cargo', str(cargo)]


def control_command(build, output, hepta):
    native = output / 'native';seal = native / 'result.json'
    return [sys.executable, '-I', '-B', str(ROOT / 'scripts/check_stamp_evidence.py'),
        '--repo', str(ROOT), '--hepta', str(hepta), '--build', str(build), '--native', str(native),
        '--original', str(output / 'original'), '--native-evidence', str(seal),
        '--native-evidence-sha256', q.pin(seal)['sha256'], '--output', str(output / 'controls')]


def verify(build, output, hepta, rustc, cargo):
    build_receipt = q.build_evidence(ROOT, build, hepta=hepta)
    native = output / 'native';seal = native / 'result.json';digest = q.pin(seal)['sha256']
    native_receipt = reference.captured_native(ROOT, build, native, seal, digest)
    native_process, stdout, stderr = q.process_evidence(output / 'native-run-process', native_command(build, output), ROOT)
    q.require(not stderr and json.loads(stdout) == {'status': 'PASS', 'mandatory_processes': 6,
        'actual_original_executions': 0, 'production_activated': False}, 'complete native runner differs')
    original_receipts = {};original_processes = {}
    for domain in reference.DOMAINS:
        original_receipts[domain] = reference.original_evidence(ROOT, build, native,
            output / 'original' / domain, domain, seal, digest)
        row, stdout, stderr = q.process_evidence(output / 'original-processes' / domain,
            original_command(build, output, domain, rustc, cargo), ROOT)
        q.require(not stderr and json.loads(stdout) == {'status': 'PASS', 'domain': domain,
            **original_receipts[domain]['comparison'], 'production_activated': False, 'whole_runtime_replaced': False},
            'actual complete original recipe stdout differs')
        original_processes[domain] = row
    baseline = {'build': build_receipt, 'native': native_receipt, 'original': original_receipts}
    control_process, stdout, stderr = q.process_evidence(output / 'controls-process',
        control_command(build, output, hepta), ROOT)
    controls = q.object_at(output / 'controls/result.json')
    q.require(not stderr and json.loads(stdout) == {'status': 'PASS', 'rejections': 19,
        'complete_readmissions': 21, 'semantic_executions_added': 0}
        and controls['status'] == 'PASS' and controls['baseline_sha256'] == q.sha(q.encoded(baseline))
        and controls['rejections'] == len(controls['controls']) == 19 and controls['complete_readmissions'] == 21
        and all(row['rejected'] is True and row['complete_readmission'] is True for row in controls['controls'])
        and controls['semantic_executions_added'] == 0, 'complete quiescent evidence controls differ')
    q.require(q.source_pins(ROOT) == native_receipt['sources'], 'source changed during final complete admission')
    return {'schema': 'hepta.audit-stamp.portable-qualification.v1', 'status': 'PASS',
        'sources': q.source_pins(ROOT), 'build': build_receipt, 'native': native_receipt,
        'original': original_receipts, 'controls': controls,
        'processes': {'native_runner': native_process, 'original': original_processes, 'controls': control_process},
        'fresh_full_cold_executed': False, 'new_executions_by_evidence_admission': 0,
        'cold_snapshot_admitted': False, 'complete_archive_acquisition_qualified': False,
        'complete_ticket_lifecycle_qualified': False, 'audit_storage_closed': False,
        'production_activated': False, 'public_request_dispatch_qualified': False,
        'whole_runtime_replaced': False, 'old_stack_removal_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True,
        choices=('build', 'native', 'original-stamp', 'original-cache_stamp', 'controls', 'verify'))
    for name in ('hepta', 'build', 'output', 'rustc', 'cargo'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args();hepta = args.hepta.resolve(strict=True)
    build, output = args.build.resolve(), args.output.resolve()
    rustc, cargo = args.rustc.absolute(), args.cargo.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    report = {'schema': 'hepta.audit-stamp.qualification-phase.v1', 'status': 'RUNNING',
        'phase': args.phase, 'sources': q.source_pins(ROOT), 'production_activated': False,
        'whole_runtime_replaced': False}
    target = output / ('phase-' + args.phase + '.json')
    q.require(not target.exists(), 'phase receipt already exists; reconcile the original process')
    save = lambda: target.write_bytes(q.encoded(report))
    save();environment = {key: value for key, value in os.environ.items() if not key.startswith('HIA_')}
    pending_final = None
    try:
        if args.phase == 'build':
            result = q.build_stamp(hepta, build, ROOT)
            report['artifacts'] = result['artifact_pins']
        elif args.phase == 'native':
            q.run_process(ROOT, output / 'native-run-process', native_command(build, output), environment=environment)
            native = output / 'native';seal = native / 'result.json'
            report['native'] = reference.captured_native(ROOT, build, native, seal, q.pin(seal)['sha256'])
        elif args.phase.startswith('original-'):
            domain = args.phase.removeprefix('original-')
            command = original_command(build, output, domain, rustc, cargo)
            q.run_process(ROOT, output / 'original-processes' / domain, command, environment=environment)
            native = output / 'native';seal = native / 'result.json'
            report['original'] = reference.original_evidence(ROOT, build, native,
                output / 'original' / domain, domain, seal, q.pin(seal)['sha256'])
        elif args.phase == 'controls':
            q.run_process(ROOT, output / 'controls-process', control_command(build, output, hepta), environment=environment)
            report['controls'] = q.object_at(output / 'controls/result.json')
        else:
            pending_final = q.encoded(verify(build, output, hepta, rustc, cargo))
        q.require(q.source_pins(ROOT) == report['sources'], 'portable source changed during actual phase')
        if pending_final is not None:
            with (output / 'result.json').open('xb') as stream:
                stream.write(pending_final)
            report['final'] = {'bytes': len(pending_final), 'sha256': q.sha(pending_final)}
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        save()
    print(json.dumps({'status': 'PASS', 'phase': args.phase, 'source_pins': len(report['sources']),
        'production_activated': False, 'whole_runtime_replaced': False}, sort_keys=True))


if __name__ == '__main__':
    main()
