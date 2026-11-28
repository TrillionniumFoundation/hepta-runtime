"""Independent complete Local text-body fixture gate; no public-route claim.

This recipe deliberately leaves aggregate runtime owners and their fixed image
profiles unchanged. It builds the private final 12-member graph, preserves all
old read/capability/ordinary cases, and fresh-builds the exact target Rust body.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/hia_native/local_text_body'
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(FIXTURE))
import portable_support as support
from hia_native_local_text_body_build import verify_build
from read_native_controls import read_compat, capabilities

PROCESS_NAMES = ('body-native-build', 'body-read-compat', 'body-capabilities',
                 'body-fresh-reference', 'body-ordinary-paired',
                 'body-complete-readback', 'body-observer-refusals')
SCOPE = dict(full_body_async_qualified=False, public_handler_qualified=False,
             whole_runtime_replaced=False, old_stack_removal_qualified=False)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def command(output, name, argv):
    started = time.monotonic()
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    row = dict(name=name, command=argv, pid=p.pid, process_group=p.pid,
               deadline_seconds=180, status='RUNNING')
    save(output / (name + '.process.json'), row)
    timed = False
    try:
        try:
            stdout, stderr = p.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            timed = True
            try: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            stdout, stderr = p.communicate(timeout=10)
        for label, raw in (('stdout', stdout), ('stderr', stderr)):
            relative = name + '.' + label
            (output / relative).write_bytes(raw)
            row[label] = dict(path=relative, **support.PIN(raw))
        row.update(exit_code=p.returncode, timed_out=timed,
                   process_reaped=p.poll() is not None, elapsed_seconds=time.monotonic() - started)
        support.require(not timed and p.returncode == 0 and row['elapsed_seconds'] <= 180,
                        'body actual process failed: ' + name)
        row['status'] = 'PASS'
        return row
    except BaseException as error:
        row.update(status='FAIL', error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        try:
            if p.poll() is None:
                try: os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                p.wait(timeout=10)
        finally:
            row.update(exit_code=p.poll(), process_reaped=p.poll() is not None,
                       elapsed_seconds=time.monotonic() - started)
            save(output / (name + '.process.json'), row)


def native_evidence(output):
    output = Path(output).resolve(strict=True)
    manifest = output / 'build/local-text-body/manifest.json'
    return dict(source_inputs=support.source_evidence(), build=verify_build(manifest, source_root=ROOT),
                read_compat=read_compat(output / 'read-compat'),
                capabilities=capabilities(output / 'capabilities', manifest), scope=SCOPE)


def complete_evidence(output):
    output = Path(output).resolve(strict=True)
    native = native_evidence(output)
    _, original = support.original_build(output / 'reference/result.json')
    from read_portable_paired import verify
    paired = verify(output / 'paired')
    refusals_raw = support.regular(output, 'observer-refusals.json')
    refusals = support.decode(refusals_raw)
    support.require(refusals['status'] == 'LOCAL_TEXT_BODY_OBSERVER_MUTATIONS_PASS'
        and refusals['actual_refusals'] == len(refusals['controls']) == 39
        and len({row['name'] for row in refusals['controls']}) == 39
        and refusals['original_capture_unchanged'] is True and refusals['native_capture_unchanged'] is True
        and refusals['actual_body_processes_started'] == 0
        and refusals['full_body_async_qualified'] is False and refusals['public_handler_qualified'] is False,
        'body complete observer refusal evidence differs')
    for name, sha in refusals['source_sha256'].items():
        support.require(hashlib.sha256(support.regular(FIXTURE, name)).hexdigest() == sha,
                        'body observer refusal source differs')
    from check_paired_observers import evaluate
    support.require(evaluate(FIXTURE, output / 'paired') == refusals,
                    'body all 39 byte-mutation refusals differ from complete captured streams')
    return dict(status='LOCAL_TEXT_BODY_COMPLETE_FIXTURE_PASS', native=native, original=original,
                paired=paired, observer_refusals=refusals, observer_refusals_sha256=hashlib.sha256(refusals_raw).hexdigest(),
                scope=SCOPE, process_launches=0)


def verify_gate(output):
    output = Path(output).resolve(strict=True)
    raw = support.regular(output, 'gate.json')
    report = support.decode(raw)
    support.require(report['schema'] == 'hepta.runtime.local-text-body-independent-gate.v1'
        and report['status'] == 'LOCAL_TEXT_BODY_COMPLETE_FIXTURE_PASS'
        and report['phase'] == 'all' and report['fresh_original_build'] is True
        and report['source_unchanged'] is True and report['source_inputs'] == support.source_evidence()
        and report['scope'] == SCOPE
        and [row['name'] for row in report['processes']] == list(PROCESS_NAMES),
        'body independent gate source/status/process set differs')
    pids = set()
    artifacts = {'gate.json': hashlib.sha256(raw).hexdigest()}
    producer = report['producer']
    src = Path(producer['source_root']); dest = Path(producer['output'])
    support.require(src.is_absolute() and dest.is_absolute() and Path(producer['python']).is_absolute()
                    and Path(producer['hepta']).is_absolute() and Path(producer['toolchain']).is_absolute(),
                    'body producer paths differ')
    fixture = src / 'tests/hia_native/local_text_body'
    manifest = dest / 'build/local-text-body/manifest.json'
    prefix = [producer['python'], '-I', '-B']
    commands = [
        [*prefix, str(src / 'scripts/hia_native_local_text_body_build.py'), '--hepta', producer['hepta'],
            '--build-root', str(dest / 'build')],
        [*prefix, str(fixture / 'qualify_read_compat.py'), '--manifest', str(manifest), '--hepta', producer['hepta'],
            '--build-root', str(dest / 'build'), '--output', str(dest / 'read-compat')],
        [*prefix, str(fixture / 'qualify_capabilities.py'), '--manifest', str(manifest), '--output', str(dest / 'capabilities')],
        [*prefix, str(fixture / 'build_reference.py'), '--output', str(dest / 'reference'), '--support', str(src),
            '--toolchain', producer['toolchain']],
        [*prefix, str(fixture / 'run_portable_paired.py'), '--reference-build', str(dest / 'reference/result.json'),
            '--native-build', str(manifest), '--output', str(dest / 'paired')],
        [*prefix, str(fixture / 'read_portable_paired.py'), '--capture', str(dest / 'paired'), '--output',
            str(dest / 'paired-readback.json'), '--retire'],
        [*prefix, str(fixture / 'check_paired_observers.py'), '--source', str(fixture), '--capture', str(dest / 'paired'),
            '--output', str(dest / 'observer-refusals.json')],
    ]
    for row, command in zip(report['processes'], commands, strict=True):
        retained = support.decode(support.regular(output, row['name'] + '.process.json'))
        support.require(row == retained and row['command'] == command
            and row['status'] == 'PASS' and row['deadline_seconds'] == 180
            and row['exit_code'] == 0 and row['timed_out'] is False and row['process_reaped'] is True
            and type(row['pid']) is int and row['pid'] > 0 and row['pid'] not in pids
            and row['process_group'] == row['pid']
            and type(row['elapsed_seconds']) in (int, float) and math.isfinite(row['elapsed_seconds'])
            and 0 <= row['elapsed_seconds'] <= 180, 'body actual complete parent process custody differs')
        pids.add(row['pid'])
        for label in ('stdout', 'stderr'):
            identity = row[label]
            expected_path = row['name'] + '.' + label
            stream = support.regular(output, expected_path)
            support.require(identity == dict(path=expected_path, **support.PIN(stream)),
                            'body complete parent process stream differs')
            artifacts[expected_path] = hashlib.sha256(stream).hexdigest()
        name = row['name'] + '.process.json'
        artifacts[name] = hashlib.sha256(support.regular(output, name)).hexdigest()
    evidence = complete_evidence(output)
    support.require(report['native_evidence'] == evidence['native']
                    and report['complete_evidence'] == evidence, 'body recomputed complete evidence differs')
    return dict(status=evidence['status'], scope=SCOPE, process_launches=0,
                top_level_artifact_sha256=artifacts, complete_evidence=evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--toolchain', type=Path)
    parser.add_argument('--phase', choices=('native', 'all', 'verify'), default='all')
    args = parser.parse_args()
    support.require(sys.flags.optimize == 0, 'body fixture assertions must remain enabled')
    support.require(os.geteuid() != 0, 'body original permission domain requires an unprivileged runner')
    before = support.source_evidence()
    output = args.output.resolve()
    if args.phase == 'verify':
        result = verify_gate(output)
        print(json.dumps({key: result[key] for key in ('status', 'scope', 'process_launches')}, sort_keys=True))
        return
    support.require(args.hepta is not None, 'body HIA compiler checkout is required')
    if args.phase == 'all': support.require(args.toolchain is not None, 'body fresh original toolchain is required')
    output.mkdir(parents=True, exist_ok=False)
    manifest = output / 'build/local-text-body/manifest.json'
    python = sys.executable
    report = dict(schema='hepta.runtime.local-text-body-independent-gate.v1', status='RUNNING',
                  source_inputs=before, phase=args.phase, scope=SCOPE, processes=[], fresh_original_build=False,
                  producer=dict(source_root=str(ROOT), output=str(output), python=python,
                      hepta=str(args.hepta.resolve(strict=True)),
                      toolchain=str(args.toolchain.resolve(strict=True)) if args.toolchain else None))
    save(output / 'gate.json', report)
    def run(name, argv):
        row = command(output, name, argv)
        report['processes'].append(row)
        save(output / 'gate.json', report)
    try:
        run(PROCESS_NAMES[0], [python, '-I', '-B', str(ROOT / 'scripts/hia_native_local_text_body_build.py'),
            '--hepta', str(args.hepta.resolve(strict=True)), '--build-root', str(output / 'build')])
        run(PROCESS_NAMES[1], [python, '-I', '-B', str(FIXTURE / 'qualify_read_compat.py'),
            '--manifest', str(manifest), '--hepta', str(args.hepta.resolve(strict=True)),
            '--build-root', str(output / 'build'), '--output', str(output / 'read-compat')])
        run(PROCESS_NAMES[2], [python, '-I', '-B', str(FIXTURE / 'qualify_capabilities.py'),
            '--manifest', str(manifest), '--output', str(output / 'capabilities')])
        report['native_evidence'] = native_evidence(output)
        if args.phase == 'all':
            toolchain = args.toolchain.resolve(strict=True)
            run(PROCESS_NAMES[3], [python, '-I', '-B', str(FIXTURE / 'build_reference.py'),
                '--output', str(output / 'reference'), '--support', str(ROOT), '--toolchain', str(toolchain)])
            support.original_build(output / 'reference/result.json')
            report['fresh_original_build'] = True
            run(PROCESS_NAMES[4], [python, '-I', '-B', str(FIXTURE / 'run_portable_paired.py'),
                '--reference-build', str(output / 'reference/result.json'), '--native-build', str(manifest),
                '--output', str(output / 'paired')])
            run(PROCESS_NAMES[5], [python, '-I', '-B', str(FIXTURE / 'read_portable_paired.py'),
                '--capture', str(output / 'paired'), '--output', str(output / 'paired-readback.json'), '--retire'])
            run(PROCESS_NAMES[6], [python, '-I', '-B', str(FIXTURE / 'check_paired_observers.py'),
                '--source', str(FIXTURE), '--capture', str(output / 'paired'), '--output', str(output / 'observer-refusals.json')])
            report['complete_evidence'] = complete_evidence(output)
        support.require(support.source_evidence() == before, 'body complete source closure changed')
        report.update(status='LOCAL_TEXT_BODY_COMPLETE_FIXTURE_PASS' if args.phase == 'all'
                      else 'LOCAL_TEXT_BODY_NATIVE_CONTROLS_PASS', source_unchanged=True)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        save(output / 'gate.json', report)
    print(json.dumps({key: report[key] for key in ('status', 'phase', 'fresh_original_build', 'scope')}, sort_keys=True))


if __name__ == '__main__':
    main()
