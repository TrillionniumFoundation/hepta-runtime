"""Substitute retained full streams and receipts against the directory checker."""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import hia_native_directory_qualification as q
from test_directory_service_build import Mutation

CASES = (
    'functional-count', 'functional-output', 'functional-filesystem', 'functional-reaping',
    'functional-original-image', 'functional-source',
    'kernel-missing-case', 'kernel-events', 'kernel-stream', 'kernel-mutation',
    'kernel-cancelled-validation', 'kernel-permit-order',
    'fault-actual-domain', 'fault-synthetic-count', 'fault-source', 'fault-missing-stream', 'fault-reaping',
    'transport-domain', 'transport-maximum', 'transport-reaping', 'transport-output',
    'process-empty-stdout', 'process-failed-exit', 'process-source', 'process-command',
    'regex-count', 'regex-stream', 'regex-filesystem', 'regex-refusal', 'regex-image', 'regex-source')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-results', type=Path, required=True)
    parser.add_argument('--original-results', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    original_sha = q.sha((args.original_results / 'original-reference.elf').read_bytes())
    source = q.source_inventory()
    report = dict(schema='hepta.directory.evidence-controls.v1', status='FAIL', accepted=[], refused=[],
        expected_refusals=list(CASES), native_semantic_cases_added=0, original_semantic_cases_added=0,
        source_inventory=source, whole_runtime_replaced=False, production_activated=False)
    def saved():
        (args.output / 'report.json').write_bytes(q.native.json_bytes(report))
    try:
        checks = [
            ('complete-functional-native', lambda: q.functional_evidence(args.native_results / 'functional', ROOT)),
            ('complete-functional-original', lambda: q.functional_evidence(args.original_results / 'functional', ROOT, original_sha)),
            ('complete-paired-kernel', lambda: q.kernel_evidence(args.original_results / 'kernel', ROOT, original_sha)),
            ('complete-fixed-faults', lambda: q.faults_evidence(args.native_results / 'faults', ROOT)),
            ('complete-transport', lambda: q.transport_evidence(args.native_results / 'transport', ROOT)),
            ('complete-builder', lambda: q.builder_evidence(args.native_results / 'builder', ROOT)),
            ('complete-native-process', lambda: q.process_evidence(args.native_results, 'functional', ROOT)),
            ('complete-original-process', lambda: q.process_evidence(args.original_results, 'kernel', ROOT)),
            ('complete-regex-native', lambda: q.regex_evidence(args.native_results / 'regex', ROOT)),
            ('complete-regex-original', lambda: q.regex_evidence(args.original_results / 'regex', ROOT, original_sha))]
        for name, action in checks:
            action(); report['accepted'].append(name)
        with tempfile.TemporaryDirectory(prefix='directory-evidence-controls-', dir=args.output) as temporary:
            tmp = Path(temporary); native = tmp / 'native'; original = tmp / 'original'
            shutil.copytree(args.native_results, native)
            original.mkdir()
            for name in ('functional', 'kernel', 'regex'):
                shutil.copytree(args.original_results / name, original / name)
            for name in CASES:
                change = Mutation()
                if name.startswith('functional-'): base, stem = original, 'functional'
                elif name.startswith('kernel-'): base, stem = original, 'kernel'
                elif name.startswith('fault-'): base, stem = native, 'faults'
                elif name.startswith('transport-'): base, stem = native, 'transport'
                elif name.startswith('regex-'): base, stem = original, 'regex'
                else: base, stem = native, 'functional'
                path = base / stem / 'report.json'; value = json.loads(path.read_bytes())
                try:
                    if name == 'functional-count': value['native_requests'] -= 1
                    elif name == 'functional-output': value['cases'][0]['process']['output_hex'] = value['cases'][0]['process']['output_hex'][:-2]
                    elif name == 'functional-filesystem': value['cases'][0]['after'][0]['mode'] ^= 1
                    elif name == 'functional-reaping': value['cases'][1]['process']['reaped'] = False
                    elif name == 'functional-original-image': value['cases'][1]['process']['elf_sha256'] = '0' * 64
                    elif name == 'functional-source': value['source_sha256'][next(iter(value['source_sha256']))] = '0' * 64
                    elif name == 'kernel-missing-case': value['cases'].pop()
                    elif name == 'kernel-events':
                        p = base / stem / 'native-soft-cancel.events.json'; events = json.loads(p.read_bytes()); events.pop(); change.json(p, events)
                    elif name == 'kernel-stream':
                        p = base / stem / 'native-soft-cancel.stdout'; raw = p.read_bytes()[:-1]; change.write(p, raw)
                        value['cases'][0].update(output_bytes=len(raw), output_sha256=q.sha(raw))
                    elif name == 'kernel-mutation': value['cases'][0]['syscall_mutations'] = 1
                    elif name == 'kernel-cancelled-validation':
                        next(c for c in value['cases'] if c['case'] == 'pending-drop')['record_validation_after_cancel'] = False
                    elif name == 'kernel-permit-order':
                        c = next(c for c in value['cases'] if c['case'] == 'outer-drop' and c['variant'] == 'native')
                        next(e for e in c['events'] if e['kind'] == 'after_cancel_before_actual_mkdir')['exclusive_available'] = False
                        change.json(base / stem / 'native-outer-drop.events.json', c['events'])
                    elif name == 'fault-actual-domain': value['cases'][10]['actual_broken_pipe'] = False
                    elif name == 'fault-synthetic-count': value['cases'][0]['synthetic_errno_injections'] = 0
                    elif name == 'fault-source': value['source_sha256']['directory_service_kernel.py'] = '0' * 64
                    elif name == 'fault-missing-stream':
                        p = base / stem / 'wake-pipe.stderr'; change.save(p); p.unlink()
                    elif name == 'fault-reaping': value['cases'][0]['all_owned_tasks_reaped'] = False
                    elif name == 'transport-domain':
                        value['expected_domains']['startup'][0] = 'invented'; value['cases'][0]['case'] = 'invented'
                    elif name == 'transport-maximum':
                        c = next(c for c in value['cases'] if c['case'] == 'exact-max-frame')
                        raw = b'x'; compressed = gzip.compress(raw, mtime=0)
                        change.write(base / stem / c['stdin_gzip'], compressed)
                        c.update(stdin_bytes=1, stdin_sha256=q.sha(raw), stdin_gzip_sha256=q.sha(compressed))
                    elif name == 'transport-reaping': value['cases'][0]['reaped'] = False
                    elif name == 'transport-output': value['cases'][-1]['stdout_hex'] = value['cases'][-1]['stdout_hex'][:-2]
                    elif name == 'regex-count': value['native_requests'] -= 1
                    elif name == 'regex-stream':
                        selected = next(c for c in value['cases'] if c['name'] == 'literal' and c['variant'] == 'native')
                        selected['process']['output_hex'] = selected['process']['output_hex'][:-2]
                    elif name == 'regex-filesystem':
                        selected = next(c for c in value['cases'] if c['name'] == 'literal' and c['variant'] == 'original')
                        selected['after'][0]['mode'] ^= 1
                    elif name == 'regex-refusal': value['cases'][0]['process']['exit_code'] = 0
                    elif name == 'regex-image': value['cases'][0]['process']['elf_sha256'] = '0' * 64
                    elif name == 'regex-source':
                        key = next(k for k in value['source_sha256'] if k.endswith('test_directory_service_regex.py'))
                        value['source_sha256'][key] = '0' * 64
                    else:
                        p = base / 'functional.process.json'; process = json.loads(p.read_bytes())
                        if name == 'process-empty-stdout':
                            raw = b'{}\n'; change.write(base / 'functional.stdout', raw)
                            process.update(stdout_bytes=len(raw), stdout_sha256=q.sha(raw))
                        elif name == 'process-failed-exit': process['exit_code'] = 1
                        elif name == 'process-source':
                            pth = 'scripts/hia_native_directory_qualification.py'
                            process['source_before'][pth]['sha256'] = process['source_after'][pth]['sha256'] = '0' * 64
                        elif name == 'process-command': process['argv'][3] = '/owned/not-the-selected-suite.py'
                        change.json(p, process)
                    change.json(path, value)
                    try:
                        if name.startswith('functional-'): q.functional_evidence(base / stem, ROOT, original_sha)
                        elif name.startswith('kernel-'): q.kernel_evidence(base / stem, ROOT, original_sha)
                        elif name.startswith('fault-'): q.faults_evidence(base / stem, ROOT)
                        elif name.startswith('transport-'): q.transport_evidence(base / stem, ROOT)
                        elif name.startswith('regex-'): q.regex_evidence(base / stem, ROOT, original_sha)
                        else: q.process_evidence(base, stem, ROOT)
                    except (ValueError, AssertionError, FileNotFoundError, KeyError) as error:
                        report['refused'].append(dict(name=name, error_type=type(error).__name__, reason=str(error)))
                    else:
                        raise AssertionError('altered directory evidence accepted: ' + name)
                finally:
                    change.restore()
        q.require(len(report['accepted']) == 10 and [x['name'] for x in report['refused']] == list(CASES),
                  'directory evidence control domain differs')
        q.require(q.source_inventory() == source, 'directory evidence control source changed')
        report.update(status='PASS', source_unchanged=True,
            test_summary=dict(tests_run=6, **q.SUMMARY))
    except BaseException as error:
        report['error'] = repr(error); raise
    finally:
        saved()
    print(json.dumps({k: v for k, v in report.items() if k not in
        ('source_inventory', 'accepted', 'refused', 'expected_refusals')}))


if __name__ == '__main__':
    main()
