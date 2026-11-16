# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Data-only rejection controls for the current completed native admission."""
from pathlib import Path
import copy
import json
import stat
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'scripts')]
from public_lifecycle_registry import encoded, regular, require, sha
from public_lifecycle_retained import admit, obj, pin, FOLDER


def run(path, expected, invocation, manifest, output):
    path, manifest = Path(path).resolve(strict=True), Path(manifest).resolve(strict=True)
    output = Path(output).absolute(); output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = admit(path, expected, invocation, ROOT, manifest, execution=True)
    raw, mode = regular(path), stat.S_IMODE(path.stat().st_mode)
    original = json.loads(raw)
    mutations = [
        ('invocation', lambda v: v.update(invocation=v['invocation']+'-old')),
        ('context-invocation', lambda v: v['context'].update(invocation=v['invocation']+'-old')),
        ('source-root', lambda v: v.update(source_root=str(ROOT.parent))),
        ('output-root', lambda v: v.update(output_root=str(path.parent.parent))),
        ('native-count', lambda v: v.update(retained_native_processes=63)),
        ('request-count', lambda v: v.update(retained_native_requests=358)),
        ('new-native-count', lambda v: v.update(native_processes_executed_by_original_recipe=1)),
        ('deadline', lambda v: v.update(original_timeout_seconds=181)),
        ('source-pin', lambda v: v['sources'].__setitem__(sorted(v['sources'])[0], '0'*64)),
        ('manifest', lambda v: v['manifest'].update(sha256='0'*64)),
        ('completed-command', lambda v: v['native_process']['command'].__setitem__(-1, '/different/output')),
        ('completed-exit', lambda v: v['native_process'].update(exit_code=1)),
        ('capture-inventory', lambda v: v['captures'].pop(sorted(v['captures'])[0])),
        ('extra-field', lambda v: v.update(untrusted_completed=True)),
    ]
    rows = []
    try:
        for name, mutate in mutations:
            value = copy.deepcopy(original); mutate(value)
            changed = encoded(value); path.write_bytes(changed)
            rejected = False
            try: admit(path, sha(changed), invocation, ROOT, manifest, execution=True)
            except (AssertionError, ValueError, KeyError): rejected = True
            require(rejected, 'coordinated admission mutation accepted: '+name)
            rows.append(dict(name=name, rejected=True, recomputed_admission_digest=True))
            path.write_bytes(raw); path.chmod(mode)
        capture = path.parent/FOLDER/'case-000/native/stdout.bin'
        saved, capture_mode = regular(capture), stat.S_IMODE(capture.stat().st_mode)
        try:
            capture.write_bytes(saved+b' ')
            rejected = False
            try: admit(path, expected, invocation, ROOT, manifest, execution=True)
            except (AssertionError, ValueError, KeyError): rejected = True
            require(rejected, 'modified complete native stream accepted')
            rows.append(dict(name='complete-native-stream', rejected=True, recomputed_admission_digest=False))
        finally:
            capture.write_bytes(saved); capture.chmod(capture_mode)
    finally:
        path.write_bytes(raw); path.chmod(mode)
    after = admit(path, expected, invocation, ROOT, manifest, execution=True)
    require(before == after and regular(path) == raw and stat.S_IMODE(path.stat().st_mode) == mode,
            'native admission not completely restored')
    report = dict(schema='hepta.public-lifecycle.retained-controls.v1', status='PASS',
        admission=pin(path), invocation=invocation, rejected_controls=15, controls=rows,
        before=before, after=after, complete_restoration=True,
        native_processes=0, original_processes=0, syscall_interception=False, fault_injection=False)
    (output/'result.json').write_bytes(encoded(report))
    return dict(status='PASS', rejected_controls=15, complete_restoration=True,
        native_processes=0, original_processes=0)


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('admission','build','output'):p.add_argument('--'+key, type=Path, required=True)
    p.add_argument('--admission-sha256', required=True); p.add_argument('--invocation', required=True)
    a = p.parse_args()
    print(json.dumps(run(a.admission,a.admission_sha256,a.invocation,a.build,a.output), sort_keys=True))
