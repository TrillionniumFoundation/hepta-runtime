# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind this invocation's complete native captures to its fresh Rust consumer."""
from pathlib import Path
import json
import os

from public_lifecycle_registry import TESTS, encoded, regular, require, sha, source_pins

ADMISSION = 'public-lifecycle-native-admission.json'
PHASE = 'public-lifecycle-native-phase.json'
FOLDER = 'public-lifecycle-native/normal'
LIFECYCLE = 'public-lifecycle-native/lifecycle'
MANIFEST = 'build/public-lifecycle/build.json'


class NativeProof:
    """One process's complete native proof; never deserialized or trusted from disk.

    Reuse still runs every source, build, completion, seal and capture byte check.
    Only deterministic semantic reconstruction of those identical bytes is reused.
    The default standalone admission always reconstructs the full native domain.
    """
    def __init__(self):
        self._key = self._evidence = self._build = self._directories = None
        self._normal = {}
        self._lifecycle = {}

    def checked(self):
        require(self._key is not None, 'native proof has not completed admission')
        path, digest, invocation, root, manifest = self._key
        return admit(path, digest, invocation, root, manifest, proof=self)

    def build(self):
        require(self._evidence is not None, 'native build has no completed proof')
        return self._build

    def normal(self, index):
        require(self._evidence is not None and set(self._normal) == set(range(64)),
                'complete normal projections are not available')
        return self._normal[index]

    def lifecycle(self, root, folder, binary):
        require(self._key is not None, 'native lifecycle has no completed proof')
        path, _, _, source, manifest = self._key
        require(Path(root).resolve(strict=True) == source
            and Path(folder).resolve(strict=True) == path.parent/LIFECYCLE
            and Path(binary).resolve(strict=True) == manifest.parent/self._build['executable'],
            'native lifecycle proof belongs to another input')
        evidence = self.checked()
        require(len(self._lifecycle) == 22, 'complete lifecycle projections are not available')
        return evidence['lifecycle'], self._lifecycle


def pin(path):
    raw = regular(path)
    return dict(bytes=len(raw), sha256=sha(raw))


def obj(path):
    value = json.loads(regular(path))
    require(type(value) is dict, 'retained native object required')
    return value


def write_new(path, value):
    with Path(path).open('xb') as stream:
        stream.write(encoded(value))


def directory_inventory(folder):
    """Bind empty directories too; file digests alone cannot prove retirement."""
    folder = Path(folder).resolve(strict=True)
    result = []
    for path in sorted(folder.rglob('*')):
        require(not path.is_symlink(), 'unexpected retained symlink')
        if path.is_dir():result.append(path.relative_to(folder).as_posix())
    return result


def retired_native_paths(output):
    for index in range(64):
        case = output/FOLDER/('case-%03d'%index)
        require(not os.path.lexists(case/'native/final-state')
                and not os.path.lexists(case/'common/state'),
                'normal native fixture was not retired')
    plan = json.loads(regular(output/LIFECYCLE/'declared-cases.json'))
    require(type(plan) is list and len(plan) == 22, 'native lifecycle plan changed')
    for row in plan:
        name = row['name']
        require(type(name) is str and name not in ('', '.', '..') and '/' not in name,
                'unconfined native lifecycle case')
        case = output/LIFECYCLE/name
        require(not os.path.lexists(case/'common/state')
                and not any(p.name.startswith('final-') for p in (case/'native').iterdir()),
                'lifecycle native fixture was not retired')


def current_invocation(invocation):
    require(type(invocation) is str and 0 < len(invocation) <= 256
            and not any(ord(c) < 32 for c in invocation), 'invalid native invocation')
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        expected = os.environ.get('GITHUB_RUN_ID', '') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '')
        require(expected not in ('-', '-1') and invocation == expected,
                'native capture belongs to another workflow invocation')


def create_admission(root, output, report, completed):
    from hia_native_public_lifecycle_qualification import native_evidence, inventory
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    evidence = native_evidence(root, output, report, completed)
    require(evidence == report['public_lifecycle_evidence'], 'completed native evidence changed')
    check, _ = completed(output, report, TESTS[1])
    lifecycle_check, _ = completed(output, report, TESTS[2])
    sources = source_pins(root)
    if 'original_shard' in report:
        binding = report['original_shard']
        invocation = binding['invocation']
        require(binding['group'] == 'public' and report['qualification_pipeline']['invocation'] == invocation,
                'native and public original invocation differ')
        context = dict(mode='ci-original-pipeline', invocation=invocation,
            native_seal_sha256=binding['native_sha256'], native_report=pin(output/'original-native-report.json'))
    else:
        require(os.environ.get('GITHUB_ACTIONS') != 'true', 'CI requires its external native seal')
        require(type(report.get('started_at')) is str and bool(report['started_at']),
                'actual native phase invocation absent')
        invocation = 'aggregate:' + report['started_at']
        phase = dict(schema='hepta.public-lifecycle.actual-native-phase.v1', status='PASS',
            invocation=invocation, source_root=str(root), source_files=sources,
            completed_checks=[check,lifecycle_check], native_evidence=evidence,
            new_native_executions=0, retained_completed_phase=True)
        write_new(output/PHASE, phase)
        context = dict(mode='owned-component-validation', invocation=invocation,
            phase_file=PHASE, phase=pin(output/PHASE))
    current_invocation(invocation)
    captures = {branch+'/'+name:digest for branch in (FOLDER,LIFECYCLE)
                for name,digest in inventory(output/branch).items()}
    admission = dict(schema='hepta.public-lifecycle.native-admission.v1',
        invocation=invocation, context=context, source_root=str(root), output_root=str(output),
        sources=sources, manifest=pin(output/MANIFEST), native_process=check,lifecycle_process=lifecycle_check,
        native_evidence=evidence, captures=captures, retained_native_processes=86,
        retained_native_requests=707, native_processes_executed_by_original_recipe=0,
        original_timeout_seconds=180)
    path = output/ADMISSION
    write_new(path, admission)
    admit(path, pin(path)['sha256'], invocation, root, output/MANIFEST, execution=True)
    return path


def context_evidence(admission, output):
    context = admission['context']
    require(context.get('invocation') == admission['invocation'], 'native context invocation changed')
    if context.get('mode') == 'ci-original-pipeline':
        require(set(context) == {'mode','invocation','native_seal_sha256','native_report'},
                'native CI context shape changed')
        seal_path, snapshot_path = output/'original-native.json', output/'original-native-report.json'
        seal = obj(seal_path)
        require(sha(regular(seal_path)) == context['native_seal_sha256']
                and seal['schema'] == 'hepta.runtime.original-native.v1', 'external native seal differs')
        for key, value in dict(invocation=admission['invocation'], source=admission['source_root'],
                               output=admission['output_root']).items():
            require(seal['context'].get(key) == value, 'native seal context differs: '+key)
        require(pin(snapshot_path) == context['native_report'], 'immutable native report changed')
        snapshot = obj(snapshot_path)
        require(snapshot['status'] == 'NATIVE_COMPONENTS_PASS'
                and snapshot['native_components_status'] == 'PASS'
                and snapshot['rust_comparison_status'] == 'PENDING'
                and snapshot['qualification_pipeline']['invocation'] == admission['invocation']
                and snapshot['checkout_head'] == seal['context']['checkout_head'],
                'sealed native phase did not complete for this source and invocation')
        for name, digest in admission['sources'].items():
            require(snapshot['source_sha256'].get(name) == digest, 'source absent from native seal: '+name)
        required = {'original-native-report.json', MANIFEST, TESTS[1]+'.stdout', TESTS[1]+'.stderr'}
        required.update((TESTS[2]+'.stdout',TESTS[2]+'.stderr'))
        required.update(admission['captures'])
        required.update(admission['native_evidence']['artifact_sha256'])
        for name in required:
            require(name in seal['files'], 'required native capture absent from seal: '+name)
            require(pin(output/name) == {k:seal['files'][name][k] for k in ('bytes','sha256')},
                    'sealed native bytes changed: '+name)
        require(snapshot['public_lifecycle_evidence'] == admission['native_evidence'],
                'sealed native domain changed')
        require([r for r in snapshot['checks'] if r.get('name') == TESTS[1]] == [admission['native_process']],
                'sealed native process absent or duplicated')
        require([r for r in snapshot['checks'] if r.get('name') == TESTS[2]] == [admission['lifecycle_process']],
                'sealed lifecycle process absent or duplicated')
        return dict(mode=context['mode'], native_seal=pin(seal_path), native_report=pin(snapshot_path))
    require(context.get('mode') == 'owned-component-validation'
            and set(context) == {'mode','invocation','phase_file','phase'}
            and context['phase_file'] == PHASE, 'native phase has no current owner')
    path = output/PHASE
    require(pin(path) == context['phase'], 'actual native phase changed')
    phase = obj(path)
    require(phase == dict(schema='hepta.public-lifecycle.actual-native-phase.v1', status='PASS',
        invocation=admission['invocation'], source_root=admission['source_root'], source_files=admission['sources'],
        completed_checks=[admission['native_process'],admission['lifecycle_process']], native_evidence=admission['native_evidence'],
        new_native_executions=0, retained_completed_phase=True), 'native phase completion differs')
    return dict(mode=context['mode'], phase=pin(path))


def admit(path, expected_sha256, invocation, root, manifest, *, execution=False, proof=None):
    from hia_native_public_lifecycle_qualification import verify_build, normal_evidence, lifecycle_evidence, inventory, test_commands
    from hia_native_public_registry_qualification import completed
    path, root, manifest = (Path(p).resolve(strict=True) for p in (path, root, manifest))
    require(proof is None or type(proof) is NativeProof, 'native proof must be process-local')
    key = (path, expected_sha256, invocation, root, manifest)
    reused = proof is not None and proof._evidence is not None
    require(not reused or proof._key == key, 'native proof identity changed')
    output = path.parent
    require(path.name == ADMISSION and manifest == output/MANIFEST,
            'native admission or manifest is outside the current output')
    raw = regular(path)
    require(sha(raw) == expected_sha256, 'external native admission digest differs')
    value = json.loads(raw)
    require(set(value) == {'schema','invocation','context','source_root','output_root','sources','manifest',
        'native_process','lifecycle_process','native_evidence','captures','retained_native_processes','retained_native_requests',
        'native_processes_executed_by_original_recipe','original_timeout_seconds'}, 'native admission shape differs')
    require(value['schema'] == 'hepta.public-lifecycle.native-admission.v1'
            and value['invocation'] == invocation and value['source_root'] == str(root)
            and value['output_root'] == str(output) and value['sources'] == source_pins(root)
            and value['manifest'] == pin(manifest) and value['retained_native_processes'] == 86
            and value['retained_native_requests'] == 707
            and value['native_processes_executed_by_original_recipe'] == 0
            and value['original_timeout_seconds'] == 180, 'native admission identity or domain differs')
    if execution:
        current_invocation(invocation)
    context = context_evidence(value, output)
    built = verify_build(root, manifest)
    row = value['native_process']
    command = test_commands(root, output, {})[TESTS[1]]
    require(row['name'] == TESTS[1], 'native process name differs')
    out, err = completed(output, TESTS[1], row, command, root, 180, aggregate=True)
    require(not err and json.loads(out) == dict(status='PASS', native_processes=64,
        native_requests=359, original_processes=0), 'actual native completion stream differs')
    row=value['lifecycle_process'];command=test_commands(root,output,{})[TESTS[2]]
    require(row['name']==TESTS[2],'lifecycle process name differs')
    out,err=completed(output,TESTS[2],row,command,root,180,aggregate=True)
    require(not err and json.loads(out)==dict(status='PASS',native_processes=22,original_processes=0,
        requests_per_implementation=348,producer_starts_per_implementation=11),
        'actual lifecycle completion stream differs')
    captures = {branch+'/'+name:digest for branch in (FOLDER,LIFECYCLE)
                for name,digest in inventory(output/branch).items()}
    require(captures == value['captures'], 'complete native capture inventory changed')
    directories = {branch:directory_inventory(output/branch) for branch in (FOLDER,LIFECYCLE)}
    retired_native_paths(output)
    require(not reused or directories == proof._directories,
            'native directory topology changed after complete admission')
    native = manifest.parent/built['executable']
    normal_projections, lifecycle_projections = {}, {}
    if reused:
        # The complete inventory, current external seal and actual build above
        # must match the proof that produced these process-local projections.
        require(value['captures'] == proof._evidence['captures'] and built == proof._build,
                'native proof bytes or build changed')
        reconstructed, finite = proof._evidence['normal'], proof._evidence['lifecycle']
    else:
        reconstructed = normal_evidence(root, output/FOLDER, native,
            projections=normal_projections if proof is not None else None)
        finite = lifecycle_evidence(root, output/LIFECYCLE, native,
            projections=lifecycle_projections if proof is not None else None)
    evidence = value['native_evidence']
    require(evidence['sources'] == value['sources'] and evidence['native_processes'] == 86
            and evidence['native_requests'] == 707 and evidence['original_processes'] == 0,
            'native phase source or process domain changed')
    for name, digest in evidence['artifact_sha256'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'unconfined native artifact')
        require(sha(regular(output/relative)) == digest, 'completed native artifact changed: '+name)
    native_result = obj(output/'public-lifecycle-native/result.json')
    require(native_result['normal'] == reconstructed and native_result['lifecycle']==finite
            and sha(regular(output/'public-lifecycle-native/result.json')) == evidence['native_result_sha256'],
            'complete native normal domain differs from its completed phase')
    result = dict(admission=pin(path), invocation=invocation, context=context,
        native_evidence=evidence, normal=reconstructed, lifecycle=finite, captures=captures,
        retained_native_processes=86, retained_native_requests=707,
        native_processes_executed_by_original_recipe=0, new_executions_in_admission=0)
    require({branch:directory_inventory(output/branch) for branch in (FOLDER,LIFECYCLE)} == directories,
            'native directories changed during complete admission')
    retired_native_paths(output)
    if reused:
        require(result == proof._evidence, 'completed native evidence changed')
    elif proof is not None:
        require(set(normal_projections) == set(range(64)) and len(lifecycle_projections) == 22,
                'native reconstruction did not complete both domains')
        proof._key, proof._evidence, proof._build, proof._directories = key, result, built, directories
        proof._normal, proof._lifecycle = normal_projections, lifecycle_projections
    return result
