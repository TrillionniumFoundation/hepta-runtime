"""Authenticate a retained failed-stage binary without pretending that stage passed."""
import hashlib
import json
from pathlib import Path
import subprocess


EXPECTED_PROFILE = dict(opt_level='1', debuginfo=0, debug_assertions=True,
                        overflow_checks=True, test=True)
PRODUCER_SHA = '9a0e5681cc63b615bb3f5fa33b98fdaba60558db00538da0b97f0261f90e5607'


def pin(path):
    path = Path(path).resolve()
    with path.open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(path=str(path), bytes=path.stat().st_size, sha256=sha)


def verify_reuse(contract):
    spec_pin = contract['retained_binary_inputs_pin']
    if pin(spec_pin['path']) != spec_pin:
        raise ValueError('retained artifact input manifest differs')
    spec = json.loads(Path(spec_pin['path']).read_text())
    directory = Path(contract['retained_binary_directory']).resolve()
    expected = {entry['path']: entry for entry in spec['files']}
    actual = {str(path.relative_to(directory)) for path in directory.rglob('*') if path.is_file()}
    if actual != set(expected) or len(expected) != 12 or spec['private_data_allowed'] is not False:
        raise ValueError('exact twelve public retained artifact files required')
    local_pins = {}
    for relative, entry in expected.items():
        unqualified = directory / relative
        path = unqualified.resolve()
        if not path.is_relative_to(directory) or unqualified.is_symlink():
            raise ValueError('retained artifact path escape')
        item = pin(path)
        if any(item[key] != entry[key] for key in ['bytes', 'sha256']):
            raise ValueError('retained artifact bytes differ: ' + relative)
        local_pins[relative] = item

    def read(relative):
        return json.loads((directory / relative).read_text())

    previous = read('owner-ci-attempt001/output/RESULTS.json')
    parent = read('owner-ci-attempt001/PROCESS.json')
    prior_contract = read('owner-ci-control/CONTRACT.json')
    admission = read('owner-ci-control/ADMISSION.json')
    package = read('owner-ci-attempt001/public_artifact/PACKAGE_FILES.json')
    old_root = Path(prior_contract['cwd'])

    def match_remote(record):
        relative = str(Path(record['path']).relative_to(old_root))
        if relative == 'qualification/weight_owner_ci_20261121/PUBLICATION_MANIFEST.json':
            relative = 'owner-ci-attempt001/public_artifact/SOURCE_MANIFEST.json'
        local = local_pins[relative]
        if any(local[key] != record[key] for key in ['bytes', 'sha256']):
            raise ValueError('retained cross-receipt identity differs')

    for record in [parent['contract_pin'], parent['authorization_pin'], parent['result_pin'],
                   admission['contract_pin'], previous['source_manifest_pin'], *package['files']]:
        match_remote(record)
    if (parent['status'] != 'FAILED_OR_UNKNOWN' or parent['returncode'] != 1 or
            parent['stop_reason'] != 'required_result_missing_or_unsuccessful' or parent['error'] is not None or
            parent['source_unchanged'] is not True or parent['residual_descendants_after_cleanup'] or
            parent['source_pins'] != prior_contract['source_pins'] or
            previous['status'] != 'FAILED' or previous['source_unchanged'] is not True or previous['binaries'] or
            previous['source_head'] != spec['source_head'] or previous['source_tree'] != spec['source_tree'] or
            previous['private_models_uploaded'] != 0 or previous['private_test_executions'] != 0 or
            prior_contract['profile_overrides'] != contract['profile_overrides']):
        raise ValueError('previous failed-stage provenance differs')
    steps = previous['steps']
    compile_command = ['cargo', 'test', '--locked', '--lib', '--all-features', '--no-run', '--message-format=json']
    strip_command = ['strip', '--strip-debug', str(old_root / spec['binary'])]
    if (len(steps) != 7 or [row['index'] for row in steps] != list(range(7)) or
            any(row['returncode'] != 0 for row in steps[:6]) or steps[6]['returncode'] != 1 or
            steps[5]['command'] != compile_command or steps[6]['command'] != strip_command):
        raise ValueError('expected compile-success/strip-permission-failure boundary differs')
    stderr = (directory / 'owner-ci-attempt001/public_artifact/FAILED_STEP_STDERR.txt').read_text()
    if 'reason: Permission denied' not in stderr:
        raise ValueError('previous strip failure is not the reviewed permission error')
    producer_path = 'qualification/weight_owner_ci_20261121/build_owner_ci.py'
    producer_records = [row for row in prior_contract['source_pins']
                        if row['path'] == str(old_root / producer_path)]
    producer = subprocess.check_output(['git', 'show', spec['source_head'] + ':' + producer_path],
                                      cwd=contract['cwd'])
    if (len(producer_records) != 1 or producer_records[0]['sha256'] != PRODUCER_SHA or
            hashlib.sha256(producer).hexdigest() != PRODUCER_SHA):
        raise ValueError('exact executed compiler/profile validation source differs')
    binary = directory / spec['binary']
    proof = dict(schema='hepta.retained-owner-binary-provenance.v1',
                 status='AUTHENTICATED_PENDING_NEW_STRIP_AND_SYNTHETIC_TESTS',
                 previous_stage_status='FAILED', previous_run_id=spec['run_id'],
                 artifact_id=spec['artifact_id'], artifact_zip_sha256=spec['artifact_zip_sha256'],
                 artifact_archive_scope='Expected immutable GitHub archive digest; every extracted file independently pinned.',
                 source_head=spec['source_head'], source_tree=spec['source_tree'],
                 result_pin=local_pins['owner-ci-attempt001/output/RESULTS.json'],
                 process_pin=local_pins['owner-ci-attempt001/PROCESS.json'],
                 source_contract_pin=local_pins['owner-ci-control/CONTRACT.json'],
                 retained_binary_pin=pin(binary), actual_compiler_artifact_json=None,
                 actual_compiler_profile=None, validated_expected_profile=EXPECTED_PROFILE,
                 compiler_profile_evidence='Executed-control-flow evidence: the pinned producer entered strip only after strict Cargo compiler-artifact profile and root-target checks. Raw compiler-artifact JSON was not retained; no JSON object is reconstructed.',
                 compiler_identity_evidence='Exact all-features cargo command, root manifest/src-lib guards and isolated-target guards in the same executed pinned source; full Cargo target identity object was not retained.',
                 producer_source_sha256=PRODUCER_SHA, new_compile_calls=0,
                 synthetic_tests_previously_executed=0, private_test_executions=0,
                 original_artifact_unchanged=True)
    return binary, proof
