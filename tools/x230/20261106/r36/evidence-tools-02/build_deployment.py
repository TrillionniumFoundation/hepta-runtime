#!/usr/bin/env python3
"""Package the reviewed local evidence transport repair; no remote calls or workloads."""
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
DIRECTORY = HERE / 'r36-evidence-tools-v2'
sys.path.insert(0, str(DIRECTORY))
import evidence_policy as policy
from scan_evidence import scan


def pin(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def create_json(path, value):
    with path.open('x') as output:
        output.write(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    helper = policy.load_helper()
    original = json.loads((HERE / 'r36-evidence-tools-v2-lineage-input.json').read_bytes())
    old = HERE / 'r36-evidence-tools'
    policy.need({name: pin(old / name) for name in original['files']} == original['files'], 'original tools changed')
    fixture = json.loads((DIRECTORY / 'fixture-run-01.json').read_bytes())
    review = json.loads((DIRECTORY / 'independent-review.json').read_bytes())
    policy.need(fixture['returncode'] == 0 and 'Ran 12 tests' in fixture['stderr']
                and review['passed'] is True and review['static_findings'] == [], 'fixture or review incomplete')
    core = {name: pin(DIRECTORY / name) for name in policy.TOOL_FILES}
    policy.need(core == review['core_files'], 'reviewed core changed')
    policy.need(pin(DIRECTORY / 'prior-capture-failure.json') == policy.PRIOR_FAILURE_PIN, 'original failure differs')
    lineage = {
        'schema': 'hepta-r36-evidence-capture-repair-lineage/v1',
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'reason': 'Original scanner queued repeated JSON strings before pop-time deduplication; five telemetry files exceeded the unchanged queue bound.',
        'repair': 'Deduplicate pending byte sequences by SHA256 and shallowest depth, separate from processed depths; preserve later shallower reprocessing.',
        'new_tool_directory': str(policy.ROOT / policy.CAPTURE_TOOLS),
        'new_export_directory': str(policy.ROOT / 'evidence-export-02'),
        'original_tools': original['files'],
        'original_failed_capture': dict(policy.PRIOR_FAILURE_PIN, path=str(policy.ROOT / 'evidence-export-01/export-failure.json'), job_id='1a1b07b073c-fc05-70c5', state='failed', exit_code=1),
        'limits_unchanged': review['scan_limits'], 'original_files_modified': False,
        'remote_operations': 0, 'performance_workloads_executed': 0, 'candidate_adopted': False,
    }
    create_json(DIRECTORY / 'repair-lineage.json', lineage)
    py_files = sorted(p for p in DIRECTORY.iterdir() if p.is_file() and p.suffix == '.py')
    for path in py_files:
        ast.parse(path.read_text(), filename=path.name)
    findings = []
    for path in sorted(DIRECTORY.iterdir()):
        if path.is_file():
            findings.extend(scan(path.read_bytes(), path.name))
    policy.need(not findings, 'local package secret or decoding-bound scan failed')
    validation = {'schema': 'hepta-r36-evidence-tools-v2-local-validation/v1', 'passed': True,
                  'core_files': core, 'python_files_parsed': [p.name for p in py_files],
                  'original_tools_unchanged': original['files'], 'local_fixture_receipt': pin(DIRECTORY / 'fixture-run-01.json'),
                  'local_fixture_tests': 12, 'local_fixture_failures': 0,
                  'independent_review': pin(DIRECTORY / 'independent-review.json'),
                  'original_capture_failure': policy.PRIOR_FAILURE_PIN,
                  'secret_scan_findings': [], 'remote_operations': 0, 'candidate_adopted': False}
    create_json(DIRECTORY / 'local-validation.json', validation)
    names = sorted(p.name for p in DIRECTORY.iterdir() if p.is_file())
    tools_manifest = {'schema': 'hepta-r36-evidence-tools-package/v2', 'deployment_directory': str(policy.ROOT / policy.CAPTURE_TOOLS),
                      'files': {name: pin(DIRECTORY / name) for name in names}, 'implementation_files': list(policy.TOOL_FILES),
                      'reviewed_helper_sha256': policy.HELPER_SHA, 'local_fixture_tests': 12, 'local_fixture_failures': 0,
                      'original_capture_failure': policy.PRIOR_FAILURE_PIN, 'remote_operations': 0, 'candidate_adopted': False}
    create_json(DIRECTORY / 'tools-manifest.json', tools_manifest)
    names.append('tools-manifest.json')
    files = {policy.CAPTURE_TOOLS + '/' + name: helper.read(DIRECTORY / name)[0] for name in sorted(names)}
    policy.need(all(0 < row['bytes'] <= 65536 for row in files.values()), 'deployment member exceeds installation bound')
    manifest = {'schema': 'hepta-r36-evidence-tools-deployment/v2', 'destination': str(policy.ROOT / policy.CAPTURE_TOOLS),
                'files': files, 'original_capture_failure': policy.PRIOR_FAILURE_PIN, 'candidate_adopted': False,
                'remote_operations': 0, 'runtime_source_modified': False}
    archive = HERE / 'r36-evidence-tools-v2-deploy.tar.xz'
    manifest_raw, verification = helper.write_archive(archive, manifest, files)
    archive_pin = {key: verification['identity'][key] for key in ('bytes', 'sha256')}
    manifest_pin = {'bytes': len(manifest_raw), 'sha256': hashlib.sha256(manifest_raw).hexdigest()}
    pins = {'archive': archive_pin, 'manifest': manifest_pin,
            'files': {name: {key: value[key] for key in ('bytes', 'sha256')} for name, value in files.items()},
            'prior_tools': original['files'], 'prior_failure': policy.PRIOR_FAILURE_PIN}
    template = (HERE / 'r36-evidence-tools-v2-installer-body.py').read_text()
    marker = 'PINS = None  # Package builder replaces this single assignment with exact pins.'
    policy.need(template.count(marker) == 1, 'installer pin marker differs')
    installer = HERE / 'r36-install-evidence-tools-02.py'
    with installer.open('x') as output:
        output.write(template.replace(marker, 'PINS = ' + repr(pins)))
    ast.parse(installer.read_text(), filename=installer.name)
    payload = HERE / 'r36-evidence-tools-v2-install-payload.json'
    create_json(payload, {'schema': 'hepta-r36-evidence-tools-install-input/v2', 'archive_base64': base64.b64encode(archive.read_bytes()).decode()})
    policy.need(payload.stat().st_size <= 1048576, 'native stdin would exceed 1 MiB')
    policy.need({name: pin(old / name) for name in original['files']} == original['files'], 'original tools changed while packaging')
    policy.need({name: pin(DIRECTORY / name) for name in policy.TOOL_FILES} == core, 'reviewed core changed while packaging')
    receipt = {'schema': 'hepta-r36-evidence-tools-v2-deployment-receipt/v1', 'ready_for_reviewed_installation': True,
               'files': len(files), 'archive': dict(archive_pin, path=str(archive)),
               'embedded_manifest': manifest_pin, 'archive_verification': verification,
               'tools_manifest': pin(DIRECTORY / 'tools-manifest.json'),
               'installer': dict(pin(installer), path=str(installer)), 'installer_template': pin(HERE / 'r36-evidence-tools-v2-installer-body.py'),
               'payload': dict(pin(payload), path=str(payload)), 'pins': pins,
               'original_tools_unchanged': True, 'original_capture_failure_unchanged': True,
               'core_files_unchanged_from_independent_review': True, 'remote_operations': 0,
               'performance_workloads_executed': 0, 'candidate_adopted': False}
    create_json(HERE / 'r36-evidence-tools-v2-deploy.json', receipt)
    print(json.dumps({key: receipt[key] for key in ('files', 'archive', 'embedded_manifest', 'installer', 'payload')}, indent=2))


if __name__ == '__main__':
    main()
