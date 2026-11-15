#!/usr/bin/env python3
"""Create an unsealed R33 collector draft from the exact frozen R31 original.

Local source preparation only: no collector, native API, test, or auditor is run.
An optional actual-bindings JSON may supply original identities already retrieved
by root. Missing pins keep the output unsealed; a sealed output is create-only.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import pprint

HERE = Path(__file__).resolve().parent
TRANSFER = Path('/tmp/hepta-runtime-recovery-20261106/audit-archive/transferred-01')
REMOTE = '/home/qian/hepta-runtime-optimization-20261106-r33'
REFERENCE_SHA = '296d84668c1703361cb3dfe6b3a8b0849aed561d125f4a39988a44cda21fd7dc'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actual-bindings', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    original = (HERE / 'reference/archive_r31_observation.py').read_text()
    assert digest(original.encode()) == REFERENCE_SHA
    tree = ast.parse(original)
    assignments = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                assignments[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    old = assignments['PINNED']
    pins = {}
    for name, sha in old.items():
        if name.startswith('boundary-tools-02/'):
            pins[name.replace('boundary-tools-02/', 'boundary-tools-01/')] = sha
        elif name.startswith('external/r16/') and '/r31-cancel-recovery-02/' not in name:
            pins[name] = sha
        elif name.startswith('campaign-02/'):
            pins[name.replace('campaign-02/', 'campaign-01/')] = None
        elif name.startswith('external/r16/r31-cancel-recovery-02/'):
            pins[name.replace('r31-cancel-recovery-02', 'r33-cancel-recovery-01')] = None
    pins['campaign-01/summary.json'] = '8c2633a55d461802fbb9c5ed8c6b14b2e0715a70da9300a246e44e4351b80f1b'
    pins['observation-postflight-01.json'] = '975c0a362e8faecf24eb6fdaa9a6ee57557a2776b94e7d54dc814d8b8104861f'
    for name in ('campaign-inputs-01.json', 'observation-holder-native-01.json',
                 'observation-holder-read-01.json', 'lifecycle-materialization-native-01.json',
                 'lifecycle-materialization-read-01.json'):
        pins[name] = None
    qmanifest = json.loads((TRANSFER / 'qualification-evidence-01.manifest.json').read_bytes())
    for name in ('preparation.json', 'qualification-terminal-status-01.json',
                 'qualification-01/report.json', 'qualification-01/source-map.json',
                 'qualification-01/isolated-tests/summary.json'):
        pins[name] = qmanifest['files'][name]['sha256']
    install = json.loads((TRANSFER / 'parent-tools-install-01.json').read_bytes())
    for value in install['files'].values():
        assert value['path'].startswith(REMOTE + '/')
        pins[value['path'][len(REMOTE) + 1:]] = value['sha256']
    pins['parent-tools-install-01.json'] = digest((TRANSFER / 'parent-tools-install-01.json').read_bytes())
    ci_install = json.loads((TRANSFER / 'parent-ci-install-01/report.json').read_bytes())
    for row in ci_install['uploaded']:
        if row['path'].startswith(REMOTE + '/tools-01/'):
            pins[row['path'][len(REMOTE) + 1:]] = row['sha256']
    lifecycle_job = None
    bindings = None
    if args.actual_bindings is not None:
        bindings = json.loads(args.actual_bindings.read_bytes())
        assert bindings['schema'] == 'hepta-r33-original-observation-archive-bindings/v1'
        lifecycle_job = bindings['lifecycle_materialization_job_id']
        assert isinstance(lifecycle_job, str) and lifecycle_job
        for name, value in bindings['sha256'].items():
            assert name in pins, ('unexpected selected identity', name)
            assert isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
            assert pins[name] in (None, value), ('original fixed identity changed', name)
            pins[name] = value
    missing = sorted(name for name, value in pins.items() if value is None)
    sealed = not missing and lifecycle_job is not None
    text = original

    def replace(old_text, new_text, count=1):
        nonlocal text
        assert text.count(old_text) == count, (old_text, text.count(old_text), count)
        text = text.replace(old_text, new_text)

    replace('Archive the original R31 observation', 'Archive the original R33 observation')
    replace("ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r31')", "ROOT = Path('" + REMOTE + "')")
    replace("REFERENCE_SHA = '" + assignments['REFERENCE_SHA'] + "'", "REFERENCE_SHA = '" + REFERENCE_SHA + "'")
    replace("QUALIFICATION_ARCHIVE_SHA = '" + assignments['QUALIFICATION_ARCHIVE_SHA'] + "'", "QUALIFICATION_ARCHIVE_SHA = 'fa8a1bfcfe46b96aa59021c7f9ff20695fcc84b224c4ed0be811eda02c550c2f'")
    replace("CI_ARCHIVE_SHA = '" + assignments['CI_ARCHIVE_SHA'] + "'", "CI_ARCHIVE_SHA = 'bf993f6e81d4f50930c35e7ddf73d229a0264733a1718b34699852e038948210'")
    replace("HOLDER_01_JOB = '" + assignments['HOLDER_01_JOB'] + "'\nHOLDER_02_JOB = '" + assignments['HOLDER_02_JOB'] + "'", "HOLDER_JOB = '1a1aecd302a-fc05-6294'")
    replace("LIFECYCLE_MATERIALIZATION_JOB = '" + assignments['LIFECYCLE_MATERIALIZATION_JOB'] + "'", "LIFECYCLE_MATERIALIZATION_JOB = " + repr(lifecycle_job) + "\nSEALED = " + repr(sealed))
    begin = text.index('SELECTED_DIRS = ')
    end = text.index('\n\ndef need(', begin)
    selection = "SELECTED_DIRS = ('campaign-01', 'tools-01', 'boundary-tools-01', 'lifecycle-tools-01')\n"
    selection += "EXTERNAL_DIRS = ('measurement-tools', 'boundary-tools', 'r33-cancel-recovery-01')\n"
    selection += "OPTIONAL_FILES = ('qualification-compact-01.json',)\n"
    selection += "NAMESPACE_PATHS = ('lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01')\n\n"
    selection += 'PINNED = ' + pprint.pformat(pins, sort_dicts=True, width=110) + '\n'
    selection += 'REQUIRED = tuple(PINNED)\n'
    text = text[:begin] + selection + text[end:]
    replace('source outside explicit R31/R16 mapping', 'source outside explicit R33/R16 mapping')
    replace("    prior = read('campaign-01/report.json')\n", '')
    text = text.replace('campaign-02/', 'campaign-01/')
    replace("parent.get('attempt') == '02'", "parent.get('attempt') == '01'")
    text = text.replace('r31-cancel-recovery-02', 'r33-cancel-recovery-01')
    replace("        ('observation-01', 'observation-holder', HOLDER_01_JOB),\n        ('observation-02', 'observation-holder', HOLDER_02_JOB),", "        ('observation-01', 'observation-holder', HOLDER_JOB),")
    replace("        attempt = '02' if label == 'observation-02' else '01'", "        attempt = '01'")
    text = text.replace('HOLDER_02_JOB', 'HOLDER_JOB')
    replace("        'prior_observation_preflight_failure': {'job_id': HOLDER_01_JOB, 'reported_passed': prior.get('passed'),\n            'error': prior.get('error'), 'stages': prior.get('stages'), 'quiescence_present': 'quiescence' in prior},\n", '')
    replace("def create_archive():\n", "def create_archive():\n    need(SEALED and LIFECYCLE_MATERIALIZATION_JOB is not None\n         and all(isinstance(value, str) and len(value) == 64 for value in PINNED.values()),\n         'unsealed R33 collector: original receipt identities are still missing')\n")
    text = text.replace('hepta-r31-observation-evidence-archive/v1', 'hepta-r33-observation-evidence-archive/v1')
    text = text.replace("'r31_directories'", "'r33_directories'").replace("'optional_r31_files'", "'optional_r33_files'")
    ast.parse(text)
    assert 'HOLDER_01_JOB' not in text and 'HOLDER_02_JOB' not in text
    assert 'prior_observation_preflight_failure' not in text and 'campaign-02' not in text
    assert '20261105-r31' not in text and 'r31-cancel-recovery' not in text
    args.out.mkdir(parents=True, exist_ok=False)
    name = 'archive_r33_observation.py' if sealed else 'archive_r33_observation.unsealed.py'
    with (args.out / name).open('x') as stream:
        stream.write(text)
    info = {'schema': 'hepta-r33-observation-archiver-preparation/v1', 'sealed': sealed,
            'reference': {'git_blob': 'a159114d1f51e4d409b47ca07531d585b002eb69', 'sha256': REFERENCE_SHA},
            'script': {'name': name, 'bytes': len(text.encode()), 'sha256': digest(text.encode())},
            'missing_sha256': missing, 'missing_lifecycle_job': lifecycle_job is None,
            'bindings_sha256': digest(args.actual_bindings.read_bytes()) if bindings else None,
            'collector_executed': False, 'auditors_reexecuted': False, 'remote_calls': 0}
    with (args.out / 'preparation.json').open('x') as stream:
        json.dump(info, stream, sort_keys=True, indent=2);stream.write('\n')
    print(json.dumps(info, sort_keys=True))


if __name__ == '__main__':
    main()
