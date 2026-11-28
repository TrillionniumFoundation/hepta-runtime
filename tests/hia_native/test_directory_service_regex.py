"""Real installed regex continuations before the unchanged directory caller."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from directory_service_support import OBSERVED, Session, configuration, exclusive, require
from test_directory_service import snapshot

ROOT = Path(__file__).resolve().parents[2]
SETTINGS = None
CASES = []
sha = lambda raw: hashlib.sha256(raw).hexdigest()
VALID = (
    ('literal', ['a']),
    ('character-class', [r'[a-z]+']),
    ('unicode-property', [r'\p{Greek}+']),
    ('anchored-wrapper-alternation', [r')|foo(?:']),
    ('size-bound-accepted', ['a{327674}']),
    ('ordered-multiple', ['a', r'\p{Greek}+', r')|foo(?:']),
)
INVALID = (
    ('syntax', '('), ('unicode-size', r'\w{500}'),
    ('size-bound-refused', 'a{327675}'), ('invalid-byte', r'(?-u:\xFF)'),
)
DOMAIN = tuple(name for name, _ in INVALID) + (
    'regex-before-later-action', 'earlier-action-before-regex') + tuple(name for name, _ in VALID)


def action(patterns):
    return {'executable': '/echo', 'allow_extra_args': True, 'extra_arg_patterns': patterns}


def one(name, actions, reference, error=None):
    base = SETTINGS.output / 'fixtures' / name
    require(not base.exists(), 'regex fixture was not retired')
    work, config, env = configuration(base, fence=error is None)
    state = base / 'state'
    (work / 'ordinary').write_bytes(b'original file bytes')
    (work / 'ordinary').chmod(0o600)
    value = json.loads(config.read_bytes())
    value['hosts']['h']['privileged_actions'] = actions
    config.write_text(json.dumps(value, sort_keys=True))
    before = snapshot(base)
    observed = len(OBSERVED)
    session = Session(SETTINGS.manifest, work, config=config, env=env, reference=reference)
    results = []
    try:
        if error is not None:
            session.process.stdin.close(); session.process.stdin = None
            stdout, stderr = session.process.communicate(timeout=30)
            require((session.process.returncode, stdout, stderr) == (78, b'', error + b'\n'),
                    (name, 'actual startup refusal differs', session.process.returncode, stdout, stderr))
            require(not state.exists(), 'invalid regex caused state installation effects')
            require(not Path('/proc', str(session.process.pid)).exists(), 'startup process was not reaped')
            process = {'variant': session.variant, 'elf_sha256': sha(session.exe.read_bytes()),
                'pid': session.process.pid, 'exit_code': 78, 'reaped': True, 'events': [],
                'input_hex': '', 'output_hex': stdout.hex(), 'snapshot_hex': session.snapshot.hex(),
                'stderr_hex': stderr.hex(), 'elapsed_seconds': time.monotonic() - session.started}
            session.closed = True
        else:
            tag, text = session.complete(1, 'first/child')
            require(tag == 0, (name, 'valid installed regex refused', tag, text))
            results.append({'id': 1, 'tag': tag, 'text_hex': text.hex()})
            for lock_name in ('controller.owner.lock', 'controller.lock'):
                with (state / lock_name).open('rb') as lock:
                    require(not exclusive(lock), 'installed config lock not retained')
            # Editing the administrator pathname after installation cannot
            # replace the immutable configuration used by ordinary tool calls.
            changed = dict(value, state_dir=str(base / 'not-installed'))
            changed['hosts'] = {'h': dict(value['hosts']['h'], privileged_actions={'inspect': action(['('])})}
            config.write_text(json.dumps(changed, sort_keys=True))
            for number, path, expected in [(2, 'second/child', 0), (3, 'ordinary/child', 1)]:
                tag, text = session.complete(number, path)
                require(tag == expected, (name, number, tag, text))
                results.append({'id': number, 'tag': tag, 'text_hex': text.hex()})
                with (base / 'authority/.owner.lock').open('rb') as lock:
                    require(exclusive(lock), 'completed regex-profile caller leaked a fence permit')
            require(not (base / 'not-installed').exists(), 'ordinary request reinstalled changed config')
            session.close()
            require(len(OBSERVED) == observed + 1, 'actual regex-profile process observation missing')
            process = OBSERVED[-1]
            for lock_name in ('controller.owner.lock', 'controller.lock'):
                with (state / lock_name).open('rb') as lock:
                    require(exclusive(lock), 'completed process leaked installed config locks')
        after = snapshot(base)
        row = {'name': name, 'variant': session.variant, 'startup_error_hex': None if error is None else error.hex(),
               'before': before, 'after': after, 'results': results, 'process': process}
        CASES.append(row)
        shutil.rmtree(base)
        return row
    finally:
        if not session.closed:
            if session.process.poll() is None:
                session.process.kill()
            session.process.wait()


def paired(name, actions, error=None):
    native = one(name, actions, None, error)
    if SETTINGS.reference is not None:
        original = one(name, actions, SETTINGS.reference, error)
        for field in ('before', 'after', 'results', 'startup_error_hex'):
            require(native[field] == original[field], (name, 'actual original regex domain differs', field))
        require(native['process']['input_hex'] == original['process']['input_hex']
                and native['process']['output_hex'] == original['process']['output_hex']
                and native['process']['snapshot_hex'] == original['process']['snapshot_hex'],
                'actual original full regex-profile streams differ')


class DirectoryRegexTests(unittest.TestCase):
    def test_actual_valid_regex_then_immutable_directory_authority(self):
        for name, patterns in VALID:
            paired(name, {'inspect': action(patterns)})

    def test_actual_invalid_regex_before_state_effects(self):
        for name, pattern in INVALID:
            paired(name, {'inspect': action([pattern])}, b'host `h` privileged action `inspect` has invalid argument regex')

    def test_actual_original_action_order(self):
        actions = {'middle': action(['a', '(']), 'zlast': {'executable': 'relative'}}
        paired('regex-before-later-action', actions,
               b'host `h` privileged action `middle` has invalid argument regex')
        paired('earlier-action-before-regex', dict(actions, afirst={'executable': 'relative'}),
               b'host `h` has invalid privileged action `afirst`')


def main():
    global SETTINGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--reference-sha256')
    SETTINGS = parser.parse_args()
    SETTINGS.output = SETTINGS.output.resolve(); SETTINGS.output.mkdir(parents=True, exist_ok=False)
    if SETTINGS.reference is not None:
        require(SETTINGS.reference_sha256 is not None, 'actual original image pin required')
        SETTINGS.reference = {'path': str(SETTINGS.reference), 'sha256': SETTINGS.reference_sha256}
    source_paths = [Path(__file__), Path(__file__).with_name('directory_service_support.py'),
                    Path(__file__).with_name('test_directory_service.py')]
    before = {str(path.resolve().relative_to(ROOT)): sha(path.read_bytes()) for path in source_paths}
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DirectoryRegexTests))
    summary = dict(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
        skipped=len(result.skipped), expected_failures=len(result.expectedFailures), unexpected_successes=len(result.unexpectedSuccesses))
    expected_summary = dict(tests_run=3, failures=0, errors=0, skipped=0, expected_failures=0, unexpected_successes=0)
    expected_counts = dict(native_processes=12, original_processes=12 if SETTINGS.reference else 0,
        native_requests=18, original_requests=18 if SETTINGS.reference else 0,
        native_startup_refusals=6, original_startup_refusals=6 if SETTINGS.reference else 0)
    counts = {}
    for variant in ('native', 'original'):
        selected = [row for row in CASES if row['variant'] == variant]
        counts[variant + '_processes'] = len(selected)
        counts[variant + '_requests'] = sum(len(row['results']) for row in selected)
        counts[variant + '_startup_refusals'] = sum(row['process']['exit_code'] == 78 for row in selected)
    after = {name: sha((ROOT / name).read_bytes()) for name in before}
    report = dict(schema='hepta.directory-service.regex.v1',
        status='PASS' if summary == expected_summary and counts == expected_counts and before == after else 'FAIL',
        test_summary=summary, expected_test_summary=expected_summary, expected_domains=list(DOMAIN),
        expected_counts=expected_counts, **counts, source_sha256=before, source_unchanged=before == after,
        manifest_sha256=sha(SETTINGS.manifest.read_bytes()), cases=CASES,
        elapsed_seconds=time.monotonic() - started, production_activated=False, whole_runtime_replaced=False)
    (SETTINGS.output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key not in ('cases', 'source_sha256')}, sort_keys=True))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
