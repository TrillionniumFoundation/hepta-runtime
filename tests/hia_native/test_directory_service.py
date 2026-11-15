"""Actual static-ELF directory caller, configuration, Session, policy and fence."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from directory_service_support import OBSERVED, Session, configuration, exclusive, require

HERE = Path(__file__).resolve().parents[2]
SETTINGS = None
CAPTURED = []
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def meta(workdir, **extra):
    return json.dumps({'io.modelcontextprotocol/clientCapabilities':
        {'experimental': {'session': {'workdir': str(workdir)}}}, **extra}, separators=(',', ':')).encode()


def legacy(workdir):
    return json.dumps({'experimental': {'session': {'workdir': str(workdir)}}}, separators=(',', ':')).encode()


def snapshot(root):
    """Full owned visible effects, retaining raw Unix names without following links."""
    output = []
    root = os.fsencode(root)
    def walk(directory, prefix):
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            rel = prefix + name
            info = os.lstat(path)
            row = {'path_hex': rel.hex(), 'mode': stat.S_IMODE(info.st_mode)}
            if stat.S_ISDIR(info.st_mode):
                row['kind'] = 'directory'; output.append(row); walk(path, rel + b'/')
            elif stat.S_ISLNK(info.st_mode):
                row.update(kind='symlink', target_hex=os.readlink(path).hex()); output.append(row)
            elif stat.S_ISREG(info.st_mode):
                raw = Path(os.fsdecode(path)).read_bytes()
                row.update(kind='file', bytes=len(raw), sha256=sha(raw)); output.append(row)
            else:
                raise AssertionError(('unexpected fixture inode type', rel))
    walk(root, b'')
    return output


def fixture(name, *, installed=True, fenced=False, root_kind='normal', roots_kind='workspace'):
    base = SETTINGS.output / 'fixtures' / name
    if base.exists():
        shutil.rmtree(base)
    base.parent.mkdir(parents=True, exist_ok=True)
    work, config, env = configuration(base, fence=fenced)
    alternative = work / 'alternate'; alternative.mkdir(mode=0o700)
    outside = base / 'outside'; outside.mkdir(mode=0o700)
    (work / 'existing').mkdir(mode=0o700)
    (work / 'ordinary').write_bytes(b'original file content')
    (work / 'ordinary').chmod(0o600)
    (work / 'link-in').symlink_to(work / 'existing', target_is_directory=True)
    (work / 'link-out').symlink_to(outside, target_is_directory=True)
    if roots_kind != 'workspace':
        data = json.loads(config.read_bytes())
        data['controller_workspace_roots'] = [] if roots_kind == 'empty' else [str(base)]
        config.write_text(json.dumps(data))
    root = work
    if root_kind == 'raw':
        root = Path(os.fsdecode(os.fsencode(work) + b'/raw-\xff'))
        root.mkdir(mode=0o700)
    elif root_kind == 'remote':
        root = Path('ssh://h/remote')
    elif root_kind == 'relative':
        root = Path('qualification-relative-root')
    return base, work, alternative, outside, root, config if installed else None, env


def scenario(name, build, *, installed=True, fenced=False, root_kind='normal', roots_kind='workspace',
             mode=0, legacy_kind=None, env_override=None, close_stderr=False, blocked_sigchld=False):
    def one(reference):
        base, work, alternative, outside, root, config, env = fixture(name, installed=installed,
            fenced=fenced, root_kind=root_kind, roots_kind=roots_kind)
        env.update(env_override or {})
        initial = snapshot(base)
        old = legacy(alternative) if legacy_kind == 'alternate' else legacy(outside) if legacy_kind == 'outside' else None
        if legacy_kind == 'invalid-known':
            old = b'{"roots":{"listChanged":null}}'
        operations = build(base, work, alternative, outside)
        before = len(OBSERVED)
        results = []
        with Session(SETTINGS.manifest, root, config=config, mode=mode, legacy=old, env=env,
                     close_stderr=close_stderr, blocked_sigchld=blocked_sigchld, reference=reference) as session:
            for number, (path, metadata, expected) in enumerate(operations, 1):
                tag, text = session.complete(number, path, metadata)
                if expected is not None:
                    require(tag == expected, (name, number, path, tag, text))
                results.append({'id': number, 'tag': tag, 'text_hex': text.hex()})
                if fenced:
                    with (base / 'authority/.owner.lock').open('rb') as lock:
                        require(exclusive(lock), 'finished caller leaked an actual fence permit')
        require(len(OBSERVED) == before + 1, 'process receipt missing')
        final = snapshot(base)
        record = {'name': name, 'variant': 'original' if reference else 'native', 'results': results,
                  'before': initial, 'after': final, 'process': OBSERVED[-1]}
        # Closed fixtures include symlinks. Preserve their complete observed
        # names/type/mode/content/target above, then remove only this owned tree.
        shutil.rmtree(base)
        CAPTURED.append(record)
        return record
    native = one(None)
    if SETTINGS.reference:
        original = one(SETTINGS.reference)
        require(native['before'] == original['before'], (name, 'before fixture mismatch'))
        require(native['results'] == original['results'], (name, 'actual original results differ', native['results'], original['results']))
        require(native['after'] == original['after'], (name, 'actual filesystem effects differ', native['after'], original['after']))
    return native


class DirectoryServiceTests(unittest.TestCase):
    def test_actual_create_and_safe_refusals(self):
        def paths(base, work, alternative, outside):
            good = ['new/a/b', 'new/a/b', 'existing', 'space name/child', '雪/🙂',
                    'trailing///', './dot/./nested', 'pre|post', ' leading ', '\tblank\n', 'a\\b']
            bad = ['', ' ', '|empty', 'ordinary', 'ordinary/child', 'link-in/child',
                   'link-out/child', '../outside/refused', 'new/../unsafe', 'nul\0name',
                   'x' * 256, str(outside / 'refused'), 'octofs://resource', '/']
            return [(p, None, 0) for p in good] + [(p, None, 1) for p in bad]
        scenario('safe-paths', paths)

    def test_preflight_and_body_are_distinct(self):
        def paths(base, work, alternative, outside):
            return [('one | two', None, 0), ('one|', None, 1), ('  ', None, 1),
                    ('\u3000trimmed\u3000', None, 0), ('a\u0085|\u2003b', None, 0),
                    ('ssh://missing/remote', None, 1), ('ssh://h/remote/new', None, 1),
                    ('sftp://operator@h/remote/new', None, 1), ('ssh://h:22/remote/new', None, 1),
                    (' ssh://h/remote/new', None, 1), (str(work) + '//abs/leaf', None, 0)]
        scenario('preflight', paths)
        scenario('no-roots', lambda *_: [('child', None, 1)], roots_kind='empty')
        scenario('relative-root', lambda *_: [('child', None, 1)], root_kind='relative')
        scenario('remote-root', lambda *_: [('child', None, 1)], root_kind='remote')

    def test_installed_absent_and_fence_order(self):
        scenario('absent', lambda *_: [('child', None, 1), ('', None, 1), ('ssh://h/path', None, 1)], installed=False)
        scenario('absent-required', lambda *_: [('child', None, 1)], installed=False,
                 env_override={'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '1'})
        scenario('fenced', lambda *_: [('one/two', None, 0), ('one/two', None, 0), ('ordinary', None, 1)], fenced=True)
        scenario('wrong-owner', lambda *_: [('child', None, 1)], fenced=True,
                 env_override={'HEPTA_EFFECT_OWNER_SELF': 'different'})

    def test_full_metadata_first_latch(self):
        scenario('modern-meta', lambda b,w,a,o: [('one', meta(a), 0), ('two', meta(w), 0)], mode=1)
        scenario('legacy-fallback', lambda b,w,a,o: [('one', None, 0), ('two', meta(w), 0)], legacy_kind='alternate')
        scenario('modern-no-fallback', lambda b,w,a,o: [('one', None, 0)], mode=1, legacy_kind='alternate')
        scenario('invalid-modern-capabilities', lambda b,w,a,o: [('one', b'{"io.modelcontextprotocol/clientCapabilities":{"experimental":{"session":7}}}', 0), ('two', meta(a), 0)], mode=1)
        scenario('outside-workdir', lambda b,w,a,o: [('one', meta(o), 0)], mode=1)
        scenario('unknown-meta', lambda b,w,a,o: [('one', b'{"unknown":[1,2]}', 0), ('two', meta(a), 0)], mode=1)
        scenario('duplicate-meta', lambda b,w,a,o: [('one', b'{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientCapabilities":'+legacy(a)+b'}', 0)], mode=1)
        scenario('legacy-meta-fallback', lambda b,w,a,o: [('one', b'{"io.modelcontextprotocol/clientCapabilities":null}', 0)], legacy_kind='alternate')

    def test_raw_root_and_descriptor_signal_custody(self):
        scenario('raw-root', lambda *_: [('child', None, 0), ('child', None, 0)], root_kind='raw')
        scenario('closed-stderr', lambda *_: [('one', None, 0), ('two', None, 0)], fenced=True, close_stderr=True)
        scenario('blocked-child-signal', lambda *_: [('one', None, 0), ('two', None, 0)], fenced=True, blocked_sigchld=True)
        scenario('missing-user', lambda *_: [('child', None, 0)], env_override={'USER': None})
        scenario('empty-user', lambda *_: [('child', None, 0)], env_override={'USER': ''})


def main():
    global SETTINGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--reference-sha256')
    SETTINGS = parser.parse_args()
    SETTINGS.output = SETTINGS.output.resolve()
    SETTINGS.output.mkdir(parents=True, exist_ok=False)
    if SETTINGS.reference is not None:
        require(SETTINGS.reference_sha256 is not None, 'original binary pin required')
        SETTINGS.reference = {'path': str(SETTINGS.reference), 'sha256': SETTINGS.reference_sha256}
    before = {str(p.relative_to(HERE)): sha(p.read_bytes()) for p in [Path(__file__).resolve(), Path(__file__).with_name('directory_service_support.py')]}
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DirectoryServiceTests))
    summary = dict(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
        skipped=len(result.skipped), expected_failures=len(result.expectedFailures), unexpected_successes=len(result.unexpectedSuccesses))
    expected = dict(tests_run=5, failures=0, errors=0, skipped=0, expected_failures=0, unexpected_successes=0)
    after = {name: sha((HERE / name).read_bytes()) for name in before}
    counts = dict(native_processes=sum(x['variant'] == 'native' for x in CAPTURED),
        original_processes=sum(x['variant'] == 'original' for x in CAPTURED),
        native_requests=sum(len(x['results']) for x in CAPTURED if x['variant'] == 'native'),
        original_requests=sum(len(x['results']) for x in CAPTURED if x['variant'] == 'original'))
    expected_counts = dict(native_processes=22, native_requests=67,
        original_processes=22 if SETTINGS.reference else 0, original_requests=67 if SETTINGS.reference else 0)
    report = {'schema':'hepta.directory-service.functional.v1', 'status':'PASS' if summary == expected and before == after and counts == expected_counts else 'FAIL',
        'test_summary':summary, 'expected_test_summary':expected, 'source_sha256':before, 'source_unchanged':before == after,
        'cases':CAPTURED, **counts, 'expected_counts':expected_counts,
        'elapsed_seconds':time.monotonic()-started, 'production_activated':False, 'public_mcp_transport_complete':False,
        'whole_runtime_replaced':False}
    path = SETTINGS.output / 'report.json'
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k:report[k] for k in ('status','test_summary','native_processes','original_processes','native_requests','original_requests','elapsed_seconds')}))
    if report['status'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
