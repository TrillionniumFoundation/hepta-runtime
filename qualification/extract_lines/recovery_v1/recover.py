"""Recover only inert readers from the exact retained successful semantic capture."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import time
import zipfile

ROOT = Path(__file__).resolve().parent
HEAD = 'a1ad1d8b2fb8d0944c8348f6760b1ef5e1f1b43b'
SOURCE = 'ab117630de23d39dec8f909afba5460690c04fd2ed0e7f351ba65903fbf198b0'
ARTIFACT = 14274914569
ZIP = dict(bytes=90994723, sha256='51b283457a9c1901dbb04d2f671333aa7a420cd8fc9c14b49157f91ad9cfc4d4')
TAR = dict(bytes=91663536, sha256='7e5c31baa0a05026f461891dd1c0ef7ffcd7af4b13b0086c877a03f84a7f7bb5')


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def loads(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def pin(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and path.resolve() == path.absolute(), 'ordinary retained file')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.lstat()
    identity = lambda row: (row.st_mode, row.st_size, row.st_mtime_ns, row.st_ctime_ns, row.st_ino, row.st_dev)
    require(identity(before) == identity(after), 'stable complete retained file')
    return dict(bytes=before.st_size, sha256=digest)


def safe(name):
    require(type(name) is str and name and not name.startswith('/') and '\0' not in name
            and all(x not in ('', '.', '..') for x in name.split('/')), 'canonical archive path')
    return Path(*name.split('/'))


def files(root):
    result = {}
    for path in sorted(Path(root).rglob('*')):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'ordinary archive entry')
        if stat.S_ISREG(info.st_mode):
            result[path.relative_to(root).as_posix()] = dict(**pin(path), mode=stat.S_IMODE(info.st_mode))
    return result


def source(expected):
    manifest = ROOT / 'RECOVERY_SOURCE.json'
    require(pin(manifest)['sha256'] == expected, 'explicit frozen recovery source')
    data = loads(manifest.read_bytes())
    actual = files(ROOT)
    actual.pop('RECOVERY_SOURCE.json')
    require(data['files'] == actual and data['producer_source_head'] == HEAD
            and data['producer_source_manifest_sha256'] == SOURCE
            and data['original_artifact'] == ARTIFACT and data['original_zip'] == ZIP,
            'complete frozen recovery source, producer and domain')
    return data


def expand(archive, output):
    require(pin(archive) == ZIP, 'exact retained failed artifact ZIP')
    outer = output / 'outer'
    outer.mkdir()
    outer_rows = {}
    with zipfile.ZipFile(archive) as bundle:
        for item in bundle.infolist():
            require(not item.is_dir() and item.filename not in outer_rows
                    and not stat.S_ISLNK(item.external_attr >> 16), 'regular unique ZIP member')
            target = outer / safe(item.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(item) as reader, target.open('xb') as writer:
                shutil.copyfileobj(reader, writer, 1024 * 1024)
            require(target.stat().st_size == item.file_size, 'complete ZIP member')
            outer_rows[item.filename] = dict(**pin(target), zip_mode=item.external_attr >> 16)
    require(set(outer_rows) == {'extract-lines-body.tar.gz', 'extract-lines-body.tar.gz.json',
                              'extract-lines-body-export.stdout', 'extract-lines-body-export.stderr'},
            'all original artifact files')
    tar_path = outer / 'extract-lines-body.tar.gz'
    receipt = loads((outer / 'extract-lines-body.tar.gz.json').read_bytes())
    require(pin(tar_path) == TAR == {k: receipt[k] for k in ('bytes', 'sha256')}
            and receipt['all_members_reread'] is True, 'full retained TAR and original receipt')
    expanded = output / 'retained'
    expanded.mkdir()
    observed = {}
    with tarfile.open(tar_path, 'r|gz') as bundle:
        while item := bundle.next():
            require(item.isfile() and item.name not in observed, 'unique regular TAR member')
            target = expanded / safe(item.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(item) as reader, target.open('xb') as writer:
                shutil.copyfileobj(reader, writer, 1024 * 1024)
            target.chmod(item.mode & 0o777)
            require(target.stat().st_size == item.size, 'complete TAR member')
            observed[item.name] = dict(**pin(target), mode=item.mode & 0o777)
            bundle.members.clear()
    metadata = loads((expanded / 'artifact-manifest.json').read_bytes())
    expected = dict(metadata['files'])
    expected['artifact-manifest.json'] = dict(**pin(expanded / 'artifact-manifest.json'), mode=0o644)
    require(observed == expected == files(expanded) and len(observed) == receipt['files'] == 4810
            and sum(row['bytes'] for row in observed.values()) == receipt['logical_bytes'] == 322127020,
            'every original source and evidence file, complete bytes and modes')
    require(metadata['git_head'] == HEAD and metadata['run_id'] == '43964900937'
            and metadata['gate_status'] == 'FAIL'
            and pin(expanded / 'source/SOURCE_MANIFEST.json')['sha256'] == SOURCE,
            'retained source and original failed gate identity')
    require(pin(expanded / 'run/GATE.json') == dict(bytes=1843,
            sha256='2cf5cd8d2fd793e9f34b9a72f9a7df9633b87928fd7748e45be04fc6eba7c33d'),
            'original failure is preserved exactly')
    require(pin(expanded / 'run/reader-processes/readonly-semantic.stderr') == dict(bytes=3067,
            sha256='91c0a0bdaa8514048e53eb58893a0e225932ea72d17808da120c9e437b413f83'),
            'exact original lazy gzip guard refusal')
    record = dict(schema='hepta.extract-lines.retained-artifact-readback.v1', artifact=ARTIFACT,
                  producer_source_head=HEAD, source_manifest_sha256=SOURCE, zip=ZIP, tar=TAR,
                  files=4810, logical_bytes=322127020, all_members_reread=True,
                  outer_files=outer_rows, original_gate_preserved=True, semantic_reexecutions=0)
    (output / 'ORIGINAL_READBACK.json').write_bytes(encoded(record))
    return expanded


PRELOAD = '''import sys,json,gzip
from pathlib import Path
source=Path(sys.argv[1]);output=Path(sys.argv[2]);sys.path.insert(0,str(source));sys.dont_write_bytecode=True
import read_capture,reader_controls
from read_only_guard import guarded
from common import source as verify_source
assert verify_source()==sys.argv[3]
'''
SEMANTIC = PRELOAD + '''proof=guarded(lambda:read_capture.semantic(output/'semantic'),roots=[source,output/'semantic'],foreign_path=Path('/dev/null'))
assert proof['before']==proof['after'] and len(proof['probes'])==12
assert proof['native_or_rust_executions']==proof['reader_writes']==0
print(json.dumps(proof,sort_keys=True,allow_nan=False))
'''
CONTROLS = PRELOAD + "reader_controls.run(output,sys.argv[3])\n"
COMPLETE = PRELOAD + '''proof=guarded(lambda:read_capture.verify(output,require_controls=True),roots=[source,output],foreign_path=Path('/dev/null'))
assert proof['before']==proof['after'] and len(proof['probes'])==12
assert proof['native_or_rust_executions']==proof['reader_writes']==0
print(json.dumps(proof,sort_keys=True,allow_nan=False))
'''


def run(archive, output, expected_source):
    frozen = source(expected_source)
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    result = dict(schema='hepta.extract-lines.retained-recovery.v1', status='FAIL',
                  producer_source_head=HEAD, source_manifest_sha256=SOURCE,
                  recovery_source_manifest_sha256=expected_source, original_artifact=ARTIFACT,
                  original_gate_status='FAIL', native_or_rust_reexecutions=0,
                  reader_deadline_seconds=180, full_body_async_qualified=False,
                  public_handler_qualified=False, remote_qualified=False, whole_runtime_replaced=False,
                  recovery_git_head=os.environ.get('GITHUB_SHA'), recovery_run_id=os.environ.get('GITHUB_RUN_ID'))
    try:
        shutil.copytree(ROOT, output / 'reader-source')
        expanded = expand(archive, output)
        retained_source = expanded / 'source'
        qualified = output / 'qualification'
        qualified.mkdir()
        shutil.copytree(expanded / 'run/semantic', qualified / 'semantic')
        require(files(expanded / 'run/semantic') == files(qualified / 'semantic'), 'complete independent semantic relocation')
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(retained_source))
        from process import Recorder
        recorder = Recorder(retained_source, output / 'recovery-processes')
        proofs = {}
        for name, script in (('readonly-semantic', SEMANTIC), ('reader-controls', CONTROLS),
                             ('readonly-complete', COMPLETE), ('independent-readonly-complete', COMPLETE)):
            raw, process = recorder.run(name, [sys.executable, '-I', '-B', '-c', script,
                retained_source, qualified, SOURCE], timeout=180)
            parsed = loads(raw)
            if name == 'reader-controls':
                require(parsed == dict(status='PASS', refusals=8, relocated_admissions=2,
                    post_refusal_admissions=2, guard_proofs=12, native_or_rust_executions=0),
                    'all fixed physical reader controls')
            else:
                require(parsed['before'] == parsed['after'] and len(parsed['probes']) == 12
                        and parsed['native_or_rust_executions'] == parsed['reader_writes'] == 0,
                        'complete bounded inert reader')
                proofs[name] = parsed['evidence']
        require(proofs['readonly-complete'] == proofs['independent-readonly-complete'],
                'fresh independent complete admission')
        complete = dict(proofs['readonly-complete'])
        controls = complete.pop('reader_controls')
        require(complete == proofs['readonly-semantic'] and controls == dict(status='PASS', refusals=8,
                relocated_admissions=2, post_refusal_admissions=2, guard_proofs=12, guards_per_proof=12,
                native_or_rust_executions=0, reader_writes=0), 'unchanged semantic evidence and full controls')
        require(source(expected_source) == frozen, 'frozen recovery source remains complete')
        require(files(expanded / 'run/semantic') == files(qualified / 'semantic'), 'original semantic bytes remain unchanged')
        result.update(status='COMPLETE_LOCAL_EXTRACT_BODY_RETAINED_READERS_PASS',
                      evidence=proofs['readonly-complete'], actual_reader_processes=4,
                      stdlib_gzip_preloaded_before_guard=True, semantic_evidence_replayed=False)
    except BaseException as failure:
        result.update(failure_type=type(failure).__name__, failure=str(failure))
        raise
    finally:
        result['elapsed_seconds'] = time.monotonic() - started
        (output / 'RECOVERY.json').write_bytes(encoded(result))
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    run(args.archive.resolve(strict=True), args.output.absolute(), args.source_manifest_sha256)
