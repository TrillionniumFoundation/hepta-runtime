"""Inert full-byte archive reader binding every retained process and physical proof."""
from pathlib import Path
import argparse
import gzip
import hashlib
import signal
import sys
import tarfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from recover import ARTIFACT, COMPLETE, CONTROLS, HEAD, SEMANTIC, SOURCE, TAR, ZIP
from recover import encoded, loads, pin, require, safe, source

ERRORS = {
    'native-image': 'native module identity',
    'original-source': 'all actual original source bytes and modes',
    'compiler-tail': 'complete compiler output and tail',
    'response-bytes': 'byte-exact original/native stdout',
    'owner-arena-tail': 'native cache used extent or complete tail differs',
    'wait-return': 'all actual physical wait returns',
    'missing-case': 'every ordinary case exactly once',
    'process-budget': 'actual process command and original budget',
}
ADMISSIONS = ['relocation-a', 'relocation-b', 'post-refusal-a', 'post-refusal-b']
PROBES = ['python-file-write', 'descriptor-open', 'descriptor-write', 'metadata-mode',
    'metadata-time', 'directory-create', 'subprocess', 'shell', 'native-dlopen',
    'native-mmap', 'producer-or-foreign-read', 'unadmitted-file-descriptor']


def expired(_signum, _frame):
    raise TimeoutError('original 180 second independent archive reader budget')


def read_archive(archive, expected_source):
    source(expected_source)
    started = time.monotonic()
    whole = pin(archive)
    receipt = loads(archive.with_suffix(archive.suffix+'.json').read_bytes())
    require({key: receipt[key] for key in ('bytes', 'sha256')} == whole
            and receipt['all_members_reread'] is receipt['all_physical_files_reread'] is True,
            'entire independent recovery archive and receipt')
    with tarfile.open(archive, 'r|gz') as bundle:
        first = bundle.next()
        require(first is not None and first.isfile() and first.name == 'manifest.json'
                and first.mode == 0o644, 'canonical complete archive map')
        raw = bundle.extractfile(first).read()
        require(len(raw) == first.size, 'entire archive map')
        meta = loads(raw)
        table = meta['files']
        require(meta['schema'] == 'hepta.extract-lines.recovery-archive.v1'
                and meta['producer_source_head'] == HEAD and meta['source_manifest_sha256'] == SOURCE
                and meta['recovery_source_manifest_sha256'] == expected_source
                and meta['original_artifact'] == ARTIFACT and meta['semantic_reexecutions'] == 0
                and meta['whole_runtime_replaced'] is False
                and meta['status'] == 'COMPLETE_LOCAL_EXTRACT_BODY_RETAINED_READERS_PASS',
                'frozen producer, reader and recovered finite domain')
        unique = {}
        for name, row in table.items():
            safe(name)
            require(set(row) == {'bytes', 'sha256', 'mode'} and type(row['bytes']) is int and row['bytes'] >= 0
                    and type(row['mode']) is int and 0 <= row['mode'] <= 0o7777
                    and len(row['sha256']) == 64 and all(c in '0123456789abcdef' for c in row['sha256']),
                    'complete logical file identity')
            if row['sha256'] in unique:
                require(unique[row['sha256']] == row['bytes'], 'exact deduplicated length')
            unique[row['sha256']] = row['bytes']
        require(meta['logical_files'] == receipt['logical_files'] == len(table)
                and meta['logical_bytes'] == receipt['logical_bytes'] == sum(r['bytes'] for r in table.values())
                and meta['unique_contents'] == receipt['unique_contents'] == len(unique)
                and meta['unique_content_bytes'] == receipt['unique_content_bytes'] == sum(unique.values()),
                'all complete logical files and unique bytes')
        needed = {'RECOVERY.json', 'ORIGINAL_READBACK.json', 'reader-source/RECOVERY_SOURCE.json',
            'retained/source/SOURCE_MANIFEST.json', 'retained/artifact-manifest.json',
            'retained/run/GATE.json', 'qualification/CONTROLS.json',
            'qualification/semantic/CAPTURE.json', 'recovery-processes/processes.json'}
        for name in ['readonly-semantic', 'reader-controls', 'readonly-complete', 'independent-readonly-complete']:
            needed.add('recovery-processes/'+name+'.stdout')
        for name in list(ERRORS)+ADMISSIONS:
            needed.add('qualification/controls/'+name+'/PROOF.json')
            needed.add('qualification/controls/'+name+'/capture/CAPTURE.json')
        require(needed <= set(table), 'all physical admissions and refusal records retained')
        wanted = {table[name]['sha256'] for name in needed}
        content = {}
        seen = set()
        bundle.members.clear()
        while item := bundle.next():
            require(item.isfile() and item.mode == 0o644 and item.name.startswith('blobs/'), 'ordinary complete content blob')
            digest = item.name[6:]
            require(digest in unique and digest not in seen and item.size == unique[digest], 'exact unique content set')
            with bundle.extractfile(item) as stream:
                if digest in wanted:
                    data = stream.read()
                    require(len(data) == item.size, 'entire retained proof or declaration')
                    actual = hashlib.sha256(data).hexdigest()
                    content[digest] = data
                else:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            require(actual == digest, 'every full retained blob SHA256')
            seen.add(digest)
            bundle.members.clear()
        require(seen == set(unique) and set(content) == wanted, 'every retained byte is independently read')

    def raw(name):
        return content[table[name]['sha256']]

    def data(name):
        return loads(raw(name))

    def mapping(prefix):
        return {name[len(prefix):]: row for name, row in table.items() if name.startswith(prefix)}

    def file_pin(name):
        return {key: table[name][key] for key in ('bytes', 'sha256')}

    old_source = mapping('retained/source/')
    original_manifest = data('retained/source/SOURCE_MANIFEST.json')
    require(file_pin('retained/source/SOURCE_MANIFEST.json')['sha256'] == SOURCE
            and set(old_source) == set(original_manifest['files']) | {'SOURCE_MANIFEST.json'}, 'complete exact producer source set')
    for name, row in original_manifest['files'].items():
        require(old_source[name] == dict(**row, mode=0o644), 'full producer source bytes and mode')
    recovery_manifest = data('reader-source/RECOVERY_SOURCE.json')
    recovery_files = mapping('reader-source/')
    require(recovery_files.pop('RECOVERY_SOURCE.json')['sha256'] == expected_source
            and recovery_files == recovery_manifest['files'], 'complete exact inert recovery source')
    archived_original = data('retained/artifact-manifest.json')
    actual_original = mapping('retained/')
    actual_original.pop('artifact-manifest.json')
    require(actual_original == archived_original['files'] and archived_original['git_head'] == HEAD
            and archived_original['run_id'] == '43964900937' and archived_original['gate_status'] == 'FAIL',
            'every original failed artifact byte and mode preserved')
    original = data('ORIGINAL_READBACK.json')
    require(original['zip'] == ZIP and original['tar'] == TAR and original['files'] == 4810
            and original['logical_bytes'] == 322127020 and original['all_members_reread'] is True
            and original['semantic_reexecutions'] == 0 and data('retained/run/GATE.json')['status'] == 'FAIL',
            'complete original archive readback remains retained')
    baseline = mapping('qualification/semantic/')
    require(baseline == mapping('retained/run/semantic/'), 'unchanged complete original semantic evidence')
    envelope = data('qualification/semantic/CAPTURE.json')
    require(envelope['files'] == {name: row for name, row in baseline.items() if name != 'CAPTURE.json'}
            and envelope['source_manifest_sha256'] == SOURCE and envelope['status'] == 'PASS',
            'exact complete original successful semantic envelope')

    def proof(value, capture_prefix):
        require(value['schema'] == 'hepta.runtime.scope-span-readonly.v2'
                and value['source_bound_guard'] is True and value['native_or_rust_executions'] == value['reader_writes'] == 0
                and value['before'] == value['after'] and type(value['pid']) is int and value['pid'] > 1
                and value['ppid'] != value['pid'], 'complete inert physical guard proof')
        require([row['name'] for row in value['probes']] == PROBES
                and all(row['refusal'].startswith('owner-export read-only guard: ') for row in value['probes']),
                'all twelve actual guard refusals')
        for index, expected in enumerate((old_source, mapping(capture_prefix))):
            observed = {name.split(':', 1)[1]: row for name, row in value['before'].items()
                        if name.startswith(str(index)+':') and row['sha256'] is not None}
            require(set(observed) == set(expected), 'every protected complete file retained')
            for name, row in expected.items():
                actual = observed[name]
                require(actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256']
                        and actual['mode'] & 0o777 == row['mode'], 'complete guard proof content and mode binding')
        return value['evidence']

    control = data('qualification/CONTROLS.json')
    require(control['source_manifest_sha256'] == SOURCE and control['guard_proofs'] == control['guards_per_proof'] == 12
            and control['native_or_rust_executions'] == control['reader_writes'] == 0
            and [row['name'] for row in control['refusals']] == list(ERRORS)
            and [row['name'] for row in control['admissions']] == ADMISSIONS, 'all frozen physical controls')
    semantic_evidence = proof(data('recovery-processes/readonly-semantic.stdout'), 'qualification/semantic/')
    for row in control['refusals'] + control['admissions']:
        name = row['name']
        require(row['capture'] == 'controls/'+name+'/capture'
                and row['proof']['file'] == 'controls/'+name+'/PROOF.json', 'fixed physical control paths')
        prefix = 'qualification/controls/'+name+'/'
        require(file_pin(prefix+'PROOF.json') == {key: row['proof'][key] for key in ('bytes', 'sha256')}, 'complete physical control proof')
        require(proof(data(prefix+'PROOF.json'), prefix+'capture/') == row['evidence'], 'physical control and guard agree')
        actual = mapping(prefix+'capture/')
        if name in ERRORS:
            require(row['evidence'] == dict(status='REFUSED', reason=ERRORS[name]), 'specific source-owned semantic refusal')
            expected = dict(baseline)
            require(row['mutations'], 'physical mutation is nonempty')
            for path, mutation in row['mutations'].items():
                require(mutation['before'] == {key: baseline[path][key] for key in ('bytes', 'sha256')}
                        and mutation['after'] == {key: actual[path][key] for key in ('bytes', 'sha256')},
                        'complete actual mutation before and after bytes')
                expected[path] = dict(**mutation['after'], mode=baseline[path]['mode'])
            rebound = dict(envelope, files={path: item for path, item in expected.items() if path != 'CAPTURE.json'})
            rebound_raw = encoded(rebound)
            expected['CAPTURE.json'] = dict(bytes=len(rebound_raw), sha256=hashlib.sha256(rebound_raw).hexdigest(),
                                            mode=baseline['CAPTURE.json']['mode'])
            require(actual == expected and raw(prefix+'capture/CAPTURE.json') == rebound_raw,
                    'only complete declared physical mutations with fully rebound envelope')
        else:
            require(actual == baseline and row['evidence'] == semantic_evidence, 'complete relocation or post-refusal admission')
    full = proof(data('recovery-processes/readonly-complete.stdout'), 'qualification/')
    independent = proof(data('recovery-processes/independent-readonly-complete.stdout'), 'qualification/')
    require(full == independent and {k: v for k, v in full.items() if k != 'reader_controls'} == semantic_evidence,
            'fresh complete independent semantic and control admissions')
    processes = data('recovery-processes/processes.json')
    names = ['readonly-semantic', 'reader-controls', 'readonly-complete', 'independent-readonly-complete']
    require([row['name'] for row in processes] == names and len({row['pid'] for row in processes}) == 4,
            'four fresh independent bounded reader processes')
    for row, script in zip(processes, (SEMANTIC, CONTROLS, COMPLETE, COMPLETE), strict=True):
        require(row['timeout_seconds'] == 180 and 0 < row['elapsed_seconds'] <= 180 and row['exit_code'] == 0
                and row['timed_out'] is False and row['completed'] is True and row['stdin'] is None
                and row['pgid'] == row['pid'] and row['parent_pid'] != row['pid'], 'original bounded inert process custody')
        argv = row['argv']
        require(len(argv) == 8 and argv[1:5] == ['-I', '-B', '-c', script]
                and argv[5] == row['cwd'] and argv[-1] == SOURCE, 'exact frozen inert reader command')
        for stream in ('stdout', 'stderr'):
            require(row[stream]['file'] == row['name']+'.'+stream
                    and {k: row[stream][k] for k in ('bytes', 'sha256')} == file_pin('recovery-processes/'+row[stream]['file']),
                    'complete bounded process output')
        if row['name'] != 'reader-controls':
            require(data('recovery-processes/'+row['name']+'.stdout')['pid'] == row['pid'], 'actual guard reader process identity')
    result = data('RECOVERY.json')
    require(result['status'] == meta['status'] and result['evidence'] == full and result['actual_reader_processes'] == 4
            and result['source_manifest_sha256'] == SOURCE and result['recovery_source_manifest_sha256'] == expected_source
            and result['native_or_rust_reexecutions'] == 0 and result['semantic_evidence_replayed'] is False
            and result['original_gate_status'] == 'FAIL' and result['reader_deadline_seconds'] == 180,
            'complete retained recovery result')
    return dict(schema='hepta.extract-lines.recovery-archive-readonly.v1',
        status='COMPLETE_LOCAL_EXTRACT_BODY_ARCHIVE_READONLY_PASS', archive=whole,
        producer_source_head=HEAD, recovery_source_manifest_sha256=expected_source,
        source_manifest_sha256=SOURCE, logical_files=len(table), unique_contents=len(unique),
        logical_bytes=meta['logical_bytes'], unique_content_bytes=meta['unique_content_bytes'],
        original_failed_artifact_preserved=True, full_file_bytes_and_modes=True,
        actual_reader_processes=4, physical_refusals=8, relocations=2, post_refusal_admissions=2,
        physical_control_guard_proofs=12, independent_complete_proofs=2, guards_per_proof=12,
        evidence=full, native_or_rust_executions=0, reader_writes=0,
        deadline_seconds=180, elapsed_seconds=time.monotonic()-started,
        full_body_async_qualified=False, public_handler_qualified=False, remote_qualified=False, whole_runtime_replaced=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    result = read_archive(args.archive.resolve(strict=True), args.source_manifest_sha256)
    signal.alarm(0)
    print(encoded(result).decode(), end='')
