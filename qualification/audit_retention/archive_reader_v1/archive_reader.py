"""Independent complete archive and physical-buffer reader; no target code execution."""
from pathlib import Path
import argparse
import base64
import encodings.cp437
import gzip
import hashlib
import io
import json
import os
import stat
import struct
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from read_only_guard import guarded


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def identity():
    raw = (ROOT / 'SOURCE_MANIFEST.json').read_bytes()
    value = json.loads(raw)
    actual = {}
    for path in sorted(ROOT.rglob('*')):
        assert not path.is_symlink()
        if path.is_dir():
            continue
        assert path.is_file()
        name = path.relative_to(ROOT).as_posix()
        if name != 'SOURCE_MANIFEST.json':
            actual[name] = dict(**pin(path.read_bytes()), mode=stat.S_IMODE(path.stat().st_mode))
    assert actual == value['files']
    return hashlib.sha256(raw).hexdigest()


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).hostname != 'api.github.com':
            new.remove_header('Authorization')
        return new


def fetch(folder, binding):
    folder.mkdir(parents=True, exist_ok=False)
    target = folder / 'complete.zip'
    request = urllib.request.Request(
        'https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/'
        + str(binding['artifact_id']) + '/zip',
        headers={'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                 'X-GitHub-Api-Version': '2022-11-28'})
    count, digest = 0, hashlib.sha256()
    with urllib.request.build_opener(Redirect()).open(request, timeout=60) as source, target.open('xb') as out:
        while block := source.read(1 << 20):
            count += len(block)
            assert count <= binding['zip']['bytes']
            digest.update(block); out.write(block)
    result = dict(bytes=count, sha256=digest.hexdigest())
    assert result == binding['zip']
    return dict(status='PASS', archive=result, target_native_or_rust_executions=0)


def full_tar(stream, retain):
    observed, content, manifest = {}, {}, None
    with tarfile.open(fileobj=stream, mode='r|gz') as archive:
        while member := archive.next():
            path = Path(member.name)
            assert member.isfile() and member.name not in observed and not path.is_absolute()
            assert '..' not in path.parts and member.mode in (0o600, 0o644, 0o755)
            with archive.extractfile(member) as handle:
                if retain or member.name == 'artifact-manifest.json':
                    raw = handle.read()
                    item = pin(raw)
                else:
                    digest, count = hashlib.sha256(), 0
                    while block := handle.read(1 << 20):
                        count += len(block); digest.update(block)
                    item = dict(bytes=count, sha256=digest.hexdigest())
            assert item['bytes'] == member.size
            observed[member.name] = dict(**item, mode=member.mode)
            if member.name == 'artifact-manifest.json':
                assert member.mode == 0o644
                manifest = raw
            else:
                assert len(path.parts) == 2 and path.parts[0] == 'objects'
                assert member.name == 'objects/' + item['sha256'] + '-' + format(member.mode, '03o')
                if retain:
                    content[member.name] = raw
            archive.members.clear()
    assert manifest is not None
    index = json.loads(manifest)
    expected = {'artifact-manifest.json': dict(**pin(manifest), mode=0o644)}
    for name, row in index['files'].items():
        path = Path(name)
        assert not path.is_absolute() and '..' not in path.parts
        item = {key: row[key] for key in ('bytes', 'sha256', 'mode')}
        assert row['object'] == 'objects/' + row['sha256'] + '-' + format(row['mode'], '03o')
        if row['object'] in expected:
            assert expected[row['object']] == item
        expected[row['object']] = item
    assert observed == expected
    return index, manifest, observed, content


def inspect(folder, binding):
    path = folder / 'complete.zip'
    assert pin(path.read_bytes()) == binding['zip']
    outer, small = {}, {}
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            name = Path(item.filename)
            assert not item.is_dir() and item.filename not in outer and not name.is_absolute() and '..' not in name.parts
            with archive.open(item) as stream:
                if item.file_size < (5 << 20):
                    raw = stream.read(); value = pin(raw); small[item.filename] = raw
                else:
                    digest, count = hashlib.sha256(), 0
                    while block := stream.read(1 << 20):
                        count += len(block); digest.update(block)
                    value = dict(bytes=count, sha256=digest.hexdigest())
            assert value['bytes'] == item.file_size
            outer[item.filename] = dict(**value, mode=item.external_attr >> 16)
        expected_outer = {'audit-retention-recovery.tar.gz', 'audit-retention-recovery.tar.gz.json'}
        for stage in ('restore', 'export'):
            for name in (stage+'.stdout', stage+'.stderr', 'processes.json'):
                expected_outer.add('audit-retention-recovery-stage-processes/'+stage+'/'+name)
        assert set(outer) == expected_outer
        assert {key: outer['audit-retention-recovery.tar.gz'][key] for key in ('bytes','sha256')} == binding['tar']
        receipt = json.loads(small['audit-retention-recovery.tar.gz.json'])
        with archive.open('audit-retention-recovery.tar.gz') as stream:
            manifest, manifest_raw, objects, content = full_tar(stream, True)
    assert manifest['schema'] == 'hepta.audit-retention.complete-deduplicated-archive.v1'
    assert manifest['git_head'] == binding['head'] and int(manifest['run_id']) == binding['run_id']
    assert manifest['semantic_reexecutions'] == 0 and manifest['whole_runtime_replaced'] is False
    index = manifest['files']
    logical_bytes = sum(row['bytes'] for row in index.values())
    unique_bytes = sum(row['bytes'] for name,row in objects.items() if name != 'artifact-manifest.json')
    assert len(index) == receipt['logical_files'] == binding['logical_files']
    assert logical_bytes == receipt['logical_bytes'] == binding['logical_bytes']
    assert len(objects)-1 == receipt['unique_objects'] == binding['unique_objects']
    assert unique_bytes == receipt['unique_bytes'] == binding['unique_bytes']
    assert {key:receipt[key] for key in ('bytes','sha256')} == binding['tar']
    assert receipt['all_object_bytes_and_modes_reread'] is True and receipt['all_logical_files_reread'] is True

    def body(name):
        row = index[name]
        raw = content[row['object']]
        assert pin(raw) == {key:row[key] for key in ('bytes','sha256')}
        return raw

    def table(prefix):
        return {name[len(prefix):]:{key:row[key] for key in ('bytes','sha256','mode')}
                for name,row in index.items() if name.startswith(prefix)}

    def source(prefix, expected):
        raw = body(prefix+'SOURCE_MANIFEST.json')
        assert hashlib.sha256(raw).hexdigest() == expected
        specification = json.loads(raw)
        actual = table(prefix)
        assert set(actual) == set(specification['files']) | {'SOURCE_MANIFEST.json'}
        for name,row in specification['files'].items():
            assert {key:actual[name][key] for key in ('bytes','sha256')} == {key:row[key] for key in ('bytes','sha256')}
            assert actual[name]['mode'] == 0o644
        return actual

    source_files = source('evidence/producer/source/', binding['producer']['producer_source_sha256'])
    recovery_files = source('recovery-source/', binding['recovery_source_sha256'])
    assert table('evidence/producer/run/semantic/source/') == source_files
    assert body('evidence/producer/source/read_only_guard.py') == (ROOT/'read_only_guard.py').read_bytes()
    producer_zip = body('evidence/producer.zip')
    assert pin(producer_zip) == binding['producer']['producer_zip']
    nested_outer = {}
    with zipfile.ZipFile(io.BytesIO(producer_zip)) as archive:
        assert len(archive.infolist()) == 5
        for item in archive.infolist():
            assert not item.is_dir() and item.filename not in nested_outer
            with archive.open(item) as stream:
                digest, count = hashlib.sha256(), 0
                while block := stream.read(1 << 20):
                    count += len(block); digest.update(block)
            assert count == item.file_size
            nested_outer[item.filename] = dict(bytes=count, sha256=digest.hexdigest())
        assert nested_outer['audit-retention.tar.gz'] == binding['producer']['producer_tar']
        with archive.open('audit-retention.tar.gz') as stream:
            old_manifest, old_raw, old_objects, unused = full_tar(stream, False)
    assert old_manifest['git_head'] == binding['producer']['producer_head']
    assert int(old_manifest['run_id']) == binding['producer']['producer_run'] and old_manifest['gate_status'] == 'FAIL'
    assert len(old_manifest['files']) == binding['producer']['logical_files']
    assert sum(row['bytes'] for row in old_manifest['files'].values()) == binding['producer']['logical_bytes']
    assert len(old_objects)-1 == binding['producer']['unique_objects']
    assert body('evidence/producer/artifact-manifest.json') == old_raw
    original_files = {}
    for name,row in old_manifest['files'].items():
        expected = {key:row[key] for key in ('bytes','sha256','mode')}
        assert {key:index['evidence/producer/'+name][key] for key in expected} == expected
        original_files[name] = expected
    original_files['artifact-manifest.json'] = dict(**pin(old_raw),mode=0o644)
    restore = json.loads(body('evidence/RESTORE.json'))
    assert restore['files'] == original_files and restore['original_gate_status'] == 'FAIL'
    assert restore['semantic_reexecutions'] == 0 and restore['complete_disk_reread'] is True
    assert restore['temporary_object_retirement']['complete_set_bytes_and_modes_equal'] is True
    original_run_files = {name[4:]:row for name,row in original_files.items() if name.startswith('run/')}

    guard_names = ['python-file-write','descriptor-open','descriptor-write','metadata-mode','metadata-time',
                   'directory-create','subprocess','shell','native-dlopen','native-mmap',
                   'producer-or-foreign-read','unadmitted-file-descriptor']
    guards = 0
    def guard(proof, expected_roots):
        nonlocal guards
        assert proof['schema'] == 'hepta.runtime.scope-span-readonly.v2'
        assert proof['source_bound_guard'] is True
        assert proof['native_or_rust_executions'] == proof['reader_writes'] == 0
        assert proof['before'] == proof['after']
        assert [row['name'] for row in proof['probes']] == guard_names
        assert all(row['refusal'].startswith('owner-export read-only guard: ') for row in proof['probes'])
        assert proof['pid'] > 1 and proof['pid'] != proof['ppid']
        for number, expected in enumerate(expected_roots):
            observed = {name.split(':',1)[1]:dict(bytes=row['bytes'],sha256=row['sha256'],mode=row['mode']&0o777)
                        for name,row in proof['before'].items()
                        if name.startswith(str(number)+':') and row['sha256'] is not None}
            assert observed == expected
        guards += len(proof['probes'])

    stage_reports = {}
    for stage in ('read','controls','independent'):
        report = json.loads(body('evidence/'+stage.upper()+'.json'))
        records = json.loads(body('evidence/processes/'+stage+'/processes.json'))
        assert len(records)==1 and report['process']==records[0] and report['status']=='PASS'
        process=records[0]
        assert process['completed'] and not process['timed_out'] and process['exit_code']==0
        assert process['timeout_seconds']==180 and 0<=process['elapsed_seconds']<=180
        assert process['name']==stage and process['pgid']==process['pid'] and process['pid']>1
        for stream in ('stdout','stderr'):
            raw=body('evidence/processes/'+stage+'/'+stage+'.'+stream)
            assert pin(raw)=={key:process[stream][key] for key in ('bytes','sha256')}
            if stream=='stderr':assert not raw
        result=json.loads(body('evidence/processes/'+stage+'/'+stage+'.stdout'))
        if stage!='controls':
            scope=original_run_files if stage=='read' else table('evidence/producer/run/')
            guard(result,[source_files,scope,recovery_files])
            assert result['evidence']==report['evidence']
        else:
            assert result['status']=='PASS' and result['refusals']==12 and result['admissions']==4
        assert report['semantic_reexecutions']==0 and report['preserved_producer_files']==len(original_files)
        stage_reports[stage]=report
    controls=json.loads(body('evidence/producer/run/CONTROLS.json'))
    assert len(controls['refusals'])==12 and len(controls['admissions'])==4
    for row in controls['refusals']+controls['admissions']:
        prefix='evidence/producer/run/'
        raw=body(prefix+row['proof']['file'])
        assert pin(raw)=={key:row['proof'][key] for key in ('bytes','sha256')}
        proof=json.loads(raw)
        guard(proof,[source_files,table(prefix+row['capture']+'/'),recovery_files])
        assert proof['evidence']==row['evidence']
        if row in controls['refusals']:
            assert proof['evidence']['status']=='REFUSED'
        else:
            assert proof['evidence']==stage_reports['read']['evidence']
    assert guards==216

    base='evidence/producer/run/semantic/'
    capture=json.loads(body(base+'CAPTURE.json'))
    assert capture['status']=='PASS' and capture['git_head']==binding['producer']['producer_head']
    assert capture['source_manifest_sha256']==binding['producer']['producer_source_sha256']
    assert capture['files']=={name:row for name,row in table(base).items() if name!='CAPTURE.json'}
    original_processes=json.loads(body(base+'processes/processes.json'))
    assert len(original_processes)==9
    for row in original_processes:
        assert row['completed'] and not row['timed_out'] and row['exit_code']==0
        assert row['elapsed_seconds']<=row['timeout_seconds']
        for stream in ('stdout','stderr','stdin'):
            item=row[stream]
            if item is not None:
                assert pin(body(base+'processes/'+item['file']))=={key:item[key] for key in ('bytes','sha256')}
    original=body(base+'processes/original.stdout')
    actual=body(base+'processes/native.stdout')
    assert original==actual and pin(original)==binding['stdout'] and len(original.splitlines())==binding['cases']
    assert pin(body(base+'build/modules/audit-retention/module.image.bin'))==binding['native_image']
    for label in ('B1','B2','B3'):
        assert pin(body(base+'build/bootstrap/'+label+'.image.bin'))==dict(bytes=673413,sha256='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0')
    compiler=json.loads(body('evidence/producer/source/COMPILER_IDENTITY.json'))
    assert len(compiler['files'])==1080
    assert set(table(base+'build/compiler-source/'))==set(compiler['files'])
    for name,digest in compiler['files'].items():
        assert index[base+'build/compiler-source/'+name]['sha256']==digest

    native=json.loads(body(base+'native/NATIVE.json'))
    invocations=json.loads(body(base+'native/INVOCATIONS.json'))
    assert native['native_calls']==native['completed_calls']==len(invocations)==binding['native_calls']
    assert native['cases']==native['completed_cases']==binding['cases']
    assert native['effects']==binding['effects'] and native['policy_calls']==binding['policy_calls']
    assert native['protocol_refusals']==binding['protocol_refusals']
    assert native['journal']==pin(body(base+'native/buffers.bin.gz'))==binding['journal']
    assert native['invocations']==pin(body(base+'native/INVOCATIONS.json'))
    assert native['status']=='PASS' and native['semantic_host_fallback'] is False
    case_data=gzip.decompress(base64.b64decode(body('evidence/producer/source/CASES.jsonl.gz.b64'),validate=True))
    cases=[json.loads(line) for line in case_data.splitlines()]
    assert len(cases)==binding['cases']
    extents=[]
    for case in cases:
        wire=bytes.fromhex(case['initial_hex'])
        extents.append(128+8*struct.unpack_from('<Q',wire,16)[0]+len(wire))
    logical=8
    with gzip.GzipFile(fileobj=io.BytesIO(body(base+'native/buffers.bin.gz')),mode='rb') as stream:
        assert stream.read(8)==b'HATLOG01'
        for ordinal,row in enumerate(invocations):
            header=stream.read(72)
            assert len(header)==72 and header[:8]==b'HATCAL01'
            assert struct.unpack('<8Q',header[8:])==(ordinal,row['case'],row['step'],int(row['probe']!=''),row['result'],
                row['source_size'],row['output_size'],row['workspace_size'])
            before,after=[],[]
            for size in (row['source_size']+16,row['output_size']+16,row['workspace_size']+16):
                left,right=stream.read(size),stream.read(size)
                assert len(left)==len(right)==size
                before.append(left);after.append(right);logical+=2*size
            logical+=72
            assert before[0]==after[0] and before[0][-16:]==b'\xc3'*16
            assert after[1][-16:]==b'\xa5'*16 and after[2][-16:]==b'\x5a'*16
            if row['probe']:
                assert row['result'] in (0xffffffff,0xfffffffe) and before[1:]==after[1:]
            else:
                assert row['result']==128 and after[1][128:]==before[1][128:]
                assert after[2][extents[row['case']]:]==before[2][extents[row['case']]:]
        assert stream.read(1)==b''
    assert logical==native['logical_physical_bytes']==binding['physical_bytes']

    for stage in ('restore','export'):
        prefix='audit-retention-recovery-stage-processes/'+stage+'/'
        rows=json.loads(small[prefix+'processes.json'])
        assert len(rows)==1
        process=rows[0]
        assert process['completed'] and not process['timed_out'] and process['exit_code']==0
        assert process['timeout_seconds']==180 and process['elapsed_seconds']<=180
        for stream in ('stdout','stderr'):
            assert pin(small[prefix+stage+'.'+stream])=={key:process[stream][key] for key in ('bytes','sha256')}
            if stream=='stderr':assert not small[prefix+stage+'.'+stream]
    return dict(schema='hepta.audit-retention.independent-complete-archive-read.v1',status='PASS',
        zip=binding['zip'],tar=binding['tar'],zip_members=len(outer),tar_members=len(objects),
        logical_files=len(index),logical_bytes=logical_bytes,unique_objects=len(objects)-1,unique_bytes=unique_bytes,
        producer_files=len(original_files),all_nested_producer_bytes_and_modes_equal=True,
        original_native_cases=binding['cases'],native_calls=binding['native_calls'],effects=binding['effects'],
        protocol_refusals=binding['protocol_refusals'],complete_physical_bytes=logical,
        retained_guard_proofs=18,retained_guard_probes=guards,native_image=binding['native_image'],
        original_run_status='FAIL',recovery_run_status='SUCCESS',source_manifest_sha256=identity(),
        semantic_reexecutions=0,reader_writes=0,public_handler_qualified=False,whole_runtime_replaced=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=['fetch','read'])
    parser.add_argument('--artifact-root',type=Path,required=True)
    parser.add_argument('--source-manifest-sha256',required=True)
    args=parser.parse_args()
    assert identity()==args.source_manifest_sha256
    binding=json.loads((ROOT/'BINDING.json').read_bytes())
    folder=args.artifact_root.absolute()
    if args.stage=='fetch':
        print(encoded(fetch(folder,binding)).decode(),end='')
    else:
        proof=guarded(lambda:inspect(folder,binding),roots=[ROOT,folder],foreign_path=Path('/dev/null'))
        assert proof['before']==proof['after'] and len(proof['probes'])==12
        print(encoded(proof).decode(),end='')


if __name__=='__main__':
    main()
