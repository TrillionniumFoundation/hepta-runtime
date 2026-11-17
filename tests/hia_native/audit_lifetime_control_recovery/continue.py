"""Continue only the pending inert read of sixteen already completed physical controls."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
import urllib.request
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
PREVIOUS = ROOT.parent / 'audit_lifetime_read_recovery'
sys.path.insert(0, str(PREVIOUS))
import archive
import repair


def identity():
    raw = (ROOT / 'SOURCE_MANIFEST.json').read_bytes()
    manifest = json.loads(raw)
    assert archive.inventory(ROOT) == dict(manifest['files'], **{
        'SOURCE_MANIFEST.json': dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=0o644)})
    assert repair.identity() == 'c7075d0f97931bc282891432d173dc205c865f7628ed0a258d8e9f0632b05301'
    return hashlib.sha256(raw).hexdigest()


def map_name(name):
    path = Path(name)
    assert not path.is_absolute() and '..' not in path.parts and str(path) == name
    if name.startswith('evidence/'):
        return name[len('evidence/'):]
    assert name.startswith('recovery-source/')
    return 'prior-reader-source/' + name[len('recovery-source/'):]


def restore(destination):
    assert not destination.exists()
    binding = json.loads((ROOT / 'BINDING.json').read_bytes())
    destination.mkdir(parents=True)
    downloaded = destination.parent / 'audit-lifetime-completed-controls.zip'
    assert not downloaded.exists()
    request = urllib.request.Request(
        'https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/'
        + str(binding['artifact_id']) + '/zip',
        headers={'Accept':'application/vnd.github+json','Authorization':'Bearer ' + os.environ['GH_TOKEN'],
                 'X-GitHub-Api-Version':'2022-11-28'})
    with urllib.request.build_opener(archive.Redirect()).open(request,timeout=60) as response, downloaded.open('xb') as out:
        count = 0
        while block := response.read(1 << 20):
            count += len(block)
            assert count <= binding['zip']['bytes']
            out.write(block)
    assert {k:archive.digest(downloaded)[k] for k in ('bytes','sha256')} == binding['zip']
    objects, outer, raw = {}, {}, None
    with zipfile.ZipFile(downloaded) as z:
        assert len(z.infolist()) == 4
        for item in z.infolist():
            assert not item.is_dir() and item.filename not in outer
            with z.open(item) as stream:
                sha = hashlib.file_digest(stream,'sha256').hexdigest()
            outer[item.filename] = dict(bytes=item.file_size,sha256=sha,mode=item.external_attr >> 16)
        receipt = json.loads(z.read('audit-lifetime-recovery.tar.gz.json'))
        assert {k:outer['audit-lifetime-recovery.tar.gz'][k] for k in ('bytes','sha256')} == {k:receipt[k] for k in ('bytes','sha256')}
        with z.open('audit-lifetime-recovery.tar.gz') as stream, tarfile.open(fileobj=stream,mode='r|gz') as tar:
            while member := tar.next():
                assert member.isfile() and member.name not in objects
                with tar.extractfile(member) as content:
                    if member.name == 'artifact-manifest.json':
                        raw = content.read()
                        sha = hashlib.sha256(raw).hexdigest()
                    else:
                        sha = hashlib.file_digest(content,'sha256').hexdigest()
                        assert member.name == 'objects/' + sha + '-' + format(member.mode,'03o')
                objects[member.name] = dict(bytes=member.size,sha256=sha,mode=member.mode)
                tar.members.clear()
        assert raw is not None and dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) == binding['archive_manifest']
        manifest = json.loads(raw)
        assert manifest['git_head'] == binding['head'] and int(manifest['run_id']) == binding['run_id']
        assert manifest['semantic_reexecutions'] == 0 and manifest['whole_runtime_replaced'] is False
        expected, by_object = {}, {}
        for name, row in manifest['files'].items():
            mapped = map_name(name)
            assert mapped not in expected
            expected[mapped] = {k:row[k] for k in ('bytes','sha256','mode')}
            assert objects[row['object']] == expected[mapped]
            by_object.setdefault(row['object'],[]).append(mapped)
        assert set(by_object) | {'artifact-manifest.json'} == set(objects)
        assert len(expected) == binding['logical_files'] == receipt['logical_files']
        assert sum(row['bytes'] for row in expected.values()) == binding['logical_bytes'] == receipt['logical_bytes']
        with z.open('audit-lifetime-recovery.tar.gz') as stream, tarfile.open(fileobj=stream,mode='r|gz') as tar:
            while member := tar.next():
                if member.name in by_object:
                    names = by_object[member.name]
                    first = destination / names[0]
                    first.parent.mkdir(parents=True,exist_ok=True)
                    with tar.extractfile(member) as content, first.open('xb') as output:
                        shutil.copyfileobj(content,output,1 << 20)
                    first.chmod(member.mode)
                    assert archive.digest(first) == objects[member.name]
                    for name in names[1:]:
                        target = destination / name
                        target.parent.mkdir(parents=True,exist_ok=True)
                        assert not target.exists()
                        shutil.copyfile(first,target)
                        target.chmod(member.mode)
                tar.members.clear()
    assert archive.inventory(destination) == expected
    assert archive.inventory(destination / 'prior-reader-source') == archive.inventory(PREVIOUS)
    controls = json.loads((destination / 'producer/run/CONTROLS.json').read_bytes())
    assert len(controls['refusals']) == 12 and len(controls['admissions']) == 4
    for row in controls['refusals'] + controls['admissions']:
        proof = json.loads((destination / 'producer/run' / row['proof']['file']).read_bytes())
        assert proof['evidence'] == row['evidence'] and proof['before'] == proof['after']
        assert len(proof['probes']) == 12 and proof['native_or_rust_executions'] == proof['reader_writes'] == 0
    failure = json.loads((destination / 'processes/controls/processes.json').read_bytes())[0]
    assert failure['timed_out'] and failure['timeout_seconds'] == 180 and failure['exit_code'] != 0
    result = dict(schema='hepta.audit-lifetime.completed-controls-restoration.v1',
                  prior_head=binding['head'],prior_run=binding['run_id'],files=expected,outer=outer,
                  complete_disk_reread=True,prior_conclusion='failure',retained_control_proofs=16,
                  retained_guard_probes=192,semantic_reexecutions=0,physical_control_reexecutions=0)
    (destination / 'RESTORE_CONTROLS.json').write_bytes(archive.encoded(result))
    return dict(status='PASS',files=len(expected),logical_bytes=binding['logical_bytes'],
                retained_control_proofs=16,retained_guard_probes=192,semantic_reexecutions=0,physical_control_reexecutions=0)


def preserve(destination):
    expected = json.loads((destination / 'RESTORE_CONTROLS.json').read_bytes())['files']
    for name, row in expected.items():
        assert archive.digest(destination / name) == row, name
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=['restore','independent','export'])
    parser.add_argument('--destination',type=Path,required=True)
    parser.add_argument('--source-manifest-sha256',required=True)
    args = parser.parse_args()
    assert identity() == args.source_manifest_sha256
    destination = args.destination.absolute()
    if args.stage == 'restore':
        result = restore(destination)
    elif args.stage == 'export':
        result = archive.export(ROOT,destination,destination.parent / 'audit-lifetime-recovery.tar.gz')
    else:
        original = destination / 'producer/source'
        sys.path.insert(0,str(original))
        from process import Recorder
        recorder = Recorder(ROOT,destination / 'continuation-processes/independent')
        argv = [sys.executable,'-I','-B',destination / 'prior-reader-source/repair.py',
                '--source',original,'--output',destination / 'producer/run',
                '--source-manifest-sha256','c7075d0f97931bc282891432d173dc205c865f7628ed0a258d8e9f0632b05301',
                '--require-controls']
        try:
            raw,row = recorder.run('independent',argv,timeout=180)
            proof = json.loads(raw)
            assert proof['before'] == proof['after'] and len(proof['probes']) == 12
            assert proof['native_or_rust_executions'] == proof['reader_writes'] == 0
            assert proof['evidence']['controls']['status'] == 'PASS'
            result = dict(stage='independent',status='PASS',process=row,evidence=proof['evidence'],
                          continuation_source_sha256=args.source_manifest_sha256,
                          preserved_prior_files=preserve(destination),preserved_producer_files=1860,
                          semantic_reexecutions=0,physical_control_reexecutions=0)
            (destination / 'INDEPENDENT.json').write_bytes(archive.encoded(result))
            (destination / 'CONTROLS.json').write_bytes(archive.encoded(dict(
                stage='retained-controls-independent-read',status='PASS',
                evidence=proof['evidence']['controls'],preserved_producer_files=1860,
                preserved_prior_files=result['preserved_prior_files'],semantic_reexecutions=0,
                physical_control_reexecutions=0,prior_control_process_conclusion='timeout')))
        except BaseException:
            for path in sorted((destination / 'continuation-processes/independent').glob('*.stderr')):
                print(path.read_text(),file=sys.stderr)
            raise
    print(json.dumps(result,sort_keys=True,allow_nan=False))


if __name__ == '__main__':
    main()
