"""Independently read every retained object and every logical file identity."""
from pathlib import Path
import argparse
import hashlib
import json
import tarfile
import time
import zipfile


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path, required=True)
    parser.add_argument('--zip-bytes', type=int, required=True)
    parser.add_argument('--zip-sha256', required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--reader-source-sha256', required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--require-pass', action='store_true')
    args = parser.parse_args()
    started = time.monotonic()
    before = args.zip.stat()
    with args.zip.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    assert before.st_size == args.zip_bytes and digest == args.zip_sha256
    outer, objects = {}, {}
    with zipfile.ZipFile(args.zip) as archive:
        for item in archive.infolist():
            assert not item.is_dir() and item.filename not in outer
            with archive.open(item) as stream:
                sha = hashlib.file_digest(stream, 'sha256').hexdigest()
            outer[item.filename] = dict(bytes=item.file_size, sha256=sha, mode=item.external_attr >> 16)
        expected_names = {'audit-lifetime-recovery.tar.gz', 'audit-lifetime-recovery.tar.gz.json',
                          'audit-lifetime-recovery-export.stdout', 'audit-lifetime-recovery-export.stderr'}
        assert set(outer) == expected_names
        receipt = json.loads(archive.read('audit-lifetime-recovery.tar.gz.json'))
        assert {k: outer['audit-lifetime-recovery.tar.gz'][k] for k in ('bytes', 'sha256')} == {k: receipt[k] for k in ('bytes', 'sha256')}
        manifest_raw = None
        with archive.open('audit-lifetime-recovery.tar.gz') as stream, tarfile.open(fileobj=stream, mode='r|gz') as tar:
            while member := tar.next():
                assert member.isfile() and member.name not in objects
                name = Path(member.name)
                assert not name.is_absolute() and '..' not in name.parts
                with tar.extractfile(member) as content:
                    if member.name == 'artifact-manifest.json':
                        manifest_raw = content.read()
                        observed = pin(manifest_raw)
                    else:
                        assert name.parts[0] == 'objects' and len(name.parts) == 2
                        observed = dict(bytes=member.size, sha256=hashlib.file_digest(content, 'sha256').hexdigest())
                        assert member.name == 'objects/' + observed['sha256'] + '-' + format(member.mode, '03o')
                assert observed['bytes'] == member.size
                objects[member.name] = dict(**observed, mode=member.mode)
                tar.members.clear()
        assert manifest_raw is not None
        manifest = json.loads(manifest_raw)
        assert manifest['schema'] == 'hepta.audit-lifetime.complete-deduplicated-archive.v1'
        assert manifest['git_head'] == args.head and manifest['semantic_reexecutions'] == 0
        assert manifest['whole_runtime_replaced'] is False
        files = manifest['files']
        used = set()
        for name, row in files.items():
            path = Path(name)
            assert not path.is_absolute() and '..' not in path.parts
            assert {key: row[key] for key in ('bytes', 'sha256', 'mode')} == objects[row['object']]
            used.add(row['object'])
        assert used | {'artifact-manifest.json'} == set(objects)
        assert len(files) == receipt['logical_files'] and len(used) == receipt['unique_objects']
        assert sum(row['bytes'] for row in files.values()) == receipt['logical_bytes']
        assert sum(objects[name]['bytes'] for name in used) == receipt['unique_bytes']
        wanted = {'recovery-source/SOURCE_MANIFEST.json',
                  'evidence/producer/source/SOURCE_MANIFEST.json',
                  'evidence/producer/artifact-manifest.json', 'evidence/RESTORE.json'}
        wanted.update(name for name in ('evidence/READ.json','evidence/CONTROLS.json','evidence/INDEPENDENT.json',
                                        'evidence/producer/run/GATE.json', 'evidence/producer/run/CONTROLS.json') if name in files)
        content_by_object = {}
        selected = {files[name]['object'] for name in wanted}
        with archive.open('audit-lifetime-recovery.tar.gz') as stream, tarfile.open(fileobj=stream, mode='r|gz') as tar:
            while member := tar.next():
                if member.name in selected:
                    with tar.extractfile(member) as content:
                        raw = content.read()
                    assert pin(raw) == {key: objects[member.name][key] for key in ('bytes','sha256')}
                    content_by_object[member.name] = raw
                tar.members.clear()
        assert set(content_by_object) == selected
        data = {name: content_by_object[files[name]['object']] for name in wanted}
        for prefix, expected_sha, count, modes in (
                ('recovery-source/', args.reader_source_sha256, 6, True),
                ('evidence/producer/source/', '37310e4744addbab580cf4106545c54872c1b34f4990ebc675fe996c867648be', 40, False)):
            raw = data[prefix + 'SOURCE_MANIFEST.json']
            assert hashlib.sha256(raw).hexdigest() == expected_sha
            source = json.loads(raw)
            actual = {name[len(prefix):]: row for name, row in files.items() if name.startswith(prefix)}
            assert len(actual) == count and set(actual) == set(source['files']) | {'SOURCE_MANIFEST.json'}
            for name, row in source['files'].items():
                keys = ('bytes','sha256','mode') if modes else ('bytes','sha256')
                assert {key: actual[name][key] for key in keys} == row and actual[name]['mode'] == 0o644
        original = json.loads(data['evidence/producer/artifact-manifest.json'])
        restoration = json.loads(data['evidence/RESTORE.json'])
        original_expected = dict(original['files'])
        original_expected['artifact-manifest.json'] = dict(**pin(data['evidence/producer/artifact-manifest.json']), mode=0o644)
        assert restoration['files'] == original_expected and len(original_expected) == 1860
        for name, row in original_expected.items():
            actual = files['evidence/producer/' + name]
            assert {key: actual[key] for key in ('bytes','sha256','mode')} == row
        assert original['git_head'] == 'c690fbd394aab187d58d43f7c9d27b09704cb35b' and original['gate_status'] == 'FAIL'
        summaries = {name: json.loads(raw) for name, raw in data.items() if name in (
            'evidence/READ.json', 'evidence/CONTROLS.json','evidence/INDEPENDENT.json','evidence/producer/run/GATE.json')}
        if args.require_pass:
            for stage in ('READ','CONTROLS','INDEPENDENT'):
                row = summaries['evidence/' + stage + '.json']
                assert row['status'] == 'PASS' and row['semantic_reexecutions'] == 0
                assert row['preserved_producer_files'] == 1860
            evidence = summaries['evidence/INDEPENDENT.json']['evidence']
            assert evidence['paired_cases'] == 16 and evidence['controls']['refusals'] == 12
            assert evidence['controls']['guard_proofs'] == 16 and evidence['controls']['guards_per_proof'] == 12
            assert evidence['whole_runtime_replaced'] is False and evidence['public_handler_qualified'] is False
    after = args.zip.stat()
    assert (before.st_size,before.st_ino,before.st_mtime_ns,before.st_ctime_ns) == (after.st_size,after.st_ino,after.st_mtime_ns,after.st_ctime_ns)
    proof = dict(schema='hepta.audit-lifetime.independent-complete-archive-read.v1', head=args.head,
                 reader_source_sha256=args.reader_source_sha256, zip=dict(bytes=args.zip_bytes,sha256=args.zip_sha256),
                 outer=outer, archive_manifest=pin(manifest_raw), logical_files=len(files),
                 logical_bytes=receipt['logical_bytes'], unique_objects=len(used), unique_bytes=receipt['unique_bytes'],
                 all_complete_object_bytes_and_modes=True, all_logical_file_identities_equal=True,
                 original_1860_files_unchanged=True, original_gate_status='FAIL',
                 exact_original_source_files=40, exact_recovery_source_files=6,
                 summaries=summaries, elapsed_seconds=time.monotonic()-started,
                 semantic_executions=0, whole_runtime_replaced=False)
    args.report.write_text(json.dumps(proof,sort_keys=True,indent=2,allow_nan=False)+'\n')
    print(json.dumps({key:proof[key] for key in ('head','logical_files','logical_bytes','unique_objects','unique_bytes','elapsed_seconds','semantic_executions')},sort_keys=True))


if __name__ == '__main__':
    main()
