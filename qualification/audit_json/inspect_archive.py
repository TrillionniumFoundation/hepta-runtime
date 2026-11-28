"""Independent complete audit-codec artifact byte and guarded-proof inspection."""
from pathlib import Path
import argparse
import base64
import gzip
import hashlib
import io
import json
import tarfile
import time
import zipfile

SOURCE_COMMIT = '15f560cf20834b5a24844e0eb7e699dcc6dd81ec'
SOURCE_SHA = '0bf9ff533011ce1435b9c8630681d7117dd79fb211dae6573c07c9d669da45a3'
RUN = 43999196601


def require(value,message):
    if not value:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key,value in items:
        require(key not in result,'duplicate JSON key')
        result[key] = value
    return result


def loads(raw):
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda item:(_ for _ in ()).throw(ValueError(item)))


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def stream_pin(handle):
    digest,count = hashlib.sha256(),0
    while block := handle.read(1 << 20):
        digest.update(block);count += len(block)
    return dict(bytes=count,sha256=digest.hexdigest())


def inspect(archive,receipt):
    started = time.monotonic()
    with archive.open('rb') as handle:
        zip_identity = stream_pin(handle)
    outer,objects,small = {},{},{}
    manifest_raw = None
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            name = Path(item.filename)
            require(not item.is_dir() and not name.is_absolute() and '..' not in name.parts
                    and item.filename not in outer,'complete unique regular ZIP members')
            with z.open(item) as handle:
                identity = stream_pin(handle)
            require(identity['bytes'] == item.file_size,'every complete ZIP member byte')
            outer[item.filename] = dict(**identity,mode=item.external_attr >> 16)
        require(set(outer) == {'audit-json.tar.gz','audit-json.tar.gz.json',
            'audit-json-export-processes/complete-export.stdout','audit-json-export-processes/complete-export.stderr',
            'audit-json-export-processes/processes.json'},'complete exact outer artifact set')
        with z.open('audit-json.tar.gz') as handle,tarfile.open(fileobj=handle,mode='r|gz') as tar:
            while member := tar.next():
                require(member.isfile() and member.name not in objects,'unique regular TAR objects')
                with tar.extractfile(member) as data:
                    if member.name == 'artifact-manifest.json' or member.size <= 2 << 20:
                        raw = data.read()
                        identity = pin(raw)
                        small[member.name] = raw
                    else:
                        identity = stream_pin(data)
                require(identity['bytes'] == member.size,'complete TAR object bytes')
                objects[member.name] = dict(**identity,mode=member.mode)
                tar.members.clear()
        manifest_raw = small['artifact-manifest.json']
        manifest = loads(manifest_raw)
        require(manifest['schema'] == 'hepta.audit-json.complete-archive.v1'
                and manifest['git_head'] == SOURCE_COMMIT and int(manifest['run_id']) == RUN
                and manifest['source_manifest']['sha256'] == SOURCE_SHA
                and manifest['native_or_rust_executions'] == 0 and manifest['whole_runtime_replaced'] is False,
                'exact frozen artifact producer and source')
        logical = manifest['files']
        referenced = set()
        for name,row in logical.items():
            path = Path(name)
            require(not path.is_absolute() and '..' not in path.parts and path.parts[0] in ('source','run')
                    and path.as_posix() == name,'canonical complete logical artifact path')
            require(row['object'] == 'objects/'+row['sha256']+'-'+format(row['mode'],'03o')
                    and objects.get(row['object']) == {key:row[key] for key in ('bytes','sha256','mode')},
                    'every logical file maps to its complete bytes and mode')
            referenced.add(row['object'])
        require(set(objects) == referenced|{'artifact-manifest.json'},'all unique archive objects are referenced')
        export = loads(z.read('audit-json.tar.gz.json'))
        require(export['schema'] == 'hepta.audit-json.complete-archive-read.v1'
                and {key:export[key] for key in ('bytes','sha256')} == {key:outer['audit-json.tar.gz'][key] for key in ('bytes','sha256')}
                and export['logical_files'] == len(logical) and export['unique_objects'] == len(referenced)
                and export['logical_bytes'] == sum(row['bytes'] for row in logical.values())
                and export['unique_bytes'] == sum(objects[name]['bytes'] for name in referenced)
                and export['all_object_bytes_and_modes_reread'] is True and export['all_logical_files_reread'] is True,
                'complete CI export and independent archive inventory agree')
        process = loads(z.read('audit-json-export-processes/processes.json'))
        require(len(process) == 1 and process[0]['name'] == 'complete-export' and process[0]['exit_code'] == 0
                and process[0]['completed'] is True and process[0]['timed_out'] is False
                and process[0]['timeout_seconds'] == 180 and process[0]['elapsed_seconds'] <= 180,
                'actual completed export within its fixed budget')
        for kind in ('stdout','stderr'):
            entry = process[0][kind]
            require(entry['file'] == 'complete-export.'+kind
                    and pin(z.read('audit-json-export-processes/'+entry['file'])) == {key:entry[key] for key in ('bytes','sha256')},
                    'complete actual export streams')
        require(z.read('audit-json-export-processes/complete-export.stderr') == b'', 'empty successful exporter stderr')
        wanted = ['source/SOURCE_MANIFEST.json','source/DOMAIN.json','source/CASES.jsonl.gz.b64','run/GATE.json',
            'run/semantic/CAPTURE.json','run/semantic/native/NATIVE.json','run/semantic/processes/processes.json',
            'run/semantic/processes/original.stdout','run/semantic/processes/native.stdout',
            'run/reader-processes/processes.json','run/CONTROLS.json',
            'run/reader-processes/readonly-semantic.stdout','run/reader-processes/readonly-complete.stdout']
        wanted.extend(name for name in logical if name.startswith('run/controls/') and name.endswith('/PROOF.json'))
        needed = {logical[name]['object'] for name in wanted if name in logical}
        missing = needed-set(small)
        if missing:
            with z.open('audit-json.tar.gz') as handle,tarfile.open(fileobj=handle,mode='r|gz') as tar:
                while member := tar.next():
                    if member.name in missing:
                        with tar.extractfile(member) as data:
                            small[member.name] = data.read()
                        require(pin(small[member.name]) == {key:objects[member.name][key] for key in ('bytes','sha256')},
                                'complete selected large proof read')
                    tar.members.clear()
    def raw(name):
        return small[logical[name]['object']]
    def read_json(name):
        return loads(raw(name))
    source = read_json('source/SOURCE_MANIFEST.json')
    require(pin(raw('source/SOURCE_MANIFEST.json'))['sha256'] == SOURCE_SHA,'exact full frozen source manifest')
    expected_source = dict(source['files'])
    expected_source['SOURCE_MANIFEST.json'] = pin(raw('source/SOURCE_MANIFEST.json'))
    actual_source = {name.removeprefix('source/'):row for name,row in logical.items() if name.startswith('source/')}
    require(set(actual_source) == set(expected_source) and len(actual_source) == 36,'all frozen source files exactly once')
    for name,expected in expected_source.items():
        require({key:actual_source[name][key] for key in ('bytes','sha256')} == expected
                and actual_source[name]['mode'] == 0o644,'every frozen source byte and mode')
    domain = read_json('source/DOMAIN.json')
    concrete = gzip.decompress(base64.b64decode(raw('source/CASES.jsonl.gz.b64'),validate=True))
    require(pin(concrete) == {key:domain['cases'][key] for key in ('bytes','sha256')}
            and len(concrete.splitlines()) == 3511,'complete frozen concrete input bytes')
    gate = read_json('run/GATE.json')
    require(gate['status'] == manifest['gate_status'] == export['gate_status'],'unchanged original gate outcome')
    require(gate['status'] == 'COMPLETE_PRIVATE_HIA_AUDIT_JSON_PASS'
            and gate['actual_original_cases'] == gate['actual_hia_calls'] == 3511
            and gate['source_manifest_sha256'] == SOURCE_SHA and gate['runtime_rust_required'] is False
            and gate['runtime_python_required'] is False and gate['public_handler_qualified'] is False
            and gate['whole_runtime_replaced'] is False,'closed private codec gate scope')
    capture = read_json('run/semantic/CAPTURE.json')
    captured = {name.removeprefix('run/semantic/'): {key:row[key] for key in ('bytes','sha256','mode')}
                for name,row in logical.items() if name.startswith('run/semantic/') and name != 'run/semantic/CAPTURE.json'}
    require(capture['files'] == captured and capture['status'] == 'PASS','complete original sealed semantic capture')
    require(raw('run/semantic/processes/original.stdout') == raw('run/semantic/processes/native.stdout'),
            'complete archived original and native stdout equality')
    native = read_json('run/semantic/native/NATIVE.json')
    require(native['status'] == 'PASS' and native['calls'] == native['completed_calls'] == 3511,'actual complete native calls')
    processes = read_json('run/semantic/processes/processes.json')
    require(len(processes) == 9 and all(row['exit_code'] == 0 and row['completed'] is True
            and row['timed_out'] is False and row['elapsed_seconds'] <= row['timeout_seconds'] for row in processes),
            'all actual producer processes completed within fixed budgets')
    readers = read_json('run/reader-processes/processes.json')
    require([row['name'] for row in readers] == ['readonly-semantic','reader-controls','readonly-complete']
            and all(row['completed'] is True and row['exit_code'] == 0 and row['timed_out'] is False
                    and row['timeout_seconds'] == 180 and row['elapsed_seconds'] <= 180 for row in readers),
            'all fixed reader processes completed within 180 seconds')
    proofs = []
    for name in wanted:
        if name.endswith('/PROOF.json') or name.endswith('readonly-semantic.stdout') or name.endswith('readonly-complete.stdout'):
            proof = read_json(name)
            require(proof['before'] == proof['after'] and len(proof['probes']) == 12
                    and proof['native_or_rust_executions'] == proof['reader_writes'] == 0
                    and proof['source_bound_guard'] is True,'complete unchanged pure-read guard proof')
            proofs.append(dict(file=name,files=sum(row['sha256'] is not None for row in proof['before'].values()),
                               probes=len(proof['probes']),evidence=proof['evidence']))
    require(len(proofs) == 18,'sixteen physical-control proofs and two full reader proofs')
    controls = read_json('run/CONTROLS.json')
    require(len(controls['refusals']) == 12 and len(controls['admissions']) == 4
            and controls['guard_proofs'] == 16 and controls['guards_per_proof'] == 12,'complete physical refusal and admission domain')
    final = read_json('run/reader-processes/readonly-complete.stdout')['evidence']
    require(final['status'] == 'PASS' and final['controls']['status'] == 'PASS'
            and final['semantic']['cases'] == 3511,'actual final independent semantic and controls result')
    result = dict(schema='hepta.audit-json.independent-complete-archive-read.v1',status='PASS',
        source_commit=SOURCE_COMMIT,source_manifest_sha256=SOURCE_SHA,run=RUN,zip=zip_identity,outer=outer,
        manifest=pin(manifest_raw),logical_files=len(logical),logical_bytes=export['logical_bytes'],
        unique_objects=len(referenced),unique_bytes=export['unique_bytes'],source_files=36,
        all_unique_object_bytes_and_modes_read=True,all_logical_file_bindings_read=True,
        all_original_source_bytes_and_modes_read=True,all_original_native_stdout_read=True,
        original_hia_cases=3511,physical_control_proofs=16,guard_proofs=18,guard_probes=216,
        gate=gate,native=native,final_independent_evidence=final,processes=processes,readers=readers,
        elapsed_seconds=time.monotonic()-started,local_native_or_rust_executions=0,
        public_handler_qualified=False,whole_runtime_replaced=False)
    receipt.write_text(json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+'\n')
    print(json.dumps({key:value for key,value in result.items()
                     if key not in ('outer','gate','native','final_independent_evidence','processes','readers')},sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    args = parser.parse_args()
    inspect(args.archive.resolve(strict=True),args.receipt.absolute())
