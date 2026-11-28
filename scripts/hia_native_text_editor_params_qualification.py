"""Portable native capture and fresh target-type evidence for Text Editor."""
from __future__ import annotations
from pathlib import Path, PurePosixPath
import copy
import gzip
import hashlib
import importlib.util
import json
import math
import os
import shutil
import struct
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
KEY = 'text_editor_params'
FOLDER = 'text-editor-params'
DRIVERS = 'tests/hia_native/text_editor_params'
REFERENCE = DRIVERS + '/reference'
BUNDLE = 'build/text-editor-params.json'
TESTS = ('test_text_editor_params.py', 'test_text_editor_params_evidence.py')
PROCESS_NAMES = ('text-editor-params-rust-version', 'text-editor-params-rust-build',
                 'text-editor-params-original')
COMPILER_SHA = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
COMPILER_COMMIT = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
TARGET = '737acf6f901e46c57b0b4374e323e0d1132e0d49'
SOURCE_PINS = {
    'native/text_editor_params.hepta': '310368785b761a4c1dbde449f3ebba2cb20df9d0f91cc9264ec8b2afbc20a262',
    'native/serde_json_span.hepta': '8ccf013c44c6635e131505a628aa3b7732eaae95b0d8b4fae8bdd6b140607840',
    'native/text_budget.hepta': '89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9',
    'native/view_params.hepta': 'f507e8658e3a3905f3d7a9da8c18a0d4863a327015800a649c85b99de739a830',
    'scripts/hia_native_build.py': '02cc0f23764d3a2bc6c1325e2ed5beb7986a6b64b22827c6ddcb10d2799de7d1',
    'scripts/hia_native_loader.py': '58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06',
}
REFERENCE_PINS = {
    'Cargo.toml': '23f257f1804025c1f7645378e006e2fe55f0a901844a60a837211f2d1105c964',
    'Cargo.lock': '00d188f54ccc72216665494b50645570acc6a5313413356d133ceaa1265b7ac6',
    'src/main.rs': 'fb07a5f88955b56c480cf41ee0fea50bc16211a37232ab74bca0f623967753cc',
    'src/original.rs': 'cec940c0f8c90753f65294063ebc3dc5fc8b4e1d6feda40cb3e2854612e63f53',
    'source_manifest.json': '08c7b9b52f4159a498a90d764901f54fdeebcd550621de9d60e23be2df3eb851',
}
SOURCES = (*SOURCE_PINS, 'native/text_editor_params_abi.md',
    'native/text_editor_params_composition.json',
    'scripts/hia_native_text_editor_params_qualification.py',
    *(DRIVERS + '/' + name for name in ('cases.py', 'native_capture.py')),
    *('tests/hia_native/' + name for name in TESTS),
    *(REFERENCE + '/' + name for name in REFERENCE_PINS))
MODULE = dict(key=KEY, name='text-editor-params', source='native/text_editor_params.hepta',
              builder=KEY, manifest_env='HIA_TEXT_EDITOR_PARAMS_BUNDLE', test=TESTS[0],
              additional_tests=TESTS[1:], companion_sources=('native/serde_json_span.hepta',))
COUNTS = dict(cases=1992, native_calls=11991, controls=34, value_admitted=1983,
              typed_successes=160, full_record_bytes=665635980)
SCOPE = dict(original_handler_executed=False, sdk_protocol_executed=False,
             public_route_replaced=False, production_activated=False,
             whole_runtime_replaced=False, old_stack_removal_qualified=False)
CONTROL_KINDS = ('source', 'counts', 'case-order', 'result-frame', 'call-return',
                 'call-omission', 'stream-truncation')
word = lambda raw, at: struct.unpack_from('<Q', raw, at)[0]
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate evidence key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite evidence')))


def same(a, b, message):
    require(canonical(a) == canonical(b), message)


def owned(base, name):
    require(type(name) is str and name and PurePosixPath(name).as_posix() == name
            and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
            'invalid evidence relative path')
    path = Path(base) / name
    require(path.is_file() and not path.is_symlink() and path.resolve() == path.absolute(),
            'evidence is not an ordinary owned path: ' + name)
    return path


def pin(path):
    path = Path(path)
    with path.open('rb') as stream:
        return dict(bytes=path.stat().st_size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())


def source_evidence(root=ROOT):
    files = {name: pin(owned(root, name)) for name in SOURCES}
    for name, digest in SOURCE_PINS.items():
        require(files[name]['sha256'] == digest, 'native dependency source differs: ' + name)
    for name, digest in REFERENCE_PINS.items():
        require(files[REFERENCE + '/' + name]['sha256'] == digest, 'original type reference differs: ' + name)
    proof = decode(owned(root, 'native/text_editor_params_composition.json').read_bytes())
    require(proof['source_sha256'] == SOURCE_PINS['native/text_editor_params.hepta'], 'typed owner composition differs')
    for item in proof['imports']:
        require(files[item['source']]['sha256'] == item['source_sha256'], 'typed owner imported source differs')
    reference = decode(owned(root, REFERENCE + '/source_manifest.json').read_bytes())
    require(reference['target_commit'] == TARGET and reference['original_types_unchanged'] is True,
            'typed reference target differs')
    for name, value in reference['files'].items():
        same(files[REFERENCE + '/' + name], value, 'target reference file identity differs')
    lock = tomllib.loads(owned(root, REFERENCE + '/Cargo.lock').read_text())
    registry = [{k: row[k] for k in ('name', 'version', 'source', 'checksum')}
                for row in lock['package'] if 'source' in row]
    targets = {(row['name'], row['version']): row['package'] for row in reference['target_packages']}
    require(len(registry) == 17, 'target type dependency closure differs')
    for row in registry:
        original = targets[(row['name'], row['version'])]
        same(row, {key: original[key] for key in row}, 'target package version or checksum differs')
    return dict(files=files, reference_registry=registry, target_commit=TARGET, **SCOPE)


def cases(root=ROOT):
    path = owned(root, DRIVERS + '/cases.py')
    spec = importlib.util.spec_from_file_location('_text_editor_params_cases', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(hepta, output, *, source_root=ROOT):
    from hia_native_build import NativeBuild, write_new, json_bytes
    source_evidence(source_root)
    builder = NativeBuild(hepta, Path(output) / 'build')
    members = {}
    for name, source in (('serde_json_span', 'serde_json_span'), ('text_editor_params', 'text_editor_params')):
        path = builder.compile('text-editor-' + ('value' if name == 'serde_json_span' else 'params'),
            Path(source_root) / 'native' / (source + '.hepta'), standalone=None, buffer_profile='history.v1')
        metadata = decode(path.read_bytes())
        members[name] = dict(manifest=str(path.relative_to(output)), manifest_sha256=sha(path.read_bytes()),
                             source_sha256=metadata['source_sha256'], image_sha256=metadata['image_sha256'])
    bundle = Path(output) / BUNDLE
    write_new(bundle, json_bytes(dict(schema='hepta.runtime.text-editor-params-build.v1', members=members,
        compiler_commit=COMPILER_COMMIT, compiler_sha256=COMPILER_SHA, **SCOPE)))
    return bundle


def module_evidence(root, output, report=None):
    path = owned(output, BUNDLE)
    bundle = decode(path.read_bytes())
    require(bundle['schema'] == 'hepta.runtime.text-editor-params-build.v1'
            and bundle['compiler_commit'] == COMPILER_COMMIT and bundle['compiler_sha256'] == COMPILER_SHA,
            'typed bundle compiler differs')
    same({k: bundle[k] for k in SCOPE}, SCOPE, 'typed bundle scope differs')
    same(sorted(bundle['members']), ['serde_json_span', 'text_editor_params'], 'typed bundle member set differs')
    artifacts = {BUNDLE: pin(path)}
    for name, member in bundle['members'].items():
        path = owned(output, member['manifest'])
        require(sha(path.read_bytes()) == member['manifest_sha256'], 'typed member manifest differs')
        meta = decode(path.read_bytes())
        require(meta['compiler_commit'] == COMPILER_COMMIT and meta['compiler_sha256'] == COMPILER_SHA
                and meta.get('buffer_profile') == 'history.v1' and meta.get('standalone') is None,
                'typed member profile differs')
        same([meta[k] for k in ('input_capacity','output_capacity','workspace_capacity')],
             [128 << 20, 128 << 20, 256 << 20], 'typed member capacity differs')
        require(meta['source_sha256'] == SOURCE_PINS['native/' + name + '.hepta'] == member['source_sha256']
                and meta['image_sha256'] == member['image_sha256'], 'typed member source/image identity differs')
        for artifact in (path, owned(path.parent, meta['source']), owned(path.parent, meta['image'])):
            artifacts[str(artifact.relative_to(output))] = pin(artifact)
        require(pin(path.parent / meta['source'])['sha256'] == meta['source_sha256']
                and pin(path.parent / meta['image'])['sha256'] == meta['image_sha256'], 'typed member complete bytes differ')
    if report is not None:
        same(report['modules'][KEY], dict(manifest=BUNDLE, source=MODULE['source'], builder=KEY,
                                          sha256=artifacts[BUNDLE]['sha256']), 'registered typed module differs')
        require(report['compiler_image_sha256'] == COMPILER_SHA, 'registered typed compiler differs')
    return artifacts


def _frame(owner, code, out):
    header = 32 if owner == 1 else 128
    require(code == header and out[:8] == (b'HJSVR002' if owner == 1 else b'HTEPRR02'), 'native typed response framing differs')
    status = word(out, 8)
    needed = word(out, 24 if owner == 1 else 80)
    require(status in ((0,1,2,3,5) if owner == 1 else (0,1,2,3)), 'native typed status differs')
    if status in (2,3):
        size = header
        require(needed > 0, 'native typed growth omitted capacity')
    else:
        require(needed == 0, 'native typed completion requests growth')
        size = header + (word(out,16) if owner == 1 else
                         sum(word(out,at) for at in (24,40,48,56)) if status == 0 else word(out,72))
    require(size <= len(out) and out[size:] == b'\xa5' * (len(out) - size), 'native typed output extent or tail differs')
    if owner == 2:
        require(out[88:128] == bytes(40), 'native typed reserved bytes differ')
        if status != 0:
            require(out[16:72] == bytes(56), 'native typed failure exposes success fields')
        if status == 0:
            require(word(out,16) in (1,2,3,4) and word(out,32) < 16 and word(out,64) in (0,1),
                    'native typed success fields differ')
    return status, needed, out[:size]


def read_capture(root, output, *, capture_root=None):
    root, output = Path(root), Path(output)
    folder = Path(capture_root) if capture_root is not None else output / FOLDER / 'native'
    artifacts = module_evidence(root, output)
    raw_files = {}
    def read(name):
        raw = owned(folder, name).read_bytes()
        raw_files[name] = dict(bytes=len(raw), sha256=sha(raw))
        return raw
    summary = decode(read('capture-result.json'))
    require(summary['status'] == 'PASS' and summary['original_results_read'] is False
            and summary['original_handler_executed'] is False and summary['public_route_replaced'] is False,
            'native typed capture status/scope differs')
    same({k: summary[k] for k in COUNTS}, COUNTS, 'native typed capture domain differs')
    same(summary['source_inputs'], source_evidence(root), 'native typed capture source differs')
    same(summary['artifacts'], artifacts, 'native typed capture build bytes differ')
    require(type(summary['pid']) is int and summary['pid'] > 0, 'native typed producer process absent')
    require(type(summary['python']) is str and Path(summary['python']).is_absolute(), 'native typed Python identity absent')
    origin = summary['origin']
    require(set(origin) == {'source_root','output'} and all(type(v) is str and Path(v).is_absolute()
            and '..' not in Path(v).parts for v in origin.values()), 'native typed execution origin differs')
    domain = cases(root)
    require(read('input.jsonl') == domain.encoded(), 'native typed input domain changed')
    index = [decode(line) for line in read('calls.jsonl').splitlines()]
    rows = [decode(line) for line in read('native-cases.jsonl').splitlines()]
    results = [decode(line) for line in read('native-results.jsonl').splitlines()]
    controls = [decode(line) for line in read('controls.jsonl').splitlines()]
    require(len(index) == COUNTS['native_calls'] and len(rows) == len(results) == COUNTS['cases']
            and len(controls) == COUNTS['controls'], 'native typed record counts differ')
    expected = domain.cases()
    semantic = {}
    for declared, result, case in zip(rows, results, expected):
        same([declared['case_id'],declared['name']], [case['case_id'],case['name']], 'native typed case order differs')
        same([result['case_id'],result['name']], [case['case_id'],case['name']], 'native result case order differs')
        require(declared['input_sha256'] == sha(case['raw_json'].encode()), 'native case input identity differs')
        require(type(declared['value_admitted']) is bool and type(declared['typed_success']) is bool,
                'native typed declaration kinds differ')
        for owner, key in ((1,'value_calls'), (2,'params_calls')):
            sequence = declared[key]
            require(type(sequence) is list and (sequence or owner == 2 and not declared['value_admitted']),
                    'native typed call chain omitted')
            require(len(sequence) <= 12 and all(type(n) is int and 1 <= n <= len(index) for n in sequence),
                    'native typed call identifiers differ')
            for position, call in enumerate(sequence):
                require(call not in semantic, 'native semantic call counted twice')
                semantic[call] = (owner, case, declared, result['result'], position, len(sequence))
    expected_control_calls = set()
    for row in controls:
        for call in [row['call']] if 'call' in row else row.get('calls', []):
            require(call not in expected_control_calls and call not in semantic, 'native control call counted twice')
            expected_control_calls.add(call)
        for call in row.get('resume_calls', []):
            require(call not in expected_control_calls and call not in semantic, 'native growth call counted twice')
            expected_control_calls.add(call)
    require(set(semantic) | expected_control_calls == set(range(1,len(index)+1)), 'native call was omitted from all domains')
    path = owned(folder, 'calls.bin.gz')
    raw_files['calls.bin.gz'] = pin(path)
    offset = 0
    previous = {}
    completed = {}
    with gzip.open(path,'rb') as stream:
        for ordinal, row in enumerate(index,1):
            require(type(row['bytes']) is int and 64 <= row['bytes'] <= 32 << 20, 'native record extent differs')
            raw = stream.read(row['bytes'])
            require(len(raw) == row['bytes'] and sha(raw) == row['record_sha256'], 'complete native record bytes differ')
            require(row['offset'] == offset and row['call'] == ordinal, 'native record offset/order differs')
            fields = struct.unpack_from('<8Q',raw)
            require(fields == (ordinal,row['owner'],row['case_id'],row['return_code'],row['input_bytes'],
                                row['output_capacity'],row['workspace_capacity'],0), 'native record header differs')
            _, owner, cid, code, inp, ocap, wcap, _ = fields
            cursor, arrays = 64, []
            for size, label in ((inp,'input'),(wcap,'before'),(ocap,'output_before'),(ocap,'output'),(wcap,'after')):
                part = raw[cursor:cursor+size]
                require(len(part) == size and sha(part) == row[label+'_sha256'], 'native complete '+label+' differs')
                arrays.append(part); cursor += size
            require(cursor == len(raw), 'native record has unbound bytes')
            wire, before, old, out, after = arrays
            require(old == b'\xa5' * ocap and owner in (1,2), 'native caller output initialization differs')
            if ordinal in semantic:
                want_owner, case, declared, result, position, length = semantic[ordinal]
                require(owner == want_owner and cid == case['case_id'] and row['label'] == 'semantic', 'native call owner/case differs')
                if owner == 1:
                    value = case['raw_json'].encode()
                    wanted_wire = b'HJSMS002' + struct.pack('<2Q',1,len(value)) + value
                else:
                    require((cid,1) in completed and completed[cid,1][:8] == b'HJSVR002', 'typed projection preceded map completion')
                    value = completed[cid,1][32:]
                    wanted_wire = b'HTEPRQ02' + struct.pack('<2Q',len(value),0) + value
                require(wire == wanted_wire, 'native actual input differs from source-owned call chain')
                if position == 0:
                    require(before == bytes(16512 if owner == 1 else 32768) and ocap == (32 if owner == 1 else 128),
                            'native first-call capacities differ')
                else:
                    old_status, needed, prior_after, prior_cap = previous[cid,owner]
                    require(old_status in (2,3), 'native chain retried a completed result')
                    require(before == (prior_after + bytes(needed-len(prior_after)) if old_status == 2 else prior_after)
                            and ocap == (prior_cap if old_status == 2 else needed), 'native continuation lost owned bytes')
                status, needed, frame = _frame(owner,code,out)
                if status in (2,3):
                    require(position + 1 < length and needed > (wcap if status == 2 else ocap), 'native growth is not followed by its retry')
                else:
                    require(position + 1 == length, 'native completion is not terminal')
                    completed[cid,owner] = frame
                    if owner == 1:
                        same(result['value_admitted'],status == 0,'native map admission result differs')
                        same(declared['value_admitted'],status == 0,'native map admission declaration differs')
                        if status == 0:
                            require(frame[32:].decode() == result['canonical'], 'native canonical bytes differ from result')
                        else:
                            require(not declared['params_calls'] and not declared['typed_success'], 'refused map reached typed owner')
                    else:
                        require(frame.hex() == result['frame_hex'], 'native complete typed frame differs from result')
                        same(result['ok'],status == 0,'native typed success differs')
                        same(declared['typed_success'],status == 0,'native typed success declaration differs')
                previous[cid,owner] = (status,needed,after,ocap)
            elif code in (0xffffffff,0xfffffffe):
                require(out == old and after == before, 'private refusal changed owned buffers')
            else:
                status, needed, frame = _frame(owner,code,out)
                if row['label'] == 'workspace-growth':
                    require(status == 2 and after == before and needed == len(wire)+32768, 'workspace refusal changed buffers')
            offset += len(raw)
        require(stream.read(1) == b'', 'native stream has unbound trailing bytes')
    require(offset == COUNTS['full_record_bytes'], 'native complete stream byte count differs')
    require(sum(row['value_admitted'] for row in rows) == COUNTS['value_admitted']
            and sum(row['typed_success'] for row in rows) == COUNTS['typed_successes'], 'native semantic domain totals differ')
    return dict(status='PASS', counts=COUNTS, source_inputs=summary['source_inputs'], origin=origin,
                producer_pid=summary['pid'], python=summary['python'], artifact_sha256={
                    **{name: item['sha256'] for name,item in artifacts.items()},
                    **{FOLDER+'/native/'+name: item['sha256'] for name,item in raw_files.items()}},
                complete_stream_read=True, **SCOPE)


def check_process(output, report, name, command, *, expected_json=None):
    rows = [row for row in report['checks'] if row.get('name') == name]
    require(len(rows) == 1, 'one actual process required: ' + name)
    row = rows[0]
    require(row.get('command') == command and row.get('exit_code') == 0
            and row.get('phase') == ('native_components' if name in TESTS else 'original_rust_comparison')
            and row.get('timed_out') is False and row.get('timeout_seconds') == 180
            and not row.get('start_error') and type(row.get('elapsed_seconds')) in (int,float)
            and math.isfinite(row['elapsed_seconds']) and 0 <= row['elapsed_seconds'] <= 180,
            'actual process identity or completion differs: ' + name)
    streams, artifacts = {}, {}
    for kind in ('stdout','stderr'):
        path = owned(output,name+'.'+kind)
        streams[kind] = path.read_bytes()
        same(pin(path),dict(bytes=row[kind+'_bytes'],sha256=row[kind+'_sha256']), 'complete actual '+kind+' differs')
        artifacts[name+'.'+kind] = sha(streams[kind])
    if expected_json is not None:
        same(decode(streams['stdout']),expected_json,'actual process JSON differs')
        same(row.get('summary'),expected_json,'retained process summary differs')
        require(streams['stderr'] == b'', 'native typed suite wrote unexpected stderr')
    return row, streams, artifacts


def evidence_controls(root, output):
    root, output = Path(root), Path(output)
    baseline = read_capture(root,output)
    source = output / FOLDER / 'native'
    controls = []
    with tempfile.TemporaryDirectory(prefix='text-editor-evidence-', dir=output/FOLDER) as temporary:
        copied = Path(temporary)/'capture'
        shutil.copytree(source,copied)
        same(read_capture(root,output,capture_root=copied),baseline,'physical capture relocation differs')
        for kind in CONTROL_KINDS:
            name = 'capture-result.json' if kind in ('source','counts') else 'native-cases.jsonl' if kind == 'case-order' else \
                   'native-results.jsonl' if kind == 'result-frame' else 'calls.bin.gz' if kind == 'stream-truncation' else 'calls.jsonl'
            path = copied/name
            original = path.read_bytes()
            if name == 'capture-result.json':
                value = decode(original)
                if kind == 'source': value['source_inputs']['files']['native/text_editor_params.hepta']['sha256'] = '0'*64
                else: value['cases'] -= 1
                changed = canonical(value)
            elif kind == 'stream-truncation':
                changed = original[:-1]
            else:
                rows = [decode(line) for line in original.splitlines()]
                if kind == 'case-order': rows[0], rows[1] = rows[1], rows[0]
                elif kind == 'result-frame':
                    row = next(row for row in rows if row['result'].get('frame_hex'))
                    row['result']['frame_hex'] = '00' + row['result']['frame_hex'][2:]
                elif kind == 'call-return': rows[0]['return_code'] += 1
                else: rows.pop()
                changed = b''.join(canonical(row) for row in rows)
            path.write_bytes(changed)
            refused = False
            try:
                read_capture(root,output,capture_root=copied)
            except (ValueError,AssertionError,EOFError,OSError,KeyError,struct.error):
                refused = True
            finally:
                path.write_bytes(original)
            require(refused,'changed evidence was accepted: '+kind)
            controls.append(kind)
    result = dict(status='PASS',refused=controls,physical_capture_relocations=1,
                  native_evidence_sha256=sha(canonical(baseline)),new_native_or_rust_processes=0,**SCOPE)
    (output/FOLDER/'evidence-controls.json').write_bytes(canonical(result))
    print(canonical(result).decode(),end='',flush=True)


def native_evidence(output, report, *, source_root=ROOT):
    root, output = Path(source_root), Path(output)
    module_evidence(root,output,report)
    native = read_capture(root,output)
    same({name:report['source_sha256'].get(name) for name in SOURCES},
         {name:row['sha256'] for name,row in native['source_inputs']['files'].items()}, 'aggregate typed source closure differs')
    summary = decode(owned(output,FOLDER+'/native/capture-result.json').read_bytes())
    origin = Path(native['origin']['source_root'])
    row, streams, artifacts = check_process(output,report,TESTS[0],
        [native['python'],'-I','-B',str(origin/'tests/hia_native'/TESTS[0])], expected_json=summary)
    require(row.get('pid') == native['producer_pid'], 'native typed process PID differs')
    control_path = owned(output,FOLDER+'/evidence-controls.json')
    control = decode(control_path.read_bytes())
    expected = dict(status='PASS',refused=list(CONTROL_KINDS),physical_capture_relocations=1,
                    native_evidence_sha256=sha(canonical(native)),new_native_or_rust_processes=0,**SCOPE)
    same(control,expected,'typed evidence refusal domain differs')
    _, _, extra = check_process(output,report,TESTS[1],
        [native['python'],'-I','-B',str(origin/'tests/hia_native'/TESTS[1])], expected_json=control)
    native['evidence_controls'] = control
    native['artifact_sha256'].update(artifacts)
    native['artifact_sha256'].update(extra)
    native['artifact_sha256'][FOLDER+'/evidence-controls.json'] = sha(control_path.read_bytes())
    return native


def original_commands(output, rustc):
    folder = Path(output)/FOLDER/'original'
    return {PROCESS_NAMES[0]:[str(rustc),'--version'],
            PROCESS_NAMES[1]:[str(Path(rustc).with_name('cargo')),'build','--release','--locked','--offline',
                              '--manifest-path',str(folder/'source/Cargo.toml')],
            PROCESS_NAMES[2]:[str(folder/'target/release/hepta-text-editor-params-original-oracle')]}


def original_evidence(output, report, rustc, *, source_root=ROOT):
    root, output = Path(source_root), Path(output)
    native = native_evidence(output,report,source_root=root)
    same(report.get('text_editor_params_evidence'),native,'admitted native typed evidence changed')
    folder = output/FOLDER/'original'
    receipt = decode(owned(folder,'reference.json').read_bytes())
    require(receipt['status'] == 'PASS' and receipt['fresh_target_directory'] is True
            and receipt['fresh_locked_builds'] == 1 and receipt['target_commit'] == TARGET,
            'fresh locked typed reference not completed')
    same(receipt['source_inputs'],source_evidence(root),'original typed source closure differs')
    commands = original_commands(output,rustc)
    same(receipt['commands'],commands,'original typed command set differs')
    for name,digest in REFERENCE_PINS.items():
        require(pin(owned(folder,'source/'+name))['sha256'] == digest,'copied original type source differs')
    require(pin(Path(rustc)) == receipt['compiler_before']['rustc'] == receipt['compiler_after']['rustc']
            and pin(Path(rustc).with_name('cargo')) == receipt['compiler_before']['cargo'] == receipt['compiler_after']['cargo'],
            'original typed compiler bytes differ')
    domain = cases(root)
    require(owned(folder,'input.jsonl').read_bytes() == domain.encoded(),'original typed replay input differs')
    artifacts = dict(native['artifact_sha256'])
    observed = None
    for name in PROCESS_NAMES:
        row, streams, current = check_process(output,report,name,commands[name])
        same(row.get('environment_binding'),receipt['environment_binding'],'original typed process environment differs')
        artifacts.update(current)
        if name == PROCESS_NAMES[0]:
            require(streams['stdout'] == b'rustc 1.95.0 (59807616e 2026-04-14)\n'
                    and streams['stderr'] == b'','original typed Rust version differs')
        elif name == PROCESS_NAMES[1]:
            require(streams['stdout'] == b'', 'original typed build stdout differs')
        else:
            require(streams['stderr'] == b'', 'original typed replay wrote stderr')
            same(row.get('input_identity'),pin(owned(folder,'input.jsonl')),'original typed actual input identity differs')
            observed = [decode(line) for line in streams['stdout'].splitlines()]
    actual = [decode(line) for line in owned(output,FOLDER+'/native/native-results.jsonl').read_bytes().splitlines()]
    require(len(observed) == len(actual) == COUNTS['cases'],'original typed replay omitted cases')
    compared = 0
    for have,want in zip(actual,observed):
        same([have['case_id'],have['name']],[want['case_id'],want['name']],'original typed case order differs')
        a,b = have['result'],want['result']
        same(a['value_admitted'],b['value_admitted'],'typed-map admission differs')
        if a['value_admitted']:
            for key in ('canonical','ok','frame_hex'):
                same(a[key],b[key],'original typed '+key+' differs')
            compared += len(bytes.fromhex(a['frame_hex']))
    binary = owned(folder,'target/release/hepta-text-editor-params-original-oracle')
    same(pin(binary),receipt['executable'],'original typed executable differs')
    for path in (folder/'reference.json',folder/'input.jsonl',binary,
                 *(folder/'source'/name for name in REFERENCE_PINS)):
        artifacts[str(path.relative_to(output))] = pin(path)['sha256']
    return dict(status='PASS',cases=COUNTS['cases'],admitted_maps=COUNTS['value_admitted'],
                successful_typed_values=COUNTS['typed_successes'],complete_compared_frame_bytes=compared,
                actual_original_commands=list(PROCESS_NAMES),fresh_locked_builds=1,target_commit=TARGET,
                source_inputs=source_evidence(root),artifact_sha256=dict(sorted(artifacts.items())),**SCOPE)


def compare_original(output, report, rustc):
    import qualify_hia_runtime_native as q
    output, rustc = Path(output), Path(rustc)
    native = native_evidence(output,report)
    same(report.get('text_editor_params_evidence'),native,'typed native producer was not admitted')
    folder = output/FOLDER/'original'
    folder.mkdir(exist_ok=False)
    shutil.copytree(ROOT/REFERENCE,folder/'source')
    require(not(folder/'target').exists(),'original typed target was not fresh')
    wire = cases().encoded()
    (folder/'input.jsonl').write_bytes(wire)
    env = q.qualification_env()
    for key in tuple(env):
        if key.startswith(('RUST','CARGO','SCCACHE','CCACHE')):
            del env[key]
    binding = dict(PATH=str(rustc.parent)+':/usr/bin:/bin',RUSTC=str(rustc),
                   CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(folder/'target'),LC_ALL='C',
                   RUSTFLAGS='',CARGO_ENCODED_RUSTFLAGS='')
    env.update(binding)
    before = dict(rustc=pin(rustc),cargo=pin(rustc.with_name('cargo')))
    commands = original_commands(output,rustc)
    receipt = dict(status='BUILDING',fresh_target_directory=True,fresh_locked_builds=1,
                   target_commit=TARGET,source_inputs=source_evidence(),commands=commands,
                   environment_binding=binding,compiler_before=before)
    def save(): (folder/'reference.json').write_bytes(canonical(receipt))
    save()
    try:
        for name in PROCESS_NAMES:
            q.record_check(output,report,name=name,command=commands[name],timeout=180,env=env,
                           input_bytes=wire if name == PROCESS_NAMES[2] else None,record_identity=True)
            report['checks'][-1]['environment_binding'] = binding
            if name == PROCESS_NAMES[2]:
                report['checks'][-1]['input_identity'] = dict(bytes=len(wire),sha256=sha(wire))
            q.save_report(output/'result.json',report)
        receipt['compiler_after'] = dict(rustc=pin(rustc),cargo=pin(rustc.with_name('cargo')))
        same(receipt['compiler_after'],before,'typed compiler changed during execution')
        receipt['executable'] = pin(folder/'target/release/hepta-text-editor-params-original-oracle')
        receipt['status'] = 'PASS'
        save()
        return original_evidence(output,report,rustc)
    except BaseException as error:
        receipt.update(status='FAIL',error=repr(error))
        save()
        raise
