"""Twelve physical mutations, two relocations, and two post-refusal admissions."""
from pathlib import Path
import argparse
import gzip
import shutil
import struct
import sys
sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT, encoded, envelope, files, loads, pin, read, require, source
from read_only_guard import guarded
import read_capture

ERRORS = {
    'compiled-image':'complete compiled native image binding',
    'compiler-generation':'actual exact fixed compiler generations',
    'process-budget':'actual command and frozen process budget',
    'dependency-source':'every original dependency source byte',
    'native-return':'actual native return equals the original return',
    'output-suffix':'exact original result and complete untouched output suffix',
    'output-guard':'complete output guard tail',
    'workspace-guard':'complete workspace guard tail',
    'borrowed-input':'complete immutable borrowed input',
    'missing-invocation':'every physical invocation header',
    'case-order':'every physical invocation matches its exact frozen input and capacities',
    'workspace-suffix':'complete untouched high workspace suffix',
}
ADMISSIONS = ('relocation-a','relocation-b','post-refusal-a','post-refusal-b')


def mutation(root,name):
    paths = {'compiled-image':'build/modules/audit-json/module.image.bin',
             'compiler-generation':'build/bootstrap/B3.image.bin'}
    if name in paths:
        path = paths[name]
        raw = bytearray(read(root/path));raw[0] ^= 1
        return {path:bytes(raw)}
    if name == 'process-budget':
        path = 'processes/processes.json'
        rows = loads(read(root/path));rows[-1]['timeout_seconds'] += 1
        return {path:encoded(rows)}
    if name == 'dependency-source':
        path = 'vendor/serde-1.0.229/src/lib.rs'
        return {path:read(root/path)+b'\n'}
    path = 'native/buffers.bin.gz'
    raw = bytearray(gzip.decompress(read(root/path)))
    require(raw[:8] == b'HAJLOG01' and raw[8:16] == b'HAJCAL01','original physical journal for mutation')
    _,_,input_size,output_size,work_size = struct.unpack('<5Q',raw[16:56])
    input_before = 56
    input_after = input_before+input_size+16
    output_before = input_after+input_size+16
    output_after = output_before+output_size+16
    work_before = output_after+output_size+16
    work_after = work_before+work_size+16
    if name == 'native-return':
        struct.pack_into('<Q',raw,24,struct.unpack_from('<Q',raw,24)[0]+1)
    elif name == 'output-suffix':
        raw[output_after+output_size-1] ^= 1
    elif name == 'output-guard':
        raw[output_after+output_size] ^= 1
    elif name == 'workspace-guard':
        raw[work_after+work_size] ^= 1
    elif name == 'borrowed-input':
        raw[input_after] ^= 1
    elif name == 'case-order':
        struct.pack_into('<Q',raw,16,1)
    elif name == 'workspace-suffix':
        raw[work_after+work_size-1] ^= 1
    elif name == 'missing-invocation':
        at,last = 8,8
        while at < len(raw):
            require(raw[at:at+8] == b'HAJCAL01','complete original invocation framing')
            _,_,a,b,c = struct.unpack_from('<5Q',raw,at+8)
            last,at = at,at+48+2*(a+b+c+48)
        require(at == len(raw),'complete original journal before last invocation removal')
        del raw[last:]
    else:
        raise ValueError('unknown fixed physical mutation')
    compressed = gzip.compress(bytes(raw),compresslevel=6,mtime=0)
    report = loads(read(root/'native/NATIVE.json'))
    report['journal'] = pin(compressed)
    return {path:compressed,'native/NATIVE.json':encoded(report)}


def refused(capture,expected):
    envelope(capture)
    try:
        read_capture.semantic(capture)
    except ValueError as failure:
        require(str(failure) == expected,'specific semantic refusal rather than another failure')
        return dict(status='REFUSED',reason=str(failure))
    raise ValueError('fixed physical mutant was admitted')


def check_proof(proof,capture):
    require(proof['schema'] == 'hepta.runtime.scope-span-readonly.v2'
            and proof['source_bound_guard'] is True
            and proof['native_or_rust_executions'] == proof['reader_writes'] == 0
            and proof['before'] == proof['after'], 'complete inert guard proof')
    names = ['python-file-write','descriptor-open','descriptor-write','metadata-mode','metadata-time',
             'directory-create','subprocess','shell','native-dlopen','native-mmap',
             'producer-or-foreign-read','unadmitted-file-descriptor']
    require([row['name'] for row in proof['probes']] == names
            and all(row['refusal'].startswith('owner-export read-only guard: ') for row in proof['probes']),
            'all twelve explicit guard refusals')
    require(type(proof['pid']) is int and proof['pid'] > 1 and proof['ppid'] != proof['pid'], 'reader process identity')
    for index,root in enumerate((ROOT,capture)):
        expected = files(root)
        observed = {key.split(':',1)[1]:row for key,row in proof['before'].items()
                    if key.startswith(str(index)+':') and row['sha256'] is not None}
        require(set(expected) == set(observed),'complete protected file set')
        for name,row in expected.items():
            value = observed[name]
            require(value['bytes'] == row['bytes'] and value['sha256'] == row['sha256']
                    and value['mode'] & 0o777 == row['mode'], 'complete protected file bytes and modes')


def run(output,identity):
    require(source() == identity,'fixed physical control source')
    original = output/'semantic'
    baseline = read_capture.semantic(original)
    controls = output/'controls'
    controls.mkdir()
    refusals,admissions = [],[]
    for name,expected in ERRORS.items():
        folder = controls/name;folder.mkdir()
        capture = folder/'capture'
        shutil.copytree(original,capture)
        mutations = mutation(original,name)
        changes = {}
        for path,raw in mutations.items():
            changes[path] = dict(before=pin(read(capture/path)),after=pin(raw))
            (capture/path).write_bytes(raw)
        seal = loads(read(capture/'CAPTURE.json'))
        seal['files'] = files(capture,('CAPTURE.json',))
        (capture/'CAPTURE.json').write_bytes(encoded(seal))
        proof = guarded(lambda:refused(capture,expected), roots=[ROOT,capture], foreign_path=Path('/dev/null'))
        check_proof(proof,capture)
        raw = encoded(proof);(folder/'PROOF.json').write_bytes(raw)
        refusals.append(dict(name=name,changes=changes,capture=str(capture.relative_to(output)),
            proof=dict(file=str((folder/'PROOF.json').relative_to(output)),**pin(raw)), evidence=proof['evidence']))
    for name in ADMISSIONS:
        folder = controls/name;folder.mkdir()
        capture = folder/'capture'
        shutil.copytree(original,capture)
        require(files(capture) == files(original),'complete relocated source evidence bytes and modes')
        proof = guarded(lambda:read_capture.semantic(capture), roots=[ROOT,capture], foreign_path=Path('/dev/null'))
        check_proof(proof,capture)
        require(proof['evidence'] == baseline,'same evidence after relocation or refusal')
        raw = encoded(proof);(folder/'PROOF.json').write_bytes(raw)
        admissions.append(dict(name=name,capture=str(capture.relative_to(output)),
            proof=dict(file=str((folder/'PROOF.json').relative_to(output)),**pin(raw)),evidence=proof['evidence']))
    result = dict(schema='hepta.audit-json.reader-controls.v1',source_manifest_sha256=identity,
        refusals=refusals,admissions=admissions,guard_proofs=16,guards_per_proof=12,
        native_or_rust_executions=0,reader_writes=0,whole_runtime_replaced=False)
    (output/'CONTROLS.json').write_bytes(encoded(result))
    # Independent full verification has its own unchanged 180-second reader stage.
    print(encoded(dict(status='PASS',refusals=12,admissions=4,guard_proofs=16,
                       native_or_rust_executions=0,reader_writes=0)).decode(),end='')


def verify(output,baseline):
    report = loads(read(output/'CONTROLS.json'))
    require(report['schema'] == 'hepta.audit-json.reader-controls.v1' and report['source_manifest_sha256'] == source()
            and report['guard_proofs'] == 16 and report['guards_per_proof'] == 12
            and report['native_or_rust_executions'] == report['reader_writes'] == 0
            and report['whole_runtime_replaced'] is False,'source-bound complete inert reader controls')
    require([row['name'] for row in report['refusals']] == list(ERRORS)
            and [row['name'] for row in report['admissions']] == list(ADMISSIONS),'complete fixed physical control domain')
    original = output/'semantic'
    baseline_files = files(original)
    for row in report['refusals']+report['admissions']:
        name = row['name']
        require(row['capture'] == 'controls/'+name+'/capture'
                and row['proof']['file'] == 'controls/'+name+'/PROOF.json','fixed retained control paths')
        capture = output/row['capture']
        raw = read(output/row['proof']['file'])
        require(pin(raw) == {key:row['proof'][key] for key in ('bytes','sha256')},'complete retained guard proof')
        proof = loads(raw);check_proof(proof,capture)
        require(proof['evidence'] == row['evidence'],'retained control evidence agrees with complete guard')
        if name in ERRORS:
            mutations = mutation(original,name)
            expected_files = dict(baseline_files)
            changes = {}
            for path,content in mutations.items():
                require(read(capture/path) == content,'exact physical mutation bytes')
                expected_files[path] = dict(**pin(content),mode=baseline_files[path]['mode'])
                changes[path] = dict(before=pin(read(original/path)),after=pin(content))
            seal = loads(read(original/'CAPTURE.json'))
            seal['files'] = {name:identity for name,identity in expected_files.items() if name != 'CAPTURE.json'}
            expected_files['CAPTURE.json'] = dict(**pin(encoded(seal)),mode=baseline_files['CAPTURE.json']['mode'])
            require(files(capture) == expected_files and row['changes'] == changes,'complete exact rebound physical mutation')
            require(refused(capture,ERRORS[name]) == row['evidence'],'independent physical refusal')
        else:
            require(files(capture) == baseline_files and read_capture.semantic(capture) == baseline == row['evidence'],
                    'complete relocated or post-refusal evidence remains admissible')
    return dict(status='PASS',refusals=12,relocations=2,post_refusal_admissions=2,guard_proofs=16,
                guards_per_proof=12,native_or_rust_executions=0,reader_writes=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-manifest-sha256',required=True)
    args = parser.parse_args()
    run(args.output.resolve(strict=True),args.source_manifest_sha256)
