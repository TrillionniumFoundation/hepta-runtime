"""Strict complete evidence for the private Linux exclusive-create leaf.

Readers do not execute a native image or Rust. Only compare_original starts the
explicit fresh locked reference build and its three retained semantic replays.
"""
from __future__ import annotations
import collections
import gzip
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import sys
import tomllib

from hia_native_local_create_build import verify_build, source_evidence as build_sources

ROOT = Path(__file__).resolve().parents[1]
FOLDER = 'local-create'
DRIVERS = 'tests/hia_native/local_create'
REFERENCE = DRIVERS + '/reference'
TESTS = ('test_local_create.py', 'test_local_create_build.py', 'test_local_create_evidence.py')
MODULE = dict(key='local_create_file', name='local-create-file', source='native/local_create_file.hepta',
              builder='local_create', manifest_env='HIA_LOCAL_CREATE_MANIFEST',
              test=TESTS[0], additional_tests=TESTS[1:],
              companion_sources=('native/local_create_packer.hepta',), buffer_profile='history.v1')
PROCESS_NAMES = ('local-create-rust-version', 'local-create-cargo-version',
                 'local-create-cargo-metadata', 'local-create-rust-build',
                 'local-create-kernel-original', 'local-create-race-original',
                 'local-create-fault-original')
SCOPE = dict(production_activated=False, whole_runtime_replaced=False,
             old_stack_removal_qualified=False, async_cancellation_qualified=False,
             public_handler_qualified=False, full_create_file_spec_qualified=False)
COUNTS = dict(actual_native_state_calls=54030, kernel_cases=285, race_pairs=32,
              fault_cases=8, actual_native_elf_processes=357)
BUILD_COUNTS = dict(actual_assembler_processes=3, complete_adapter_comparisons=1,
                    actual_packer_calls=24, artifact_refusals=14, source_refusals=4,
                    valid_artifact_admissions=1)
CONTROL_COUNTS = dict(actual_captures=2, process_refusals=10,
                      source_refusals=4, artifact_refusals=12)
CORPUS_SHA = '9236bba1a427654228e4e4cae6a58d8c65d127e3a588e3f64d16d0e4d359d408'
REFERENCE_PINS = {
    'Cargo.toml': '5455b86b260ca27a2721ef115b2135bb00b1e88f58380b2db86aa17ffa077b44',
    'Cargo.lock': 'e406efc4da7bc4ceff2cdf2a4ff01e942cc6b85695e7556b0a6c1a168c62de0a',
    'src/main.rs': '40f173ebca9264f15f34187ca6dcd68759e51515ef57b1a8b28d6d839b823750',
    'file_ops.rs': '487524ea40ebc2fd7ddec1676d927237127b768804a73bddeff0d4dc510d206a',
}
SOURCE_FILES = (
    'native/local_create_file.hepta', 'native/local_create_packer.hepta',
    'native/local_create_file_component.json', 'native/local_create_file_abi.md',
    'scripts/local_create_adapter.S', 'scripts/hia_native_local_create_build.py',
    'scripts/hia_native_local_create_qualification.py', 'scripts/hia_native_loader.py',
    'scripts/hia_native_build.py', 'tests/hia_native/evidence_snapshot.py',
    *( 'tests/hia_native/' + name for name in TESTS),
    *(DRIVERS + '/' + name for name in ('kernel_cases.py', 'state_controls.py',
                                      'race_cases.py', 'fault_cases.py', 'corpus_pins.json')),
    *(REFERENCE + '/' + name for name in REFERENCE_PINS),
)
MASK = (1 << 64) - 1
Q = lambda n: struct.pack('<Q', n)
U = lambda raw, at: struct.unpack_from('<Q', raw, at)[0]


def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(raw): return dict(bytes=len(raw), sha256=sha(raw))
def compact(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def exact(actual, expected, message):
    if compact(actual) != compact(expected): raise ValueError(message)
def require(condition, message):
    if not condition: raise ValueError(message)
def finite(value, maximum):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('duplicate JSON evidence key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON')))


def owned(base, name):
    require(type(name) is str and name and PurePosixPath(name).as_posix() == name
            and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
            'local-create evidence path is not an admitted relative file')
    path = Path(base) / name
    require(path.is_file() and not path.is_symlink() and path.resolve() == path.absolute(),
            'local-create evidence requires an ordinary unaliased file: ' + name)
    return path


class Evidence:
    def __init__(self, output):
        self.output = Path(output).resolve(strict=True)
        self.artifact_sha256 = {}
    def read(self, name):
        raw = owned(self.output, name).read_bytes()
        self.artifact_sha256[name] = sha(raw)
        return raw
    def object(self, name): return decode(self.read(name))
    def compressed(self, name): return gzip.decompress(self.read(name))


def source_evidence(root=ROOT):
    root = Path(root).resolve(strict=True)
    component = build_sources(root)
    files = {name: pin(owned(root, name).read_bytes()) for name in SOURCE_FILES}
    require(files[DRIVERS+'/corpus_pins.json']['sha256'] == CORPUS_SHA, 'local-create frozen corpus changed')
    for name, expected in REFERENCE_PINS.items():
        require(files[REFERENCE+'/'+name]['sha256'] == expected, 'local-create locked original source changed: '+name)
    reference = component['target_reference']
    original = owned(root, REFERENCE+'/file_ops.rs').read_bytes()
    body = original[reference['function_start']:reference['function_end']]
    require(len(original) == reference['target_file']['bytes']
            and hashlib.sha1(b'blob '+str(len(original)).encode()+b'\0'+original).hexdigest()
                == reference['target_file']['git_blob']
            and sha(body) == reference['function_sha256']
            and owned(root, REFERENCE+'/src/main.rs').read_bytes().count(body) == 1,
            'local-create exact current-target function differs')
    require(reference['target_commit'] == '737acf6f901e46c57b0b4374e323e0d1132e0d49',
            'local-create target commit differs')
    lock = tomllib.loads(owned(root, REFERENCE+'/Cargo.lock').read_text())
    registry = [{k: p[k] for k in ('name', 'version', 'source', 'checksum')}
                for p in lock['package'] if 'source' in p]
    require(len(registry) == 3 and {p['name'] for p in registry} == {'tokio','bytes','pin-project-lite'},
            'local-create minimal registry closure differs')
    return dict(component=component, files=files, reference_registry=registry, **SCOPE)


def driver(root, name):
    path = owned(root, DRIVERS+'/'+name)
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location('_local_create_'+path.stem, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def corpus(root=ROOT): return decode(owned(root, DRIVERS+'/corpus_pins.json').read_bytes())


def process(evidence, report, name, command, phase, *, groups=None, timeout=180):
    rows = [row for row in report['checks'] if row.get('name') == name]
    require(len(rows) == 1, 'local-create requires one actual completed process: '+name)
    row = rows[0]
    stdout = evidence.read(name+'.stdout'); stderr = evidence.read(name+'.stderr')
    want = dict(name=name, command=command, phase=phase, exit_code=0, timed_out=False,
                timeout_seconds=timeout, stdout_bytes=len(stdout), stderr_bytes=len(stderr),
                stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
    exact({key: row.get(key) for key in want}, want, 'local-create process completion or complete streams differ: '+name)
    require('start_error' not in row and finite(row.get('elapsed_seconds'), timeout),
            'local-create process did not complete inside its retained deadline')
    if groups is not None:
        text = stderr.decode('utf-8')
        require(len(re.findall(r'\.\.\. ok\n', text)) == groups
                and re.search(r'\nRan '+str(groups)+r' tests in [0-9.]+s\n\nOK\n\Z', text),
                'local-create complete unittest domain did not pass')
        summary = decode(stdout)
        exact(row.get('summary'), summary, 'local-create outer summary differs from actual stdout')
        require(summary.get('status') == 'PASS' and summary.get('tests_run') == groups
                and type(summary.get('tests_run')) is int, 'local-create actual suite summary incomplete')
        for field in ('failures','errors','skipped','expected_failures','unexpected_successes'):
            require(type(summary.get(field)) is int and summary[field] == 0, 'local-create incomplete suite: '+field)
        return summary
    return stdout, stderr, row


def module_evidence(evidence, report, root):
    row = report['modules']['local_create_file']; relative = row['manifest']
    raw = evidence.read(relative)
    exact({k: row.get(k) for k in ('source','builder','sha256')},
          dict(source='native/local_create_file.hepta',builder='local_create',sha256=sha(raw)),
          'local-create registered native build differs')
    manifest = verify_build(owned(evidence.output, relative), source_root=Path(root))
    folder = PurePosixPath(relative).parent
    for name in ('manifest.json','owner.json','owner.hepta','owner.image.bin','packer.json',
                 'packer.hepta','packer.image.bin','pack.input.bin','pack.output.bin',
                 'pack.receipt.json','local-create.elf'):
        evidence.read(str(folder/name))
    compiler = evidence.read('build/bootstrap/B3.image.bin')
    evidence.read('build/bootstrap/bootstrap.json')
    require(sha(compiler) == manifest['compiler_sha256'] == report['compiler_image_sha256']
            and manifest['compiler_commit'] == report['compiler_commit'], 'local-create aggregate compiler custody differs')
    return dict(manifest=relative,manifest_sha256=sha(raw),executable=str(folder/'local-create.elf'),
                executable_sha256=sha(evidence.read(str(folder/'local-create.elf'))),
                owner_image_sha256=sha(evidence.read(str(folder/'owner.image.bin'))))


def effects(raw, path_size):
    require(len(raw) % 96 == 0, 'truncated actual syscall effect stream')
    records=[]
    for at in range(0,len(raw),96):
        magic,sequence,action,a,b,c,d,ready,value,error,token,reserved=struct.unpack_from('<12Q',raw,at)
        require(magic==int.from_bytes(b'HLCREF01','little') and sequence==len(records)+1
                and ready==1 and reserved==0 and action in (1,2,3), 'actual syscall effect frame differs')
        require(error<=4095 and (not error or (value==(-error&MASK) and token==0)), 'actual syscall completion differs')
        if action==1:
            require((a,b,c,d)==(512,path_size,0x800c1,0o666), 'exclusive-open effect differs')
            require(error or (value<=0x7fffffff and token==1), 'open descriptor custody differs')
        elif action==2:
            require(a==1 and 0<c<=2**21 and d==token==0 and (error or value<=c), 'write effect differs')
        else:
            require((a,b,c,d,token)==(1,0,0,0,0) and (error or value==0), 'close effect differs')
        records.append(dict(sequence=sequence,action=action,args=[a,b,c,d],raw=value,errno=error,token=token))
    return records


def result_body(stdout, native):
    if native:
        require(len(stdout)==56 and U(stdout,0)==48, 'native static complete result extent differs')
        stdout=stdout[8:]
    require(len(stdout)==48 and stdout[:8]==b'HLCRER01', 'complete result frame differs')
    extent,kind,error,written,reserved=struct.unpack_from('<5Q',stdout,8)
    require(extent==48 and kind<=3 and reserved==0
            and (1<=error<=4095 if kind==1 else error==0), 'typed filesystem result differs')
    return kind,error,written,stdout


def check_state(evidence, base, pins, component):
    summary=evidence.object(base+'/summary.json')
    expected=dict(schema='hepta.runtime.local-create-state-controls.v1',status='PASS',error=None,
        counts=pins['state_counts'],source_sha256=component['source_sha256']['native/local_create_file.hepta'],
        image_sha256=component['owner_image_sha256'],actual_kernel_effects=0,typed_completions_only=True,
        original_rust_execution_performed=False,whole_runtime_replaced=False,public_handler_qualified=False)
    exact({k:summary.get(k) for k in expected},expected,'complete state capture domain or scope differs')
    require(finite(summary.get('elapsed_seconds'),180),'state capture deadline differs')
    entries=[decode(line) for line in evidence.compressed(base+'/entries.jsonl.gz').splitlines()]
    require(len(entries)==54030,'state call count differs')
    wire=evidence.read(base+'/complete-arrays.bin.gz');stream=gzip.GzipFile(fileobj=io.BytesIO(wire))
    full=hashlib.sha256();declarations=hashlib.sha256();total=0;categories=collections.Counter()
    guards=((b'i'*16,b'I'*16),(b'o'*16,b'O'*16),(b'w'*16,b'W'*16))
    for number,row in enumerate(entries,1):
        require(type(row.get('number')) is int and row['number']==number and row.get('complete_buffers_checked') is True,
                'state call numbering/capture differs')
        require(type(row.get('elapsed_ns')) is int and row['elapsed_ns']>=0,'state call time differs')
        declaration={k:v for k,v in row.items() if k!='elapsed_ns'}
        declarations.update(compact(declaration)+b'\n');categories[row['category']]+=1
        capacities=row['capacities'];require(len(capacities)==3 and all(type(x)is int and x>=0 for x in capacities),'state capacities differ')
        arrays=[]
        for capacity in capacities*2:
            head=stream.read(8);require(len(head)==8 and U(head,0)==capacity+32,'state complete array extent differs')
            raw=stream.read(capacity+32);require(len(raw)==capacity+32,'state array truncated')
            full.update(head);full.update(raw);total+=len(head)+len(raw);arrays.append(raw)
        before,after=arrays[:3],arrays[3:]
        require(before[0]==after[0],'state input changed')
        for raw,(left,right) in zip(after,guards):require(raw[:16]==left and raw[-16:]==right,'state guard changed')
        returned=row['returned'];require(type(returned)is int,'state return is not an integer')
        if returned==48:require(after[1][64:]==before[1][64:],'state result tail changed')
        else:require(after[1]==before[1],'non-result state output changed')
        if returned in (0xffffffff,0xfffffffe):require(after[2]==before[2],'state refusal mutated workspace')
    require(stream.read(1)==b'','state arrays have trailing bytes');stream.close()
    exact(dict(bytes=total,sha256=full.hexdigest()),pins['state_arrays'],'complete retained state buffers differ')
    exact(declarations.hexdigest(),pins['state_declarations_sha256'],'ordered complete state call declarations differ')
    exact(dict(categories),pins['state_categories'],'state category domain differs')
    return expected


def fixture_rows(spec, success):
    entries={};groups={}
    for kind,name,data in spec['setup']:
        if kind=='directory':entries[name]=dict(kind='directory',mode=0o755,nlink=2)
        elif kind=='symlink':entries[name]=dict(kind='symlink',mode=0o777,nlink=1,target_hex=data.hex())
        elif kind=='file':
            entries[name]=dict(kind='file',mode=0o640,nlink=1,data=data);groups[name]=[name]
        elif kind=='hardlink':
            require(data in groups,'fixture hardlink target differs')
            entries[name]=dict(entries[data]);groups[data].append(name)
    for members in groups.values():
        for name in members:entries[name]['nlink']=len(members)
    if success:
        name={'repeated-slashes':b'dir/created','dot-components':b'dir/created',
              'dotdot-components':b'created','parent-symlink':b'dir/created'}.get(spec['name'],spec['path'])
        require(name not in entries and b'\0' not in name,'successful fixture path differs')
        entries[name]=dict(kind='file',mode=0o666&~spec['umask'],nlink=1,data=spec['data'])
    rows=[];contents={}
    for name,record in sorted(entries.items()):
        row=dict(path_hex=name.hex(),**record)
        if row['kind']=='file':
            data=row.pop('data');file='file-'+str(len(rows))+'.bin.gz'
            row.update(bytes=len(data),sha256=sha(data),content=file);contents[file]=data
        rows.append(row)
    return rows,contents


def check_snapshot(evidence, base, rows, expected):
    want,contents=expected
    exact(rows,want,'complete filesystem snapshot metadata differs')
    for name,data in contents.items():
        require(evidence.compressed(base+'/'+name)==data,'complete captured filesystem bytes differ')


def execution_streams(evidence, base, execution, stdin, command, cwd, *, umask=None):
    raw_stdin=evidence.compressed(base+'/stdin.bin.gz')
    stdout=evidence.read(base+'/stdout.bin');stderr=evidence.read(base+'/stderr.bin')
    require(raw_stdin==stdin,'actual filesystem process input differs')
    want=dict(command=[command],cwd=cwd,environment={'PATH':'','LC_ALL':'C'},
              timeout_seconds=60,exit_code=0,stdin=pin(stdin),stdout=pin(stdout),stderr=pin(stderr))
    if umask is not None and 'umask' in execution:want['umask']=umask
    exact({k:execution.get(k) for k in want},want,'filesystem process command, bytes or completion differs')
    require(finite(execution.get('elapsed_seconds'),60),'filesystem process exceeded its deadline')
    return stdout,stderr


def check_kernel(evidence, base, root, native, executable, origin):
    d=driver(root,'kernel_cases.py');specs=d.cases();pins=corpus(root)
    require(len(specs)==285,'kernel domain shrank')
    summary=evidence.object(base+'/summary.json')
    want=dict(status='PASS',cases=285,actual_processes=285,native=native,
              original_rust_execution_performed=not native,public_handler_qualified=False,whole_runtime_replaced=False)
    exact({k:summary.get(k) for k in want},want,'kernel actual process domain differs')
    require(finite(summary.get('elapsed_seconds'),180),'kernel corpus deadline differs')
    inputs=hashlib.sha256();outputs=hashlib.sha256();input_bytes=output_bytes=effects_count=0
    for index,spec in enumerate(specs):
        prefix=base+'/'+str(index);row=evidence.object(prefix+'/result.json')
        require(row.get('name')==spec['name'],'kernel ordered case name differs')
        exact(evidence.object(prefix+'/execution.json'),row['execution'],'kernel process receipt copy differs')
        wire=d.frame(spec['path'],spec['data']);normalized=Q(len(wire))+wire
        inputs.update(normalized);input_bytes+=len(normalized)
        stdin=normalized if native else wire
        stdout,stderr=execution_streams(evidence,prefix,row['execution'],stdin,executable,
            origin+'/'+prefix+'/files',umask=spec['umask'])
        kind,error,written,body=result_body(stdout,native)
        exact([row.get('kind'),row.get('errno'),row.get('written')],[kind,error,written],'kernel typed result receipt differs')
        if native:
            actual=effects(stderr,len(spec['path']));exact(actual,row['effects'],'kernel complete effect receipt differs')
            if b'\0' in spec['path']:require(kind==2 and not actual,'NUL unexpectedly caused a kernel operation')
            elif kind:
                require(len(actual)==1 and actual[0]['action']==1 and actual[0]['errno']==error,'open error effect differs')
            else:
                require([r['action'] for r in actual]==[1]+[2]*((len(spec['data'])+(1<<21)-1)//(1<<21))+[3],
                        'kernel successful effect order differs')
                progress=0
                for r in actual[1:-1]:
                    require(r['errno']==0 and r['args'][1]==513+len(spec['path'])+progress
                            and r['args'][2]==r['raw']==min(1<<21,len(spec['data'])-progress),
                            'kernel complete write extent differs')
                    progress+=r['raw']
                require(actual[0]['errno']==actual[-1]['errno']==0 and progress==len(spec['data']),
                        'successful kernel effect failed')
            effects_count+=len(actual)
        else:
            require(stderr==b'HLCREATE-REFERENCE-BEGIN\nHLCREATE-REFERENCE-END\n' and row['effects']==[],
                    'original helper markers or injected-effect claim differ')
        require(written==(len(spec['data']) if kind==0 else 0),'kernel complete write count differs')
        outputs.update(body);output_bytes+=len(body)
        check_snapshot(evidence,prefix+'/before',row['before'],fixture_rows(spec,False))
        check_snapshot(evidence,prefix+'/after',row['after'],fixture_rows(spec,kind==0))
    exact(dict(bytes=input_bytes,sha256=inputs.hexdigest()),pins['kernel_requests'],'complete kernel request stream differs')
    exact(dict(bytes=output_bytes,sha256=outputs.hexdigest()),pins['kernel_results'],'complete kernel typed results differ')
    require(summary['actual_native_kernel_effects']==effects_count and type(summary['actual_native_kernel_effects'])is int,
            'kernel effect count differs')
    require(summary['total_input_bytes']==input_bytes-(0 if native else 8*285)
            and summary['total_output_bytes']==output_bytes+(8*285 if native else 0),'kernel complete stream totals differ')
    return dict(cases=285,requests=pins['kernel_requests'],results=pins['kernel_results'],kernel_effects=effects_count)


def check_races(evidence, base, native, executable, origin):
    summary=evidence.object(base+'/result.json')
    want=dict(schema='hepta.runtime.local-create-races.v1',status='PASS',error=None,pairs=32,
              actual_processes=64,original_rust=not native,executable=executable,
              timeout_seconds_per_process=60,native_public_handler_qualified=False,whole_runtime_replaced=False)
    exact({k:summary.get(k) for k in want},want,'actual race domain differs')
    require(finite(summary.get('elapsed_seconds'),180),'race corpus deadline differs')
    payloads=[b'first caller bytes',b'second caller bytes'];pids=set()
    for number in range(32):
        prefix=base+'/'+str(number);row=evidence.object(prefix+'/result.json')
        require(type(row.get('number'))is int and row['number']==number
                and row.get('both_processes_live_before_input_release')is True,'race synchronization receipt differs')
        processes=row['processes'];require(len(processes)==2,'race is not two actual processes')
        results=[];pair_pids=[]
        for index,actual in enumerate(processes):
            require(actual.get('index')==index and type(actual.get('pid'))is int and actual['pid']>0
                    and type(actual.get('exit_code'))is int and actual['exit_code']==0
                    and finite(actual.get('elapsed_seconds'),60),'race process completion differs')
            pair_pids.append(actual['pid']);pids.add(actual['pid'])
            wire=b'HLCREQ01'+struct.pack('<7Q',1,7,len(payloads[index]),0,0,0,0)+b'created'+payloads[index]
            require(evidence.compressed(prefix+'/'+str(index)+'.stdin.bin.gz')==(Q(len(wire))+wire if native else wire),
                    'race actual input differs')
            stdout=evidence.read(prefix+'/'+str(index)+'.stdout.bin');stderr=evidence.read(prefix+'/'+str(index)+'.stderr.bin')
            exact(actual.get('stdout'),pin(stdout),'race complete stdout receipt differs')
            exact(actual.get('stderr'),pin(stderr),'race complete stderr receipt differs')
            kind,error,written,body=result_body(stdout,native)
            require((kind,error)in((0,0),(1,17)) and written==(len(payloads[index]) if not kind else 0),
                    'race result differs')
            if native:
                trace=effects(stderr,7)
                require([r['action']for r in trace]==([1,2,3]if kind==0 else[1]),'race effect order differs')
                if kind:require(trace[0]['errno']==17,'race loser did not fail atomically')
                else:require(all(r['errno']==0 for r in trace) and trace[1]['raw']==len(payloads[index]),'race successful write differs')
            else:require(stderr==b'HLCREATE-REFERENCE-BEGIN\nHLCREATE-REFERENCE-END\n','race original helper markers differ')
            results.append([kind,error])
        require(len(set(pair_pids))==2 and sorted(results)==[[0,0],[1,17]],'race lacks exactly one creator')
        exact(row.get('results'),results,'race retained results differ')
        winner=results.index([0,0]);require(type(row.get('winner'))is int and row['winner']==winner,'race winner differs')
        actual=evidence.read(prefix+'/created.bin');require(actual==payloads[winner],'race complete winner bytes differ')
        exact(row.get('final_file'),pin(actual),'race captured file receipt differs')
    return dict(pairs=32,actual_processes=64)


def check_faults(evidence, base, root, native, executable, origin):
    d=driver(root,'fault_cases.py');specs=d.cases();require(len(specs)==8,'fault domain shrank')
    summary=evidence.object(base+'/summary.json')
    want=dict(schema='hepta.runtime.local-create-faults.v1',status='PASS',error=None,cases=8,actual_processes=8,
              native=native,executable=executable,timeout_seconds_per_process=60,
              actual_kernel_operations=True,injected_completions=False,
              original_rust_execution_performed=not native,public_handler_qualified=False,
              full_create_file_spec_qualified=False,async_cancellation_qualified=False,whole_runtime_replaced=False)
    exact({k:summary.get(k) for k in want},want,'fault actual process domain differs')
    require(finite(summary.get('elapsed_seconds'),180),'fault corpus deadline differs')
    total=0
    for index,(limit,size) in enumerate(specs):
        prefix=base+'/'+str(index);row=evidence.object(prefix+'/result.json');data=d.payload(size)
        wire=d.frame(data);stdin=Q(len(wire))+wire if native else wire
        stdout,stderr=execution_streams(evidence,prefix,row,stdin,executable,origin+'/'+prefix+'/files',umask=0o022)
        want=dict(index=index,limit=limit,input_bytes=size,umask=0o022,rlimit_fsize=[limit,limit],sigxfsz='ignored')
        exact({k:row.get(k) for k in want},want,'fault resource limit or ordered case differs')
        kind,error,written,body=result_body(stdout,native)
        exact([kind,error],[1,27] if size>limit else [0,0],'actual EFBIG classification differs')
        exact([row.get('kind'),row.get('errno'),row.get('written_field')],[kind,error,written],'fault result receipt differs')
        actual=evidence.read(prefix+'/created.bin');require(actual==data[:min(size,limit)],'fault complete retained prefix differs')
        exact(row.get('file'),dict(**pin(actual),mode=0o644),'fault file receipt differs')
        if native:
            trace=effects(stderr,7);exact(trace,row['effects'],'fault full effect receipt differs')
            require(trace[0]['action']==1 and trace[0]['errno']==0 and trace[-1]['action']==3
                    and trace[-1]['errno']==0,'fault open/close custody differs')
            progress=0
            for ordinal,r in enumerate(trace[1:-1],1):
                require(r['action']==2 and r['args'][1]==520+progress,'fault write source offset differs')
                if r['errno']:
                    require(r['errno']==27 and ordinal==len(trace)-2 and size>limit,'fault error priority/order differs')
                else:
                    require(0<r['raw']<=r['args'][2],'fault successful partial write differs');progress+=r['raw']
            require(written==progress==len(actual),'fault actual written progress differs')
            require(size<=limit or trace[-2]['errno']==27,'fault omitted actual write error')
            total+=len(trace)
        else:
            require(stderr==b'HLCREATE-REFERENCE-BEGIN\nHLCREATE-REFERENCE-END\n' and row['effects']==[],
                    'fault original execution markers differ')
            require(written==(size if not kind else 0),'original error progress must remain unobserved')
    exact(summary.get('actual_kernel_effects'),total,'fault actual kernel effect count differs')
    return dict(cases=8,actual_processes=8,kernel_effects=total)


def fixture_directories(base):
    return [base+'/'+kind+'/'+str(i)+'/files' for kind,count in (('kernel',285),('race',32),('fault',8)) for i in range(count)]


def retire_fixtures(output, base, capture, *, create=False):
    output=Path(output).resolve();paths=fixture_directories(base)
    expected=dict(schema='hepta.runtime.local-create-fixture-retirement.v1',status='PASS',
                  capture_sha256=sha(compact(capture)),directories=paths,retired_directories=325,
                  native_or_original_reexecuted=False)
    path=output/base/'retirement.json'
    if create:
        require(not path.exists(),'fixture retirement already exists')
        for name in paths:
            directory=output/name
            require(directory.is_dir() and not directory.is_symlink()
                    and directory.resolve()==directory.absolute(),'owned fixture directory changed before retirement')
        for name in paths:shutil.rmtree(output/name)
        path.write_bytes(compact(expected)+b'\n')
    evidence=Evidence(output);exact(evidence.object(base+'/retirement.json'),expected,'fixture retirement receipt differs')
    require(all(not (output/name).exists() and not (output/name).is_symlink() for name in paths),
            'live filesystem fixture remains in aggregate artifact inventory')
    return evidence.artifact_sha256


def capture_native(output, manifest_path, *, source_root=ROOT, execution=None):
    output=Path(output).resolve();source_root=Path(source_root).resolve();manifest_path=Path(manifest_path).resolve()
    sources=source_evidence(source_root);component=sources['component'];evidence=Evidence(output)
    relative=str(manifest_path.relative_to(output))
    report=dict(compiler_commit=component['compiler_commit'],compiler_image_sha256=component['compiler_sha256'],
        modules={'local_create_file':dict(manifest=relative,sha256=sha(manifest_path.read_bytes()),
                 source='native/local_create_file.hepta',builder='local_create')})
    module=module_evidence(evidence,report,source_root)
    execution=execution or dict(source_root=str(source_root),output=str(output),manifest=str(manifest_path))
    exact(execution['manifest'],str(Path(execution['output'])/relative),'native manifest origin differs')
    require(all(type(execution[k])is str and Path(execution[k]).is_absolute()
                and '..' not in Path(execution[k]).parts for k in ('source_root','output','manifest')),
            'native execution origin is not an absolute admitted path')
    executable=str(Path(execution['output'])/module['executable']);base=FOLDER+'/native'
    state=check_state(evidence,base+'/state',corpus(source_root),component)
    kernel=check_kernel(evidence,base+'/kernel',source_root,True,executable,execution['output'])
    races=check_races(evidence,base+'/race',True,executable,execution['output'])
    faults=check_faults(evidence,base+'/fault',source_root,True,executable,execution['output'])
    for name,relative_summary in [('race','result.json'),('fault','summary.json')]:
        require(evidence.object(base+'/'+name+'/'+relative_summary).get('executable_sha256')==module['executable_sha256'],
                'native filesystem corpus executable identity differs')
    for label in ('state','kernel','race','fault'):evidence.read(base+'/'+label+'.driver.stdout')
    exact(source_evidence(source_root),sources,'native sources changed during complete evidence readback')
    return dict(schema='hepta.runtime.local-create-native-capture.v1',status='PASS',counts=COUNTS,
        source_inputs=sources,module=module,execution=execution,state=state,kernel=kernel,races=races,faults=faults,
        artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),**SCOPE)


def suite_command(report,name,origin):
    rows=[row for row in report['checks'] if row.get('name')==name]
    require(len(rows)==1,'suite completion absent or duplicated: '+name)
    command=rows[0].get('command',[])
    require(type(command)is list and len(command)==4 and type(command[0])is str
            and Path(command[0]).is_absolute() and Path(command[0]).name.startswith('python'),
            'native suite interpreter differs')
    return [command[0],'-I','-B',str(Path(origin)/'tests/hia_native'/name)]


def check_build_controls(evidence, report, source_root, module, execution):
    summary=process(evidence,report,TESTS[1],suite_command(report,TESTS[1],execution['source_root']),
                    'native_components',groups=3)
    base=FOLDER+'/build-controls'
    exact(evidence.object(base+'/summary.json'),summary,'build control retained summary differs')
    exact(summary.get('counts'),BUILD_COUNTS,'build control count domain differs')
    exact(summary.get('manifest_sha256'),module['manifest_sha256'],'build control manifest differs')
    exact(summary.get('expected_tests'),3,'build control expected domain differs')
    prefix=bytes.fromhex(build_sources(source_root)['prefix_hex'])
    records=evidence.object(base+'/assembler-processes.json')
    origin=Path(execution['output'])/base
    commands=[['as','--64','-o',str(origin/'adapter.o'),str(Path(execution['source_root'])/'scripts/local_create_adapter.S')],
              ['objcopy','-O','binary','-j','.text',str(origin/'adapter.o'),str(origin/'adapter.bin')],
              ['readelf','-r',str(origin/'adapter.o')]]
    require(len(records)==3,'actual assembler process domain differs')
    for index,(record,command) in enumerate(zip(records,commands,strict=True)):
        stdout=evidence.read(base+'/'+str(index)+'.stdout');stderr=evidence.read(base+'/'+str(index)+'.stderr')
        exact(record,dict(command=command,exit_code=0,timeout_seconds=30,stdout=pin(stdout),stderr=pin(stderr)),
              'actual assembler completion or complete output differs')
    require(b'There are no relocations' in stdout,'bridge contains relocations')
    evidence.read(base+'/adapter.o');require(evidence.read(base+'/adapter.bin')==prefix[176:]+b'\xcc','actual assembled bridge differs')
    folder=PurePosixPath(module['manifest']).parent
    image=evidence.read(str(folder/'owner.image.bin'));elf=evidence.read(module['executable'])
    wire=b'HLCREPK1'+Q(len(image))+image
    cases=[('exact',wire,len(elf),len(elf)),('tail',wire,len(elf)+37,len(elf)),
           ('short-output',wire,len(elf)-1,0xfffffffe),('zero-output',wire,0,0xfffffffe),
           ('magic',b'X'+wire[1:],len(elf),0xffffffff),
           ('length-low',wire[:8]+Q(len(image)-1)+image,len(elf),0xffffffff),
           ('length-high',wire[:8]+Q(len(image)+1)+image,len(elf),0xffffffff),
           ('empty-image',b'HLCREPK1'+bytes(8),len(elf),0xffffffff)]
    cases.extend(('short-'+str(size),wire[:size],len(elf),0xffffffff)for size in range(16))
    calls=evidence.object(base+'/packer-calls.json');require(len(calls)==24,'actual packer control domain differs')
    guards=((b'i'*16,b'I'*16),(b'o'*16,b'O'*16),(b'w'*16,b'W'*16))
    for (name,request,capacity,returned),row in zip(cases,calls,strict=True):
        exact(row,dict(name=name,returned=returned,capacities=[len(request),capacity,64],complete_arrays_checked=True),
              'actual packer control declaration differs')
        before=[left+raw+right for (left,right),raw in zip(guards,(request,b'\xa7'*capacity,b'\x5a'*64))]
        after=list(before)
        if returned<0xffff0000:after[1]=guards[1][0]+elf+b'\xa7'*(capacity-len(elf))+guards[1][1]
        for phase,arrays in (('before',before),('after',after)):
            for index,raw in enumerate(arrays):
                require(evidence.read(base+'/'+name+'/'+phase+str(index)+'.bin')==raw,
                        'complete actual packer array or guard differs')
    expected=['schema','activation-bool','activation-number','compiler','owner-source','owner-image',
              'packer-source','packer-image','owner-capacity','elf','pack-input','pack-output-tail',
              'pack-receipt','pack-source-custody','native/local_create_file.hepta',
              'native/local_create_packer.hepta','scripts/local_create_adapter.S','native/local_create_file_component.json']
    exact(evidence.object(base+'/refusals.json'),expected,'build source/artifact refusal domain differs')
    return summary


def core_evidence(output, report, *, source_root=ROOT):
    output=Path(output).resolve();source_root=Path(source_root).resolve();evidence=Evidence(output)
    stored=evidence.object(FOLDER+'/native/summary.json');execution=stored.get('execution')
    require(type(execution)is dict,'native execution origin absent')
    summary=process(evidence,report,TESTS[0],suite_command(report,TESTS[0],execution['source_root']),
                    'native_components',groups=4)
    exact(summary,stored,'native suite stdout differs from retained summary')
    module=module_evidence(evidence,report,source_root)
    capture=capture_native(output,owned(output,module['manifest']),source_root=source_root,execution=execution)
    expected=dict(schema='hepta.runtime.local-create-native-suite.v1',status='PASS',tests_run=4,expected_tests=4,
                  failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0,
                  counts=COUNTS,source_inputs=source_evidence(source_root),execution=execution,
                  manifest_sha256=module['manifest_sha256'],capture_sha256=sha(compact(capture)),sources_unchanged=True,**SCOPE)
    exact(summary,expected,'native suite source, domain or scope differs')
    evidence.artifact_sha256.update(capture['artifact_sha256'])
    evidence.artifact_sha256.update(retire_fixtures(output,FOLDER+'/native',capture))
    build=check_build_controls(evidence,report,source_root,module,execution)
    return dict(schema='hepta.runtime.local-create-core-evidence.v1',status='PASS',counts=COUNTS,
        source_inputs=capture['source_inputs'],module=module,native_capture_sha256=sha(compact(capture)),
        build_counts=BUILD_COUNTS,artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),**SCOPE)


def native_evidence(output, report, *, source_root=ROOT):
    result=core_evidence(output,report,source_root=source_root);evidence=Evidence(output)
    origin=evidence.object(FOLDER+'/native/summary.json')['execution']['source_root']
    summary=process(evidence,report,TESTS[2],suite_command(report,TESTS[2],origin),'native_components',groups=4)
    exact(evidence.object(FOLDER+'/evidence-controls.json'),summary,'evidence control stdout differs')
    expected=dict(schema='hepta.runtime.local-create-evidence-controls.v1',status='PASS',tests_run=4,expected_tests=4,
                  failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0,
                  counts=CONTROL_COUNTS,source_inputs=source_evidence(source_root),
                  native_evidence_sha256=sha(compact(result)),new_native_calls=0,synthetic_receipt_controls=True,**SCOPE)
    exact(summary,expected,'strict evidence control domain/source/scope differs')
    result['evidence_controls']=CONTROL_COUNTS
    result['artifact_sha256'].update(evidence.artifact_sha256)
    result['artifact_sha256']=dict(sorted(result['artifact_sha256'].items()))
    return result


BUILD_VARIABLES=('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER',
    'RUSTC_BOOTSTRAP','CARGO_BUILD_TARGET','RUST_TARGET_PATH','CARGO_BUILD_RUSTC',
    'CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_RUSTFLAGS')


def build_override(key):
    return key in BUILD_VARIABLES or key.startswith('CARGO_PROFILE_') or (key.startswith('CARGO_TARGET_')and key.endswith('_RUSTFLAGS'))


def reference_environment(inherited,rustc):
    env=dict(inherited);removed=sorted(key for key in env if build_override(key))
    for key in removed:env.pop(key,None)
    selected={'RUSTC':str(rustc),'CARGO_ENCODED_RUSTFLAGS':'',
              'RUSTC_WRAPPER':'','RUSTC_WORKSPACE_WRAPPER':''}
    env.update(selected)
    return env,dict(selected=selected,removed_inherited_variables=removed,
        removal_policy=dict(names=list(BUILD_VARIABLES),cargo_profile_prefix=True,cargo_target_rustflags=True))


def compiler_identity(path):
    path=Path(path);resolved=path.resolve(strict=True)
    require(resolved.is_file(),'selected original compiler is absent')
    return dict(invocation_path=str(path),resolved_path=str(resolved),**pin(resolved.read_bytes()))


def original_commands(output,rustc,*,source_root=ROOT,python=None):
    folder=Path(output)/FOLDER/'original';rustc=Path(rustc);cargo=rustc.with_name('cargo')
    python=python or sys.executable
    config=['--config','build.rustc='+json.dumps(str(rustc))]
    commands={
        PROCESS_NAMES[0]:[str(rustc),'--version','--verbose'],
        PROCESS_NAMES[1]:[str(cargo),'--version'],
        PROCESS_NAMES[2]:[str(cargo),*config,'metadata','--locked','--format-version=1','--manifest-path',str(folder/'source/Cargo.toml')],
        PROCESS_NAMES[3]:[str(cargo),*config,'build','--locked','--release','--manifest-path',str(folder/'source/Cargo.toml'),
                          '--target-dir',str(folder/'target')],
    }
    binary=folder/'target/release/hepta-local-create-original-oracle'
    for name,script,kind in zip(PROCESS_NAMES[4:],('kernel_cases.py','race_cases.py','fault_cases.py'),('kernel','race','fault'),strict=True):
        commands[name]=[python,'-I','-B',str(Path(source_root)/DRIVERS/script),
                        '--binary',str(binary),'--output',str(folder/kind),'--original']
    return commands


def metadata_evidence(raw,source):
    metadata=decode(raw);packages={p['id']:p for p in metadata['packages']}
    resolved=metadata['resolve']['nodes'];registry={};roots=[]
    expected={p['name']:(p['version'],p['source'])for p in source['reference_registry']}
    for node in resolved:
        package=packages[node['id']]
        if package.get('source')is None:
            require(package['name']=='hepta-local-create-original-oracle' and package['version']=='0.1.0'
                    and node['features']==[],'original Cargo workspace differs')
            roots.append(package['name'])
            require(len(package['dependencies'])==1,'original fixture gained an extra dependency')
            dep=package['dependencies'][0]
            require(dep['name']=='tokio' and dep['req']=='=1.53.1' and set(dep['features'])=={'rt','fs','io-util'},
                    'original declared Tokio dependency differs')
        else:
            require(package['name']in expected and (package['version'],package['source'])==expected[package['name']],
                    'original actual registry package differs')
            registry[package['name']]=node['features']
    exact(roots,['hepta-local-create-original-oracle'],'original Cargo root differs')
    exact(registry,{'bytes':['default','std'],'pin-project-lite':[],
                    'tokio':['bytes','default','fs','io-util','rt']},'original actual feature closure differs')
    return registry


def captured_original(output,report,rustc,*,source_root=ROOT,require_retired=True):
    output=Path(output).resolve();source_root=Path(source_root).resolve();evidence=Evidence(output)
    source=source_evidence(source_root);base=FOLDER+'/original'
    receipt=evidence.object(base+'/reference-build.json')
    require(receipt.get('status')in('REFERENCE_EXECUTED','PASS'),'fresh original execution did not complete')
    exact(receipt.get('source_inputs'),source,'original source custody differs')
    exact(receipt.get('scope'),SCOPE,'original exceeded private blocking scope')
    require(receipt.get('fresh_target_directory')is True and receipt.get('fresh_locked_builds')==1
            and type(receipt.get('fresh_locked_builds'))is int,'original did not use one fresh locked build')
    for name in REFERENCE_PINS:
        require(evidence.read(base+'/source/'+name)==owned(source_root,REFERENCE+'/'+name).read_bytes(),
                'fresh original build source differs: '+name)
    origin=receipt['execution']
    require(set(origin)=={'source_root','output','python'} and all(type(v)is str and Path(v).is_absolute() and '..'not in Path(v).parts for v in origin.values()),
            'original execution origin differs')
    require(Path(origin['python']).name.startswith('python'),'original replay interpreter differs')
    commands=original_commands(Path(origin['output']),rustc,source_root=Path(origin['source_root']),python=origin['python'])
    exact(receipt.get('commands'),commands,'original exact command inventory differs')
    tools={'rustc':compiler_identity(rustc),'cargo':compiler_identity(Path(rustc).with_name('cargo'))}
    exact(receipt.get('compiler_before'),tools,'selected original compiler bytes changed before capture')
    exact(receipt.get('compiler_after'),tools,'selected original compiler bytes changed after capture')
    binding=receipt['environment_binding'];removed=binding.get('removed_inherited_variables')
    require(type(removed)is list and removed==sorted(set(removed)) and all(type(x)is str and build_override(x)for x in removed),
            'original environment removal receipt differs')
    _,expected_binding=reference_environment({name:'removed'for name in removed},rustc)
    exact(binding,expected_binding,'original compiler/profile environment policy differs')
    features=None
    for name in PROCESS_NAMES:
        stdout,stderr,row=process(evidence,report,name,commands[name],'original_rust_comparison')
        exact(row.get('environment_binding'),binding,'actual original process environment binding differs')
        if name==PROCESS_NAMES[0]:require(stdout.startswith(b'rustc 1.95.0 ') and not stderr,'original Rust version differs')
        elif name==PROCESS_NAMES[1]:require(stdout.startswith(b'cargo 1.95.0 ') and not stderr,'original Cargo version differs')
        elif name==PROCESS_NAMES[2]:features=metadata_evidence(stdout,source)
        elif name==PROCESS_NAMES[3]:require(stdout==b'','original Cargo build wrote unexpected stdout')
        elif name==PROCESS_NAMES[4]:
            require(not stderr,'kernel reference driver leaked diagnostics')
            lines=stdout.splitlines();require(len(lines)==7,'kernel replay progress framing differs')
            for line,count in zip(lines[:-1],(1,51,101,151,201,251),strict=True):
                item=decode(line);require(set(item)=={'native','cases','elapsed'} and item['native']is False
                    and type(item['cases'])is int and item['cases']==count and finite(item['elapsed'],180),
                    'kernel replay progress declaration differs')
            exact(decode(lines[-1]),evidence.object(base+'/kernel/summary.json'),'complete kernel replay stdout differs')
        else:
            require(not stderr,'original filesystem replay leaked diagnostics')
            suffix='race/result.json'if name==PROCESS_NAMES[5]else'fault/summary.json'
            exact(decode(stdout),evidence.object(base+'/'+suffix),'complete original replay stdout differs')
    binary_relative=base+'/target/release/hepta-local-create-original-oracle'
    binary=evidence.read(binary_relative);exact(receipt.get('executable'),dict(path=binary_relative,**pin(binary)),
                                             'fresh original executable identity differs')
    executable=str(Path(origin['output'])/binary_relative)
    kernel=check_kernel(evidence,base+'/kernel',source_root,False,executable,origin['output'])
    races=check_races(evidence,base+'/race',False,executable,origin['output'])
    faults=check_faults(evidence,base+'/fault',source_root,False,executable,origin['output'])
    for name,file in (('race','result.json'),('fault','summary.json')):
        require(evidence.object(base+'/'+name+'/'+file).get('executable_sha256')==sha(binary),
                'original corpus was not run by the admitted fresh binary')
    # Both sides above check every decoded file byte against the fixed original
    # fixture contents, including partial-file prefixes. Also compare both actual
    # retained sides directly so this is not a metadata-only equality claim.
    for index in range(285):
        native=evidence.object(FOLDER+'/native/kernel/'+str(index)+'/result.json')
        original=evidence.object(base+'/kernel/'+str(index)+'/result.json')
        for key in ('name','kind','errno','before','after'):exact(native[key],original[key],'native/original complete filesystem results differ')
        if native['kind']==0:exact(native['written'],original['written'],'successful original count differs')
        for phase in ('before','after'):
            for item in native[phase]:
                if item['kind']=='file':
                    left=evidence.compressed(FOLDER+'/native/kernel/'+str(index)+'/'+phase+'/'+item['content'])
                    right=evidence.compressed(base+'/kernel/'+str(index)+'/'+phase+'/'+item['content'])
                    require(left==right,'actual native/original decoded file bytes differ')
    for index in range(8):
        require(evidence.read(FOLDER+'/native/fault/'+str(index)+'/created.bin')==evidence.read(base+'/fault/'+str(index)+'/created.bin'),
                'actual native/original partial-file bytes differ')
    capture=dict(schema='hepta.runtime.local-create-original-capture.v1',status='PASS',
                 source_inputs=source,features=features,executable=receipt['executable'],kernel=kernel,races=races,faults=faults,
                 # The mutable build receipt records this digest; exclude only
                 # that receipt to avoid a self-referential artifact hash.
                 artifact_sha256={k:v for k,v in sorted(evidence.artifact_sha256.items()) if k!=base+'/reference-build.json'},**SCOPE)
    if require_retired:
        require(receipt.get('status')=='PASS','original final receipt is incomplete')
        exact(receipt.get('capture_sha256'),sha(compact(capture)),'original capture binding differs')
        evidence.artifact_sha256.update(retire_fixtures(output,base,capture))
    return capture,evidence.artifact_sha256


def original_evidence(output,report,rustc):
    native=native_evidence(output,report)
    exact(report.get('local_create_file_evidence'),native,'native create evidence changed before original admission')
    capture,artifacts=captured_original(output,report,rustc)
    native_artifacts=native['artifact_sha256']
    return dict(status='PASS',reference_kind='unchanged current-target local create function through locked Tokio',
        kernel_cases=285,race_pairs=32,fault_cases=8,actual_original_processes=357,
        source_inputs=source_evidence(),native_capture_sha256=native['native_capture_sha256'],
        original_capture=capture,artifact_sha256=dict(sorted({**native_artifacts,**artifacts}.items())),**SCOPE)


def compare_original(output,report,rustc):
    import qualify_hia_runtime_native as q
    output=Path(output).resolve();rustc=Path(rustc);native=native_evidence(output,report)
    exact(report.get('local_create_file_evidence'),native,'native evidence is not the admitted registered capture')
    folder=output/FOLDER/'original';folder.mkdir(exist_ok=False)
    source=source_evidence();before={'rustc':compiler_identity(rustc),'cargo':compiler_identity(rustc.with_name('cargo'))}
    env,binding=reference_environment(q.qualification_env(),rustc)
    for name in REFERENCE_PINS:
        path=folder/'source'/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(owned(ROOT,REFERENCE+'/'+name).read_bytes())
    require(not(folder/'target').exists(),'original target directory was not fresh')
    commands=original_commands(output,rustc)
    receipt=dict(schema='hepta.runtime.local-create-reference-build.v1',status='BUILDING',source_inputs=source,
        scope=SCOPE,fresh_target_directory=True,fresh_locked_builds=1,compiler_before=before,
        compiler_after=None,environment_binding=binding,commands=commands,
        execution=dict(source_root=str(ROOT),output=str(output),python=sys.executable))
    def save():(folder/'reference-build.json').write_bytes(compact(receipt)+b'\n')
    save()
    try:
        for name in PROCESS_NAMES:
            q.record_check(output,report,name=name,command=commands[name],timeout=180,env=env)
            report['checks'][-1]['environment_binding']=binding;q.save_report(output/'result.json',report)
        receipt['compiler_after']={'rustc':compiler_identity(rustc),'cargo':compiler_identity(rustc.with_name('cargo'))}
        exact(receipt['compiler_after'],before,'selected compiler changed during original execution')
        executable=folder/'target/release/hepta-local-create-original-oracle'
        receipt['executable']=dict(path=str(executable.relative_to(output)),**pin(executable.read_bytes()))
        receipt['status']='REFERENCE_EXECUTED';save()
        capture,_=captured_original(output,report,rustc,require_retired=False)
        retire_fixtures(output,FOLDER+'/original',capture,create=True)
        receipt['status']='PASS';receipt['capture_sha256']=sha(compact(capture));save()
        exact(source_evidence(),source,'original sources changed during full replay')
        return original_evidence(output,report,rustc)
    except BaseException as error:
        receipt['status']='FAIL';receipt['error']=repr(error);save();raise
