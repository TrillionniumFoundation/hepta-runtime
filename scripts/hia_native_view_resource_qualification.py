"""Admit complete mechanical resource evidence for the frozen view engine.

The C fixture executes the real mapping helpers with an initialization stub.
It does not execute HIA semantics, a Rust reference, or production lease retire.
"""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path
import re
import stat
import struct
import sys

FOLDER = 'view-call/resources'
SUITE = 'test_view_call_resources.py'
ENGINE_SHA256 = 'b138920b829acb0ad2bd6b116735ea86cc87f0bc7dea4e6bd4c86f006c70bde5'
ENGINE_BYTES = 1807945728
PAGE = 4096
SOURCE_PATHS = (
    'scripts/view_call_engine.S',
    'scripts/hia_native_view_resource_qualification.py',
    'tests/hia_native/test_view_call_resources.py',
    'tests/hia_native/view_engine_resource_control.c',
    'tests/hia_native/view_engine_resource_stubs.S',
)
CC_FLAGS = ('-std=c11','-O2','-Wall','-Wextra','-Werror','-fno-pie','-no-pie',
            '-Wl,--build-id=none','-Wl,-z,noexecstack')
COMPILE_ENV = {'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC','SOURCE_DATE_EPOCH':'0'}
CONTROL_ENV = {'PATH':'','LC_ALL':'C'}
CONTROL_SPECS = (
    ('create-destroy',('create-destroy',)),
    ('create-enomem-0',('create-enomem','0')),
    ('create-enomem-16384',('create-enomem','16384')),
    ('create-enomem-262144',('create-enomem','262144')),
    ('create-enomem-20971520',('create-enomem','20971520')),
    ('create-enomem-67108864',('create-enomem','67108864')),
    ('create-enomem-134217728',('create-enomem','134217728')),
    ('resize-grow',('resize-grow',)),
    ('resize-enomem',('resize-enomem',)),
    ('resize-unaligned-old',('resize-unaligned-old',)),
)
COUNTS = dict(actual_controls=10,actual_c_compiles=1,actual_child_processes=11,
              actual_hia_semantic_calls=0,actual_rust_reference_processes=0)
FALSE_FLAGS = ('hia_semantics_executed','rust_reference_executed',
               'production_scope_retirement_executed','whole_view_replaced')
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError('view resource evidence: '+message)


def encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def exact(actual, expected, message):
    if isinstance(actual,bytes) or isinstance(expected,bytes):
        require(type(actual) is bytes and type(expected) is bytes and actual==expected,message)
    else:
        require(encode(actual)==encode(expected),message)


def decode(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'duplicate JSON key')
            result[key]=value
        return result
    def constant(_):
        raise ValueError('view resource evidence: nonfinite JSON constant')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)


def positive_time(value,maximum):
    return type(value) in (int,float) and math.isfinite(value) and 0<value<maximum


def absolute(value):
    require(type(value) is str and Path(value).is_absolute() and '..' not in Path(value).parts
            and Path(value).as_posix()==value,'invalid retained absolute path')
    return Path(value)


def owned(root,name):
    require(type(name) is str,'artifact path is not text')
    rel=Path(name)
    require(not rel.is_absolute() and bool(rel.parts) and '..' not in rel.parts
            and rel.as_posix()==name,'artifact escaped its owner')
    path=root/rel
    require(path.resolve()==path.absolute() and stat.S_ISREG(path.lstat().st_mode),
            'artifact is not an owned regular file')
    return path


def identity(raw):
    return dict(bytes=len(raw),sha256=sha(raw))


def source_binding(root):
    result={name:identity(owned(root,name).read_bytes()) for name in SOURCE_PATHS}
    require(result['scripts/view_call_engine.S']['sha256']==ENGINE_SHA256,
            'frozen engine source changed')
    return result


class Evidence:
    def __init__(self,output):
        self.output=output
        self.artifact_sha256={}
        self.artifacts={}

    def read(self,name):
        raw=owned(self.output,name).read_bytes()
        self.artifact_sha256[name]=sha(raw)
        self.artifacts[name]=dict(path=name,**identity(raw))
        return raw

    def object(self,name):
        value=decode(self.read(name))
        require(type(value) is dict,'artifact is not a JSON object: '+name)
        return value

    def stream(self,descriptor,expected_path):
        exact(sorted(descriptor),['bytes','path','sha256'],'stream descriptor fields differ')
        exact(descriptor['path'],expected_path,'stream path differs')
        require(type(descriptor['bytes']) is int and 0<=descriptor['bytes']<=64<<20,
                'stream length is not a supported integer')
        require(type(descriptor['sha256']) is str and re.fullmatch('[0-9a-f]{64}',descriptor['sha256']),
                'stream hash is not SHA256')
        raw=self.read(FOLDER+'/'+expected_path)
        exact(identity(raw),{key:descriptor[key] for key in ('bytes','sha256')},
              'complete stream bytes differ')
        return raw


def check_control(value,args):
    require(type(value) is dict,'control output is not an object')
    expected=dict(schema='hepta.runtime.view-engine-resource-control.v1',status='PASS',
                  control=args[0],mapping_bytes=0,budget_bytes=-1,
                  old_allocated_capacity=0,resize_old_capacity=0,resize_new_capacity=0,
                  old_pointer_offset=0,preserved_old_bytes=0,new_zero_tail_bytes=0,
                  explicit_cleanup_calls=0,old_mapping_survived=False,
                  old_mapping_unmapped=False,fixture_retired_flag_written=False,
                  initialization_stub_calls=0,unexpected_dispatch_calls=0,
                  initialization_stub_return=32,hia_semantics_executed=False)
    if args[0]=='create-destroy':
        expected.update(mapping_bytes=ENGINE_BYTES,explicit_cleanup_calls=1,
                        fixture_retired_flag_written=True,initialization_stub_calls=1)
    elif args[0]=='create-enomem':
        expected['budget_bytes']=int(args[1])
    elif args[0]=='resize-grow':
        expected.update(mapping_bytes=36864,old_allocated_capacity=8192,
                        resize_old_capacity=8192,resize_new_capacity=32768,
                        preserved_old_bytes=8192,new_zero_tail_bytes=24576,
                        explicit_cleanup_calls=1,old_mapping_unmapped=True)
    elif args[0]=='resize-enomem':
        expected.update(mapping_bytes=12288,budget_bytes=0,old_allocated_capacity=8192,
                        resize_old_capacity=8192,resize_new_capacity=32768,
                        preserved_old_bytes=8192,explicit_cleanup_calls=1,old_mapping_survived=True)
    elif args[0]=='resize-unaligned-old':
        expected.update(mapping_bytes=12288,old_allocated_capacity=8192,
                        resize_old_capacity=4096,resize_new_capacity=16384,old_pointer_offset=1,
                        preserved_old_bytes=8192,explicit_cleanup_calls=1,old_mapping_survived=True)
    else:
        raise ValueError('view resource evidence: unknown control')
    dynamic=('baseline_vm_bytes','after_call_vm_bytes','after_cleanup_vm_bytes','returned_address_or_errno')
    exact(sorted(value),sorted([*expected,*dynamic]),'control output field inventory differs')
    for key,want in expected.items():
        exact(value[key],want,'control observation differs: '+key)
    for key in dynamic:
        require(type(value[key]) is int,'control observation is not an integer: '+key)
    before=value['baseline_vm_bytes']
    require(before>0 and before%PAGE==0,'baseline VM is not positive and page aligned')
    exact(value['after_cleanup_vm_bytes'],before,'mapping did not return to baseline')
    exact(value['after_call_vm_bytes'],before+expected['mapping_bytes'],'complete mapped-byte delta differs')
    returned=value['returned_address_or_errno']
    if args[0] in ('create-destroy','resize-grow'):
        require(0<returned<(1<<63) and returned%PAGE==0,'successful allocation did not return an address')
    else:
        exact(returned,-22 if args[0]=='resize-unaligned-old' else -12,'actual syscall failure differs')
    return value


def process(evidence,row,name,command,environment,binary=None):
    fields=('name','command','cwd','environment','timeout_seconds','elapsed_seconds','exit_code',
            'timed_out','start_error','pid','stdin','stdout','stderr','binary')
    exact(sorted(row),sorted(fields),'child process receipt fields differ')
    exact(row['name'],name,'child process identity differs')
    exact(row['command'],command,'child command differs')
    exact(row['environment'],environment,'child environment differs')
    require(type(row['timeout_seconds']) is int and row['timeout_seconds']==20,
            'child timeout differs from 20 seconds')
    require(positive_time(row['elapsed_seconds'],20),'child elapsed time is not finite within 20 seconds')
    require(type(row['exit_code']) is int and row['exit_code']==0 and row['timed_out'] is False
            and row['start_error'] is None,'child did not successfully finish')
    require(type(row['pid']) is int and row['pid']>0,'child process id absent')
    exact(row['binary'],binary,'child executable identity differs')
    exact(evidence.object(FOLDER+'/processes/'+name+'.json'),row,'raw child receipt copy differs')
    streams={suffix:evidence.stream(row[suffix],'processes/'+name+'.'+suffix)
             for suffix in ('stdin','stdout','stderr')}
    exact(streams['stdin'],b'','resource child received unexpected stdin')
    return streams


def native_evidence(root,output,report,completed):
    root=Path(root).resolve();output=Path(output).resolve()
    binding=source_binding(root)
    evidence=Evidence(output)
    rows=[row for row in report.get('checks',[]) if row.get('name')==SUITE]
    require(len(rows)==1,'exactly one outer suite process required')
    outer=rows[0]
    exact(outer.get('command'),[sys.executable,'-I','-B',str(root/'tests/hia_native'/SUITE)],
          'outer suite command differs')
    require(type(outer.get('timeout_seconds')) is int and outer['timeout_seconds']==180
            and positive_time(outer.get('elapsed_seconds'),180),'outer suite budget differs')
    require(type(outer.get('exit_code')) is int and outer['exit_code']==0
            and outer.get('timed_out') is False and not outer.get('start_error'),
            'outer suite did not successfully finish')
    outer_raw={suffix:evidence.read(SUITE+'.'+suffix) for suffix in ('stdout','stderr')}
    for suffix,raw in outer_raw.items():
        exact(identity(raw),dict(bytes=outer.get(suffix+'_bytes'),sha256=outer.get(suffix+'_sha256')),
              'outer complete raw stream differs')
    summary=decode(outer_raw['stdout'])
    exact(summary,outer.get('summary'),'outer receipt summary differs')
    exact(list(completed(output,report,SUITE)),[outer,summary],'completed callback selected different evidence')
    stderr=outer_raw['stderr'].decode()
    require(len(re.findall(r'\.\.\. ok\n',stderr))==10
            and re.search(r'\nRan 10 tests in [0-9.]+s\n\nOK\n\Z',stderr),
            'not all ten unittest controls completed')
    result=evidence.object(FOLDER+'/result.json')
    exact(result,summary,'resource capture differs from complete outer stdout')
    expected_fields=('schema','status','groups','counts','elapsed_seconds','source_binding',
                     'sources_unchanged','execution','compiler','executable','processes',
                     'hia_semantics_executed','rust_reference_executed',
                     'production_scope_retirement_executed','whole_view_replaced',
                     'c_fixture_uses_libc','initialization_stub_return',
                     'create_destroy_retired_bit_is_fixture')
    exact(sorted(result),sorted(expected_fields),'resource result fields differ')
    exact(result['schema'],'hepta.runtime.view-engine-resource-tests.v1','resource schema differs')
    exact(result['status'],'PASS','resource tests did not pass')
    exact(result['groups'],10,'resource group count differs')
    exact(result['counts'],COUNTS,'resource process inventory differs')
    require(positive_time(result['elapsed_seconds'],180),'resource suite elapsed is not finite')
    exact(result['source_binding'],binding,'executed source closure differs')
    require(result['sources_unchanged'] is True,'source closure changed during test')
    for flag in FALSE_FLAGS:
        require(result[flag] is False,'unqualified semantic claim: '+flag)
    exact(result['c_fixture_uses_libc'],True,'mechanical C fixture scope differs')
    exact(result['initialization_stub_return'],32,'initialization stub result differs')
    exact(result['create_destroy_retired_bit_is_fixture'],True,'destroy fixture scope not declared')
    for name in SOURCE_PATHS:
        raw=evidence.read(FOLDER+'/sources/'+name)
        exact(identity(raw),binding[name],'captured source bytes differ: '+name)
        exact(raw,owned(root,name).read_bytes(),'captured source is not the current source: '+name)
    origin=result['execution']
    exact(sorted(origin),['capture_root','runtime_root'],'execution origin fields differ')
    origin_root=absolute(origin['runtime_root']);origin_capture=absolute(origin['capture_root'])
    require(origin_capture.parts[-2:]==('view-call','resources'),'capture origin suffix differs')
    compiler=result['compiler']
    exact(sorted(compiler),['executable','snapshot'],'compiler identity fields differ')
    compiler_path=absolute(compiler['executable'])
    compiler_raw=evidence.stream(compiler['snapshot'],'build/compiler.bin')
    require(compiler_raw.startswith(b'\x7fELF'),'compiler snapshot is not an ELF executable')
    executable=result['executable']
    binary=evidence.stream(executable,'build/view-engine-resource-control')
    require(len(binary)>=64 and binary[:6]==b'\x7fELF\x02\x01','control is not little-endian ELF64')
    require(struct.unpack_from('<HH',binary,16)==(2,62),'control ELF is not x86-64 ET_EXEC')
    controls=result['processes']
    require(type(controls) is list and len(controls)==11,'actual process count differs')
    exact([row['name'] for row in controls],['compile',*[name for name,_ in CONTROL_SPECS]],
          'child process order or inventory differs')
    compile_command=[str(compiler_path),*CC_FLAGS,'-o',str(origin_capture/'build/view-engine-resource-control'),
                     str(origin_root/'tests/hia_native/view_engine_resource_control.c'),
                     str(origin_root/'tests/hia_native/view_engine_resource_stubs.S'),
                     str(origin_root/'scripts/view_call_engine.S')]
    for row in controls:
        exact(row['cwd'],str(origin_root),'child working directory differs')
    compile_streams=process(evidence,controls[0],'compile',compile_command,COMPILE_ENV,compiler['snapshot'])
    exact(compile_streams['stdout'],b'','compiler unexpectedly emitted stdout')
    # Compiler stderr is retained in full; warnings are not silently discarded.
    observations={}
    executable_path=str(origin_capture/'build/view-engine-resource-control')
    for row,(name,args) in zip(controls[1:],CONTROL_SPECS):
        streams=process(evidence,row,name,[executable_path,*args],CONTROL_ENV,executable)
        exact(streams['stderr'],b'','successful control emitted diagnostics')
        require(streams['stdout'].endswith(b'\n') and streams['stdout'].count(b'\n')==1,
                'control stdout is not a complete single JSON line')
        observations[name]=check_control(decode(streams['stdout']),args)
    exact(source_binding(root),binding,'current source changed while reading evidence')
    return dict(schema='hepta.runtime.view-engine-resource-qualification.v1',status='PASS',
                counts=COUNTS,engine_source_sha256=ENGINE_SHA256,engine_mapping_bytes=ENGINE_BYTES,
                executable=executable,compiler=compiler,source_binding=binding,
                controls=observations,hia_semantics_executed=False,rust_reference_executed=False,
                production_scope_retirement_executed=False,whole_view_replaced=False,
                create_destroy_retired_bit_is_fixture=True,
                actual_syscall_failures=['ENOMEM','EINVAL'],
                artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
                artifacts=[evidence.artifacts[name] for name in sorted(evidence.artifacts)])
