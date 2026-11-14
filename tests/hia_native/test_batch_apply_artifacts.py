"""Fresh static-ELF, complete Unicode classification and native plan-to-apply joins."""
from __future__ import annotations
import argparse
import importlib.util
import itertools
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(Path(__file__).parent))
from hia_native_batch_apply_build import inspect_bundle,read,sha
from hia_native_batch_apply_qualification import source_contract,execution_source_pins,PROPERTIES_SHA
from hia_native_loader import NativeModule
from batch_apply_harness import NativeApply,CAPACITY,INVALID
import batch_apply_reference as model
from test_batch_apply import cases

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,default=os.environ.get('HIA_APPLY_BUNDLE'))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();assert args.bundle
    start=time.monotonic();args.output.mkdir(exist_ok=False)
    closure=source_contract(reference=model.RUNTIME)
    pins=execution_source_pins(reference=model.RUNTIME)
    bundle=inspect_bundle(args.bundle,reference_root=model.RUNTIME)
    with NativeModule(bundle['probe_manifest'],manifest_sha256=bundle['probe_manifest_sha256']) as probe:
        code,actual,workspace=probe.invoke_raw(struct.pack('<8s2Q',b'HBAUNI01',0,0x110000),
            output_capacity=0x110000,workspace_capacity=24576,output_fill=0xa5,workspace_fill=0x5a)
        assert code==0x110000 and sha(actual)==PROPERTIES_SHA and workspace==bytes(24576)
        (args.output/'native-debug-properties.bin').write_bytes(actual)
    reference=model.RUNTIME
    planner_harness=load('batch_plan_harness',reference/'tests/hia_native/batch_plan_harness.py')
    os.environ['HIA_REFERENCE_RUNTIME']=str(reference)
    planner_test=load('_batch_apply_planner_packets',reference/'tests/hia_native/test_batch_plan.py')
    planner=planner_harness.NativePlan(bundle['manifests'],source_root=reference,reference_root=reference)
    apply=NativeApply(bundle['manifests'][4],bundle['manifests'][5],editable_source=ROOT/'native/editable_content.hepta')
    joined=[]
    try:
        for ordinal,(domain,raw,operations,mode) in enumerate(itertools.islice(cases(),8)):
            lines=[value.decode() for value in model.logical_lines(model.Editable(raw).normalized())]
            def target(index):return f'{index}:{model.line_hash(lines[index-1].encode())}'
            public=[]
            for kind,first,last,content in operations:
                assert content
                row={'operation':'insert' if kind==1 else 'replace','start':0 if first==0 else target(first),'content':content.decode()}
                if kind==2:row['end']=target(last)
                public.append(row)
            plan_wire=planner_test.packet(public,lines=lines,path='fixture.txt')
            expected_wire=model.packet(raw,operations,mode);expected_plan=expected_wire[64+len(raw):]
            plan=planner.invoke(plan_wire,len(expected_plan))
            assert plan['code']==len(expected_plan) and plan['output']==expected_plan
            wire=struct.pack('<8s7Q',b'HBACT001',mode,len(raw),len(plan['output']),0,0,0,0)+raw+plan['output']
            assert wire==expected_wire
            expected=model.response(raw,operations,mode);got=apply.invoke(wire,len(expected))
            assert got['code']==len(expected) and got['output']==expected
            joined.append({'original_corpus_ordinal':ordinal,'domain':domain,'planner_input_hex':plan_wire.hex(),
                'planner_output_hex':plan['output'].hex(),'planner_trace':plan['trace'],
                'apply_input_sha256':sha(wire),'apply_output_sha256':sha(got['output']),
                'apply_trace':got['trace'],'apply_output_bytes':len(got['output'])})
    finally:planner.close();apply.close()
    raw=b'alpha\r\nbeta\nlast';operations=[(1,1,0,b'new\n'),(2,3,3,b'tail\r\r')]
    requests=[model.packet(raw,operations,mode) for mode in (0,1,2)]
    expected=[model.response(raw,operations,mode) for mode in (0,1,2)]
    for raw,operations in [(b'\r',[(1,1,0,b'X')]),(b'a\nb',[(1,0,0,b'x'),(1,0,0,b'y')]),(b'x\x01\nb',[(2,2,2,b'x\x01')])]:
        requests.append(model.packet(raw,operations));expected.append(model.response(raw,operations))
    requests.append(b'BAD');expected.append(INVALID)
    text=b'\x01'*(1<<19)
    requests.append(model.packet(text+b'\nX',[(2,2,2,text)]));expected.append(CAPACITY)
    wire=b''.join(value.hex().encode()+b'\n' for value in requests)
    wanted=b''.join((f'{value:08x}:\n'.encode() if type(value) is int else f'{len(value):08x}:'.encode()+value.hex().encode()+b'\n') for value in expected)
    manifest=json.loads(read(bundle['elf_manifest']))
    executable=bundle['elf_manifest'].parent/manifest['executable']
    run=subprocess.run([str(executable),'--local-read-profile','/batch-apply-fixture'],input=wire,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env={'PATH':'/does-not-exist','LANG':'C'})
    (args.output/'elf-input.txt').write_bytes(wire);(args.output/'elf-output.txt').write_bytes(run.stdout)
    (args.output/'elf-stderr.txt').write_bytes(run.stderr)
    assert run.returncode==0 and not run.stderr and run.stdout==wanted,(run.returncode,run.stderr,run.stdout[:256],wanted[:256])
    result={'schema':'hepta.runtime.batch-apply-artifacts.v1','status':'PASS','elapsed_seconds':time.monotonic()-start,
        'bundle_sha256':bundle['manifest_sha256'],'source_contract':closure,
        'unicode_codepoints':0x110000,'unicode_valid_scalars':1112064,'unicode_surrogates':2048,
        'native_debug_probe_calls':1,'native_debug_properties_sha256':sha(actual),
        'native_debug_probe_manifest_sha256':bundle['probe_manifest_sha256'],
        'native_plan_counts':planner.counts,'native_apply_counts':apply.counts,'joined_cases':joined,
        'joined_loaded_artifacts':planner.loaded+apply.loaded,'original_cases_added_by_join':0,
        'real_elf_processes':1,'real_elf_requests':len(requests),'real_elf_capacity_refusals':1,
        'real_elf_invalid_refusals':1,'elf_sha256':sha(read(executable)),
        'elf_input_sha256':sha(wire),'elf_output_sha256':sha(run.stdout),'elf_stderr_sha256':sha(run.stderr),
        'elf_returncode':run.returncode,'runtime_python_required':False,'production_activated':False,
        'original_rust_executions_in_this_suite':0}
    assert execution_source_pins(reference=model.RUNTIME)==pins
    result['execution_source_pins']=pins
    (args.output/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('joined_cases','source_contract','joined_loaded_artifacts')},sort_keys=True))

if __name__=='__main__':main()
