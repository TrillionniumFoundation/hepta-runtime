"""Actual native continuation, atomic-refusal and cleanup controls."""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(Path(__file__).parent))
import batch_apply_reference as model
from batch_apply_harness import NativeApply,CHILD,CAPACITY,sha
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_batch_apply_build import inspect_bundle
from hia_native_batch_apply_qualification import execution_source_pins

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,default=os.environ.get('HIA_APPLY_BUNDLE'))
    parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_APPLY_MANIFEST'))
    parser.add_argument('--editable',type=Path,default=os.environ.get('HIA_APPLY_EDITABLE_MANIFEST'))
    parser.add_argument('--editable-source',type=Path,default=os.environ.get('HIA_APPLY_EDITABLE_SOURCE'))
    parser.add_argument('--result',type=Path,required=True)
    args=parser.parse_args();bundle=None
    pins=execution_source_pins(reference=model.RUNTIME)
    if args.bundle:
        bundle=inspect_bundle(args.bundle,source_root=ROOT,reference_root=model.RUNTIME)
        args.manifest=bundle['manifests'][4];args.editable=bundle['manifests'][5]
        args.editable_source=ROOT/'native/editable_content.hepta'
    assert args.manifest and args.editable
    owner=NativeApply(args.manifest,args.editable,editable_source=args.editable_source)
    raw=b'alpha\r\nbeta\nlast';ops=[(1,1,0,b'new\n'),(2,3,3,b'tail\r\r')]
    wire=model.packet(raw,ops,2);expected=model.response(raw,ops,2)
    rows=[];start=time.monotonic()
    def record(name,*,mutation=None,initial=None,phase=None,code=CHILD):
        applied=[]
        def fault(state):
            if state['phase']==phase:
                mutation(state);applied.append(phase)
        result=owner.invoke(wire,4096,fault=fault if mutation else None,initial=initial)
        assert result['code']==code and result['output']==b'',(name,result)
        assert (applied==[phase]) if mutation else not applied,(name,applied)
        assert result['cleared_prefix_bytes']>0 and result['input_unchanged'] and result['guards_unchanged']
        rows.append({'case':name,'phase':phase,'fault_applied':applied,'code':code,
            'controller_calls':1+len(result['trace']),'editable_calls':len(result['trace']),
            'trace':result['trace'],'cleared_prefix_bytes':result['cleared_prefix_bytes'],
            'workspace_capacity':result['workspace_capacity'],'workspace_tail_bytes':result['workspace_tail_bytes'],
            'output_capacity':result['output_capacity'],'output_bytes':0,'output_untouched':result['output_tail_unchanged'],
            'input_unchanged':result['input_unchanged'],'guards_unchanged':result['guards_unchanged']})
    try:
        actual=owner.invoke(wire,len(expected))
        assert actual['code']==len(expected) and actual['output']==expected
        assert [item['phase'] for item in actual['trace']]==[1,2,3]
        for phase in (1,2,3):
            footer_values={0:0,8:0,16:4,24:1,32:0,40:0,48:1,56:0,64:0,72:1,80:79,88:0,96:0,104:1,120:2,128:3}
            for offset,value in footer_values.items():
                record(f'footer_{offset}_phase_{phase}',phase=phase,
                    mutation=lambda s,offset=offset,value=value:s['put'](s['footer']+offset,value))
            record(f'child_invalid_phase_{phase}',phase=phase,mutation=lambda s:s['put'](s['footer']+80,0xffffffff))
            record(f'child_capacity_phase_{phase}',phase=phase,code=CAPACITY,mutation=lambda s:s['put'](s['footer']+80,CAPACITY))
            for offset,value in {0:0,8:1,16:999,24:0,32:2,40:1<<63,48:1<<63,56:1<<63,64:1<<63,72:1}.items():
                record(f'result_{offset}_phase_{phase}',phase=phase,
                    mutation=lambda s,offset=offset,value=value:s['put'](s['destination']+offset,value))
            record(f'utf8_phase_{phase}',phase=phase,
                mutation=lambda s:ctypes.memset(s['work']+s['destination']+80,0xff,1))
            record(f'unknown_phase_{phase}',phase=phase,mutation=lambda s:s['put'](0,4))
            for name in ('input','output'):
                record(f'{name}_capacity_changed_phase_{phase}',phase=phase,
                    mutation=lambda s,name=name:s['lengths'].__setitem__(name,s['lengths'][name]-1))
            def secret(state):
                state['put'](state['destination']+8,1)
                secret_bytes=b'KNOWN_SECRET'
                assert state['capacity']>=80+len(secret_bytes)
                ctypes.memmove(state['work']+state['destination']+80,secret_bytes,len(secret_bytes))
            record(f'known_private_bytes_cleared_phase_{phase}',phase=phase,mutation=secret)
        record('sequence_exhausted',initial=lambda s:s['put'](s['footer']+8,(1<<64)-1))
        record('wrong_initial_event',initial=lambda s:s['put'](s['footer']+120,0))
        record('wrong_initial_caller',initial=lambda s:s['put'](s['footer']+128,0))
        result={'schema':'hepta.runtime.batch-apply-contract.v1','status':'PASS',
            'elapsed_seconds':time.monotonic()-start,'loaded_artifacts':owner.loaded,
            'source_sha256':sha((ROOT/'native/batch_apply.hepta').read_bytes()),
            'requests':owner.counts['requests'],'counts':owner.counts,'fault_cases':len(rows),
            'successful_exact_capacity_cases':1,'wire_hex':wire.hex(),'success_hex':expected.hex(),'success_trace':actual['trace'],'rows':rows,
            'bundle_sha256':bundle['manifest_sha256'] if bundle else None}
    finally:owner.close()
    assert execution_source_pins(reference=model.RUNTIME)==pins
    result['execution_source_pins']=pins
    args.result.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows','wire_hex','success_hex')},sort_keys=True))

if __name__=='__main__':main()
