"""Execute all list, retained-operation, capacity and dirty-session calls."""
import argparse
from contextlib import ExitStack
import ctypes
import json
from pathlib import Path
import sys
import time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import static_common as c
from read_static_build import build_check

def run(build,output):
    c.source_check();build_check(build,ROOT);output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(ROOT/'pipeline/policy_base/runtime_support/scripts'))
    from hia_native_loader import NativeModule
    records=[];started=time.monotonic_ns()
    with ExitStack() as stack:
        modules={}
        for name in c.source_pins():
            path=build/'modules'/name/'manifest.json'
            modules[name]=stack.enter_context(NativeModule(path,manifest_sha256=c.sha(path.read_bytes())))
        session=None
        for ordinal,case in enumerate(c.cases()):
            owner_rows=[]
            for name in (('catalog-nine','catalog-eleven') if case['paired'] else ('catalog-eleven',)):
                oc,wc=case['output_capacity'],case['workspace_capacity']
                if case['group']:
                    assert name=='catalog-eleven'
                    if session is None:
                        session=stack.enter_context(modules[name].session(output_capacity=oc,workspace_capacity=wc))
                        ctypes.memset(session._output,0xA7,oc);ctypes.memset(session._workspace,0x59,wc)
                    code,out,work=session.invoke_raw(case['wire'])
                else:
                    code,out,work=modules[name].invoke_raw(case['wire'],output_capacity=oc,
                        workspace_capacity=wc,output_fill=0xA7,workspace_fill=0x59)
                row=c.pipeline.record(output,f'case-{ordinal:03d}-{name}',case['wire'],code,out,work)
                owner_rows.append({'owner':name,**row})
            records.append({'case':case['name'],'calls':owner_rows})
    result={'schema':'hepta.runtime.catalog-eleven-static-native.v1','status':'PASS','records':records,
        'actual_native_calls':sum(len(row['calls'])for row in records),'elapsed_ns':time.monotonic_ns()-started,
        'source_profile':c.pin((ROOT/'source-profile.json').read_bytes()),'public_all_configuration_qualified':False,
        'whole_runtime_replaced':False}
    c.put(output/'result.json',result)
    from read_static import verify
    value=verify(ROOT,build,output);c.put(output/'verification.json',value)
    return {k:v for k,v in value.items()if k not in ('source_files','build_files','native_files','case_rows')}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(run(a.build.resolve(strict=True),a.output.absolute()),sort_keys=True))
