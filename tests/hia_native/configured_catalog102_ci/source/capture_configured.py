"""Execute every configured and retained catalog case, preserving all buffers."""
import argparse
from contextlib import ExitStack
import ctypes
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import configured_common as c


def run(build, output):
    c.source_check(ROOT);c.build_check(build,ROOT)
    output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(ROOT/"retained/pipeline/policy_base/runtime_support/scripts"))
    from hia_native_loader import NativeModule
    records=[];started=time.monotonic_ns()
    with ExitStack() as stack:
        modules={}
        for name in ("catalog-eleven","catalog-configured"):
            path=build/"modules"/name/"manifest.json"
            modules[name]=stack.enter_context(NativeModule(path,manifest_sha256=c.sha(path.read_bytes())))
        sessions={}
        for ordinal,case in enumerate(c.cases(ROOT)):
            calls=[]
            for name in case["owners"]:
                oc,wc=case["output_capacity"],case["workspace_capacity"]
                if case["group"]:
                    key=(case["group"],name)
                    if key not in sessions:
                        session=stack.enter_context(modules[name].session(output_capacity=oc,workspace_capacity=wc))
                        ctypes.memset(session._output,0xA7,oc);ctypes.memset(session._workspace,0x59,wc)
                        sessions[key]=session
                    code,out,work=sessions[key].invoke_raw(case["wire"])
                else:
                    code,out,work=modules[name].invoke_raw(case["wire"],output_capacity=oc,workspace_capacity=wc,output_fill=0xA7,workspace_fill=0x59)
                call=c.retained.pipeline.record(output,f"case-{ordinal:04d}-{name}",case["wire"],code,out,work)
                calls.append({"owner":name,**call})
            records.append({"case":case["name"],"calls":calls})
    result={"schema":"hepta.runtime.catalog-configured-native.v1","status":"ACTUAL_NATIVE_CAPTURE_READER_REQUIRED",
        "records":records,"actual_native_calls":sum(len(row["calls"]) for row in records),
        "pid":os.getpid(),"parent_pid":os.getppid(),"pgid":os.getpgid(0),
        "elapsed_ns":time.monotonic_ns()-started,"native_deadline_seconds":180,
        "source_profile":c.pin((ROOT/"source-profile.json").read_bytes()),
        "public_all_configuration_qualified":False,"whole_runtime_replaced":False}
    c.put(output/"result.json",result)
    from read_configured import verify
    verified=verify(ROOT,build,output);c.put(output/"verification.json",verified)
    return {k:v for k,v in verified.items() if k not in ("source_files","build_files","native_files","case_rows")}


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--build",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();print(c.encoded(run(a.build.resolve(strict=True),a.output.absolute())).decode())
