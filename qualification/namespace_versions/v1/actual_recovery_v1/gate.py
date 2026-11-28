"""One previously unexecuted actual group after complete pure dependency admission."""
import argparse,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,loads,read,encoded,require,pin
from protocol import domain
from process import Recorder,environment
def run(workspace,group):
    identity=source();require(group in domain()["groups"],"one complete frozen actual group")
    output=workspace/"run";output.mkdir();retained=workspace/"retained";python=Path(sys.executable).resolve(strict=True)
    env,binding=environment(os.environ);recorder=Recorder(ROOT,output/"processes",env)
    commands=[
        ("source",[python,"-I","-B",ROOT/"source_check.py"],60),
        ("restore",[python,"-I","-B",ROOT/"restore.py","--workspace",workspace],180),
        ("read-native",[python,"-I","-B",retained/"native/source/read_build.py","--build",retained/"native/run/build",
            "--authored",retained/"native/run/authored","--output",output/"NATIVE-BUILD-GUARDED.json"],180),
        ("read-original",[python,"-I","-B",ROOT/"read_original.py","--original",retained/"original","--output",output/"ORIGINAL-BUILD-GUARDED.json"],180),
        ("strace-version",["/usr/bin/strace","--kill-on-exit","--version"],60),
        ("application",[python,"-I","-B",ROOT/"run_pairs.py","--retained",retained,"--binary",retained/"original/run/original.elf",
            "--output",output/"group","--fixture",output/"group/fixture","--group",group],60),
        ("read",[python,"-I","-B",ROOT/"read_actual.py","--workspace",workspace,"--group",group,"--output",output/"ACTUAL-GUARDED.json"],180)]
    meta=dict(schema="hepta.namespace-versions.actual-run.v1",status="RUNNING",group=group,source_manifest_sha256=identity,
        source_root=str(ROOT),workspace=str(workspace),pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),
        application_replays=0,environment=binding,commands=[dict(name=n,argv=list(map(str,a)),cwd=str(ROOT),timeout_seconds=t)for n,a,t in commands])
    (output/"RUN.json").write_bytes(encoded(meta));results={}
    try:
        for name,args,budget in commands:
            if name=="application":
                require(results["read-native"]["status"]=="COMPLETE_NAMESPACE_VERSIONS_CALLABLE_BUILD_READ_PASS"
                    and results["read-original"]["status"]=="COMPLETE_ORIGINAL_NAMESPACE_RECOVERED_READ_PASS","both complete actual builds admitted")
                admitted=dict(schema="hepta.namespace-versions.actual-build-admission.v1",status="PASS",source_manifest_sha256=identity,
                    native=results["read-native"],original=results["read-original"],native_application_calls=0,original_application_calls=0,
                    original_compile_replays=0,native_compile_replays=0)
                (retained/"ADMISSION.json").write_bytes(encoded(admitted))
                # Remove the already-used download token from the application environment.
                recorder.env.pop("GH_TOKEN",None)
            raw,_=recorder.run(name,args,timeout=budget)
            if name!="strace-version":results[name]=loads(raw)
            print("NAMESPACE_ACTUAL_PROCESS "+name+" PASS",flush=True)
        require(source()==identity,"complete actual source remains frozen")
        final=dict(schema="hepta.namespace-versions.actual-gate.v1",status="NAMESPACE_VERSIONS_ACTUAL_GROUP_PASS",
            group=group,source_manifest_sha256=identity,read=results["read"],processes=recorder.records,
            actual_original_processes=1,actual_native_processes=2,application_replays=0,
            namespace_version_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
        (output/"GATE.json").write_bytes(encoded(final));meta.update(status="PASS",processes=recorder.records)
        (output/"RUN.json").write_bytes(encoded(meta));print("NAMESPACE_ACTUAL_GATE_BEGIN");print(encoded(final).decode(),end="");print("NAMESPACE_ACTUAL_GATE_END")
    except BaseException as error:
        meta.update(status="FAIL",exception=repr(error),processes=recorder.records);(output/"RUN.json").write_bytes(encoded(meta));raise
    finally:
        for row in recorder.records:
            path=output/"processes"/row["stderr"]["file"]
            if path.exists()and path.stat().st_size:sys.stderr.buffer.write(read(path))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    run(a.workspace.resolve(strict=True),a.group)
