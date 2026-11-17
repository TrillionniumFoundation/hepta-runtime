"""Real tracer/tracee cleanup controls; no HIA or Rust application executes."""
from pathlib import Path
import argparse,os,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,pin,read,require,source
from run_pairs import Child
from trace_scope import Reaper
class OwnedAbort(Exception):pass
def run(output):
    identity=source();output.mkdir(parents=True,exist_ok=False)
    started=time.monotonic();deadline=started+60;rows=[]
    specifications=[("normal",["normal"],False),("before-ready-exit",["exit"],True),
        ("rejected-ready",["wrong-parent"],True),("one-live-tracee",["block"],True),
        ("two-live-tracees",["block","block"],True),("missing-executable",["missing"],True)]
    for name,modes,rejected in specifications:
        folder=output/name;folder.mkdir();children=[];errors=[];exception=None;reaped=[];processes=[]
        reaper=Reaper()
        try:
            for i,mode in enumerate(modes):
                argv=["/definitely-absent-owned-watcher-probe"]if mode=="missing"else[sys.executable,"-I","-B",ROOT/"trace_probe.py",mode]
                child=Child("probe",argv,folder/("child-%d"%i),deadline)
                children.append(child);child.start()
            if name in("one-live-tracee","two-live-tracees"):raise OwnedAbort("known owned fixture abort after all ready")
            for child in children:
                require(child.exchange(dict(cmd="finish",case=0))==dict(command="finish",case=0),"complete probe exchange")
                child.end_input()
            for child in children:child.finish()
        except BaseException as error:
            exception=repr(error)
            for child in children:child.failure=exception
        finally:
            for child in children:
                try:child.kill()
                except BaseException as error:errors.append("kill:"+repr(error))
            for child in children:
                try:child.wait()
                except BaseException as error:errors.append("wait:"+repr(error))
            try:reaped=reaper.finish()
            except BaseException as error:errors.append("reap:"+repr(error))
            for child in children:
                try:processes.append(child.seal(name))
                except BaseException as error:errors.append("seal:"+repr(error))
            receipt=dict(name=name,rejected=rejected,exception=exception,cleanup_errors=errors,
                prior_subreaper=reaper.prior,restored=not reaper.active,adopted_reaps=reaped,processes=processes)
            (folder/"CONTROL.json").write_bytes(encoded(receipt))
        require(not errors and not reaper.active,"every started tracer and tracee reclaimed before evidence")
        require(bool(exception)==rejected,"same intended ordinary/refusal control")
        if name=="normal":
            require(not reaped and len(processes)==1 and processes[0]["exit_code"]==0
                and processes[0]["success"],"normal application and tracer exit and no orphan")
        if name=="before-ready-exit":
            require(processes[0]["exit_code"]!=0 and b"exit_group(23)"in read(children[0].folder/"syscalls.strace"),
                "actual complete pre-ready application exit 23 retained even if tracer cleanup races")
        if name in("one-live-tracee","two-live-tracees","rejected-ready"):
            actual={c.ready["pid"]for c in children if c.ready is not None}
            require(actual and {r["pid"]for r in reaped}==actual and all(r["exit_code"]==-9 for r in reaped),
                "actual PTRACE_O_EXITKILL, subreaper ownership and complete SIGKILL wait status")
            require(all(p["exit_code"]==-9 for p in processes),"every live tracer actually killed")
        if name=="missing-executable":require(processes[0]["exit_code"]!=0,"actual missing executable refusal")
        rows.append(receipt)
    require(time.monotonic()<=deadline and source()==identity,"whole unchanged 60-second control deadline and frozen source")
    result=dict(status="OWNED_TRACER_CUSTODY_CONTROLS_PASS",source_manifest_sha256=identity,controls=rows,
        elapsed_seconds=time.monotonic()-started,timeout_seconds=60,pid=os.getpid(),parent_pid=os.getppid(),
        pgid=os.getpgrp(),native_executions=0,rust_executions=0)
    (output/"CONTROLS.json").write_bytes(encoded(result));print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.output.absolute())
