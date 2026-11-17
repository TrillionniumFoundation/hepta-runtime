"""One owned independent partition, with the unchanged per-copy control body."""
from pathlib import Path
import argparse,os,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import physical_common as pc
import bundle,mutations,physical_controls,physical_parallel

def run(retained,output,part):
    identity=pc.source();parent_raw=pc.read(output/"PARENT.json");parent=pc.loads(parent_raw)
    pc.check(type(part) is int and part in (0,1),"exact worker partition")
    pc.check(parent["pid"]==os.getppid() and parent["pgid"]==os.getpgrp() and
             parent["source_root"]==str(ROOT) and parent["retained_root"]==str(retained) and parent["output_root"]==str(output) and
             parent["source_manifest_sha256"]==identity and parent["deadline_ns"]==parent["started_ns"]+physical_parallel.LIMIT_NS and
             time.monotonic_ns()<parent["deadline_ns"],"actual inherited parent identity and unchanged whole deadline")
    baseline_raw=pc.read(output/"BASELINE.json");baseline=pc.loads(baseline_raw)
    prepared=bundle.prepare(retained/"restored/prior/source")
    names=physical_parallel.parts(physical_controls.ADMISSIONS,mutations.NAMES)[part]
    rows=physical_controls.run_subset(output/"baseline",output,prepared,names,baseline)
    pc.check(time.monotonic_ns()<parent["deadline_ns"] and pc.source()==identity,"complete worker finished before same parent deadline")
    report=dict(schema="hepta.namespace-fingerprint.physical-part.v1",status="PASS",part=part,names=list(names),rows=rows,
                parent_evidence=pc.pin(parent_raw),baseline=pc.pin(baseline_raw),pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),
                source_root=str(ROOT),retained_root=str(retained),output_root=str(output),source_manifest_sha256=identity,
                native_or_rust_executions=0)
    raw=pc.enc(report);(output/"workers"/str(part)/"REPORT.json").write_bytes(raw)
    print(pc.enc(physical_parallel.child_summary(report,raw)).decode(),end="")

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--retained",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--part",type=int,required=True);a=p.parse_args()
    run(a.retained.resolve(strict=True),a.output.resolve(strict=True),a.part)
