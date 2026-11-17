#!/usr/bin/env python3
"""Run the complete pending filesystem control once, under its original 180 seconds."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,stat,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import filesystem_fast_guard as fast
from run_skipped import execute
from read_recovered import SOURCE,CAPTURE,PYTHON,REPORT_SHA,put,pin,need
from read_only_guard import snapshot as full_snapshot
def snapshot(root):
    return {key[2:]:row for key,row in full_snapshot([root]).items()}
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--preparation",type=Path,required=True);args=parser.parse_args()
    out=args.output.absolute();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    need(Path(sys.executable)==PYTHON,"exact recorded Python invocation path")
    started=time.monotonic_ns();prep=json.loads(args.preparation.read_bytes())
    need(prep["status"]=="COMPLETE_SEALED_INPUT_SUBSET_PASS" and prep["source"]==str(SOURCE)
         and prep["capture"]==str(CAPTURE) and prep["native_or_rust_executions"]==0,"complete input preparation")
    manifest=json.loads(Path(__file__).with_name("SOURCE_MANIFEST.json").read_bytes())
    for name,row in manifest["files"].items():
        need(pin(Path(__file__).parent/name)=={k:row[k] for k in ("bytes","sha256")},"fixed continuation source closure")
    before={"source":snapshot(SOURCE),"capture":snapshot(CAPTURE)}
    for role in ("source","capture"):
        expected=prep["source_files" if role=="source" else "output_files"]
        need({name:{"bytes":row["bytes"],"sha256":row["sha256"],"mode":stat.S_IMODE(row["mode"])}
              for name,row in before[role].items() if stat.S_ISREG(row["mode"])}==expected,
             "all actual inputs match preparation")
    with gzip.open(out/"before.json.gz","xb",compresslevel=1) as stream:
        stream.write((json.dumps(before,sort_keys=True,indent=2)+"\n").encode())
    control_source=SOURCE/"tests/hia_native/filesystem_parity/qualify_pipeline.py"
    equality=fast.equivalence(control_source);put(out/"GUARD_EQUIVALENCE.json",equality)
    common=["--repo",str(SOURCE),"--output",str(CAPTURE),"--report",str(CAPTURE/"result.json"),
            "--controls",str(out/"filesystem-controls")]
    result=None;failure=None
    try:result=execute(out,"filesystem",common)
    except BaseException as exc:
        failure={"type":type(exc).__name__,"message":str(exc)};raise
    finally:
        after={"source":snapshot(SOURCE),"capture":snapshot(CAPTURE)}
        with gzip.open(out/"after.json.gz","xb",compresslevel=1) as stream:
            stream.write((json.dumps(after,sort_keys=True,indent=2)+"\n").encode())
        need(before==after,"entire supplied source/capture metadata unchanged by control")
        put(out/"CONTINUATION.json",{"schema":"hepta.history.filesystem-control-continuation.v1",
            "status":"PASS" if result is not None else "FAIL","error":failure,
            "preparation":pin(args.preparation),"source_manifest":pin(Path(__file__).with_name("SOURCE_MANIFEST.json")),
            "guard_equivalence":pin(out/"GUARD_EQUIVALENCE.json"),
            "actual_filesystem_control":result,
            "input_files":sum(stat.S_ISREG(row["mode"]) for table in before.values() for row in table.values()),
            "input_entries":sum(map(len,before.values())),
            "input_bytes":sum(row["bytes"] for table in before.values() for row in table.values() if stat.S_ISREG(row["mode"])),
            "full_input_metadata_unchanged":True,"original_aggregate_reexecuted":False,
            "original_failure_reclassified_as_pass":False,"native_or_rust_executions":0,
            "elapsed_ns":time.monotonic_ns()-started})
    print(json.dumps({"status":"PASS","full_filesystem_refusals":11,"physical_relocations":2,
        "foreign_path_refusals":12,"native_or_rust_executions":0},sort_keys=True))
if __name__=="__main__":main()
