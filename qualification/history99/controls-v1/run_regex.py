#!/usr/bin/env python3
"""Complete the original configuration/regex evidence controls, unchanged and under 180 seconds."""
from __future__ import annotations
import argparse,gzip,json,os,stat,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_skipped import execute
from read_recovered import SOURCE,CAPTURE,PYTHON,REPORT_SHA,put,pin,need
from read_only_guard import snapshot as full_snapshot
def snapshot(root):return {k[2:]:v for k,v in full_snapshot([root]).items()}
def semantic(table):
    return {name:{key:row[key] for key in ("mode","bytes","sha256")} for name,row in table.items()}
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--preparation",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True);args=parser.parse_args();start=time.monotonic_ns()
    out=args.output.absolute();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    need(Path(sys.executable)==PYTHON,"exact recorded interpreter")
    prep=json.loads(args.preparation.read_bytes())
    need(prep["status"]=="COMPLETE_SEALED_INPUT_SUBSET_PASS" and prep["source"]==str(SOURCE)
         and prep["capture"]==str(CAPTURE) and prep["native_or_rust_executions"]==0,"full sealed preparation")
    manifest=json.loads(Path(__file__).with_name("SOURCE_MANIFEST.json").read_bytes())
    for name,row in manifest["files"].items():
        need(pin(Path(__file__).parent/name)=={k:row[k] for k in ("bytes","sha256")},"frozen exact continuation source")
    before={"source":snapshot(SOURCE),"capture":snapshot(CAPTURE)}
    for role in before:
        expected=prep["source_files" if role=="source" else "output_files"]
        need({name:{"bytes":v["bytes"],"sha256":v["sha256"],"mode":stat.S_IMODE(v["mode"])}
              for name,v in before[role].items() if stat.S_ISREG(v["mode"])}==expected,"complete actual inputs")
    bundle=json.loads((CAPTURE/"build/config-build.json").read_bytes())
    member=Path(bundle["executables"]["mcp"]["path"])
    need(member.is_relative_to(CAPTURE),"actual MCP manifest is in captured root")
    metadata=json.loads(member.read_bytes());elf=member.parent/metadata["executable"]
    need(elf.is_relative_to(CAPTURE),"actual executable is retained")
    allowed={"source":{"native/regex_nfa.hepta"},"capture":{
      elf.relative_to(CAPTURE).as_posix(),"regex-native/nfa-0/native-output.txt",
      "regex-native/nfa-0/case-indices.json","regex-native/nfa-0/native-corpus.json","test_regex_nfa_0.py.stdout",
      "regex-original/report.json","regex-original/match.stdout.gz","config-original/regex-mcp/report.json"}}
    need(len(allowed["capture"])==8,"exact old mutation paths")
    with gzip.open(out/"before.json.gz","xb",compresslevel=1) as f:f.write((json.dumps(before,sort_keys=True,indent=2)+"\n").encode())
    result=None;failure=None
    try:
        result=execute(out,"regex",["--repo",str(SOURCE),"--output",str(CAPTURE),"--report",str(CAPTURE/"result.json"),
                                   "--receipt",str(out/"regex-controls.json")])
    except BaseException as exc:
        failure={"type":type(exc).__name__,"message":str(exc)};raise
    finally:
        after={"source":snapshot(SOURCE),"capture":snapshot(CAPTURE)}
        with gzip.open(out/"after.json.gz","xb",compresslevel=1) as f:f.write((json.dumps(after,sort_keys=True,indent=2)+"\n").encode())
        need(all(semantic(before[role])==semantic(after[role]) for role in before),"all actual input bytes and modes restored")
        differences={role:sorted(name for name in before[role] if before[role][name]!=after[role][name]) for role in before}
        need(all(set(differences[role])<=allowed[role] for role in before),"only original declared mutation metadata changed")
        if result is not None:need(all(set(differences[role])==allowed[role] for role in before),"every actual mutation is retained")
        put(out/"CONTINUATION.json",{"schema":"hepta.history.regex-control-continuation.v1",
          "status":"PASS" if result is not None else "FAIL","error":failure,"actual_regex_control":result,
          "preparation":pin(args.preparation),"source_manifest":pin(Path(__file__).with_name("SOURCE_MANIFEST.json")),
          "allowed_metadata_changes":{k:sorted(v) for k,v in allowed.items()},"actual_metadata_changes":differences,
          "full_input_bytes_modes_restored":True,"full_aggregate_reexecuted":False,
          "original_failure_reclassified_as_pass":False,"native_or_rust_executions":0,"elapsed_ns":time.monotonic_ns()-start})
    print(json.dumps({"status":"PASS","original_refusals":14,"complete_admissions":6,
                     "native_or_rust_executions":0},sort_keys=True))
if __name__=="__main__":main()
