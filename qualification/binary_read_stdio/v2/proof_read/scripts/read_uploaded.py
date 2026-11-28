#!/usr/bin/env python3
"""Full uploaded proof read; no application, compiler, syscall fixture or control replay."""
from pathlib import Path
import argparse,encodings.cp437,gzip,json,stat,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from readonly import guarded
import restore_uploaded
PROBES=["write","os-open-write","mkdir","rename","unlink","chmod","utime","subprocess","ctypes","mmap","foreign-read"]
def full(work,bound):
    archive=restore_uploaded.verify(ROOT,work/"semantic",bound)
    retained=work/"semantic/original/restored";source=retained/"source";run=retained/"run"
    expected=decode((ROOT/bound["expected"]["path"]).read_bytes())
    identity=source_evidence(source);gate=decode((run/"GATE.json").read_bytes())
    require(gate["status"]=="PASS"and gate["group"]==bound["group"]and gate["source"]==identity
        and gate["application_executions"]==0,"exact successful original pure read identity")
    rows=decode((run/"processes/processes.json").read_bytes())
    require(rows==gate["processes"]and [(r["name"],r["timeout_seconds"])for r in rows]==
        [("semantic-fetch",60),("semantic-unpack",180),("semantic-admit",180),("independent-full-read",180)],
        "complete four natural bounded pure processes")
    values={}
    for row in rows:
        require(row["completed"]is True and row["timed_out"]is False and row["exit_code"]==0
            and type(row["pid"])is int and row["pid"]>0 and row["pid"]==row["pgid"]
            and type(row["parent_pid"])is int and row["parent_pid"]>0 and row["stdin"]is None
            and 0<=row["elapsed_seconds"]<row["timeout_seconds"]+1,
            "successful bounded retained proof process")
        require(len(row["argv"])>=5 and row["argv"][1:4]==["-I","-S","-B"]
            and row["argv"][4].endswith("/scripts/"+("read_uploaded.py"if row["name"]=="independent-full-read"else"restore_uploaded.py")),
            "only frozen pure reader source commands")
        for channel in("stdout","stderr"):
            item=row[channel]
            require(item["file"]==row["name"]+"."+channel and pin(run/"processes"/item["file"])==
                {k:item[k]for k in("bytes","sha256")},"whole retained proof stream")
        require(row["stderr"]["bytes"]==0,"retained successful proof stderr")
        values[row["name"]]=decode((run/"processes"/row["stdout"]["file"]).read_bytes())
    guard=values["independent-full-read"]
    require((run/"READONLY.json").read_bytes()==(run/"processes/independent-full-read.stdout").read_bytes(),
        "exact complete saved guard publication")
    require(guard["status"]=="READONLY_PASS"and guard["before"]==guard["after"]
        and guard["native_executed"]is guard["rust_executed"]is guard["evidence_written"]is False
        and guard["probes"]==[dict(name=p,rejected=True)for p in PROBES]
        and guard["entries"]==len(guard["before"])==gate["entries"]==expected["entries"]
        and gate["guard_probes"]==expected["guard_probes"]==11,
        "complete saved nonexecuting eleven-guard result")
    require(guard["evidence"]==gate["read"]==expected["read"]
        and expected["status"]=="COMPLETE_STDIO_READ67_INDEPENDENT_READ_PASS"
        and expected["group"]==bound["group"]and expected["elapsed_seconds"]==rows[-1]["elapsed_seconds"],
        "exact full result emitted by independently observed terminal job")
    require(len(guard["roots"])==2 and guard["roots"]==sorted(set(guard["roots"]))
        and rows[0]["cwd"]in guard["roots"],"complete saved reader roots")
    source_number=guard["roots"].index(rows[0]["cwd"])
    source_entries={r["path"]:r for r in guard["before"]if r["root"]==source_number}
    require(len(source_entries)==sum(r["root"]==source_number for r in guard["before"]),
        "unique saved source entries")
    source_paths=[source,*sorted(source.rglob("*"))]
    require(set(source_entries)=={"."if p==source else p.relative_to(source).as_posix()for p in source_paths},
        "all saved reader source entries")
    for p in source_paths:
        key="."if p==source else p.relative_to(source).as_posix();r=source_entries[key]
        require(r["mode"]&0o777==p.stat().st_mode&0o777,"saved source mode")
        if p.is_file():
            require(stat.S_ISREG(r["mode"])and {k:r[k]for k in("bytes","sha256")}==pin(p),
                "complete saved reader source bytes")
        else:require(stat.S_ISDIR(r["mode"])and "sha256"not in r,"saved source directory")
    seen=set()
    for r in guard["before"]:
        require(type(r["root"])is int and r["root"]in(0,1)and(r["root"],r["path"])not in seen,
            "complete unique saved guard entry")
        seen.add((r["root"],r["path"]))
        require(stat.S_ISDIR(r["mode"])or stat.S_ISREG(r["mode"]),"ordinary saved guard entry")
        if stat.S_ISREG(r["mode"]):
            require(type(r["bytes"])is int and r["bytes"]>=0 and len(r["sha256"])==64,
                "complete saved guarded file identity")
    q=expected["read"]["qualification"]
    require(q["new_application_calls"]==q["new_physical_controls"]==0
        and q["physical_refusals"]==8 and q["complete_relocations"]==2
        and q["original_failure_preserved"]is True and q["original_failure_reproduced_by_pure_reader"]is True,
        "retained actual gate recovery scope")
    return dict(status="COMPLETE_STDIO_READ67_UPLOADED_PROOF_PASS",group=bound["group"],archive=archive,
        prior_independent_result=expected,complete_proof_files=archive["logical_files"],
        complete_proof_bytes=archive["logical_bytes"],saved_source_entries=len(source_entries),
        all_saved_guard_entries=len(seen),saved_guard_probes=11,application_executions=0,
        physical_control_executions=0,original_semantic_archive_reexecuted=False)
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    work=a.work.resolve(strict=True);before=source_evidence(ROOT);bound=restore_uploaded.selection(ROOT,a.group)
    result=guarded(lambda:full(work,bound),roots=[ROOT,work/"semantic"])
    require(source_evidence(ROOT)==before,"proof reader source unchanged")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
