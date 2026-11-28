#!/usr/bin/env python3
"""Read the same two already-completed probes and complete uploaded archive; no execution."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,source_evidence
from readonly import guarded
from restore_observer import verify as archive,selection
from preflight import full
def verify(work):
    work=Path(work);binding=selection(ROOT,"observer");restored=work/"original/restored"
    archived=archive(ROOT,work,binding);old=restored/"source";run=restored/"run";identity=source_evidence(old)
    gate=decode((run/"GATE.json").read_bytes());rows=decode((run/"processes/processes.json").read_bytes())
    require(gate["source"]==identity and gate["processes"]==rows and len(rows)==2,"entire original preflight producer record")
    for row,(name,limit,code)in zip(rows,(("source-check",60,0),("observer-probes",180,1))):
        require(row["name"]==name and row["timeout_seconds"]==limit and row["exit_code"]==code
            and row["completed"]is True and row["timed_out"]is False and row["pid"]==row["pgid"]
            and 0<row["elapsed_seconds"]<limit+1 and row["stdin"]is None,"original bounded preflight process")
        for channel in("stdout","stderr"):
            record=row[channel];require(record["file"]==name+"."+channel and pin(run/"processes"/record["file"])==
                {k:record[k]for k in("bytes","sha256")},"every actual preflight process output byte")
    checked=decode((run/"processes/source-check.stdout").read_bytes())
    require(checked["source"]==identity and checked["actual_application_calls"]==checked["compiler_calls"]==0
        and not(run/"processes/source-check.stderr").read_bytes(),"original source-only admission")
    require(b"ValueError: whole process exits at observed syscall"in(run/"processes/observer-probes.stderr").read_bytes(),
        "retained exact reader-only failure")
    probes=full(run/"probes")
    return dict(status="STDIO_OBSERVER_ORIGINAL_CAPTURE_RECOVERY_PASS",archive=archived,probes=probes,
        original_failure_preserved=True,first_source=binding["commit"],first_run=binding["run"],
        original_target_applications=0,hia_applications=0,probe_replays=0,physical_control_replays=0,
        pure_reader_correction="compare open_exit to actual ENTER payload without log record/trace_row decoration")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);a=p.parse_args()
    result=guarded(lambda:verify(a.work),roots=[ROOT,a.work])
    print(canonical(result).decode(),end="")
