"""Independently read complete callable evidence and original recovery process custody."""
from pathlib import Path
import argparse,math,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from independent_support import source,expected,read,loads,encoded,pin,need,files

def custody(capture,e,evidence):
    recovery=capture/"recovery"
    proofs={}
    process_rows=[]
    previous_cwd=python=None
    for phase in ("semantic","controls","final"):
        folder=recovery/"processes"/phase
        rows=loads(read(folder/"processes.json"))
        need(len(rows)==1,"one actual original recovery process per phase")
        row=rows[0];name="readonly-"+phase
        need(set(files(folder))=={"processes.json",name+".stdout",name+".stderr"} and
             row["name"]==name and type(row["timeout_seconds"]) is int and row["timeout_seconds"]==180 and
             type(row["exit_code"]) is int and row["exit_code"]==0 and row["completed"] is True and
             row["timed_out"] is False and row["stdin"] is None and
             type(row["elapsed_seconds"]) in (int,float) and math.isfinite(row["elapsed_seconds"]) and
             0<row["elapsed_seconds"]<=180,"complete original successful reader and unchanged deadline")
        need(all(type(row[k]) is int and row[k]>1 for k in ("pid","parent_pid","pgid")) and
             row["pid"]==row["pgid"] and row["pid"]!=row["parent_pid"],"actual owned original reader group")
        cwd=Path(row["cwd"]);args=row["argv"]
        need(cwd.is_absolute() and cwd.name=="recovery-source" and type(args) is list and
             args and Path(args[0]).is_absolute(),"actual immutable recovery source/process roots")
        if previous_cwd is None:previous_cwd,python=cwd,args[0]
        need(cwd==previous_cwd and args[0]==python,"same original source and Python executable")
        ws=cwd.parent
        wanted=[python,"-I","-B",str(cwd/"reader_cli.py"),"--phase",phase,
            "--original",str(ws/"original/source"),"--capture",str(ws/"original/run/semantic"),
            "--retained",str(ws/"original/retained"),"--controls",str(ws/"recovery/controls"),
            "--report",str(ws/"recovery"/(phase+"-read.json"))]
        need(args==wanted,"complete actual original reader invocation")
        streams={}
        for which in ("stdout","stderr"):
            raw=read(folder/(name+"."+which))
            need(row[which]==dict(file=name+"."+which,**pin(raw)),"whole original reader process stream")
            streams[which]=raw
        need(streams["stderr"]==b"","original reader had no unbound stderr")
        proof=loads(read(recovery/(phase+"-read.json")));proofs[phase]=proof
        need(proof["reader_adapter_source_sha256"]==e["reader_source_sha256"] and
             proof["original_source_manifest_sha256"]==e["original_source_sha256"] and
             proof["original_failure_preserved"] is True,"exact reader-source and original failure identity")
        if phase=="controls":
            control_report=loads(read(recovery/"controls/CONTROLS.json"))
            need(proof["evidence"]==control_report and proof["native_or_rust_executions"]==0 and
                 control_report["status"]=="PASS" and control_report["refusals"]==13 and
                 control_report["admissions"]==2,"all original physical refusal and admission records")
            for control in control_report["rows"]:
                guard=loads(read(recovery/"controls"/control["proof"]))
                need(guard["pid"]==row["pid"] and guard["ppid"]==row["parent_pid"] and
                     guard["pgid"]==row["pgid"],"all physical guards belong to the actual owned reader")
            summary=dict(status="PASS",refusals=13,admissions=2,native_or_rust_executions=0,
                mutation_writes_outside_guards=True,reader_adapter_source_sha256=e["reader_source_sha256"])
        else:
            need(proof["pid"]==row["pid"] and proof["ppid"]==row["parent_pid"] and proof["pgid"]==row["pgid"] and
                 proof["before"]==proof["after"] and len(proof["probes"])==12 and
                 proof["native_or_rust_executions"]==proof["reader_writes"]==0 and
                 proof["source_bound_guard"] is True,"original complete before/after guarded read and PID")
            wanted_evidence=dict(evidence)
            if phase=="semantic":wanted_evidence.pop("physical_controls")
            need(proof["evidence"]==wanted_evidence,"original whole evidence equals this independent full reread")
            summary=dict(status="PASS",native_or_rust_executions=0,reader_writes=0,guard_probes=12,
                physical_entries=len(proof["before"]),reader_adapter_source_sha256=e["reader_source_sha256"],
                original_source_manifest_sha256=e["original_source_sha256"],evidence=proof["evidence"])
        need(streams["stdout"]==encoded(summary),"all complete original reader stdout fields")
        process_rows.append(dict(name=name,pid=row["pid"],parent_pid=row["parent_pid"],pgid=row["pgid"],
            elapsed_seconds=row["elapsed_seconds"],timeout_seconds=180,exit_code=0,stdout=pin(streams["stdout"])))
    gate=loads(read(recovery/"GATE.json"))
    need(gate==dict(schema="hepta.audit-record-callable.recovered-gate.v1",status="PASS",
        reader_adapter_source_sha256=e["reader_source_sha256"],original_source_manifest_sha256=e["original_source_sha256"],
        original_head=e["original_head"],original_run=e["original_run"],original_status="FAIL",original_failure_preserved=True,
        cases=219,operations=459,observer_off_cases=219,observer_off_operations=459,
        transport_refusals=45,transport_recoveries=45,physical_reader_refusals=13,physical_admissions=2,
        final_read=pin(read(recovery/"final-read.json")),
        final_process=pin(read(recovery/"processes/final/processes.json")),
        native_or_rust_executions=0,original_rust_replay=0,whole_runtime_replaced=False,
        archive_and_hot_cache_qualified=False,begin_finish_caller_qualified=False,public_handler_qualified=False),
        "exact actual original final gate and all boundaries")
    return process_rows

def run(capture,report):
    identity=source();e=expected()
    sys.path.insert(0,str(capture/"recovery-source"))
    import reader_adapter,recovery_common
    need(recovery_common.source()==e["reader_source_sha256"],"exact qualified pure reader before preload")
    legacy,physical=reader_adapter.install(capture/"original/source")
    prepared=legacy.prepare(capture/"original/retained")
    def operation():
        need(source()==identity and recovery_common.source()==e["reader_source_sha256"],"complete independent/reader source")
        evidence=legacy.operation(capture/"original/run/semantic",prepared,capture/"recovery/controls")
        rows=custody(capture,e,evidence)
        old=loads(read(capture/"admission/ORIGINAL_ARCHIVE_MANIFEST.json"))
        unchanged={name:{k:row[k] for k in ("bytes","sha256","mode")} for name,row in old["files"].items()}
        need(files(capture/"original")==unchanged and len(unchanged)==44786 and
             sum(r["bytes"] for r in unchanged.values())==2581124108,"all original failure bytes remain exact")
        return dict(schema="hepta.audit-record-callable.independent-read.v1",status="PASS",
            independent_source_sha256=identity,reader_adapter_source_sha256=e["reader_source_sha256"],
            original_source_manifest_sha256=e["original_source_sha256"],
            recovery_processes=rows,evidence=evidence,original_unchanged_files=44786,
            original_unchanged_bytes=2581124108,original_status="FAIL",native_or_rust_executions=0,
            reader_writes=0,public_handler_qualified=False,whole_runtime_replaced=False)
    proof=legacy.read_only_guard.guarded(operation,roots=[capture,ROOT],
        foreign_path=str(capture.parent/"unadmitted-producer-copy/CAPTURE.json"))
    need(source()==identity,"same full independent source after complete guard")
    report.write_bytes(encoded(proof))
    result=dict(status="PASS",independent_source_sha256=identity,complete_guard=pin(read(report)),
        physical_entries=len(proof["before"]),guard_probes=len(proof["probes"]),
        all_entry_bytes_and_metadata_unchanged=proof["before"]==proof["after"],
        recovery_processes=proof["evidence"]["recovery_processes"],
        image=proof["evidence"]["evidence"]["fresh_build"]["image"],
        original_unchanged_files=44786,original_unchanged_bytes=2581124108,
        native_or_rust_executions=0,reader_writes=0,public_handler_qualified=False)
    print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--capture",type=Path,required=True);p.add_argument("--report",type=Path,required=True)
    a=p.parse_args();run(a.capture.resolve(strict=True),a.report.absolute())
