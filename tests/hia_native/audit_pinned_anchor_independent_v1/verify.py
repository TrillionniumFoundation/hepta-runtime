"""Independent full archived evidence verification; no semantic subprocess or mapping."""
from pathlib import Path
import argparse,importlib.util,math,os,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from read_archive import check,enc,pin,loads,regular,source_files
def run(destination,receipt,source_sha256):
    fixed=loads(regular(ROOT/"TARGET.json"))
    source_files(ROOT,source_sha256)
    recovery=destination/"recovery-source";original=destination/"restored/prior/source"
    capture=destination/"restored/prior/run/semantic";out=destination/"recovery-run";controls=out/"controls"
    sys.path.insert(0,str(recovery))
    spec=importlib.util.spec_from_file_location("anchor_frozen_recovery",recovery/"reader.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    identity,cli,read_capture,reader_controls=module.prepare(original)
    check(identity==fixed["recovery_source_sha256"],"same uploaded exact recovery reader")
    def operation():
        source_files(ROOT,source_sha256)
        check(module.rc.source()==identity,"full uploaded recovery source inside guard")
        baseline=read_capture.verify(capture)
        result=dict(baseline,controls=reader_controls.verify(capture,controls,baseline))
        gate=loads(regular(out/"GATE.json"))
        old_final=loads(regular(out/"final.json"));old_semantic=loads(regular(out/"semantic.json"))
        check(old_semantic["evidence"]["complete_evidence"]==baseline and old_final["evidence"]["complete_evidence"]==result,"entire old/new semantic and final reader evidence identical")
        for old in (old_semantic,old_final):
            check(old["before"]==old["after"] and len(old["probes"])==12 and len({p["name"] for p in old["probes"]})==12 and
                  old["native_or_rust_executions"]==old["reader_writes"]==0,"all retained full guard proofs")
        check(gate["schema"]=="hepta.audit-pinned-anchor.reader-recovery.v1" and gate["status"]=="PASS" and gate["prior_status"]=="FAIL" and
              gate["prior_head"]=="a30d3e93185e84ee2a0e8c4abbdcc0d23177676a" and gate["source_sha256"]==identity and
              gate["original_source_sha256"]==fixed["original_source_sha256"] and
              gate["cases"]==fixed["cases"] and gate["operations"]==fixed["operations"] and
              gate["observed"]==result["observed"] and gate["observer_off"]==result["observer_off"] and gate["original"]==result["original"] and
              all(gate[k]==result[k] for k in ("transport_controls","owner_controls")) and gate["reader_controls"]==result["controls"],"complete saved successor gate")
        # The evidence calls the physical reader result "controls"; preserve
        # the original gate's reader_controls spelling without modifying it.
        records={};seen=set();old_cwd=None
        for phase in ("semantic","controls","final"):
            body=regular(out/"processes"/phase/"processes.json");rows=loads(body)
            check(len(rows)==1,"one actual recorded pure reader per phase");row=rows[0]
            cwd=Path(row["cwd"])
            if old_cwd is None:old_cwd=cwd
            check(cwd==old_cwd and cwd.name=="source" and cwd.parent.name=="audit-pinned-anchor-recovery-v2","exact original successor process root")
            expected=[row["argv"][0],"-I","-B",str(cwd/"reader.py"),"--phase",phase,"--original-source",str(cwd.parent/"restored/prior/source"),"--capture",str(cwd.parent/"restored/prior/run/semantic"),"--receipt",str(cwd.parent/"output"/(phase+".json"))]
            if phase in ("controls","final"):expected+=["--controls",str(cwd.parent/"output/controls")]
            check(row["argv"]==expected and row["argv"][0]=="/usr/bin/python3" and row["name"]=="pure-"+phase and
                  row["completed"] is True and row["timed_out"] is False and row["stdin"] is None and
                  type(row["exit_code"]) is int and row["exit_code"]==0 and type(row["timeout_seconds"]) is int and row["timeout_seconds"]==180 and
                  type(row["elapsed_seconds"]) in (int,float) and math.isfinite(row["elapsed_seconds"]) and 0<row["elapsed_seconds"]<=180 and
                  all(type(row[k]) is int and row[k]>1 for k in ("pid","pgid","parent_pid")) and row["pid"]==row["pgid"]!=row["parent_pid"] and row["pid"] not in seen,
                  "actual exact bounded pure reader process")
            seen.add(row["pid"])
            value=loads(regular(out/(phase+".json")))
            stdout=value if phase=="controls" else {k:v for k,v in value.items() if k not in ("before","after")}
            for stream in ("stdout","stderr"):
                filename="pure-"+phase+"."+stream;data=regular(out/"processes"/phase/filename)
                check(row[stream]==dict(file=filename,**pin(data)) and data==(enc(stdout) if stream=="stdout" else b""),"all complete successful reader streams")
            check(gate["processes"][phase]==dict(process=pin(body),receipt=pin(regular(out/(phase+".json")))),"all gate process pins")
            records[phase]=dict(pid=row["pid"],parent_pid=row["parent_pid"],pgid=row["pgid"],elapsed_seconds=row["elapsed_seconds"],timeout_seconds=180)
        check(set(gate["processes"])==set(records) and gate["final_receipt"]==pin(regular(out/"final.json")),"exact complete reader phase set")
        original_failed=loads(regular(destination/"restored/prior/run/reader-processes/semantic/processes.json"))
        check(len(original_failed)==1 and original_failed[0]["exit_code"]==1 and original_failed[0]["timed_out"] is False and
              pin(regular(destination/"restored/prior/run/reader-processes/semantic/readonly-semantic.stderr"))==dict(bytes=2236,sha256="47a8d021bedf27a66c1b501838bcd8983e4132fb366b4051ca642922d6f88c94"),"original failed reader retained exactly")
        check(gate["native_executions"]==gate["rust_executions"]==0 and all(gate[k] is False for k in ("archive_store_qualified","hot_cache_qualified","begin_finish_caller_qualified","public_handler_qualified")),"scope not enlarged")
        return dict(status="INDEPENDENT_COMPLETE_PINNED_ANCHOR_READ_PASS",source_sha256=identity,producer_head=fixed["head"],
                    cases=fixed["cases"],operations=fixed["operations"],processes=records,evidence=result,
                    original_failed_read_preserved=True,native_executions=0,rust_executions=0)
    # One guard over every restored source, original failure, ordinary buffer,
    # independent physical copy and all old phase receipts.
    proof=cli.read_only_guard.guarded(operation,roots=[destination,ROOT],foreign_path=str(destination.parent/"unadmitted-original/CAPTURE.json"))
    receipt.write_bytes(enc(proof))
    e=proof["evidence"]
    summary=dict(status=e["status"],cases=e["cases"],operations=e["operations"],guard_entries=len(proof["before"]),guard_probes=len(proof["probes"]),
        before_after_unchanged=proof["before"]==proof["after"],source_sha256=identity,actual_prior_reader_processes=e["processes"],
        observed=e["evidence"]["observed"],observer_off=e["evidence"]["observer_off"],original=e["evidence"]["original"],
        owner_controls=e["evidence"]["owner_controls"],transport_controls=e["evidence"]["transport_controls"],physical_controls=e["evidence"]["controls"],
        full_guard_report=pin(regular(receipt)),native_executions=0,rust_executions=0,public_handler_qualified=False)
    receipt.with_name("RESULT.json").write_bytes(enc(summary));print(enc(summary).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--destination",type=Path,required=True);p.add_argument("--receipt",type=Path,required=True);p.add_argument("--source-sha256",required=True);a=p.parse_args();run(a.destination.resolve(strict=True),a.receipt,a.source_sha256)
