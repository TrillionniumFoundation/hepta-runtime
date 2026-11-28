"""Full new control buffers read under the unchanged fixed-reader guard."""
from pathlib import Path
import argparse,sys,math
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import control_common as rc
import execute

def process_custody(output):
    reports={phase:rc.loads(rc.read(output/(phase+"-controls")/"CONTROLS.json")) for phase in ("owner","transport")}
    old_capture=reports["owner"]["observed_root"]
    rc.check(type(old_capture) is str and old_capture.startswith("/") and old_capture.endswith("/run/semantic"),"original recorded restored capture path")
    old_prior=old_capture[:-len("/run/semantic")];old_output=reports["owner"]["output_root"]
    rc.check(old_output.endswith("/owner-controls"),"recorded owner control output")
    old_output=old_output[:-len("/owner-controls")]
    old_source=reports["transport"]["source_root"]
    rc.check(all(type(x) is str and x.startswith("/") and str(Path(x))==x and ".." not in Path(x).parts
                 for x in (old_source,old_prior,old_output)),"absolute inert recorded control roots")
    rows={}
    for phase,report in reports.items():
        directory=output/"processes"/phase;items=rc.loads(rc.read(directory/"processes.json"));name="fingerprint-"+phase
        rc.check(type(items) is list and len(items)==1,"one bounded owned control process")
        row=items[0];argv=row["argv"]
        rc.check(type(argv) is list and len(argv)==10 and type(argv[0]) is str and argv[0].startswith("/") and
                 argv[1:]==["-I","-B",old_source+"/execute.py","--prior",old_prior,"--output",old_output+"/"+phase+"-controls","--phase",phase] and
                 row["name"]==name and row["cwd"]==old_source and row["stdin"] is None and
                 type(row["timeout_seconds"]) is int and row["timeout_seconds"]==60 and
                 type(row["exit_code"]) is int and row["exit_code"]==0 and row["completed"] is True and row["timed_out"] is False and
                 type(row["elapsed_seconds"]) in (int,float) and math.isfinite(row["elapsed_seconds"]) and 0<row["elapsed_seconds"]<=60,
                 "exact complete control command and original deadline")
        rc.check(all(type(row[k]) is int and row[k]>1 for k in ("pid","parent_pid","pgid")) and
                 row["pgid"]==row["pid"]!=row["parent_pid"] and
                 all(type(report[k]) is int and report[k]==row[k] for k in ("pid","parent_pid","pgid")),
                 "actual control child PID, parent and process group")
        rc.check(report["source_root"]==(old_prior+"/source" if phase=="owner" else old_source) and
                 report["build_root"]==old_capture+"/build" and report["output_root"]==old_output+"/"+phase+"-controls",
                 "recorded exact control source/build/output roots")
        if phase=="transport":rc.check(report["fixture"]==old_output+"/owned-transport-fixture" and report["original_source_root"]==old_prior+"/source","exact private transport fixture and original source ownership")
        expected={"processes.json"}
        for kind in ("stdout","stderr"):
            filename=name+"."+kind;body=rc.read(directory/filename)
            rc.check(row[kind]==dict(file=filename,**rc.pin(body)),"complete owned control stream")
            rc.check(body==(rc.enc(report) if kind=="stdout" else b""),"exact actual complete control report and empty stderr")
            expected.add(filename)
        rc.check(set(rc.files(directory))==expected,"whole exact owned control process file set")
        rows[phase]=row
    rc.check(rows["owner"]["argv"][0]==rows["transport"]["argv"][0],"same actual Python implementation for new controls")
    return rows

def run(prior,output):
    original=prior/"source";capture=prior/"run/semantic";identity,owner,transport,transport_reader=execute.prepare(original)
    import read_only_guard,read_capture,read_callable_build
    def operation():
        rc.check(rc.source()==identity,"all new control source bytes inside guard")
        processes=process_custody(output)
        semantic=read_capture.verify(capture)
        own=owner.verify(output/"owner-controls",capture,capture/"build/modules/namespace-fingerprint/manifest.json")
        trans=transport_reader.verify(output/"transport-controls",capture,capture/"build")
        return dict(status="FINGERPRINT_SEMANTIC_AND_ABI_CONTROLS_PASS",semantic=semantic,owner_controls=own,
                    transport_controls=trans,control_processes=processes,control_source_sha256=identity,native_or_rust_executions=0,reader_writes=0)
    return read_only_guard.guarded(operation,roots=[capture,original,ROOT,output],
        foreign_path=str(prior.parent/"not-admitted/CAPTURE.json"))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--prior",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True);a=p.parse_args();result=run(a.prior.resolve(strict=True),a.output.resolve(strict=True))
    a.receipt.write_bytes(rc.enc(result))
    print(rc.enc({k:v for k,v in result.items() if k not in ("before","after")}).decode(),end="")
