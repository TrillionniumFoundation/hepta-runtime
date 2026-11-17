"""Explicit new physical controls and pure existing-evidence verification."""
from pathlib import Path
import argparse,sys,math
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import physical_common as pc
import bundle,physical_controls

def custody(output):
    report=pc.loads(pc.read(output/"physical/CONTROLS.json"))
    rows=pc.loads(pc.read(output/"processes/physical/processes.json"));pc.check(len(rows)==1,"one actual physical-control process")
    row=rows[0];old_source=report["source_root"];old_retained=report["retained_root"];old_output=report["output_root"]
    pc.check(row["name"]=="fingerprint-physical" and row["cwd"]==old_source and
             len(row["argv"])==10 and row["argv"][0].startswith("/") and
             row["argv"][1:]==["-I","-B",old_source+"/entry.py","--retained",old_retained,"--output",old_output.rsplit("/",1)[0],"--phase","physical"] and
             row["stdin"] is None and type(row["exit_code"]) is int and row["exit_code"]==0 and
             row["completed"] is True and row["timed_out"] is False and type(row["timeout_seconds"]) is int and row["timeout_seconds"]==180 and
             type(row["elapsed_seconds"]) in (int,float) and math.isfinite(row["elapsed_seconds"]) and 0<row["elapsed_seconds"]<=180,
             "complete bounded actual physical-control process")
    pc.check(all(type(row[k]) is int and row[k]>1 for k in ("pid","parent_pid","pgid")) and row["pid"]==row["pgid"]!=row["parent_pid"] and
             all(type(report[k]) is int and report[k]==row[k] for k in ("pid","parent_pid","pgid")),"actual physical-control PID custody")
    for kind in ("stdout","stderr"):
        name="fingerprint-physical."+kind;raw=pc.read(output/"processes/physical"/name)
        pc.check(row[kind]==dict(file=name,**pc.pin(raw)) and raw==(pc.enc(physical_controls.summary(output/"physical",report)) if kind=="stdout" else b""),
                 "complete actual physical-control streams")
    pc.check(set(pc.files(output/"processes/physical"))=={"processes.json","fingerprint-physical.stdout","fingerprint-physical.stderr"},"entire physical process file set")
    return row

def verify(retained,output):
    prepared=bundle.prepare(retained/"restored/prior/source")
    def operation():
        pc.check(pc.source()==prepared["identity"],"all current source inside strict guard")
        process=custody(output);value=physical_controls.verify(retained,output/"physical",prepared)
        return dict(status="PRIVATE_NAMESPACE_FINGERPRINT_QUALIFIED",physical=value,process=process,source_manifest_sha256=prepared["identity"],
                    native_or_rust_executions=0,reader_writes=0,namespace_version_qualified=False,
                    archive_store_qualified=False,hot_cache_qualified=False,begin_finish_caller_qualified=False,public_handler_qualified=False)
    return prepared["guard"].guarded(operation,roots=[retained,output,ROOT],foreign_path="/not-admitted-original-producer/CAPTURE.json")

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--retained",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--phase",choices=("physical","verify"),required=True);a=p.parse_args();retained=a.retained.resolve(strict=True);output=a.output.absolute()
    if a.phase=="physical":result=physical_controls.run(retained,output/"physical");print(pc.enc(result).decode(),end="")
    else:
        result=verify(retained,output)
        (output/"READBACK.json").write_bytes(pc.enc(result))
        print(pc.enc({k:v for k,v in result.items() if k not in ("before","after")}).decode(),end="")
