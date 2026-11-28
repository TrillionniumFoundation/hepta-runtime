"""Independent full uploaded fingerprint, actual controls and physical-refusal readback."""
from pathlib import Path
import argparse,math,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import final_common as fc

def prepare(restored):
    identity=fc.source();binding=fc.loads(fc.read(ROOT/"PINS.json"));archive=restored/"complete"
    frozen=archive/"source"
    fc.check(fc.pin(fc.read(frozen/"SOURCE.json"))==binding["source_manifests"]["source/SOURCE.json"],
             "whole exact immutable physical-reader source")
    sys.path.insert(0,str(frozen))
    import physical_common as pc,bundle,physical_controls,entry
    fc.check(pc.ROOT==frozen,"only exact retained physical-reader source")
    prepared=bundle.prepare(archive/"retained/restored/prior/source")
    return identity,binding,archive,pc,bundle,physical_controls,entry,prepared

def prior_process(archive,expected,pc,physical,entry):
    output=archive/"run";proof=pc.loads(pc.read(output/"READBACK.json"))
    physical.guarded_proof(proof,expected)
    rows=pc.loads(pc.read(output/"processes/verify/processes.json"))
    fc.check(type(rows)is list and len(rows)==1,"one whole prior guarded read process")
    row=rows[0];report=pc.loads(pc.read(output/"physical/CONTROLS.json"))
    old_source=report["source_root"];old_retained=report["retained_root"];old_out=report["output_root"].rsplit("/",1)[0]
    wanted=[expected["process"]["argv"][0],"-I","-B",old_source+"/entry.py","--retained",old_retained,"--output",old_out,"--phase","verify"]
    fc.check(row["name"]=="fingerprint-verify"and row["argv"]==wanted and row["cwd"]==old_source and row["stdin"]is None and
             type(row["timeout_seconds"])is int and row["timeout_seconds"]==180 and
             type(row["exit_code"])is int and row["exit_code"]==0 and row["completed"]is True and row["timed_out"]is False and
             type(row["elapsed_seconds"])in(int,float)and math.isfinite(row["elapsed_seconds"])and 0<row["elapsed_seconds"]<=180,
             "exact prior full read command, status and unchanged deadline")
    fc.check(all(type(row[k])is int and row[k]>1 for k in("pid","parent_pid","pgid"))and
             row["pid"]==row["pgid"]!=row["parent_pid"]and proof["pid"]==row["pid"]and
             proof["ppid"]==row["parent_pid"]and proof["pgid"]==row["pgid"],"actual prior reader PID chain")
    for kind in("stdout","stderr"):
        name="fingerprint-verify."+kind;raw=pc.read(output/"processes/verify"/name)
        fc.check(row[kind]==dict(file=name,**fc.pin(raw))and raw==
                 (fc.enc({k:v for k,v in proof.items()if k not in("before","after")})if kind=="stdout"else b""),
                 "complete prior read stdout and stderr")
    fc.check(set(pc.files(output/"processes/verify"))=={"processes.json","fingerprint-verify.stdout","fingerprint-verify.stderr"},
             "complete prior reader process files")
    gate=pc.loads(pc.read(output/"GATE.json"));value=expected["physical"]
    wanted_gate=dict(status=expected["status"],source_manifest_sha256=pc.source(),
        readback=fc.pin(pc.read(output/"READBACK.json")),admissions=2,physical_refusals=15,physical_guard_probes=204,
        owner_controls=value["baseline"]["owner_controls"],transport_controls=value["baseline"]["transport_controls"],
        complete_semantic_cases=72,complete_semantic_operations=156,ordinary_native_replayed=False,rust_replayed=False,
        independent_uploaded_read_pending=True,namespace_version_qualified=False,archive_store_qualified=False,hot_cache_qualified=False,
        begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    fc.check(fc.enc(gate)==fc.enc(wanted_gate),"entire retained physical qualification gate unchanged")
    return dict(process=row,proof=fc.pin(pc.read(output/"READBACK.json")),gate=fc.pin(pc.read(output/"GATE.json")))

def verify(restored):
    identity,binding,archive,pc,bundle,physical,entry,prepared=prepare(restored)
    def operation():
        fc.check(fc.source()==identity,"all final independent source bytes inside guard")
        process=entry.custody(archive/"run")
        value=physical.verify(archive/"retained",archive/"run/physical",prepared)
        expected=dict(status="PRIVATE_NAMESPACE_FINGERPRINT_QUALIFIED",physical=value,process=process,
            source_manifest_sha256=pc.source(),native_or_rust_executions=0,reader_writes=0,namespace_version_qualified=False,
            archive_store_qualified=False,hot_cache_qualified=False,begin_finish_caller_qualified=False,public_handler_qualified=False)
        prior=prior_process(archive,expected,pc,physical,entry)
        return dict(status="PRIVATE_NAMESPACE_FINGERPRINT_INDEPENDENTLY_QUALIFIED",source_manifest_sha256=identity,
            physical_reader_source_sha256=pc.source(),complete_qualification=expected,original_guarded_read=prior,archive_binding=binding,
            native_or_rust_executions=0,reader_writes=0,no_physical_control_replay=True,
            exact_public_error_rendering_qualified=False,namespace_watch_qualified=False,namespace_version_qualified=False,
            archive_store_qualified=False,hot_cache_qualified=False,begin_finish_caller_qualified=False,
            public_handler_qualified=False,whole_runtime_replaced=False)
    return prepared["guard"].guarded(operation,roots=[archive,ROOT],foreign_path="/original-producer-not-admitted/CAPTURE.json")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--restored",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();proof=verify(a.restored.resolve(strict=True));output=a.output.resolve(strict=True)
    (output/"FINAL_READBACK.json").write_bytes(fc.enc(proof))
    print(fc.enc({k:v for k,v in proof.items()if k not in("before","after")}).decode(),end="")
