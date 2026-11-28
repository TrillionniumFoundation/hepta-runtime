"""Independent complete uploaded evidence and repeated pure-reader custody."""
from pathlib import Path
import argparse,hashlib,math,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import final_common as fc

def prepare(restored):
    identity=fc.source();binding=fc.loads(fc.read(ROOT/"PINS.json"));archive=restored/"complete"
    frozen=archive/"source"
    fc.check(fc.pin(fc.read(frozen/"SOURCE.json"))==binding["source_manifests"]["source/SOURCE.json"],
             "entire immutable uploaded recovery source")
    sys.path.insert(0,str(frozen))
    import recovery_common as rc,read_adapter,read_join
    fc.check(rc.ROOT==frozen,"only exact admitted frozen recovery source")
    prepared=read_adapter.prepare(archive/"prior")
    return identity,binding,archive,rc,read_adapter,read_join,prepared

def original_verify_process(output,qualification,rc,physical,join):
    proof=rc.loads(rc.read(output/"READBACK.json"))
    expected=dict(status="PRIVATE_PUBLISH_ARCHIVE_ANCHOR_PARALLEL_READ_PASS",qualification=qualification,
                  process=None,source_manifest_sha256=rc.source(),native_or_rust_executions=0,reader_writes=0,
                  namespace_version_qualified=False,archive_store_qualified=False,hot_cache_qualified=False,
                  begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    expected["process"]=join.custody(output,qualification)
    physical.guarded_proof(proof,expected)
    rows=rc.loads(rc.read(output/"processes/verify/processes.json"));fc.check(len(rows)==1,"one original guarded join process")
    row=rows[0];parent=qualification["parent"]
    fc.check(row["name"]=="publisher-parallel-verify" and row["argv"]==
       [expected["process"]["argv"][0],"-I","-B",parent["source_root"]+"/verify.py","--complete",parent["complete_root"],
        "--output",parent["output_root"].rsplit("/",1)[0]] and row["cwd"]==parent["source_root"] and row["stdin"] is None and
        type(row["exit_code"]) is int and row["exit_code"]==0 and row["completed"] is True and row["timed_out"] is False and
        type(row["timeout_seconds"]) is int and row["timeout_seconds"]==180 and type(row["elapsed_seconds"]) in (int,float) and
        math.isfinite(row["elapsed_seconds"]) and 0<row["elapsed_seconds"]<=180,"actual prior guarded join and original deadline")
    fc.check(all(type(row[k]) is int and row[k]>1 for k in ("pid","parent_pid","pgid")) and
             row["pid"]==row["pgid"]!=row["parent_pid"] and proof["pid"]==row["pid"] and proof["ppid"]==row["parent_pid"] and
             proof["pgid"]==row["pgid"],"original actual join PID chain")
    for kind in ("stdout","stderr"):
        name="publisher-parallel-verify."+kind;raw=rc.read(output/"processes/verify"/name)
        fc.check(row[kind]==dict(file=name,**fc.pin(raw)) and raw==
                 (fc.enc({k:v for k,v in proof.items() if k not in ("before","after")}) if kind=="stdout" else b""),
                 "whole original guarded join streams")
    fc.check(set(rc.files(output/"processes/verify"))=={"processes.json","publisher-parallel-verify.stdout","publisher-parallel-verify.stderr"},
             "entire original join process directory")
    gate=rc.loads(rc.read(output/"GATE.json"))
    wanted=dict(status=expected["status"],source_manifest_sha256=rc.source(),
        readback=fc.pin(rc.read(output/"READBACK.json")),qualification=fc.pin(rc.read(output/"read/QUALIFICATION.json")),
        original_semantic_cases=99,original_semantic_operations=137,physical_refusals=15,physical_admissions=2,
        original_physical_guard_probes=204,complete_parallel_guard_probes=24,join_guard_probes=12,
        partition_reader_processes=2,no_native_or_rust_replay=True,no_physical_control_replay=True,
        original_three_physical_failures_preserved=True,independent_uploaded_read_pending=True,
        namespace_version_qualified=False,archive_store_qualified=False,hot_cache_qualified=False,
        begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    fc.check(gate==wanted,"entire original partial qualification gate preserved")
    return dict(process=row,proof=fc.pin(rc.read(output/"READBACK.json")),gate=fc.pin(rc.read(output/"GATE.json")))

def verify(restored,output):
    identity,binding,archive,rc,adapter,join,prepared=prepare(restored)
    def operation():
        fc.check(fc.source()==identity,"every independent source byte inside guard")
        old=join.verify(archive/"prior",archive/"run/read",prepared)
        fc.check(old==rc.loads(rc.read(archive/"run/read/QUALIFICATION.json")),"original complete parallel result reproduced")
        prior=original_verify_process(archive/"run",old,rc,prepared["physical"],join)
        current=join.verify(archive/"prior",output/"read",prepared)
        fc.check(current==rc.loads(rc.read(output/"read/QUALIFICATION.json")),"independent complete parallel result reproduced")
        current_process=join.custody(output,current)
        ignored={"parent","workers"}
        fc.check({k:v for k,v in old.items() if k not in ignored}==
                 {k:v for k,v in current.items() if k not in ignored},
                 "every original qualification value identical after independent relocation and pure re-read")
        return dict(status="PRIVATE_PUBLISH_ARCHIVE_ANCHOR_INDEPENDENTLY_QUALIFIED",
                    source_manifest_sha256=identity,retained_reader_source_sha256=rc.source(),
                    original_qualification=old,independent_qualification=current,
                    original_guarded_join=prior,independent_parent_process=current_process,
                    archive_binding=binding,native_or_rust_executions=0,reader_writes=0,
                    no_physical_control_replay=True,namespace_version_qualified=False,archive_store_qualified=False,
                    hot_cache_qualified=False,begin_finish_caller_qualified=False,public_handler_qualified=False,
                    whole_runtime_replaced=False)
    return prepared["old"]["guard"].guarded(operation,roots=[archive,output,ROOT],
                 foreign_path="/original-producer-not-admitted/CAPTURE.json")

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--restored",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();output=a.output.resolve(strict=True);proof=verify(a.restored.resolve(strict=True),output)
    (output/"FINAL_READBACK.json").write_bytes(fc.enc(proof))
    print(fc.enc({k:v for k,v in proof.items() if k not in ("before","after")}).decode(),end="")
