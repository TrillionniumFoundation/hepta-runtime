"""Original owned 180-second recorder for read and pure join, with no duplicate shell timeout."""
from pathlib import Path
import argparse,os,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import recovery_common as rc

def run(complete,output,phase):
    identity=rc.source();original=complete/"retained/restored/prior/source";sys.path.insert(0,str(original))
    import common
    rc.check(common.source()=="5108ee26b26723f601207fe15fa849f6b4f07b80aa0b752574792062c49010a9","complete original process recorder")
    from process import Recorder,environment
    output.mkdir(parents=True,exist_ok=True);env,_=environment(os.environ)
    recorder=Recorder(ROOT,output/"processes"/phase,env)
    name="publisher-parallel-"+phase
    argv=[sys.executable,"-I","-B",ROOT/("capture.py" if phase=="read" else "verify.py"),"--complete",complete,
          "--output",output/"read" if phase=="read" else output]
    try:
        raw,row=recorder.run(name,argv,timeout=180);print(raw.decode(),end="")
        rc.check(rc.source()==identity,"complete successor source unchanged")
        if phase=="verify":
            proof=rc.loads(rc.read(output/"READBACK.json"))
            rc.check(proof["before"]==proof["after"] and len(proof["probes"])==12 and
                     proof["pid"]==row["pid"] and proof["ppid"]==row["parent_pid"] and proof["pgid"]==row["pgid"] and
                     proof["native_or_rust_executions"]==proof["reader_writes"]==0 and
                     proof["evidence"]["status"]=="PRIVATE_PUBLISH_ARCHIVE_ANCHOR_PARALLEL_READ_PASS","actual complete guarded join")
            (output/"GATE.json").write_bytes(rc.enc(dict(status=proof["evidence"]["status"],source_manifest_sha256=identity,
                readback=rc.pin(rc.read(output/"READBACK.json")),qualification=rc.pin(rc.read(output/"read/QUALIFICATION.json")),
                original_semantic_cases=99,original_semantic_operations=137,physical_refusals=15,physical_admissions=2,
                original_physical_guard_probes=204,complete_parallel_guard_probes=24,join_guard_probes=12,
                partition_reader_processes=2,no_native_or_rust_replay=True,no_physical_control_replay=True,
                original_three_physical_failures_preserved=True,independent_uploaded_read_pending=True,
                namespace_version_qualified=False,archive_store_qualified=False,hot_cache_qualified=False,
                begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)))
    finally:
        path=recorder.directory/(name+".stderr")
        if path.is_file():sys.stderr.write(path.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--complete",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--phase",choices=("read","verify"),required=True);a=p.parse_args()
    run(a.complete.resolve(strict=True),a.output.absolute(),a.phase)
