"""Actual independent 180-second final reader; all prior semantic processes are retained only."""
from pathlib import Path
import argparse,os,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import final_common as fc

def run(restored,output):
    identity=fc.source();original=restored/"complete/prior/retained/restored/prior/source"
    sys.path.insert(0,str(original))
    import common
    fc.check(common.source()=="5108ee26b26723f601207fe15fa849f6b4f07b80aa0b752574792062c49010a9","whole unchanged actual recorder")
    from process import Recorder,environment
    env,_=environment(os.environ);rec=Recorder(ROOT,output/"processes/final",env)
    try:
        raw,row=rec.run("independent-publisher-final",[sys.executable,"-I","-B",ROOT/"verify_final.py",
                "--restored",restored,"--output",output],timeout=180)
        proof=fc.loads(fc.read(output/"FINAL_READBACK.json"))
        stderr=fc.read(rec.directory/"independent-publisher-final.stderr")
        fc.check(raw==fc.enc({k:v for k,v in proof.items() if k not in ("before","after")}) and stderr==b"" and
                 row["stdout"]==dict(file="independent-publisher-final.stdout",**fc.pin(raw)) and
                 row["stderr"]==dict(file="independent-publisher-final.stderr",**fc.pin(stderr)),
                 "complete actual final process stdout and stderr")
        fc.check(proof["before"]==proof["after"] and len(proof["probes"])==12 and
                 proof["native_or_rust_executions"]==proof["reader_writes"]==0 and
                 proof["pid"]==row["pid"] and proof["ppid"]==row["parent_pid"] and proof["pgid"]==row["pgid"] and
                 proof["evidence"]["status"]=="PRIVATE_PUBLISH_ARCHIVE_ANCHOR_INDEPENDENTLY_QUALIFIED",
                 "complete independent final guard and actual process")
        fc.check(fc.source()==identity,"complete final source unchanged")
        result=dict(status=proof["evidence"]["status"],source_manifest_sha256=identity,process=row,
                    readback=fc.pin(fc.read(output/"FINAL_READBACK.json")),unchanged_physical_entries=len(proof["before"]),
                    original_semantic_cases=99,original_semantic_operations=137,physical_refusals=15,physical_admissions=2,
                    owner_checkpoints=55,owner_calls=3606,owner_refusals=3496,owner_replays=110,
                    transport_groups=45,transport_calls=180,independent_partition_guard_probes=24,final_guard_probes=12,
                    native_or_rust_executions=0,no_physical_control_replay=True,independent_uploaded_read_pending=False,
                    namespace_version_qualified=False,archive_store_qualified=False,hot_cache_qualified=False,
                    begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
        (output/"GATE.json").write_bytes(fc.enc(result));print(fc.enc(result).decode(),end="")
    finally:
        error=rec.directory/"independent-publisher-final.stderr"
        if error.is_file():sys.stderr.write(error.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--restored",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.restored.resolve(strict=True),a.output.resolve(strict=True))
