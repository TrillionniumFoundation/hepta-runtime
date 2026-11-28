"""One owned pure 180-second verification process; no completed domain replay."""
import argparse,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import final_common as fc
from process import Recorder,environment
def run(restored,output):
    identity=fc.source();output.mkdir(parents=True,exist_ok=False)
    env,_=environment(os.environ);rec=Recorder(ROOT,output/"processes",env)
    try:
        raw,row=rec.run("watcher-engineering-read",[sys.executable,"-I","-B",ROOT/"verify.py",
            "--restored",restored,"--output",output],timeout=180)
        proof=fc.loads(fc.read(output/"READBACK.json"))
        fc.check(raw==fc.enc({k:v for k,v in proof.items()if k not in("before","after")})and
            fc.read(output/"processes/watcher-engineering-read.stderr")==b"","whole independent reader streams")
        fc.check(proof["before"]==proof["after"]and len(proof["probes"])==12 and
            proof["native_or_rust_executions"]==proof["reader_writes"]==0 and
            proof["pid"]==row["pid"]and proof["ppid"]==row["parent_pid"]and proof["pgid"]==row["pgid"],
            "complete unchanged physical domain and actual reader identity")
        result=dict(status=proof["evidence"]["status"],source_manifest_sha256=identity,
            readback=fc.pin(fc.read(output/"READBACK.json")),process=row,
            unchanged_physical_entries=len(proof["before"]),guard_probes=12,
            actual_original_native_probe=proof["evidence"]["probe"],
            native_or_rust_executions=0,no_kernel_probe_replay=True,historical_gate_failure_preserved=True,
            original_comparison_qualified=False,observer_off_qualified=False,complete_watcher_qualified=False,
            namespace_version_qualified=False,public_handler_qualified=False)
        fc.check(fc.source()==identity,"all new pure source unchanged")
        (output/"GATE.json").write_bytes(fc.enc(result))
        for name in("authoring/namespace_watcher_callable.S","native/namespace_watcher_callable.hepta",
            "native/namespace_watcher_callable.composition.json","authoring/namespace_watcher_callable.pseudo"):
            text=fc.read(restored/"complete/run/authored/generated"/name).decode()
            print("GENERATED_FILE_BEGIN "+name);print(text,end="");print("GENERATED_FILE_END "+name)
        print(fc.enc(result).decode(),end="")
    finally:
        error=output/"processes/watcher-engineering-read.stderr"
        if error.is_file():sys.stderr.write(error.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--restored",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    run(a.restored.resolve(strict=True),a.output.absolute())
