"""Bounded owned pure-reader process; no producer, compiler or native mapping."""
from pathlib import Path
import argparse,os,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import reader_common as rc
def run(prior,output):
    identity=rc.source();original=prior/"source";capture=prior/"run/semantic"
    sys.path.insert(0,str(original))
    import common
    rc.check(common.source()=="682909fbec91ce42d145ebe8ee55c6943d385f1113b9ad25f03d9c3f694bf320","exact original source before owned process recorder")
    from process import Recorder,environment
    output.mkdir(parents=True,exist_ok=False);env,_=environment(os.environ);rec=Recorder(ROOT,output/"processes",env)
    try:
        raw,row=rec.run("pure-semantic",[sys.executable,"-I","-B",ROOT/"reader.py","--original-source",original,"--capture",capture,"--receipt",output/"READBACK.json"],timeout=180)
        print(raw.decode(),end="")
        proof=rc.loads(rc.read(output/"READBACK.json"));result=proof["evidence"]["complete_evidence"]
        rc.check(proof["before"]==proof["after"] and len(proof["probes"])==12 and result["status"]=="PASS" and
                 result["cases"]==72 and result["operations"]==156,"whole semantic reader and fixed guard")
        gate=dict(status="SEMANTIC_READBACK_PASS_CONTROLS_PENDING",reader_source_sha256=identity,
            original_source_sha256=result["source_manifest_sha256"],readback=rc.pin(rc.read(output/"READBACK.json")),
            original_producer_status="PRODUCERS_PASS_READBACK_PENDING",cases=72,operations=156,
            process=row,native_executions=0,rust_executions=0,private_abi_controls_pending=True,physical_reader_controls_pending=True,
            namespace_version_qualified=False,hot_cache_qualified=False,begin_finish_caller_qualified=False,public_handler_qualified=False)
        (output/"GATE.json").write_bytes(rc.enc(gate));rc.check(rc.source()==identity,"stable reader source")
    finally:
        error=rec.directory/"pure-semantic.stderr"
        if error.is_file():sys.stderr.write(error.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--prior",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    run(a.prior.resolve(strict=True),a.output.absolute())
