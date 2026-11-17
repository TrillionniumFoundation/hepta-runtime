"""Owned process custody for only new controls and pure complete readback."""
from pathlib import Path
import argparse,os,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import control_common as rc
def run(prior,output,phase):
    identity=rc.source();original=prior/"source"
    sys.path.insert(0,str(original))
    import common
    rc.check(common.source()=="5108ee26b26723f601207fe15fa849f6b4f07b80aa0b752574792062c49010a9","exact producer before recorder")
    from process import Recorder,environment
    output.mkdir(parents=True,exist_ok=True);env,_=environment(os.environ);rec=Recorder(ROOT,output/"processes"/phase,env)
    if phase=="verify":
        command=[sys.executable,"-I","-B",ROOT/"verify_controls.py","--prior",prior,"--output",output,"--receipt",output/"READBACK.json"]
        budget=180
    else:
        command=[sys.executable,"-I","-B",ROOT/"execute.py","--prior",prior,"--output",output/(phase+"-controls"),"--phase",phase]
        budget=60
    try:
        raw,row=rec.run("publisher-"+phase,command,timeout=budget)
        print(raw.decode(),end="");rc.check(rc.source()==identity,"whole new control source unchanged")
        if phase=="verify":
            proof=rc.loads(rc.read(output/"READBACK.json"));e=proof["evidence"]
            rc.check(proof["before"]==proof["after"] and len(proof["probes"])==12 and e["status"]=="PUBLISHER_SEMANTIC_AND_ABI_CONTROLS_PASS","full guarded control readback")
            (output/"GATE.json").write_bytes(rc.enc(dict(status=e["status"],control_source_sha256=identity,
                original_source_sha256=e["semantic"]["source_manifest_sha256"],owner=e["owner_controls"],transport=e["transport_controls"],
                readback=rc.pin(rc.read(output/"READBACK.json")),new_native_abi_controls=True,ordinary_native_replayed=False,
                rust_replayed=False,physical_reader_controls_pending=True,public_handler_qualified=False)))
    finally:
        error=rec.directory/("publisher-"+phase+".stderr")
        if error.is_file():sys.stderr.write(error.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--prior",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--phase",choices=("owner","transport","verify"),required=True);a=p.parse_args()
    run(a.prior.resolve(strict=True),a.output.absolute(),a.phase)
