"""Owned pure-control processes, no native/Rust replay."""
from pathlib import Path
import argparse,os,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import physical_common as pc
def run(retained,output,phase):
    identity=pc.source();original=retained/"restored/prior/source";sys.path.insert(0,str(original))
    import common
    pc.check(common.source()=="682909fbec91ce42d145ebe8ee55c6943d385f1113b9ad25f03d9c3f694bf320","whole retained producer before recorder")
    from process import Recorder,environment
    output.mkdir(parents=True,exist_ok=True);env,_=environment(os.environ);rec=Recorder(ROOT,output/"processes"/phase,env)
    try:
        raw,row=rec.run("fingerprint-"+phase,[sys.executable,"-I","-B",ROOT/"entry.py","--retained",retained,"--output",output,"--phase",phase],timeout=180)
        print(raw.decode(),end="");pc.check(pc.source()==identity,"whole frozen physical-control source stable")
        if phase=="verify":
            proof=pc.loads(pc.read(output/"READBACK.json"));e=proof["evidence"]
            pc.check(proof["before"]==proof["after"] and len(proof["probes"])==12 and
                     e["status"]=="PRIVATE_NAMESPACE_FINGERPRINT_QUALIFIED","whole final guarded physical read")
            (output/"GATE.json").write_bytes(pc.enc(dict(status=e["status"],source_manifest_sha256=identity,
                readback=pc.pin(pc.read(output/"READBACK.json")),admissions=2,physical_refusals=15,physical_guard_probes=204,
                owner_controls=e["physical"]["baseline"]["owner_controls"],transport_controls=e["physical"]["baseline"]["transport_controls"],
                complete_semantic_cases=72,complete_semantic_operations=156,ordinary_native_replayed=False,rust_replayed=False,
                independent_uploaded_read_pending=True,namespace_version_qualified=False,archive_store_qualified=False,hot_cache_qualified=False,
                begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)))
    finally:
        error=rec.directory/("fingerprint-"+phase+".stderr")
        if error.is_file():sys.stderr.write(error.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--retained",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--phase",choices=("physical","verify"),required=True);a=p.parse_args();run(a.retained.resolve(strict=True),a.output.absolute(),a.phase)
