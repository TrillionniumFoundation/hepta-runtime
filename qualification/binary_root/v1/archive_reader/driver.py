"""Bounded custody for the complete installed binary root archive read."""
from pathlib import Path
import argparse
import json
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import archive_reader
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","read"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();identity=archive_reader.identity(a.source_manifest_sha256)
    work=a.work.absolute();work.mkdir(parents=True,exist_ok=True);proof=work/"proof";proof.mkdir(exist_ok=True)
    rec=Recorder(ROOT,proof/(a.stage+"-processes"))
    try:
        raw,row=rec.run(a.stage,[sys.executable,"-I","-S","-B",ROOT/"archive_reader.py",a.stage,
            "--work",work,"--source-manifest-sha256",identity],timeout=60 if a.stage=="fetch" else 180)
        result=archive_reader.decode(raw);archive_reader.require(result["status"]=="PASS","independent archive stage failed")
        (proof/(a.stage.upper()+"_PROCESS.json")).write_bytes(archive_reader.encoded(dict(status="PASS",
            process=row,source_manifest_sha256=identity,native_or_rust_executions=0)))
        selected={k:result[k] for k in ("status","zip","tar","original_cases","native_calls","boundary_controls",
            "physical_reader_refusals","complete_relocations","retained_guard_probes","independent_guard_probes",
            "full_native_buffer_record_bytes","native_or_rust_executions") if k in result}
        print(json.dumps(dict(stage=a.stage,elapsed_seconds=row["elapsed_seconds"],**selected),sort_keys=True))
    except BaseException:
        if rec.records:print((rec.directory/(a.stage+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
