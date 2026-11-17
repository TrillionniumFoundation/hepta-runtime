from pathlib import Path
import argparse,json,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import source_evidence,pin,require,encoded,decode
from process import Recorder
p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--manifest",required=True);a=p.parse_args()
require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.manifest,"frozen source-only binding")
identity=source_evidence(ROOT);a.output.mkdir(parents=True,exist_ok=False);rec=Recorder(ROOT,a.output/"processes")
try:
    raw,row=rec.run("source-input-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/check_source.py"],timeout=60)
    report=decode(raw);require(report["status"]=="INFO_SOURCE_AND_INPUT_ONLY_PASS","source and input gate")
    (a.output/"INPUT_DOMAIN.json").write_bytes(raw)
    (a.output/"GATE.json").write_bytes(encoded(dict(status="SOURCE_ONLY_PASS",source=identity,process=row,
        info_function_calls=0,hia_calls=0,rust_calls=0,fixture_effects=0)))
    require(source_evidence(ROOT)==identity,"source changed")
    print(encoded(dict(status="SOURCE_ONLY_PASS",observed=report["observed_inputs"],observer_off=report["observer_off_inputs"],
        groups=len(report["groups"]),process=row)).decode(),end="")
except BaseException as e:
    (a.output/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,processes=rec.records,
        type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),info_function_calls=0,hia_calls=0,rust_calls=0,fixture_effects=0)))
    if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
    raise
