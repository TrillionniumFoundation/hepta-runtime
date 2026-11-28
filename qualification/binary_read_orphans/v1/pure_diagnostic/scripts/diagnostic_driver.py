#!/usr/bin/env python3
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);p.add_argument("--manifest",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.manifest,"frozen diagnostic source")
    before=source_evidence(ROOT);work=a.work.absolute();work.mkdir(parents=True);semantic=work/"semantic";semantic.mkdir()
    rec=Recorder(ROOT,work/"processes")
    for stage,limit in(("fetch",60),("unpack",180),("admit",180)):
        raw,row=rec.run("original-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/restore_original.py",stage,
            "--source",ROOT,"--work",semantic,"--group",a.group],timeout=limit)
    raw,row=rec.run("complete-diagnostic",[sys.executable,"-I","-S","-B",ROOT/"scripts/diagnose.py",
        "--semantic",semantic,"--group",a.group],timeout=180)
    value=decode(raw);(work/"DIAGNOSTIC.json").write_bytes(raw)
    require(value["before"]==value["after"]and len(value["probes"])==11,"complete unchanged diagnostic guard")
    require(source_evidence(ROOT)==before,"diagnostic source changed")
    report=dict(status="READ_ONLY_DIAGNOSTIC_PASS",group=a.group,source=before,applications_executed=0,
        comparisons=[{k:v for k,v in x.items()if k not in("original_effects","native_effects","original_projected","native_projected")}
            for x in value["evidence"]["comparisons"]])
    (work/"RESULT.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
if __name__=="__main__":main()
