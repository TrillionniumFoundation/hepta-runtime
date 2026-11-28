# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import argparse,stat,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,source_evidence
import prior_archive,build_reuse
def paths(capture):
    base=Path(capture)/"prior/original/restored"
    return base,base/"source",base/"run/capture"
def prepare(capture):
    _,_,old=paths(capture);build_reuse.prepare_imports(old/"build-reuse")
def verify(source,capture):
    source,capture=Path(source),Path(capture);base,oldsource,old=paths(capture);binding=prior_archive.bound(source)
    manifest=decode((capture/"prior/original/ARTIFACT_MANIFEST.json").read_bytes())
    actual={p.relative_to(base).as_posix():prior_archive.identity(p)for p in base.rglob("*")if p.is_file()}
    dirs={p.relative_to(base).as_posix():stat.S_IMODE(p.stat().st_mode)for p in base.rglob("*")if p.is_dir()}
    require(actual=={n:{k:r[k]for k in("bytes","sha256","mode")}for n,r in manifest["files"].items()}
        and dirs==manifest["directories"],"complete retained failed archive changed")
    require(pin(capture/"prior/download/complete.zip")=={k:binding["artifact"][k]for k in("bytes","sha256")}
        and pin(oldsource/"SOURCE_MANIFEST.json")["sha256"]==binding["manifest_sha256"],"prior complete ZIP/source binding")
    old_identity=source_evidence(oldsource);require(source_evidence(old/"source")==old_identity,"old source copies differ")
    gate=decode((base/"run/GATE.json").read_bytes())
    require(gate["status"]=="FAIL"and gate["stage"]=="original-g06","prior failure boundary changed")
    rows=decode((old/"processes/processes.json").read_bytes());expected=["fetch-build","restore-build","read-build","setup"]
    for i in range(6):expected.extend(["original-g"+str(i).zfill(2),"native-g"+str(i).zfill(2)])
    expected.append("original-g06")
    require([r["name"]for r in rows]==expected and all(r["completed"]and not r["timed_out"]for r in rows)
        and all(r["exit_code"]==0 for r in rows[:-1])and rows[-1]["exit_code"]==1,"known prior actual process result")
    for row in rows:
        for key in("stdout","stderr"):
            require(pin(old/"processes"/row[key]["file"])=={k:row[key][k]for k in("bytes","sha256")},"complete retained process output")
    failed=old/"original/g06"
    require(all((failed/name).read_bytes()==b""for name in("original.stdin","original.stdout","exchanges.jsonl"))
        and not(failed/"CAPTURE.json").exists(),"failed group sent application input")
    require(not(old/"native/g06").exists()and not(old/"original/g07").exists()and not(old/"native/unobserved").exists(),
        "remaining domain was already executed")
    build=build_reuse.verify(source,old/"build-reuse")
    return dict(status="COMPLETE_PRIOR_CAPTURE_READ_PASS",binding=binding,files=len(actual),
        logical_bytes=sum(r["bytes"]for r in actual.values()),source=old_identity,build=build,
        retained_completed_pairs=42,failed_group_application_requests=0,application_executions=0)
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--capture",type=Path,required=True)
    a=p.parse_args();prepare(a.capture)
    from readonly import guarded
    result=guarded(lambda:verify(a.source,a.capture),roots=[a.source,a.capture/"prior"])
    print(canonical(result).decode(),end="")
