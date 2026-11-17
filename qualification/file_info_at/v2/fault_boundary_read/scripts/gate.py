#!/usr/bin/env python3
"""Pure full-byte admission of two original partial captures; no application replay."""
from pathlib import Path
import argparse,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import source_evidence,pin,require,encoded,decode
from process import Recorder
p=argparse.ArgumentParser();p.add_argument("stage",choices=("read","export"));p.add_argument("--work",type=Path,required=True)
p.add_argument("--group",required=True);p.add_argument("--manifest",required=True);p.add_argument("--output",type=Path)
a=p.parse_args();require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.manifest,"frozen partial-reader source")
identity=source_evidence(ROOT);capture=a.work/"capture"
if a.stage=="export":
    require(a.output is not None and not a.output.exists(),"fresh complete partial archive");a.output.mkdir(parents=True)
    rec=Recorder(ROOT,a.output/"processes")
    raw,row=rec.run("export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py","--capture",capture,
        "--archive",a.output/"evidence.tar.gz"],timeout=180)
    (a.output/"EXPORT.json").write_bytes(encoded(dict(archive=decode(raw),process=row)))
    print(raw.decode(),end="");raise SystemExit(0)
require(not a.work.exists(),"fresh pure read only");capture.mkdir(parents=True)
rec=Recorder(ROOT,capture/"processes");retained=capture/"retained";retained.mkdir()
try:
    raw,row=rec.run("source-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/check_source.py"],timeout=60)
    require(decode(raw)["status"]=="SOURCE_ONLY_PASS","pure source gate")
    for stage,limit in(("fetch",60),("unpack",180)):
        raw,row=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/restore_original.py",stage,
            "--source",ROOT,"--work",retained,"--group",a.group],timeout=limit)
        require(decode(raw)["status"]=="PASS","complete original fetch/unpack")
    raw,row=rec.run("full-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_main.py",
        "--source",ROOT,"--work",retained,"--group",a.group],timeout=180)
    guard=decode(raw);require(guard["evidence"]["status"]=="COMPLETE_INFO_PARTIAL_BOUNDARY_PASS"
        and guard["before"]==guard["after"]and len(guard["probes"])==11,"complete unchanged guarded partial reader")
    (capture/"READONLY.json").write_bytes(raw)
    result=dict(status="PASS",source=identity,group=a.group,processes=rec.records,evidence=guard["evidence"],
        original_applications_executed=0,native_applications_executed=0,first_failure_preserved=True)
    (capture/"GATE.json").write_bytes(encoded(result));require(source_evidence(ROOT)==identity,"frozen source changed")
    print(encoded(dict(status="PARTIAL_ORIGINAL_CAPTURE_FULL_READ_PASS",group=a.group,evidence=guard["evidence"],
        new_application_calls=0,guard_probes=11,guarded_entries=guard["entries"])).decode(),end="")
except BaseException as e:
    (capture/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,group=a.group,processes=rec.records,
        error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),new_application_calls=0)))
    if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
    raise
