#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Independently fetch, restore and fully read the completed uploaded capture."""
from pathlib import Path
import argparse,json,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from archive_reader import encode,decode,frozen,require
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    p.add_argument("--output",type=Path);a=p.parse_args();identity,binding=frozen(a.source_manifest_sha256);work=a.work.absolute()
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh proof export root")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"export.py",
            "--capture",work,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(encode(dict(status="PASS",archive=result,process=row)))
        print(json.dumps(result,sort_keys=True));return
    require(not work.exists(),"fresh independent uploaded-reader root");work.mkdir(parents=True);(work/"proof").mkdir()
    rec=Recorder(ROOT,work/"proof/processes")
    stage="fetch"
    try:
        outputs={}
        for stage,limit in(("fetch",60),("restore",180),("read",180),("controls",180),("verify",180)):
            raw,row=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"archive_reader.py",stage,
                "--work",work,"--source-manifest-sha256",a.source_manifest_sha256],timeout=limit)
            outputs[stage]=decode(raw)
        result=dict(status="PASS",stage="complete",source_manifest=identity,binding=binding,
            processes=rec.records,archive=outputs["restore"],read=outputs["read"],physical_controls=outputs["controls"],verification=outputs["verify"],
            original_producer_status="FAIL",all_application_execution_is_retained=True,
            application_hia_executions=0,rust_executions=0)
        (work/"proof/GATE.json").write_bytes(encode(result));print(encode(result).decode(),end="")
    except BaseException as error:
        (work/"proof/GATE.json").write_bytes(encode(dict(status="FAIL",stage=stage,source_manifest=identity,
            error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc(),
            processes=rec.records,application_hia_executions=0,rust_executions=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
