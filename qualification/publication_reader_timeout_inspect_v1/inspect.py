#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read the complete retained source-only timeout without restarting it."""
from pathlib import Path
import argparse,json,os,stat,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser();p.add_argument("--retained",type=Path,required=True)
    p.add_argument("--build-recipe",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(a.retained));from common import canonical,decode,pin,require,source_evidence
    import readonly
    source_evidence(a.retained)
    for row in decode((HERE/"SOURCE_MANIFEST.json").read_bytes())["files"]:
        require(pin(HERE/row["path"])=={k:row[k] for k in ("bytes","sha256")},"exact inspector source")
    sys.path.insert(0,str(a.build_recipe/"current"));from restore_full import restore
    root,archive=restore(a.output/"native",dict(artifact=14343217746,
        zip=dict(bytes=131148,sha256="ce4852165f4240d974a537a69607e519fb18c881f0c2f9dbfb145d6dc8affac5"),
        archive=dict(bytes=117804,sha256="bbe8fa23963313f1ba4f68b66360d0dd08e3651dcc2dcc6bcdbbdd6039028c5a")))
    def operation():
        n=root/"capture";rows=[]
        for q in sorted(n.rglob("*")):
            rel=q.relative_to(n).as_posix();s=q.lstat()
            row=dict(path=rel,mode=stat.S_IMODE(s.st_mode),kind="directory" if stat.S_ISDIR(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "other")
            require(row["kind"]!="other","unexpected file type")
            if row["kind"]=="file":
                row["content"]=pin(q)
                if q.suffix in (".stderr",".stdout",".json"):row["text"]=q.read_text()
            rows.append(row)
        return dict(status="COMPLETE_RETAINED_PURE_READ_TIMEOUT_INSPECTED",rows=rows,archive=archive,semantic_replay=False)
    proof=readonly.guarded(operation,roots=[HERE,a.retained,root])
    (a.output/"READONLY.json").write_bytes(canonical(proof))
    print("TIMEOUT_DIAGNOSTIC "+json.dumps(proof["evidence"],sort_keys=True),flush=True)
if __name__=="__main__":main()
