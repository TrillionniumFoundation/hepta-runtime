#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Inspect only the complete retained first native case directory custody."""
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
    root,archive=restore(a.output/"native",dict(artifact=14339243128,
        zip=dict(bytes=4126054,sha256="3505b508966a12198c2235860c84186662f59628d64cf70a782da9e465880c1c"),
        archive=dict(bytes=4021796,sha256="53d1846429b20e2c52adaebf7e67d3415aa43ccd3a5a83a933b34daeb7fd5795")))
    def operation():
        n=root/"capture/native/cases/000";rows=[]
        for q in sorted(n.rglob("*")):
            rel=q.relative_to(n).as_posix();s=q.lstat()
            if rel.startswith(("buffers/","process/")):continue
            row=dict(path=rel,mode=stat.S_IMODE(s.st_mode),kind="directory" if stat.S_ISDIR(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "other")
            require(row["kind"]!="other","unexpected file type")
            if row["kind"]=="file":row["content"]=pin(q)
            rows.append(row)
        return dict(status="COMPLETE_RETAINED_CASE_FILESET_INSPECTED",rows=rows,archive=archive,semantic_replay=False)
    proof=readonly.guarded(operation,roots=[HERE,a.retained,root])
    (a.output/"READONLY.json").write_bytes(canonical(proof))
    print("CASE_TREE "+json.dumps(proof["evidence"],sort_keys=True),flush=True)
if __name__=="__main__":main()
