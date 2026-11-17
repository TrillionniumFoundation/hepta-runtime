#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Complete immutable graph admission; no application execution."""
from pathlib import Path
import argparse,hashlib,json,stat,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def pin(p):
    v=Path(p).read_bytes();return dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest())
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    index=json.loads((HERE/"SOURCE_MANIFEST.json").read_bytes())
    files={x.relative_to(HERE).as_posix() for x in HERE.rglob("*") if x.is_file()}
    assert files=={r["path"] for r in index["files"]}|{"SOURCE_MANIFEST.json"}
    for r in index["files"]:
        target=HERE/r["path"];assert not target.is_symlink() and stat.S_IMODE(target.stat().st_mode)==0o644
        assert pin(target)=={k:r[k] for k in ("bytes","sha256")}
        if target.suffix==".py":compile(target.read_bytes(),str(target),"exec")
    info=json.loads((HERE/"BUILD_INPUT.json").read_bytes())
    command=[sys.executable,"-I","-S","-B",str(HERE/"build-reference/read_uploaded.py"),
        "--output",str(a.output),"--artifact",str(info["artifact"]),"--bytes",str(info["zip"]["bytes"]),"--sha256",info["zip"]["sha256"]]
    subprocess.run(command,check=True,timeout=180)
    assert pin(a.output/"extracted"/info["observed_binary"]["path"])=={k:info["observed_binary"][k] for k in ("bytes","sha256")}
    print(json.dumps(dict(status="COMPLETE_REAL_GRAPH_ADMITTED_FOR_NEW_PROBE",source=info["source"],native_or_rust_executed=False)))
if __name__=="__main__":main()
