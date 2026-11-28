#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Record one bounded source authoring process and export every output byte."""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def pin(path):
    raw=path.read_bytes()
    return dict(bytes=len(raw),sha256=SHA(raw),mode=oct(stat.S_IMODE(path.stat().st_mode)))
def manifest(root):
    raw=(root/"SOURCE_MANIFEST.json").read_bytes()
    expected=json.loads(raw)["files"]
    actual={}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name!="SOURCE_MANIFEST.json":
            assert not path.is_symlink()
            actual[path.relative_to(root).as_posix()]=pin(path)
    assert actual==expected,"source bytes, modes or set changed"
    return SHA(raw)
def main():
    p=argparse.ArgumentParser()
    for key in ("source","hepta","output"):p.add_argument("--"+key,required=True,type=Path)
    p.add_argument("--manifest-sha256",required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    assert not out.exists();out.mkdir(parents=True)
    assert manifest(source)==a.manifest_sha256
    for path in source.rglob("*.py"):compile(path.read_bytes(),str(path),"exec")
    argv=[sys.executable,"-I","-S","-B",str(source/"authoring/author_binary_read_at.py"),
        "--source",str(source),"--hepta",str(hepta),"--output",str(out/"generated")]
    receipt=dict(schema="hepta.runtime.binary-read-at.author-process.v1",argv=argv,cwd=str(out),
        limit_seconds=60,source_manifest_sha256=a.manifest_sha256,
        native_execution=False,rust_execution=False,timeout=False,started_ns=time.monotonic_ns())
    with (out/"author.stdin").open("xb") as stream:stream.write(b"")
    with (out/"author.stdin").open("rb") as inp,(out/"author.stdout").open("xb") as stdout,(out/"author.stderr").open("xb") as stderr:
        child=subprocess.Popen(argv,cwd=out,stdin=inp,stdout=stdout,stderr=stderr,start_new_session=True)
        receipt["pid"]=child.pid
        try:receipt["returncode"]=child.wait(timeout=60)
        except subprocess.TimeoutExpired:
            receipt["timeout"]=True
            os.killpg(child.pid,signal.SIGKILL)
            receipt["returncode"]=child.wait()
    receipt["elapsed_ns"]=time.monotonic_ns()-receipt["started_ns"]
    receipt["source_after_sha256"]=manifest(source)
    receipt["streams"]={suffix:pin(out/("author."+suffix)) for suffix in ("stdin","stdout","stderr")}
    receipt["status"]="PASS" if receipt["returncode"]==0 and not receipt["timeout"] else "FAIL"
    (out/"AUTHOR_PROCESS.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print("AUTHOR_PROCESS "+json.dumps(receipt,sort_keys=True),flush=True)
    if receipt["status"]!="PASS":
        print((out/"author.stderr").read_text(),flush=True)
        raise SystemExit(1)
    assert (out/"author.stderr").read_bytes()==b""
    members={x.relative_to(out).as_posix():pin(x) for x in sorted(out.rglob("*")) if x.is_file()}
    (out/"OUTPUT_FILES.json").write_text(json.dumps(members,sort_keys=True,indent=2)+"\n")
    for name,row in members.items():
        raw=(out/name).read_bytes()
        encoded=base64.b64encode(raw).decode()
        pieces=[encoded[i:i+16384] for i in range(0,len(encoded),16384)] or [""]
        for index,piece in enumerate(pieces):
            print("AUTHOR_BYTES "+json.dumps(dict(path=name,index=index,count=len(pieces),
                bytes=len(raw),sha256=SHA(raw),data=piece),sort_keys=True),flush=True)
    print("AUTHOR_COMPLETE "+json.dumps(dict(files=len(members),members=members),sort_keys=True),flush=True)
if __name__=="__main__":main()
