#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Execute the eight unchanged direct-future inputs on the fixed private entry."""
from pathlib import Path
import argparse,json,os,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require
def tree(root):
    return {p.relative_to(root).as_posix():dict(pin(p),mode=p.stat().st_mode&0o777,
        mtime_ns=p.stat().st_mtime_ns) for p in sorted(root.rglob("*")) if p.is_file()}
def main():
    p=argparse.ArgumentParser();p.add_argument("--prepared",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--first",type=int,required=True);p.add_argument("--count",type=int,required=True)
    a=p.parse_args();require((a.first,a.count) in ((22,2),(24,2),(26,2),(28,2)),"all8 complete direct input partitions");a.output.mkdir(parents=True,exist_ok=False)
    prep=decode((a.prepared/"PREPARED.json").read_bytes());native=Path(prep["native"])
    for name in ("PREPARED.json","SOURCE_CHECK.json","DIRECT_BUILD_READ.json","PRIOR_PROCESS.json","prior.stdout","prior.stderr"):
        shutil.copyfile(a.prepared/name,a.output/name)
    for label,folder in (("build",a.prepared/"public-prepared/build"),("original",a.prepared/"public-prepared/original"),("direct-build",a.prepared/"direct-build")):
        saved=a.output/(label+"-archive");saved.mkdir()
        for name in ("READ.json","FILES.json","ARCHIVE.json"):
            shutil.copyfile(folder/name,saved/name)
    cmd=[sys.executable,"-I","-S","-B",str(HERE/"capture_direct.py"),"--binary",prep["binary"],
        "--original",prep["original"],"--output",str(native),"--first",str(a.first),"--count",str(a.count)]
    begin=time.monotonic();rc=None
    try:
        with (a.output/"capture.stdout").open("xb") as out,(a.output/"capture.stderr").open("xb") as err:
            rc=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=out,stderr=err).returncode
    finally:
        value=dict(command=cmd,exit_code=rc,elapsed=time.monotonic()-begin,outer_timeout_seconds=None,
            child_process_limit_seconds=180,child_exchange_limit_seconds=60,
            stdout=pin(a.output/"capture.stdout"),stderr=pin(a.output/"capture.stderr"))
        (a.output/"CAPTURE_PROCESS.json").write_bytes(canonical(value))
        if native.exists():
            before=tree(native);shutil.copytree(native,a.output/"native",copy_function=shutil.copy2)
            after=tree(a.output/"native");require(before==after==tree(native),"complete frozen capture-copy bytes/modes/mtime")
            (a.output/"CAPTURE_COPY.json").write_bytes(canonical(dict(source=str(native),files=before,
                complete_bytes=True,mode_mtime=True,original_retained=True)))
    if rc:sys.stderr.buffer.write((a.output/"capture.stderr").read_bytes())
    require(rc==0,"actual native first complete case failed")
    summary=dict(status="ACTUAL_NATIVE_DIRECT_PARTITION_CAPTURED",case_count=a.count,selected_first=a.first,
        public_total=22,direct_total=8,comparison_complete=False,full_async=False,full_sdk=False)
    (a.output/"SUMMARY.json").write_bytes(canonical(summary));print(json.dumps(summary,sort_keys=True))
if __name__=="__main__":main()
