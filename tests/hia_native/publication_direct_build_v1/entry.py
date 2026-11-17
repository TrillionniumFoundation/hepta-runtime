#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Original 180-second budget for pure admission and read, with full process receipt."""
from pathlib import Path
import argparse,json,subprocess,sys,time
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("prepare","read","uploaded"))
    p.add_argument("--receipt",type=Path,required=True);a,rest=p.parse_known_args()
    a.receipt.mkdir(parents=True,exist_ok=False)
    argv=[sys.executable,"-I","-S","-B",str(HERE/(a.mode+".py")),*rest]
    start=time.monotonic();record=dict(argv=argv,timeout_seconds=180,exit_code=None,timed_out=False,application_executed=False)
    try:
        with (a.receipt/"stdout").open("xb") as stdout,(a.receipt/"stderr").open("xb") as stderr:
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=180)
        record["exit_code"]=result.returncode
    except subprocess.TimeoutExpired:
        record["timed_out"]=True;raise
    finally:
        record["elapsed_seconds"]=time.monotonic()-start
        (a.receipt/"PROCESS.json").write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
        sys.stdout.buffer.write((a.receipt/"stdout").read_bytes());sys.stderr.buffer.write((a.receipt/"stderr").read_bytes())
    if record["exit_code"]!=0:raise SystemExit(record["exit_code"])
if __name__=="__main__":main()
