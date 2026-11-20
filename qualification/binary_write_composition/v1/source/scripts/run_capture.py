#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Own the complete capture process group with the frozen 1800 + 5 second bound."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import encoded,pin,require,source_evidence

SOURCE=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    identity=source_evidence(SOURCE)
    output=args.output.absolute();require(not output.exists(),"fresh owned whole-suite directory")
    output.mkdir(parents=True)
    command=[sys.executable,"-I","-S","-B",str(SOURCE/"scripts/parent_capture.py"),
             "--build",str(args.build.resolve(strict=True)),"--output",str(output/"capture")]
    began=time.monotonic_ns()
    record=dict(schema="hepta.runtime.binary-write-composition-owned-capture.v1",argv=command,source=identity,
        whole_capture_seconds=1800,cleanup_seconds=5,started_monotonic_ns=began,timeout=False,
        python=pin(Path(sys.executable).resolve()))
    with(output/"stdout.log").open("xb")as stdout,(output/"stderr.log").open("xb")as stderr:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
        record.update(pid=process.pid,pgid=os.getpgid(process.pid),parent_pgid=os.getpgrp())
        require(record["pgid"]==process.pid and record["pgid"]!=record["parent_pgid"],"owned separate process group")
        (output/"START.json").write_bytes(encoded(record))
        try:process.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            record["timeout"]=True
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait()
        finally:
            record.update(returncode=process.returncode,elapsed_ns=time.monotonic_ns()-began)
    try:os.killpg(process.pid,0)
    except ProcessLookupError:record["whole_group_gone"]=True
    else:
        record["whole_group_gone"]=False
        # Never grant success while an owned descendant survives its supervisor.
        os.killpg(process.pid,signal.SIGKILL)
    record["streams"]={name:pin(output/(name+".log"))for name in("stdout","stderr")}
    record["source_after"]=source_evidence(SOURCE)
    record["status"]="COMPLETE_NATURAL_CAPTURE"if(process.returncode==0 and not record["timeout"]
        and record["whole_group_gone"] and record["source_after"]==identity)else"HOLD"
    (output/"OWNED.json").write_bytes(encoded(record))
    print(encoded(record).decode(),end="")
    require(record["status"]=="COMPLETE_NATURAL_CAPTURE","complete fixed original capture did not finish")


if __name__=="__main__":main()
