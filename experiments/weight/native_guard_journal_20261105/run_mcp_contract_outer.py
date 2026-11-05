#!/usr/bin/env python3
"""Measure complete owned MCP qualification process using Linux wait4."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time


def file_sha(path):
    value=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser=argparse.ArgumentParser()
    for name in ["driver","protocol","outer-protocol","binary","output"]:
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--binary-sha256",required=True)
    parser.add_argument("--outer-protocol-sha256",required=True)
    args=parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    assert file_sha(args.outer_protocol)==args.outer_protocol_sha256
    protocol=json.loads(args.outer_protocol.read_text())
    assert protocol["schema"]=="hepta.guard-journal-mcp-outer-protocol.v1"
    assert protocol["observed_wall_timeout_seconds"]==240
    assert protocol["wait_poll_interval_seconds"]==.02
    assert file_sha(args.driver)==protocol["inner_driver_sha256"]
    assert file_sha(args.protocol)==protocol["inner_protocol_sha256"]
    assert file_sha(args.binary)==args.binary_sha256
    receipt={"schema":"hepta.guard-journal-complete-process-mcp-receipt.v1",
        "started_utc":datetime.now(timezone.utc).isoformat(),
        "outer_source_sha256":file_sha(Path(__file__)),"outer_protocol_sha256":args.outer_protocol_sha256,
        "driver_sha256":protocol["inner_driver_sha256"],"inner_protocol_sha256":protocol["inner_protocol_sha256"],
        "python_version":sys.version,
        "qualified_binary_sha256":args.binary_sha256,"passed":False,"timed_out":False,
        "source_bindings_checked_before_launch":True,"whole_driver_process_waited":False,
        "internal_timers_overlap_wait4_do_not_add":True,
        "cost_scope":"Complete owned driver and its waited-for MCP child; imports, final saves and exit included",
        "cost_excludes":protocol["excludes"]}
    command=[sys.executable,"-B",str(args.driver.resolve()),"--binary",str(args.binary.resolve()),
        "--binary-sha256",args.binary_sha256,"--work-dir",str((args.output/"private-work").resolve()),
        "--output",str((args.output/"mcp_receipt.json").resolve()),"--protocol",str(args.protocol.resolve()),
        "--protocol-sha256",protocol["inner_protocol_sha256"]]

    def limits():
        for name,cap in [(resource.RLIMIT_AS,protocol["per_process_address_space_limit_bytes"]),
                         (resource.RLIMIT_NOFILE,protocol["nofile_limit"])]:
            _,hard=resource.getrlimit(name)
            cap=cap if hard==resource.RLIM_INFINITY else min(cap,hard)
            resource.setrlimit(name,(cap,cap))

    wall=time.perf_counter()
    with (args.output/"private_driver_stdout.log").open("xb") as out,(args.output/"private_driver_stderr.log").open("xb") as err:
        process=subprocess.Popen(command,stdout=out,stderr=err,start_new_session=True,preexec_fn=limits)
        deadline=wall+protocol["observed_wall_timeout_seconds"]
        while True:
            pid,status,usage=os.wait4(process.pid,os.WNOHANG)
            if pid:
                break
            if time.perf_counter()>=deadline:
                receipt["timed_out"]=True
                os.killpg(process.pid,signal.SIGTERM)
                grace=time.perf_counter()+5
                while True:
                    pid,status,usage=os.wait4(process.pid,os.WNOHANG)
                    if pid:
                        break
                    if time.perf_counter()>=grace:
                        os.killpg(process.pid,signal.SIGKILL)
                        pid,status,usage=os.wait4(process.pid,0)
                        break
                    time.sleep(.02)
                break
            time.sleep(.02)
        process.returncode=os.waitstatus_to_exitcode(status)
    receipt.update(whole_driver_process_waited=True,exit_code=process.returncode,
        observed_complete_driver_wall_seconds=time.perf_counter()-wall,
        wait4_user_cpu_seconds=usage.ru_utime,wait4_system_cpu_seconds=usage.ru_stime,
        wait4_total_cpu_seconds=usage.ru_utime+usage.ru_stime,
        wait4_max_rss_kib=usage.ru_maxrss,wait4_max_rss_is_aggregate_concurrent_rss=False)
    receipt["source_bindings_unchanged_after_exit"]=(file_sha(args.driver)==protocol["inner_driver_sha256"]
        and file_sha(args.protocol)==protocol["inner_protocol_sha256"]
        and file_sha(args.outer_protocol)==args.outer_protocol_sha256)
    inner_path=args.output/"mcp_receipt.json"
    receipt["runtime_descendant_accounting_confirmed_complete"]=False
    if inner_path.exists():
        inner=json.loads(inner_path.read_text())
        receipt["inner_receipt_sha256"]=file_sha(inner_path)
        receipt["inner_passed"]=inner["passed"]
        receipt["actual_tools_call_count"]=inner["tools_call_count"]
        receipt["runtime_descendant_accounting_confirmed_complete"]=(
            process.returncode>=0 and "finished_utc" in inner and not receipt["timed_out"])
        receipt["passed"]=(process.returncode==0 and inner["passed"] and not receipt["timed_out"]
            and receipt["source_bindings_unchanged_after_exit"])
    receipt["private_stdout_sha256"]=file_sha(args.output/"private_driver_stdout.log")
    receipt["private_stderr_sha256"]=file_sha(args.output/"private_driver_stderr.log")
    receipt["finished_utc"]=datetime.now(timezone.utc).isoformat()
    (args.output/"outer_receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,sort_keys=True))
    return 0 if receipt["passed"] else 2


if __name__=="__main__":
    raise SystemExit(main())
