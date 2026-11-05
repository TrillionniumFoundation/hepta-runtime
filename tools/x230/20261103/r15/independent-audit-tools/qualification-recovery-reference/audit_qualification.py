#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reuse the R13 qualification audit against frozen R14 raw evidence; no execution."""
import collections,datetime,hashlib,json,os
from pathlib import Path
ROOT=Path("/home/qian/hepta-runtime-optimization-20261103-r14")
QUAL=ROOT/"qualification-01"
SOURCE=ROOT/"source"
PRIOR=ROOT/"independent-audit-tools/reference-r13"
READY_SHA="efdc0a817aa4a9b80106a31b899678a4b7863523dd47e145f99b5d6ee2aa6442"
JOBS_SHA="694a4e4dcbc2be499879abd837f0b5e399f9cad95caab34716907de15cbbe82f"
PRIOR_AUDIT_SHA="c1fc88d25e3e09f6301b793533b2c9760cb2e12f0dfee9694b7b804263ad8b65"
def need(value,message):
    if not value: raise RuntimeError(message)
def sha(path):
    with Path(path).open("rb") as stream:
        before=os.fstat(stream.fileno())
        digest=hashlib.file_digest(stream,"sha256").hexdigest()
        after=os.fstat(stream.fileno())
    current=Path(path).stat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after)==identity(current),"file changed while hashing: "+str(path))
    return digest
def source_map():
    files=[SOURCE/name for name in ("Cargo.toml","Cargo.lock","rustfmt.toml")]
    for name in ("src","examples"): files.extend(p for p in (SOURCE/name).rglob("*") if p.is_file())
    return {str(p.relative_to(SOURCE)):sha(p) for p in sorted(files)}
ready_path=ROOT/"implementation-ready.json"
need(sha(ready_path)==READY_SHA,"implementation-ready binding changed")
ready=json.loads(ready_path.read_text())
need(ready["ready"] is True and ready["source_frozen"] is True and ready["physical_preparation_capacity"]==2 and ready["publication_capacity"]==8,"frozen implementation scope differs")
q=json.loads((QUAL/"report.json").read_text())
s=json.loads((QUAL/"isolated-tests/summary.json").read_text())
need(q.get("qualified") is True and q.get("finished_utc") and not q.get("error"),"qualification not successful")
need(q["automatic_test_retries"]==0 and q["service_changes"] is False,"qualification retried or changed services")
expected_stages=["format","fmt-check","harness-tests","clippy","test-build","isolated-tests","audit-isolated-tests","release"]
need([stage["name"] for stage in q["stages"]]==expected_stages and all(stage.get("returncode")==0 for stage in q["stages"]),"failed/missing qualification stage")
current=source_map()
need(len(current)==219 and current==q["source_tested"]==q["source_after"]==ready["source_after"],"frozen/tested/post/current source maps differ")
need(current["src/mcp/runtime/jobs.rs"]==JOBS_SHA,"frozen jobs source differs")
need(s.get("success") is True and s.get("enumeration_errors")==[] and s.get("retries")==0,"test enumeration or retries differ")
need(set(q["binaries"])=={"hepta-runtime","hepta-runtime-jobctl","native_process_driver"},"release binary set differs")
binaries={}
for name,binding in q["binaries"].items():
    need(binding["path"]==str(QUAL/name),"release artifact outside frozen qualification")
    actual=sha(binding["path"])
    need(actual==binding["sha256"],"release binary differs: "+name)
    binaries[name]={"path":binding["path"],"sha256":actual,"size":Path(binding["path"]).stat().st_size}
libs=[v for v in s["binaries"] if v["target"]["name"]=="hepta_runtime" and v["target"]["kind"]==["lib"]]
need(len(libs)==1,"retained libtest not unique")
lib=libs[0]
need(Path(lib["path"]).parent==QUAL/"test-binaries","libtest not retained qualification copy")
lib_sha=sha(lib["path"])
need(lib_sha==lib["sha256"],"retained libtest differs")
rows=[json.loads(line) for line in (QUAL/"isolated-tests/tests.jsonl").read_text().splitlines() if line]
counts=dict(collections.Counter(v.get("status") for v in rows))
need(set(counts)=={"passed","ignored"} and counts["passed"]>0,"raw test outcomes not clean")
observed={"passed":counts["passed"],"failed":0,"ignored":counts["ignored"],"selected":len(rows),"retries":0}
need({key:s.get(key) for key in observed}==observed,"raw and summary test counts differ")
need(len({(v["binary"],v["name"]) for v in rows})==len(rows),"duplicate raw test identities")
inventory={v["path"]:v for v in s["binaries"]}
for row in rows:
    need(row["binary"] in inventory,"unknown raw test binary")
    if row["status"]=="passed":
        need(row.get("binary_sha256")==inventory[row["binary"]]["sha256"],"test binary SHA binding differs")
        need(row.get("attempt")==1 and row.get("executed") is True and row.get("exit_code")==0 and not row.get("timed_out"),"test attempt/outcome differs")
        need(row.get("stdout_proof",{}).get("passed") is True,"single-test success proof missing")
    else: need(row.get("executed") is not True,"ignored case executed")
def key(row,table):
    target=table[row["binary"]]["target"]
    return (target["name"],tuple(target["kind"]),row["name"])
need(sha(PRIOR/"qualification-audit-summary.json")==PRIOR_AUDIT_SHA,"prior independent qualification binding changed")
prior_audit=json.loads((PRIOR/"qualification-audit-summary.json").read_text())
prior_summary_path=PRIOR/"qualification-03/isolated-tests/summary.json"
prior_rows_path=PRIOR/"qualification-03/isolated-tests/tests.jsonl"
need(sha(prior_summary_path)==prior_audit["isolated_summary_sha256"] and sha(prior_rows_path)==prior_audit["raw_tests_jsonl_sha256"],"prior raw test evidence changed")
prior_summary=json.loads(prior_summary_path.read_text())
prior_rows=[json.loads(line) for line in prior_rows_path.read_text().splitlines() if line]
prior_inventory={v["path"]:v for v in prior_summary["binaries"]}
prior_keys={key(row,prior_inventory):row["status"] for row in prior_rows}
new_keys={key(row,inventory):row["status"] for row in rows}
expected_keys=dict(prior_keys)
required_tests=[]
for old,new in ready["tests"]["renamed"].items():
    matches=[k for k in expected_keys if k[2].split("::")[-1]==old]
    need(len(matches)==1,"prior renamed test not unique: "+old)
    old_key=matches[0]
    new_key=(old_key[0],old_key[1],old_key[2].rsplit("::",1)[0]+"::"+new)
    expected_keys[new_key]=expected_keys.pop(old_key)
    required_tests.append(new_key[2])
for name in ready["tests"]["added"]:
    matches=[k for k in new_keys if k[2].split("::")[-1]==name]
    need(len(matches)==1 and new_keys[matches[0]]=="passed","new pool test missing/not passed: "+name)
    need(matches[0] not in expected_keys,"added pool test already existed")
    expected_keys[matches[0]]="passed"
    required_tests.append(matches[0][2])
need(new_keys==expected_keys,"raw test identity/status delta differs from frozen implementation plan")
need(observed["passed"]==prior_audit["tests"]["passed"]+ready["tests"]["expected_nonignored_test_count_delta"] and observed["ignored"]==prior_audit["tests"]["ignored"]+ready["tests"]["expected_ignored_test_count_delta"],"raw test count delta differs")
need(source_map()==current,"source changed during audit")
result={"schema":"hepta-x230-r14-independent-qualification-audit/v1","audited_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"success":True,"auditor_sha256":sha(__file__),"reused_r13_auditor_sha256":"0974986d2ed9e51efd46c8b8aef53743d7341223df25862398aa14dbdf91d026","qualification_report_sha256":sha(QUAL/"report.json"),"isolated_summary_sha256":sha(QUAL/"isolated-tests/summary.json"),"raw_tests_jsonl_sha256":sha(QUAL/"isolated-tests/tests.jsonl"),"source_map_sha256":sha(QUAL/"source-map.json"),"implementation_ready_sha256":READY_SHA,"source_input_count":len(current),"source_tested_after_current_equal":True,"source_matches_frozen_implementation":True,"jobs_rs_sha256":current["src/mcp/runtime/jobs.rs"],"tests":dict(observed,raw_status_counts=counts,unique_test_identities=len(rows),executed_binary_bindings_matched=True,prior_identity_delta_matches_frozen_plan=True,required_pool_tests_passed=required_tests),"release_binaries":binaries,"retained_libtest":{"path":lib["path"],"sha256":lib_sha,"size":Path(lib["path"]).stat().st_size},"qualification_stages":[{"name":v["name"],"returncode":v["returncode"],"seconds":v["seconds"]} for v in q["stages"]],"scope":"Raw test outcomes and identity delta recomputed; 219 frozen/current/compiler inputs, three release binaries and retained libtest hashed only after all measurements completed. No tests, benchmarks or source changes."}
out=ROOT/"qualification-audit-summary.json"
with out.open("x") as stream: json.dump(result,stream,indent=2); stream.write("\n")
print(json.dumps({"success":True,"path":str(out),"sha256":sha(out),"runtime_sha256":binaries["hepta-runtime"]["sha256"],"libtest_sha256":lib_sha,"tests":result["tests"],"source_inputs":len(current)}),flush=True)
