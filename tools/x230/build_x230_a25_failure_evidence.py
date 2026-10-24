#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Preserve the failed A25 ABBA experiment and reproduce its exact qualified source."""
from pathlib import Path
import difflib
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import build_x230_evidence as core

B = Path("/home/qian/hepta-runtime-optimization-20261023")
P = B / "publication-a25-r01"
def put(name, raw):
    p=P/name
    with p.open("xb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    return {"path":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def src(root):
    files={}
    for p in sorted(root.rglob("*")):
        if p.is_symlink(): raise RuntimeError("source symlink")
        if p.is_file(): files[str(p.relative_to(root))]=core.sha(p.read_bytes())
    return files

raw=(B/"obs-a20-a25-r01/report.json").read_bytes()
report=json.loads(raw)
qraw=(B/"qualification-a25-integrated-r02/report.json").read_bytes()
q=json.loads(qraw)
assert q["qualified"] is True and q["source_tested"]==q["source_after"]
assert report["binary_sha256"]["B"]==q["binary"]["sha256"]
assert report["passed"] is False
e=core.build(report,raw,"A20","A25","observation","A25 r01: unadopted failed ABBA",B/"x230_observation_benchmark.py")
e["performance_comparison_valid"]=False
e["adopted"]=False
e["unqualified_failure_inclusive_deltas"]=e.pop("candidate_change_vs_baseline")
e["candidate_change_vs_baseline"]={}
e["qualification_report_sha256"]=core.sha(qraw)
e["publication_wrapper_sha256"]=core.sha(Path(__file__).read_bytes())
e["disposition"]="One generic pidfd/post-exec proof refusal stopped the shared pool. Keep every call; no performance improvement is established."
serialized=core.canonical(e)
files=[put("x230-a25-observation-r01-20261024.json.gz",gzip.compress(serialized,mtime=0))]
summary={k:v for k,v in e.items() if k!="report"}
files.append(put("x230-a25-observation-r01-summary-20261024.json",core.canonical(summary)))
files.append(put("x230-a25-source-map-20261024.json",core.canonical(q["source_tested"])))
assert src(B/"source-a25-integrated-r02")==q["source_tested"]
d=subprocess.run(["git","diff","--no-index","--","source-a20","source-a25-integrated-r02"],cwd=B,capture_output=True)
assert d.returncode==1 and not d.stderr,d.stderr.decode()
lines=[]
for line in d.stdout.decode().splitlines(True):
    if line.startswith(("diff --git ","--- ","+++ ")):
        line=line.replace("a/source-a20/","a/").replace("b/source-a25-integrated-r02/","b/")
    lines.append(line)
patch="".join(lines).encode()
files.append(put("x230-a25-integrated-unadopted.patch",patch))
reapply=B/"reapply-a25-r02-evidence"
assert not reapply.exists()
shutil.copytree(B/"source-a20",reapply)
patch_path=P/"x230-a25-integrated-unadopted.patch"
for extra in (["--check"],[]):
    outcome=subprocess.run(["git","apply",*extra,"--whitespace=error-all",str(patch_path)],cwd=reapply,capture_output=True)
    assert outcome.returncode==0,(outcome.stdout+outcome.stderr).decode()
actual=src(reapply)
assert actual==q["source_tested"],"patch did not reproduce all qualified source bytes"
receipt={"schema":"hepta-x230-exact-source-patch/v1","candidate":"A25","adopted":False,
    "base":"qualified A20","target_qualification_report_sha256":core.sha(qraw),
    "source_map_sha256":hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
    "source_file_count":len(actual),"exact_file_set_and_all_hashes_match":True,
    "git_apply_check_and_apply_passed":True,"patch":files[-1],
    "production_service_changes":False}
files.append(put("x230-a25-source-patch-proof-20261024.json",core.canonical(receipt)))
print(json.dumps({"files":files,"verification":e["verification"],"baseline_passed":e["baseline_passed"],"candidate_passed":e["candidate_passed"]}),flush=True)
