#!/usr/bin/env python3
from pathlib import Path
import ast,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,owned,pin,require,source_evidence
identity=source_evidence(ROOT);reader=source_evidence(ROOT/"trusted-reader")
binding=decode(owned(ROOT,"UPLOAD_BINDING.json").read_bytes())
origin=decode(owned(ROOT,"trusted-reader/ORIGIN_BINDING.json").read_bytes())
require(len(binding["groups"])==27 and set(binding["groups"])==set(origin["groups"])
    and binding["new_application_executions"]==0,"complete independent 27-group domain")
require(reader["manifest"]["sha256"]=="f06db57bb94baf30a20adb00e34a7ce96d8b11efe8de364a15588ac8bb3db8ee"
    and reader["files"]==38,"exact already successful recovery reader")
recovered=[];original=[]
for group,row in binding["groups"].items():
    require(row["actual"]["group"]==group and row["gate_status"]=="PASS"
        and row["job_conclusion"]=="success","complete uploaded successful row")
    if row["kind"]=="recovered":
        require(row["manifest_sha256"]==reader["manifest"]["sha256"]
            and origin["groups"][group]["gate_status"]=="FAIL","retained failed capture recovered")
        recovered.append(group)
    else:
        require(row["kind"]=="original" and row["manifest_sha256"]==
            pin(ROOT/"trusted-reader/ORIGINAL_SOURCE_MANIFEST.json")["sha256"]
            and origin["groups"][group]["gate_status"]=="PASS","already successful original capture")
        original.append(group)
require(len(recovered)==22 and set(original)=={"validate-a","validate-b","validate-c","validate-d","observer-off"},
    "no successful domain replay")
require(sum(row["actual"]["cases"] for row in binding["groups"].values())==84
    and sum(row["actual"]["original_invocations"] for row in binding["groups"].values())==89
    and sum(row["actual"]["native_invocations"] for row in binding["groups"].values())==89,
    "all original and native actual inputs retained once")
for path in ROOT.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
print(encoded(dict(status="SOURCE_ONLY_PASS",source=identity,trusted_reader=reader,groups=27,
    recovered_groups=22,unchanged_original_successes=5,new_original_or_native_applications=0)).decode(),end="")
