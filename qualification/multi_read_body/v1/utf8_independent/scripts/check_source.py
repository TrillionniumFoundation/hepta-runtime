#!/usr/bin/env python3
from pathlib import Path
import ast,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,owned,pin,require,source_evidence
identity=source_evidence(ROOT);reader=source_evidence(ROOT/"trusted-reader")
binding=decode(owned(ROOT,"UPLOAD_BINDING.json").read_bytes())
require(len(binding["groups"])==23 and binding["new_application_executions"]==0,"complete independent domain")
require(reader["manifest"]["sha256"]=="40c40cc2b854597f684e4093299a0a7a072317083411560a9cea246d68b110bc",
    "exact already successful recovery reader")
for group,row in binding["groups"].items():
    require(row["actual"]["group"]==group and row["gate_status"]=="PASS" and row["job_conclusion"]=="success"
        and row["manifest_sha256"]==reader["manifest"]["sha256"],"complete uploaded successful row")
for path in ROOT.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
print(encoded(dict(status="SOURCE_ONLY_PASS",source=identity,trusted_reader=reader,groups=23,
    new_original_or_native_applications=0)).decode(),end="")
