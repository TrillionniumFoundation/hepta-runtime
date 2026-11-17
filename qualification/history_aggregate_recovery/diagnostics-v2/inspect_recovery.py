#!/usr/bin/env python3
"""Reopen every V6 recovery proof byte and report its precise rejection."""
from pathlib import Path
import argparse, json, sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import read_proof_archive_v2 as archive
def need(v, message):
    if not v: raise ValueError(message)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--zip",type=Path,required=True)
    p.add_argument("--metadata",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    m=json.loads(a.metadata.read_bytes())
    need(m["id"]==14290847466 and m["workflow_run"]["id"]==43996181744
         and m["workflow_run"]["head_sha"]=="25d60ce4af460293bda15ab0d1056c0b8c110311"
         and m["expired"] is False and m["size_in_bytes"]==28805438
         and m["digest"]=="sha256:0628f7f4ffa8aae1859f78eafe6de6f27b9ad40007841822a26b2e517508440a",
         "exact failed V6 artifact")
    sys.argv=[str(Path(archive.__file__)), "--zip",str(a.zip),"--zip-bytes","28805438",
        "--zip-sha256","0628f7f4ffa8aae1859f78eafe6de6f27b9ad40007841822a26b2e517508440a",
        "--source-manifest-sha256","422c0a69ddbef37fa3431a898101f87529f511b14e81284f265730f7945c6b25",
        "--output",str(a.output)]
    archive.main()
    root=a.output/"proof/recovery"
    for name in ("logs/reader.stderr","logs/preflight.stderr","logs/restoration.stderr"):
        raw=(root/name).read_bytes()
        print(json.dumps({"path":name,"complete_utf8":raw.decode("utf-8")},sort_keys=True),flush=True)
    for name in ("reader/STATIC_CODE_ADMISSION.json","reader/SOURCE_RECONSTRUCTION.json",
                 "reader/RETAINED_SCHEMA_WRITES.json","reader/MECHANICAL_READS.json",
                 "failure-working-copy-delta/DELTA.json"):
        value=json.loads((root/name).read_bytes())
        if name.endswith("DELTA.json"):
            print(json.dumps({"path":name,"complete_value":value},sort_keys=True),flush=True)
        else:
            print(json.dumps({"path":name,"keys":list(value),
                 "admissions":len(value.get("admissions",[])),
                 "records":len(value.get("records",[])),
                 "violations":value.get("violations"),
                 "execution_attempts":value.get("execution_attempts"),
                 "pending_operations":value.get("pending_operations"),
                 "physical_writes":value.get("physical_writes")},sort_keys=True),flush=True)
    print(json.dumps({"status":"COMPLETE_V6_FAILED_ARCHIVE_INSPECTED",
       "recovery_status":"FAIL","native_or_rust_executions":0},sort_keys=True),flush=True)
if __name__=="__main__":main()
