#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pure immutable capture diagnosis: retain exact failed-check context, never replay."""
from pathlib import Path
import argparse,base64,json,sys,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,pin,need,unpack,inventories
from common import source_evidence
import read_capture,kernel
def safe_value(value):
    if isinstance(value,bytes):return dict(bytes=len(value),hex=value.hex())
    if isinstance(value,(tuple,list)):return [safe_value(v)for v in value]
    if isinstance(value,dict):return {str(k):safe_value(v)for k,v in value.items()}
    if value is None or isinstance(value,(str,int,float,bool)):return value
    return repr(value)
def failure(error):
    t=error.__traceback__;detail={};summary={}
    while t:
        f=t.tb_frame
        if f.f_code.co_filename.endswith("/kernel.py"):
            loc=f.f_locals
            for k in("action","seq","physical","left","right","r","issue","op","a","b","e","pid","slot"):
                if k in loc:detail[k]=safe_value(loc[k])
            if "r"in loc and "issue"in loc and "tids"in loc:
                r=loc["r"]["event"];issue=loc["issue"]["event"]
                values=loc["tids"][r["tid"]][issue["index"]+1:r["index"]]
                detail["all_intervening_events"]=safe_value(values)
                summary["between"]=[e["body"]for e in values if not(e["name"]=="write"and"HIA-JOURNAL"in e["args"][0])]
            summary.update({k:safe_value(loc[k])for k in("action","seq","op","pid")if k in loc})
        t=t.tb_next
    return dict(error=type(error).__name__+": "+str(error),traceback=traceback.format_exc(),context=detail),summary
def main():
    p=argparse.ArgumentParser()
    for n in("source","native","original","stage","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();sys.addaudithook(read_capture.deny_application)
    need(not a.output.exists()and not a.stage.exists(),"fresh pure diagnosis");a.output.mkdir();a.stage.mkdir()
    bind=source_evidence(a.source);upload=decode((a.source/"UPLOADED.json").read_bytes());records=[]
    for role,path in(("native",a.native),("original",a.original)):
        root=unpack(path,a.stage/role,upload[role]);snap=inventories(root)
        frozen=root/"recipe-source";need(pin(frozen/"SOURCE_MANIFEST.json")==dict(bytes=12216,sha256="c48bb9cb063a99c834cd717fa28755dc75e630b5d89ceb53db66ec7a1892da79"),"actual frozen capture source")
        source_evidence(frozen);inputs=decode((frozen/"INPUTS.json").read_bytes());domain=decode((frozen/"domain.json").read_bytes())
        predecessor,original=read_capture.predecessors(root,frozen,a.stage/"compiled",inputs)
        binaries={k:v["path"]for k,v in predecessor["binaries"].items()}
        selected=inputs["application_scope"]["case_ids"]
        for c in domain["cases"]:
            if c["id"]not in selected:continue
            case=root/("case-"+str(c["id"]));row=dict(role=role,case=c["id"],process=decode((case/"PROCESS.json").read_bytes()))
            try:
                report,obs=read_capture.run_report(case,c,role);row["observations"]=obs
                row["business"]=read_capture.results(case,c,role)
                if role=="native":
                    calls,proof=read_capture.frames(case/"actual/HIA-JOURNAL.bin");row["hia"]=proof
                    row["kernel"]=kernel.verify_native(case,calls,c,report,binaries)
                else:row["kernel"]=kernel.verify_original(case,c,report,binaries)
                row["status"]="ALL_INSPECTED_CHECKS_PASS";print("CASE_DIAGNOSTIC "+canonical(dict(role=role,case=c["id"],status=row["status"],hia=row.get("hia"))).decode(),end="")
            except Exception as error:
                row["failure"],summary=failure(error);row["status"]="RETAINED_PURE_CHECK_FAILED"
                print("CASE_DIAGNOSTIC_FAILURE "+canonical(dict(role=role,case=c["id"],error=row["failure"]["error"],**summary)).decode(),end="")
            (a.output/(role+"-"+str(c["id"])+".json")).write_bytes(canonical(row));records.append({k:row[k]for k in("role","case","status")})
        need(inventories(root)==snap,"diagnostic changed actual input evidence")
    need(source_evidence(a.source)==bind,"diagnostic source changed")
    result=dict(status="IMMUTABLE_CAPTURE_DIAGNOSIS_COMPLETE",applications_executed=0,applications_replayed=0,
        qualification_pass=all(r["status"]=="ALL_INSPECTED_CHECKS_PASS"for r in records),checks=records,old_failure_preserved=True)
    (a.output/"DIAGNOSIS.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
