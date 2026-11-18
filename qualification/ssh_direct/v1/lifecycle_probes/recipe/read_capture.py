#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent full byte and kernel reader. Never starts a captured application."""
from pathlib import Path
import argparse,os,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,pin,raw_pin,need,unpack,case_bytes,inventories
from common import source_evidence
from model import q,expected
from kernel import verify_native,verify_original
def deny_application(event,args):
    if event.startswith(("subprocess.","os.exec","os.spawn","os.posix_spawn"))or event in("os.system","ctypes.dlopen"):
        raise PermissionError("pure captured-byte reader forbids executable replay")
def frames(path):
    raw=path.read_bytes();at=0;records=[];before={};local={};active={}
    while at<len(raw):
        need(len(raw)-at>=128,"complete HIA journal header");h=struct.unpack_from("<16Q",raw,at)
        need(raw[at:at+8]==b"HSSJRN01"and all(h[i]for i in(2,3,4,5,6,7,8,10,11,12,13,14,15)),"complete HIA journal capabilities")
        il,wc,oc=h[10:13];extent=128+2*(il+wc+oc)
        need(h[1]==extent and at+extent<=len(raw),"whole input/work/output capacity capture")
        record=raw[at:at+extent];p=128
        ib=record[p:p+il];p+=il;wb=record[p:p+wc];p+=wc;ob=record[p:p+oc];p+=oc
        ia=record[p:p+il];p+=il;wa=record[p:p+wc];p+=wc;oa=record[p:p+oc]
        need(ib==ia,"full original input remains read-only")
        ret,wantwork,wantoutput=expected(h[6],ib,wb,ob)
        need(h[9]==ret,"exact raw HIA return")
        need(wa==wantwork,"every complete original workspace byte matches independent transition")
        need(oa==wantoutput,"every complete output capacity byte matches independent transition")
        records.append(dict(header=h,raw=record,input=ib,before_work=wb,after_work=wa,output=oa,module=h[6],op=q(ib,8)))
        at+=extent
    need(at==len(raw)and records,"complete HIA record consumption")
    ordered=sorted(records,key=lambda r:r["header"][5]);need([r["header"][5]for r in ordered]==list(range(1,len(records)+1)),"no omitted or duplicate actual HIA invocation")
    for r in ordered:
        h=r["header"];key=(h[6],h[7]);wb=r["before_work"]
        if h[8]==1:
            need(not any(wb),"fresh independently owned policy workspace");before[key]=wb;local[key]=0
        need(key in local and h[8]==local[key]+1,"all actual per-policy calls contiguous")
        old=before[key]
        need(wb==old or(h[6]==3 and len(wb)>len(old)and wb[:len(old)]==old and not any(wb[len(old):])),"entire persistent workspace chain or unconsumed exact zero extension")
        before[key]=r["after_work"];local[key]=h[8]
        inp=r["input"]
        if h[6]in(1,5):
            request=(q(inp,16),q(inp,24));active[request[0]]=request[1];r["request"]=request
        elif h[6]==2:r["request"]=(q(inp,24)-4352,q(inp,32))
        elif h[6]==4:
            if inp[:8]==b"HSDCMD01":
                cap=h[7]-704;need(cap in active,"command belongs to original initialized request");r["request"]=(cap,active[cap])
            else:r["request"]=(q(inp,16),q(inp,24))
        else:r["request"]=None
    return records,dict(calls=len(records),full_captured_buffer_bytes=sum(2*sum(r["header"][10:13])for r in records),
        journal=pin(path),modules={str(n):sum(r["module"]==n for r in records)for n in range(1,6)})
def predecessors(root,source,stage,inputs):
    evidence=decode((root/"PREDECESSOR.json").read_bytes())
    need(evidence["inputs"]==inputs and evidence["source"]==source_evidence(root/"recipe-source"),"full frozen actual capture source binding")
    need((root/"recipe-source/SOURCE_MANIFEST.json").read_bytes()==(source/"SOURCE_MANIFEST.json").read_bytes(),"exact independent reader/source predecessor")
    builds={}
    for side in("native","original"):
        path=root/f"build-inputs/{side}.zip";need(pin(path)==inputs[side]["zip"],"complete retained immutable uploaded predecessor")
        if not(stage/side).exists():builds[side]=unpack(path,stage/side,inputs[side])
        else:builds[side]=stage/side/"capture"
    nb=decode((builds["native"]/"BUILD.json").read_bytes());ob=decode((builds["original"]/"REFERENCE.json").read_bytes())
    need(nb["applications_executed"]==ob["applications_executed"]==0,"builds did not qualify by executing")
    for build in builds.values():
        need(pin(build/"recipe-source/SOURCE_MANIFEST.json")==inputs["source_manifest"],"exact source of both actually invoked builds")
        source_evidence(build/"recipe-source")
    for row in inputs["generated_hia"]:
        need(pin(builds["native"]/row["path"])=={k:row[k]for k in("bytes","sha256")},"raw exact HIA identity; no JSON numeric reserialization")
    expected_pins=dict(child=nb["fixtures"]["child-fixture"],native=nb["fixtures"]["native-harness"],original=ob["executable"])
    for name,wanted in expected_pins.items():
        need(pin(root/"binaries"/name)==wanted and{k:evidence["binaries"][name][k]for k in("bytes","sha256")}==wanted,"every actual installed binary byte")
        need(Path(evidence["binaries"][name]["path"]).name==name,"exact recorded invocation copy name")
    tool=evidence["tools"]["strace"];need(pin(root/tool["captured_file"])=={k:tool[k]for k in("bytes","sha256")},"full actual capture tool")
    return evidence,ob
def expected_stream(c,stream):
    if c["behavior"]==0 and stream==1:
        return bytes(((i*73)^(c["id"]*19)^(i>>3))&255 for i in range(c["input_bytes"]))
    n=c["stdout_bytes"]if stream==1 else c["stderr_bytes"]
    return bytes(((i*37)+stream*29+11)&255 for i in range(n))
def results(root,c,role):
    result=[]
    for slot in range(c["count"]):
        raw=(root/f"actual/RESULT-{slot}").read_bytes();need(len(raw)==96 and raw[:8]==b"HSSRES01","complete actual result")
        value=struct.unpack("<12Q",raw);out=(root/f"actual/stdout-{slot}").read_bytes();err=(root/f"actual/stderr-{slot}").read_bytes()
        need(value[1]==96 and value[6]==value[8]==value[11]==0 and(value[7],value[9])==(len(out),len(err)),"all public result extents and pointer elision")
        successful=c["mode"]in(0,1,9)
        need(value[2]==int(not successful),"original business result success/error")
        if successful:
            need(value[5]==c["exit"]<<8 and out==expected_stream(c,1)and err==expected_stream(c,2),"complete stdin/stdout/stderr and child exit")
            need(value[3]==value[4]==0,"successful result has no error")
        else:
            need(not out and not err,"error result never returns partial pipe data")
            if role=="native":
                reasons={2:{401},3:{703},4:{104},5:{105},6:{404,405,406},7:{411},8:{412}}
                need(value[3]in reasons[c["mode"]],"exact frozen native business error")
            else:
                error=(root/f"actual/error-{slot}").read_bytes();need(error.endswith(b"\n")and error.strip(),"full original business error text")
                if c["mode"]==2:need(b"cancel"in error.lower(),"original cancellation error")
                if c["mode"]==3:need(b"timeout"in error.lower()or b"deadline"in error.lower(),"original deadline error")
        result.append(dict(slot=slot,kind=value[2],raw_status=value[5]if successful else 0,stdout=raw_pin(out),stderr=raw_pin(err)))
    return result
def run_report(root,c,role):
    n=c["count"];denied=c["mode"]==4;spawned=0 if c["mode"]in(4,5)else n
    if role=="native":
        raw=(root/"actual/RUN.bin").read_bytes();need(len(raw)==192 and raw[:8]==b"HSSRUN01","complete native report")
        r=struct.unpack("<24Q",raw)
        need(r[1:4]==(c["id"],c["mode"],n),"native frozen case report")
        need(r[4]==(n if c["entry"]else 0)and r[5]==(0 if denied or not c["entry"]else n)and r[6]==r[7]==0,"real final Entry consumed once and all guards retired")
        need(r[8]==r[9]==spawned and r[10]==r[11]==n,"all original request and child ownership retired")
        need(r[17]==r[21]==r[22]==r[23]==0 and r[18]==r[19]==r[20]==1,"one successful original owner and persistent join completion")
        need(r[12]!=r[13]and r[12]>0 and r[13]>0,"Entry runs independently of caller")
        need(r[14]==r[15]==int(c["mode"]==3)and r[16]==(n if c["mode"]==1 else 0),"caller disappearance or overlapping children proof")
        comparable=dict(case=c["id"],mode=c["mode"],requests=n,entered=r[4],dropped=r[5],live=0,spawned=r[8],registry=0,
            live_when_caller_gone=r[14],join_pending_before_release=r[15],ready_peak=r[16],join_started=True,join_success=True)
        return r,comparable
    r=decode((root/"actual/RUN.json").read_bytes())
    need(r["case"]==c["id"]and r["mode"]==c["mode"]and r["requests"]==n,"original frozen case report")
    need(r["entered"]==(n if c["entry"]else 0)and r["dropped"]==(0 if denied or not c["entry"]else n)and r["live"]==0,"original final Entry/guard lifetime")
    need(r["spawned"]==spawned and r["registry"]==0 and r["join_started"]is True and r["join_success"]is True,"original owner registry and join closed")
    need(r["entry_tid"]!=r["caller_tid"]and r["entry_tid"]>0 and r["caller_tid"]>0,"original independent Entry")
    need(r["live_when_caller_gone"]==r["join_pending_before_release"]==int(c["mode"]==3)and r["ready_peak"]==(n if c["mode"]==1 else 0),"original caller disappeared and join survived")
    comparable={k:v for k,v in r.items()if k not in("schema","entry_tid","caller_tid")}
    return r,comparable
def read_side(root,cases,role,predecessor,original,selected):
    capture=decode((root/"CAPTURE.json").read_bytes());plan=decode((root/"PLAN.json").read_bytes());ledger=decode((root/"LEDGER.json").read_bytes())
    need(capture["role"]==plan["role"]==ledger["role"]==role and capture["cases"]==plan["case_ids"]==selected,"actual frozen case/side scope")
    need(capture["applications_executed"]==ledger["applications_started"]==len(selected)and capture["completed_replayed"]==capture["unknown_replayed"]==0,"no completed or UNKNOWN replay")
    need(plan["retries"]is False and plan["application_limit_seconds"]==60,"actual fixed app bound")
    need([r["case_id"]for r in ledger["applications"]]==selected,"one process receipt per frozen case")
    outputs=[];binaries={k:v["path"]for k,v in predecessor["binaries"].items()}
    for c,receipt in zip(cases,ledger["applications"]):
        case=root/("case-"+str(c["id"]));need((case/"CASE.bin").read_bytes()==case_bytes(c),"every byte of frozen new input")
        p=decode((case/"PROCESS.json").read_bytes());need(p==receipt,"complete process receipt retained in ledger")
        need(p["status"]=="COMPLETE"and p["exit_code"]==0 and p["timed_out"]is False and p["application_timeout_seconds"]==60 and p["elapsed_ns"]<=61000000000,"one bounded completed actual application")
        need(p["input"]==pin(case/"CASE.bin")and p["streams"]=={n:pin(case/(n+".bin"))for n in("stdout","stderr")},"complete application streams and frozen input")
        need(p["kernel_files"]=={f.name:pin(f)for f in sorted(case.glob("kernel.*"))},"all actual kernel trace bytes")
        app=p["application_argv"];expected=[binaries["native"],p["cwd"]+"/CASE.bin",p["cwd"]+"/actual",binaries["child"]]if role=="native"else[binaries["original"],"--exact",original["selector"],"--test-threads=1","--nocapture"]
        need(app==expected and p["command"][-len(app):]==app and p["command"][-len(app)-1]=="--","exact actual invocation; old tests never selected")
        need(all(x in p["command"]for x in("-ff","-ttt","-T","-xx","-yy","-v","16777216")),"complete kernel string capture settings")
        need(p["environment"]==dict(PATH="/usr/bin:/bin",LC_ALL="C.UTF-8",LANG="C.UTF-8",TZ="UTC",RUST_BACKTRACE="1",
            HSS_CASE=p["cwd"]+"/CASE.bin",HSS_OUTPUT=p["cwd"]+"/actual",HSS_CHILD=binaries["child"]),"complete actual process environment")
        r,comparable=run_report(case,c,role);business=results(case,c,role)
        if role=="native":
            journal,proof=frames(case/"actual/HIA-JOURNAL.bin")
            kernel=verify_native(case,journal,c,r,binaries)
            core=[x for x in journal if x["module"]==3];last=max(core,key=lambda x:x["header"][5])
            need((case/"actual/CORE-WORK.bin").read_bytes()==last["after_work"],"complete final persistent core workspace")
        else:
            need(b"running 1 test"in(case/"stdout.bin").read_bytes()and b"1 passed; 0 failed"in(case/"stdout.bin").read_bytes(),"only exact new original test executed")
            proof=dict(calls=0,full_captured_buffer_bytes=0)
            kernel=verify_original(case,c,r,binaries)
        outputs.append(dict(case=c["id"],business=business,observations=comparable,hia=proof,kernel=kernel,process=p))
    return outputs
def main():
    p=argparse.ArgumentParser()
    for key in("native","original","source","stage","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();sys.addaudithook(deny_application)
    need(not a.stage.exists()and not a.output.exists(),"fresh pure reader outputs")
    a.stage.mkdir(parents=True);a.output.mkdir(parents=True)
    source=a.source.resolve();binding=source_evidence(source);inputs=decode((source/"INPUTS.json").read_bytes());domain=decode((source/"domain.json").read_bytes())
    selected=inputs["application_scope"]["case_ids"];need(selected==domain["probe_case_ids"],"only four frozen initial lifecycle probes")
    byid={c["id"]:c for c in domain["cases"]};cases=[byid[i]for i in selected]
    snapshots={side:inventories(root)for side,root in(("native",a.native),("original",a.original))}
    observed={}
    for side,root in(("native",a.native),("original",a.original)):
        predecessor,original=predecessors(root,source,a.stage,inputs)
        observed[side]=read_side(root,cases,side,predecessor,original,selected)
    for left,right in zip(observed["native"],observed["original"]):
        need(left["case"]==right["case"]and left["business"]==right["business"]and left["observations"]==right["observations"],"complete normalized native/original external result and lifecycle observations")
    for side,root in(("native",a.native),("original",a.original)):
        need(inventories(root)==snapshots[side],"pure reader changed evidence bytes/modes/times")
    need(source_evidence(source)==binding,"pure reader changed source")
    result=dict(status="FOUR_NEW_SSH_LIFECYCLE_PROBES_PASS",case_ids=selected,source=binding,
        applications_executed_by_reader=0,old_or_unknown_applications_replayed=0,native=observed["native"],original=observed["original"],
        scope=dict(actual_native_actor_probes=True,remaining_domain_cases=[i for i in byid if i not in selected],public_ssh=False,full_sdk=False))
    (a.output/"EVIDENCE.json").write_bytes(canonical(result));(a.output/"INPUT_INVENTORY.json").write_bytes(canonical(snapshots))
    print(canonical(dict(status=result["status"],case_ids=selected,applications_executed=0,hia_calls=sum(x["hia"]["calls"]for x in observed["native"]),
        full_buffer_bytes=sum(x["hia"]["full_captured_buffer_bytes"]for x in observed["native"]))).decode(),end="")
if __name__=="__main__":main()
