"""Pure full-byte inventory of retained UNKNOWN or failed applications; never replays or upgrades incomplete lifetimes."""
import argparse,gzip,hashlib,json,re,struct,sys,time,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,loads,read,encoded,pin,require
from comparison import Comparison
from read_only_guard import guarded
def stream_inventory(path):
    raw=read(path);decoder=zlib.decompressobj(31);pending=bytearray();position=0;objects={};used=set()
    counts={};records=logical=0;objectbytes=0;first=None;last=None;steps={};footer=None;incomplete=None;header=False
    def process():
        nonlocal position,records,logical,objectbytes,first,last,footer,header
        if not header:
            if len(pending)<8:return
            require(pending[:8]==b"HNVLOG02","exact retained native stream header");del pending[:8];position=8;header=True
        while len(pending)>=8 and footer is None:
            tag=bytes(pending[:8])
            if tag==b"NVOBJ001":
                if len(pending)<48:return
                length=struct.unpack_from("<Q",pending,8)[0];digest=bytes(pending[16:48]).hex()
                require(0<=length<=1<<20 and digest not in objects,"all bounded retained native objects")
                need=48+length
                if len(pending)<need:return
                body=bytes(pending[48:need]);require(hashlib.sha256(body).hexdigest()==digest,"every complete retained native object byte")
                objects[digest]=dict(bytes=length,sha256=digest,offset=position);objectbytes+=length
            elif tag==b"NVREC001":
                if len(pending)<16:return
                length=struct.unpack_from("<Q",pending,8)[0];require(0<length<=1<<20,"bounded complete native record")
                need=16+length
                if len(pending)<need:return
                row=loads(bytes(pending[16:need]));require(row["index"]==records and row["offset"]==position,"every retained native record index/offset")
                for ref in row["buffers"]:
                    require(ref["sha256"]in objects and ref=={k:objects[ref["sha256"]][k]for k in("bytes","sha256")},
                        "all logical retained buffer references join their full actual object")
                    used.add(ref["sha256"]);logical+=ref["bytes"]
                records+=1;counts[row["kind"]]=counts.get(row["kind"],0)+1
                detail=dict(index=row["index"],kind=row["kind"],case=row["case"],step=row["step"],operation=row["operation"],
                    tid=row["tid"],worker=row["worker"],buffer_count=len(row["buffers"]),logical_bytes=sum(v["bytes"]for v in row["buffers"]),
                    observed_ns=row["meta"].get("observed_ns"))
                event=row["meta"].get("event")
                if event:
                    e=bytes.fromhex(event);detail["event_tag"]=e[:8].decode("ascii",errors="replace")
                    if e[:8]==b"HNVOBS01":
                        detail.update(stage=int.from_bytes(e[8:16],"little"),phase=int.from_bytes(e[16:24],"little"),
                            source_generation=int.from_bytes(e[56:64],"little"),effect_sequence=int.from_bytes(e[64:72],"little"))
                if first is None:first=detail
                last=detail;key=str(row["step"]);s=steps.setdefault(key,dict(records=0,logical_bytes=0,first_observed_ns=None,last_observed_ns=None,last=detail))
                s["records"]+=1;s["logical_bytes"]+=detail["logical_bytes"];s["last"]=detail
                if detail["observed_ns"]is not None:
                    if s["first_observed_ns"]is None:s["first_observed_ns"]=detail["observed_ns"]
                    s["last_observed_ns"]=detail["observed_ns"]
            elif tag==b"NVEND001":
                if len(pending)<32:return
                footer=struct.unpack_from("<3Q",pending,8);need=32
                require(footer==(records,len(objects),logical),"complete native footer if actually present")
            else:raise ValueError("unexpected retained native stream tag at "+str(position))
            del pending[:need];position+=need
    for at in range(0,len(raw),1<<20):
        pending.extend(decoder.decompress(raw[at:at+(1<<20)]));process()
    pending.extend(decoder.flush());process()
    if pending:incomplete=dict(bytes=len(pending),sha256=hashlib.sha256(pending).hexdigest(),prefix_hex=bytes(pending[:48]).hex())
    require(not decoder.unused_data,"no unowned compressed stream suffix")
    if footer is not None:require(not pending and decoder.eof,"real native successful footer and gzip EOF agree")
    errors=None;report=None;index_state={}
    for filename in("RECORDS.json","OBJECTS.json","OBSERVER-ERRORS.json","NATIVE.json"):
        actual=path.parent/filename;index_state[filename]=actual.exists()
        if actual.exists():
            body=read(actual);value=loads(body)
            if filename=="RECORDS.json":
                require(len(value)==records,"all retained index records accounted for")
            elif filename=="OBJECTS.json":require(value==objects,"all retained physical object indexes accounted for")
            elif filename=="OBSERVER-ERRORS.json":errors=value
            else:report={k:value[k]for k in("status","role","group","pid","records","objects","logical_bytes","errors")}
    return dict(archive=pin(raw),gzip_eof=decoder.eof,successful_footer_present=footer is not None,
        uncompressed_complete_bytes=position,incomplete_record_tail=incomplete,records=records,objects=len(objects),
        referenced_objects=len(used),complete_object_bytes=objectbytes,logical_bytes=logical,counts=counts,
        first=first,last=last,steps=steps,index_files=index_state,observer_errors=errors,native_report=report)
def json_lines(raw):
    lines=raw.splitlines(keepends=True);suffix=b""
    if lines and not lines[-1].endswith(b"\n"):suffix=lines.pop()
    rows=[loads(line)for line in lines];return rows,dict(bytes=len(suffix),sha256=hashlib.sha256(suffix).hexdigest())
def verify(workspace,label):
    identity=source();row=loads(read(ROOT/"RECOVERY_DEPENDENCIES.json"))["cases"][label];prior=workspace/"retained";folder=prior/"run/group"
    require(source(prior/"source")==row["source_manifest_sha256"],"all unchanged captured source and domain bytes")
    case=next(c for c in loads(read(prior/"source/DOMAIN.json"))["cases"]if c["group"]==row["group"])
    meta=loads(read(prior/"run/RUN.json"));processes=loads(read(prior/"run/processes/processes.json"))
    require(meta["status"]=="FAIL"and meta["group"]==row["group"]and meta["source_manifest_sha256"]==row["source_manifest_sha256"]
        and meta["application_replays"]==0,"exact unchanged retained application failure")
    require([p["name"]for p in processes]==["source","restore","read-native","read-original","strace-version","application"],
        "all actual retained pre-application commands and one application attempt")
    for index,p in enumerate(processes):
        require(all(p[k]==meta["commands"][index][k]for k in("name","argv","cwd","timeout_seconds"))and(p["completed"]or label=="wide"and index==5 and p["timed_out"])
            and p["pid"]==p["pgid"]and p["parent_pid"]==meta["pid"],"whole retained actual process custody")
        for stream in("stdout","stderr"):
            require(p[stream]==dict(file=p["name"]+"."+stream,**pin(read(prior/"run/processes"/p[stream]["file"]))),
                "all complete prior process streams independently read")
        if index<5:require(p["exit_code"]==0 and not p["timed_out"],"all build admission commands completed without applications")
    actual=processes[-1]
    require(actual["timeout_seconds"]==60,"unchanged whole actual application deadline")
    if label=="wide":require(actual["timed_out"]and"TimeoutExpired"in meta["exception"],"retained UNKNOWN timeout never becomes PASS")
    else:require(not actual["timed_out"]and actual["exit_code"]==1 and b"KeyError: 'steps'"in read(prior/"run/processes/application.stderr"),
        "exact retained postoperation comparator error")
    roles=[];all_replies=[]
    for role in("native-observed","native-off","original"):
        f=folder/"roles"/role;raws={name:read(f/name)for name in("stdin","stdout","stderr","syscalls.strace")}
        requests,stdin_tail=json_lines(raws["stdin"]);responses,stdout_tail=json_lines(raws["stdout"])
        require(stdin_tail["bytes"]==0 and responses and responses[0]["command"]=="ready","whole captured command framing and actual process ready")
        for r in requests:
            if r["cmd"]=="run":require(r["case"]==case["case"]and r["operation"]==case["steps"][r["step"]]["operation"],
                "every captured operation is exactly from the unchanged source domain")
        completed=[r for r in responses if r["command"]=="run"]
        require([r["step"]for r in completed]==list(range(len(completed)))and all(r["case"]==case["case"]for r in completed),
            "whole completed original/native operation prefix")
        markers=[];stderr=raws["stderr"];begin=b"HNVORGB1"if role=="original"else b"HNVNATB1";end=b"HNVORGE1"if role=="original"else b"HNVNATE1"
        for offset in range(len(stderr)-23):
            if stderr[offset:offset+8]in(begin,end):
                ci,step=struct.unpack_from("<2Q",stderr,offset+8)
                if ci==case["case"]and step<len(case["steps"]):markers.append(dict(offset=offset,step=step,begin=stderr[offset:offset+8]==begin))
        process=loads(read(f/"PROCESS.json"))if(f/"PROCESS.json").exists()else None
        if process is not None:
            require(process["role"]==role and process["ready"]==responses[0],"entire retained role custody")
            require(all(process["streams"][name]==pin(raws[name])for name in raws),"whole sealed role streams")
        native=stream_inventory(f/"capture/complete-native-buffers.bin.gz")if role!="original"else None
        roles.append(dict(role=role,streams={name:pin(body)for name,body in raws.items()},ready=responses[0],
            sent_commands=len(requests),completed_commands=len(responses)-1,completed_source_operations=len(completed),
            last_sent=requests[-1]if requests else None,last_completed=dict(step=completed[-1]["step"],operation=completed[-1]["operation"],
                response=pin(encoded(completed[-1])))if completed else None,stdout_incomplete_tail=stdout_tail,stderr_markers=markers,
            final_retained_syscall_lines=raws["syscalls.strace"].decode().splitlines()[-12:],process=process,native=native))
        all_replies.append(completed)
    common=min(map(len,all_replies));comparison=Comparison(case);observations=[]
    for step in range(common):
        answers=[r[step]for r in all_replies];comparison.compare(answers,case["steps"][step]["operation"])
        observations.append(dict(step=step,answers=answers))
    relation=None
    if common==len(case["steps"]):relation=comparison.relations(observations)
    if label=="ids":
        require(common==17 and relation==case["relations"]and all(r[-1]["state"]["sets"]==[]for r in all_replies),
            "every completed concurrent constructor, read, and explicit set drop independently agrees")
    return dict(schema="hepta.namespace-versions.failed-actual-inventory.v1",status="COMPLETE_RETAINED_FAILURE_INVENTORY_PASS",
        source_manifest_sha256=identity,prior_source_manifest_sha256=row["source_manifest_sha256"],label=label,group=row["group"],
        retained_status="UNKNOWN_TIMEOUT"if label=="wide"else"POST_OPERATION_COMPARISON_FAIL",prior_exception=meta["exception"],
        actual_process=actual,source_operations=len(case["steps"]),complete_compared_prefix=common,relation=relation,
        roles=roles,application_replays=0,new_original_applications=0,new_native_applications=0,
        original_application_qualified=False,native_application_qualified=False,lifecycle_qualified=False,files_deleted=0)
def run(workspace,label):
    started=time.monotonic();result=guarded(lambda:verify(workspace,label),roots=[workspace],
        foreign_path="/tmp/namespace-failure-inventory-forbidden/CAPTURE.json")
    require(time.monotonic()-started<=180,"complete whole failure inventory reader deadline")
    (workspace/"run/INVENTORY-GUARDED.json").write_bytes(encoded(result));e=result["evidence"]
    (workspace/"run/GATE.json").write_bytes(encoded(e))
    summary={k:v for k,v in e.items()if k!="roles"}
    summary["guard_probes"]=len(result["probes"]);summary["elapsed_seconds"]=time.monotonic()-started
    summary["roles"]=[{k:v for k,v in r.items()if k not in("ready","stderr_markers","process","native")}|
        dict(markers=len(r["stderr_markers"]),native=None if r["native"]is None else
            {k:v for k,v in r["native"].items()if k not in("steps",)})for r in e["roles"]]
    print("FAILURE_INVENTORY_BEGIN");print(encoded(summary).decode(),end="");print("FAILURE_INVENTORY_END")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);p.add_argument("--label",choices=("wide","ids"),required=True)
    a=p.parse_args();run(a.workspace.resolve(strict=True),a.label)
