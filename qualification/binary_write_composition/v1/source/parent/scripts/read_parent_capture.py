#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""DATA-only parent qualification reader. Imports no application or build producer."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from buffer_store import Reader
from protocol import U,error_frame,stat_decode
from read_kernel import read_trace
from read_parent_build import read_build

LANES=("original-1","original-2","native-observed","native-unobserved")
JOURNALS={b"HBPWJR01",b"HBWTJR01",b"HPUBJR01",b"HBRDJR01",b"HMDTJR01",b"HENTJR01"}
U64=(1<<64)-1


def same(left,right,message):
    require(encoded(left)==encoded(right),message)


def all_buffers(value,store):
    if type(value)is dict:
        if set(value)=={"bytes","sha256","blocks"}:
            store.get(value)
        else:
            for child in value.values():all_buffers(child,store)
    elif type(value)is list:
        for child in value:all_buffers(child,store)


def final_frame(raw):
    require(len(raw)>=64 and raw[:8]==b"HBPWR001" and U(raw,56)==len(raw)-64
            and all(U(raw,p)==0 for p in(24,32,40,48)),"complete actual final parent frame")
    if U(raw,8)==0:return dict(ok=True,value=decode(raw[64:]))
    require(U(raw,8)==3,"actual parent failed to terminate")
    return dict(ok=False,error=error_frame(raw[64:]))


def filesystem(value):
    output={}
    for name,row in value.items():
        info=row["stat"]
        item={key:row[key]for key in row if key!="stat"}
        item["stat"]={key:info[key]for key in("st_mode","st_uid","st_gid","st_nlink","st_size","st_rdev","st_blksize","st_blocks")}
        if row["kind"]=="regular":
            raw=bytes.fromhex(row["hex"])
            require(len(raw)==row["bytes"]==info["st_size"] and hashlib.sha256(raw).hexdigest()==row["sha256"],"all actual filesystem bytes")
        output[name]=item
    return output


def bound_result(result,row,kernel):
    if not result["ok"]:
        return dict(ok=False,error={key:result["error"].get(key)for key in("type","errno","filename","filename2","message")})
    value=result["value"]
    require(type(value)is dict and set(value)=={"written","size","version","sha256","mode"},"entire write result schema")
    matches=[]
    for name,node in row["after_application"].items():
        if node["kind"]!="regular":continue
        info=node["stat"]
        version=":".join(str(info[key])for key in("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns"))
        if version==value["version"]:
            require(value["sha256"]==node["sha256"]and value["size"]==node["bytes"]and value["mode"]==info["st_mode"]&4095,
                    "full write result must bind its actual final inode bytes and metadata")
            matches.append(name)
    require(len(matches)==1,"one actual fully bound result inode")
    witnesses=[]
    for call in kernel["calls"]:
        if call["number"]not in(5,262)or call.get("exit",{}).get("result")!=0:continue
        span=call.get("output_spans",{}).get("stat")
        if span is None:continue
        info=stat_decode(span["raw"])
        version=":".join(str(info[key])for key in("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns"))
        if version==value["version"]:witnesses.append(call["ordinal"])
    require(witnesses,"result version has no actual complete kernel stat witness")
    return dict(ok=True,value={key:value[key]for key in value if key!="version"},actual_inode=matches[0],version_bound_to_full_kernel_stat=True)


def fd_view(rows):
    # Every raw FD/stat remains in evidence; only pipes, logs and interpreter
    # descriptors differ between the two explicitly different executable carriers.
    output={}
    for name,row in rows.items():
        target=row["target"]
        if "stat"in row and row["stat"]["st_mode"]&0o170000==0o040000:
            output[name]=dict(target=target,mode=row["stat"]["st_mode"],dev=row["stat"]["st_dev"],uid=row["stat"]["st_uid"],gid=row["stat"]["st_gid"])
    return output


def parent_kernel(kernel,reference):
    groups=[]
    last=None
    for call in kernel["calls"]:
        phase=call.get("phase")
        if phase is None or phase["magic_hex"]!=b"HBPWHK01".hex():continue
        words=phase["words"]
        key=tuple(words)
        if key!=last:
            groups.append(dict(words=words,calls=[]));last=key
        operation=words[3]
        if "exit"not in call:continue
        if operation in(1,2)and call["number"]==257:
            require(call["args"][2]==720896 and call["args"][3]==0,"exact original parent open flags/actual glibc mode")
            raw=call["input_spans"]["path"]["raw"]
            groups[-1]["calls"].append(dict(operation=operation,fd=words[4],path=raw[:-1].decode(),flags=call["args"][2],
                mode=call["args"][3],result=call["exit"]["result"],ordinal=call["ordinal"]))
        elif operation==3 and call["number"]in(3,257):
            if call["number"]==3:
                require(call["args"][0]==words[4],"actual close used another numeric descriptor")
                item=dict(operation=3,fd=words[4],result=call["exit"]["result"],ordinal=call["ordinal"])
            else:
                require(call["input_spans"]["path"]["raw"]==b"/\0"and call["args"][2:4]==[720896,0],"only the frozen descriptor actor may reopen literal root")
                item=dict(operation="actor-open",fd=words[4],result=call["exit"]["result"],ordinal=call["ordinal"])
            groups[-1]["calls"].append(item)
        elif operation==4:
            require(call["number"]not in(3,32,33,257,292),"orphan transfer performed a target FD operation")
    result=[]
    for group in groups:
        if not group["calls"]:continue
        result.extend({key:value for key,value in call.items()if key!="ordinal"}for call in group["calls"])
    return result


def actual_faults(kernel,case):
    calls=[call for call in kernel["calls"]if call["number"]==317 and call["args"][0]==1]
    require(len(calls)==len(case["fault_plans"]),"complete actual syscall fault inventory")
    for call,plan in zip(calls,case["fault_plans"]):
        family,phase,operation,occurrence,number,error,match_fd=plan
        current=call["phase"]
        require(family==6 and current is not None and current["magic_hex"]==b"HBPWHK01".hex()
                and current["words"][3]==operation and current["words"][5]==phase
                and call["exit"]["result"]==0,"actual frozen parent filter call site")
        fd=current["words"][4]
        rows=[(0x20,0,0,0),(0x15,1 if match_fd else 3,0,number),
              (0x15,0 if match_fd else 2,3,262 if number==5 else number),
              (0x20,0,0,16),(0x15,0,1,fd&0xffffffff),
              (6,0,0,0x50000|error),(6,0,0,0x7fff0000)]
        expected=b"".join(struct.pack("<HBBI",*item)for item in rows)
        before=call["input_spans"]
        require(before["seccomp-bpf"]["raw"]==expected and U(before["sock-fprog"]["raw"],8)==before["seccomp-bpf"]["address"]
                and struct.unpack_from("<H",before["sock-fprog"]["raw"])[0]==7,"actual complete kernel filter program")


def journal(folder,binding,store):
    path=folder/"carrier.journal.gz"
    same(pin(path),binding["compressed"],"complete compressed native journal")
    digest=hashlib.sha256();count=0;actors=[];all_count=0;pending=None;last_workspace=None;last_output=None
    errors=[];last_error=None;last_body=None;parent_calls=0;body_calls=0;growth=None
    def read(stream,size):
        nonlocal count
        value=stream.read(size)
        require(len(value)==size,"complete native journal frame")
        digest.update(value);count+=len(value);return value
    with gzip.open(path,"rb")as stream:
        while True:
            tag=stream.read(8)
            if not tag:break
            require(len(tag)==8,"complete native journal tag")
            digest.update(tag);count+=8
            if tag in JOURNALS:
                head=tag+read(stream,120);size=U(head,32);payload=read(stream,size);all_count+=1
                event=U(head,8)
                if tag==b"HBWTJR01"and event==1:body_calls+=1
                if tag!=b"HBPWJR01":continue
                if event==1:
                    require(pending is None,"parent HIA invocation did not finish full spans")
                    pending={"input":payload};parent_calls+=1
                elif event==10:
                    require(pending is not None and set(pending)=={"input"},"complete before-workspace ordering")
                    if last_workspace is not None:require(payload==last_workspace,"owned complete parent workspace changed outside HIA/growth")
                    pending["workspace"]=payload
                elif event==12:
                    require(pending is not None and set(pending)=={"input","workspace"},"complete output-before ordering")
                    require(payload==b"\xa5"*len(payload),"entire actual parent output initialization")
                    pending["output_before"]=payload
                elif event==2:
                    require(pending is not None and set(pending)=={"input","workspace","output_before"},"complete output-after ordering")
                    require(U(head,48)==64 and len(payload)==len(pending["output_before"]),"actual HIA complete return and output span")
                    require(payload[:8]==b"HBPWR001"and U(payload,56)<=len(payload)-64,"actual HIA complete packet")
                    pending["output"]=payload;last_output=payload
                elif event==11:
                    require(pending is not None and "output"in pending and len(payload)==len(pending["workspace"]),"entire actual parent workspace-after")
                    last_workspace=payload
                    if len(payload)>=4096 and payload[:8]==b"HBPWW001":
                        error_at,error_size=U(payload,144),U(payload,280)
                        body_at,body_size=U(payload,160),U(payload,288)
                        if body_size:
                            require(body_at+body_size<=len(payload),"entire retained body result span")
                            body=payload[body_at:body_at+body_size]
                            if U(body,8)==3 and body!=last_body:
                                errors.append(error_frame(body[64:]));last_body=body
                        if error_size:
                            require(error_at+error_size<=len(payload),"entire parent error span")
                            error=payload[error_at:error_at+error_size]
                            if error!=last_error:errors.append(error_frame(error));last_error=error
                    pending=None
                elif event==3:
                    require(pending is None and payload==last_workspace,"exact old whole workspace before growth")
                    growth=payload
                elif event==4:
                    require(growth is not None and len(payload)>len(growth)and payload[:len(growth)]==growth
                            and payload[len(growth):]==bytes(len(payload)-len(growth)),"whole workspace preserved and extension zero")
                    last_workspace=payload;growth=None
                elif event in(5,8):
                    require(pending is None and last_output is not None and payload==last_output[:64+U(last_output,56)],"actual complete fixed effect/child request")
                    require(U(payload,8)==(2 if event==5 else 1),"effect/child kind")
                elif event==9:
                    require(payload[:8]==b"HBPWQ001"and len(payload)>=96 and U(payload,8)==2
                            and U(payload,88)==len(payload)-96 and payload[32:88]==bytes(56),"complete actual resume packet")
                elif event==6:
                    require(len(payload)==4096 and payload[:8]==b"HBWTCI01"and U(payload,56)==2,"actual fixed body loan copied before release")
                else:raise ValueError("unknown complete parent journal event")
            elif tag==b"HBWTER01":
                head=tag+read(stream,56);read(stream,U(head,16));all_count+=1
            elif tag==b"HBPWAC01":
                head=tag+read(stream,56)
                require(U(head,56)==0 and U(head,8)in(1,2),"frozen actual descriptor actor record")
                actors.append(dict(action=U(head,8),phase=U(head,16),fd=U(head,24),result=U(head,32)))
            else:raise ValueError("unknown native raw journal family")
    same(dict(bytes=count,sha256=digest.hexdigest()),binding["raw"],"entire native journal raw bytes")
    require(pending is None and growth is None,"partial native HIA invocation/growth")
    return dict(actors=actors,error_chain=list(reversed(errors)),parent_calls=parent_calls,
                body_calls=body_calls,all_frames=all_count,final_workspace=last_workspace)


def pool(raw,context,pid):
    require(len(raw)>=4128 and raw[:8]==b"HOPSN001","full actual process orphan pool")
    address,count,pages=U(raw,8),U(raw,16),U(raw,24)
    require(len(raw)==4128+pages*4096 and raw[32:40]==b"HPORP001"and U(raw,40)==4096
            and U(raw,48)==pid and U(raw,80)==count and U(raw,88)==pages,"entire pool header and actual creator")
    require(U(context,376)==address,"root owner uses the actual one process pool")
    records=[]
    for i in range(pages):
        page=raw[4128+i*4096:4128+(i+1)*4096]
        require(page[:8]==b"HPORL001"and U(page,8)==address and 0<U(page,24)<=126,"complete immutable process orphan record page")
        for at in range(U(page,24)):
            fd,owner,generation,ordinal=struct.unpack_from("<4Q",page,64+32*at)
            require(fd<=2147483647 and owner>0 and generation>0 and ordinal==len(records)+1,"actual appended orphan token")
            records.append(dict(fd=fd,owner=owner,generation=generation,ordinal=ordinal))
        require(page[64+32*U(page,24):]==bytes(4096-64-32*U(page,24)),"unwritten orphan record tail")
    require(len(records)==count,"all process orphan records read")
    return records


def read_case(folder,binding,case,lane,store,executable):
    same(pin(folder/"CASE.json"),binding["case"],"complete actual case record")
    raw=(folder/"CASE.json").read_bytes();row=decode(raw)
    same(row["input"],case,"fixed full case input")
    require(row["lane"]==lane and row["whole_process_exited"]is True and row["elapsed_ns"]<180_000_000_000,"actual complete bounded case")
    all_buffers(row,store)
    process=row["process"]
    same(process,decode((folder/"carrier-process.json").read_bytes()),"actual complete owned carrier process")
    require(process["returncode"]==0 and process["same_outer_process_group"]is True and process["elapsed_ns"]<180_000_000_000,"natural complete actual process")
    same(process["observer_wait"],dict(kind="SIGCHLD-pipe",parent_only=True,target_signal_replacement=False),"exact parent-only observer wait mechanism")
    native=lane.startswith("native")
    if native:same(process["binary"],executable,"actual native executable bytes")
    else:same(process["binary"],dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"),"actual original interpreter bytes")
    require((folder/"carrier.stderr").read_bytes()==b"","actual application stderr")
    for name in("stdin","stderr"):same(pin(folder/("carrier."+name)),process["streams"][name],"complete actual input/error stream")
    kernel=read_trace(folder,process["kernel"])
    require(kernel["application_calls"]>=1,"actual original/native entry did not run")
    # Every compressed byte is consumed, independent of the result summary.
    with gzip.open(folder/"carrier.stdout.gz","rb")as stream:stdout=stream.read()
    same(dict(bytes=len(stdout),sha256=hashlib.sha256(stdout).hexdigest()),process["stdout"]["raw"],"complete raw owned stdout")
    same(pin(folder/"carrier.stdout.gz"),process["stdout"]["compressed"],"complete stdout archive")
    exchanges=[decode(line)for line in (folder/"exchanges.jsonl").read_bytes().splitlines()]
    require([item["exchange"]for item in exchanges]==list(range(1,len(exchanges)+1)),"complete exchange order")
    all_buffers(exchanges,store)
    require(b"".join(store.get(item["input"])for item in exchanges)==(folder/"carrier.stdin").read_bytes(),"every exact input frame")
    require(b"".join(store.get(item["output"])for item in exchanges)==stdout,"every exact output frame")
    actual=exchanges[row["application_exchange"]-1]
    packet=store.get(row["application_input"])
    require(actual["command"]==1 and actual["application"]is True and store.get(actual["input"])[72:]==packet,"actual application input consumed")
    frame=store.get(row["application_frame"])
    require(store.get(actual["output"])[64:]==frame,"actual held full result")
    query=row["query"]
    if native:
        parts=[query["root"].encode(),query["path"].encode(),b""if query["expected_version"]is None else query["expected_version"].encode(),query["data_base64"].encode()]
        expected=b"HBPWQ001"+struct.pack("<11Q",1,0,1,*(len(value)for value in parts),int(query["expected_version"]is not None),0,0,sum(map(len,parts)))+b"".join(parts)
        require(packet==expected,"independent full HIA request encoding")
        result=final_frame(frame)
        if not result["ok"]:
            formatter=exchanges[row["formatter"]["exchange"]-1]
            require(formatter["command"]==13 and formatter["application"]is False
                    and store.get(formatter["output"])[64:]==store.get(row["formatter"]["bytes"]),
                    "exact actual retained formatter invocation and all returned bytes")
            text=store.get(row["formatter"]["bytes"]).decode()
            result["error"]["exact_str"]=text
        same(result,row["result"],"result summary differs from complete actual native bytes")
        contexts=row["snapshots"]["context"]
        context=store.get(contexts["bytes"])
        require(len(context)==4096 and context[:8]==b"HBPWCI01"and U(context,56)==2 and U(context,184)==0
                and U(context,256)==U64 and U(context,264)==U64 and U(context,272)==U(context,280)==0,"actual held parent ownership state")
        observed=contexts["actual_process_bytes"]
        require(observed["writes"]==0 and observed["observation"]=="process_vm_readv","independent complete actual context observation")
        matches=[candidate for candidate in observed["candidates"]if store.get(candidate["bytes"])==context]
        require(len(matches)==1 and matches[0]["address"]==observed["address"]and store.get(matches[0]["second"])==context,"one actual unchanged native context")
        for name in("pool","pool_after_release","pool_after_destroy"):
            pool_value=store.get(row["snapshots"][name]["bytes"])
            records=pool(pool_value,context,process["pid"])
            if name=="pool":first_pool=pool_value
            else:require(pool_value==first_pool,"process orphan records changed during root release/destroy")
        native_journal=journal(folder,process["journal"],store)
        if lane=="native-observed":
            require(native_journal["parent_calls"]==U(context,248)>0,"actual complete HIA parent invocation count")
            require(native_journal["final_workspace"]==store.get(row["snapshots"]["workspace"]["bytes"]),"actual complete final parent workspace")
            if case["descriptor_actor"]:
                require([item["action"]for item in native_journal["actors"]]==[1,2],"both actual descriptor actor operations")
            else:require(native_journal["actors"]==[],"unscheduled descriptor actor")
        else:
            require(native_journal["all_frames"]==0 and native_journal["parent_calls"]==0,"unobserved lane emitted hidden application journals")
        row["independent_error_chain"]=native_journal["error_chain"]
        row["independent_orphans"]=records
        row["independent_actor"]=native_journal["actors"]
    else:
        same(decode(packet),query,"actual unchanged original arguments")
        result=decode(frame);same(result,row["result"],"actual complete original result")
        require(result["binding"]["original"]["sha256"]=="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12"
                and result["binding"]["whole_original_main_executed"]is True
                and result["unused_fault_plans"]==0 and result["descriptor_actor_complete"]is True,"full original main/source and actual fault consumption")
        with gzip.open(folder/"carrier.journal.gz","rb")as stream:original_journal=stream.read()
        same(dict(bytes=len(original_journal),sha256=hashlib.sha256(original_journal).hexdigest()),process["journal"]["raw"],"whole original parent effect journal")
        require([decode(line)for line in original_journal.splitlines()]==result["parent_events"],"every original parent observation")
    require(len(row["hooks"]["eof"])==1 and row["hooks"]["result_substitutions"]==0
            and row["hooks"]["ack_only_eight_zero_bytes"]is True,"complete live pre-exit descriptor witness")
    for hook in row["hooks"]["events"]+row["hooks"]["eof"]:
        require(store.get(hook["ack"])==bytes(8),"observer substituted a result")
    notifications=[];acknowledgements=[]
    for call in kernel["calls"]:
        if "exit"not in call:continue
        if call["number"]==1 and call["args"][0]==4:
            require(call["exit"]["result"]==call["args"][2]==64,"whole actual before-effect write")
            notifications.append(call["input_spans"]["notification"]["raw"])
        elif call["number"]==0 and call["args"][0]==5:
            require(call["exit"]["result"]==call["args"][2]==8,"whole actual observational acknowledgement read")
            acknowledgements.append(call["output_spans"]["ack"]["raw"])
    require(notifications==[store.get(hook["raw"])for hook in row["hooks"]["events"]+row["hooks"]["eof"]]
            and acknowledgements==[bytes(8)]*len(notifications),"all actual notification/zero-ACK bytes and inventory")
    row["bound_result"]=bound_result(row["result"],row,kernel)
    row["independent_parent_kernel"]=parent_kernel(kernel,not native)
    actual_faults(kernel,case)
    require((folder/"CASE.json").read_bytes()==raw,"case raw custody changed during readback")
    return row


def compare(original,current,native):
    same(current["bound_result"],original["bound_result"],"whole actual result/error differs")
    for field in("setup","after_application","after_exit"):
        same(filesystem(current[field]),filesystem(original[field]),"complete actual filesystem differs: "+field)
    for field in("fds_with_result","fds_after_release","fds_after_destroy"):
        same(fd_view(current[field]),fd_view(original[field]),"actual complete target directory FD lifetime differs: "+field)
    same(fd_view(current["hooks"]["eof"][0]["fds"]),fd_view(original["hooks"]["eof"][0]["fds"]),"actual target FDs differ immediately before OS exit")
    if not native or current["lane"]=="native-observed":
        same(current["independent_parent_kernel"],original["independent_parent_kernel"],"actual raw parent syscall/error/descriptor order differs")
    if native and current["lane"]=="native-observed":
        same(current["independent_actor"],original["result"]["descriptor_actor"],"actual fixed descriptor actor differs")
    if not original["result"]["ok"]:
        expected=original["result"]["error"]
        if native:
            require(current["result"]["error"]["exact_str"]==expected["type"]+": "+expected["exact_str"],"actual retained formatter exact exception string")
            if current["lane"]=="native-observed":
                chain=[]
                for item in original["result"]["error_chain"]:
                    require(item["explicit_cause"]is False and item["suppress_context"]is False,"undeclared original exception chaining")
                    chain.append({key:item["error"].get(key)for key in("type","errno","filename","filename2","message")})
                same(current["independent_error_chain"],chain,"complete original error precedence/context chain differs")
        else:
            same(current["result"]["error"],expected,"all original exception attributes and display bytes")
            same(current["result"]["error_chain"],original["result"]["error_chain"],"all original exception contexts")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in("capture","images","build","output"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--capture-sha256",required=True)
    args=parser.parse_args()
    identity=source_evidence(SOURCE)
    capture=args.capture.resolve(strict=True)
    raw=(capture/"CAPTURE.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest()==args.capture_sha256,"fixed complete capture authority")
    report=decode(raw)
    require(report["status"]=="COMPLETE_ACTUAL_CAPTURE"and report["source"]==identity
            and report["planned"]==report["completed"]==992 and report["retry_planned"]==report["retry_completed"]==6
            and report["elapsed_ns"]<1800_000_000_000,
            "whole original bounded capture did not complete")
    owner_raw=(capture.parent/"OWNED.json").read_bytes();owner=decode(owner_raw)
    require(owner["status"]=="COMPLETE_NATURAL_CAPTURE" and owner["timeout"]is False and owner["returncode"]==0
            and owner["whole_group_gone"]is True and owner["whole_capture_seconds"]==1800 and owner["cleanup_seconds"]==5
            and owner["elapsed_ns"]<1800_000_000_000 and owner["source"]==owner["source_after"]==identity
            and owner["pgid"]==owner["pid"]!=owner["parent_pgid"],"whole original process-group supervision")
    for name in("stdout","stderr"):
        same(pin(capture.parent/(name+".log")),owner["streams"][name],"whole capture supervisor stream")
    require((capture.parent/"stderr.log").read_bytes()==b"","whole capture stderr")
    domain=decode((SOURCE/"DOMAIN.json").read_bytes())
    same(report["domain"],pin(SOURCE/"DOMAIN.json"),"all frozen inputs")
    same(report["limits"],domain["limits"],"all original resource budgets")
    build=read_build(SOURCE,args.images,args.build)
    same(report["executable"],build["executable"],"capture executed this exact freshly compiled/link-packed image")
    store=Reader(capture/"buffers")
    planned=[(case,lane)for case in domain["cases"]for lane in LANES
             if lane!="native-unobserved"or not(case["fault_plans"]or case["descriptor_actor"]or case["nofile"])]
    require(len(planned)==len(report["cases"])==992,"complete frozen original/current lane set")
    originals={};checked=[]
    for binding,(case,lane)in zip(report["cases"],planned):
        require((binding["id"],binding["name"],binding["lane"])==(case["id"],case["name"],lane),"complete unchanged case order")
        folder=capture/("case-%03d-"%case["id"]+lane)
        row=read_case(folder,binding,case,lane,store,build["executable"])
        require(row["process"]["parent_pgid"]==row["process"]["child_pgid"]==owner["pgid"],"case escaped owned whole-suite group")
        if lane=="original-1":originals[case["id"]]=row
        else:compare(originals[case["id"]],row,lane.startswith("native"))
        checked.append(dict(id=case["id"],lane=lane,case=binding["case"]))
    from read_retry_capture import read_retry
    retry_planned=[(case,lane)for case in domain["retry_controls"]for lane in domain["retry_lanes"]]
    require(len(retry_planned)==len(report["retry_controls"])==6,"complete frozen retry-control set")
    retries={};retry_checked=[]
    for binding,(case,lane)in zip(report["retry_controls"],retry_planned):
        require((binding["id"],binding["name"],binding["lane"])==(case["id"],case["name"],lane),"unchanged retry order")
        row=read_retry(capture/("retry-%02d-"%case["id"]+lane),binding,case,lane,store,build["executable"])
        require(row["process"]["parent_pgid"]==row["process"]["child_pgid"]==owner["pgid"],"retry escaped owned whole-suite group")
        if lane=="original-1":retries[case["id"]]=row
        else:
            original=retries[case["id"]]
            same(row["independent_parent_kernel"],original["independent_parent_kernel"],"actual original/native EINTR retry order differs")
            same(fd_view(row["cancellation"]["fds_before_signal"]),fd_view(original["cancellation"]["fds_before_signal"]),
                "actual owned target descriptors differ before retry cancellation")
        retry_checked.append(binding)
    buffers=store.finish()
    require((capture/"CAPTURE.json").read_bytes()==raw and(capture.parent/"OWNED.json").read_bytes()==owner_raw
            and source_evidence(SOURCE)==identity,"complete final source/capture custody")
    result=dict(schema="hepta.runtime.binary-parent-readback.v1",status="PASS_COMPLETE_FROZEN_PARENT_DOMAIN",
                source=identity,capture=pin(capture/"CAPTURE.json"),build=build,cases=256,complete_lane_runs=992,
                original_runs=512,native_observed_runs=256,native_unobserved_runs=224,checked=checked,buffers=buffers,
                actual_retry_controls=6,explicit_sigterm_cancellations=6,retry_checked=retry_checked,
                runtime_python_required=False,whole_runtime_replaced=False,public_binary_write_registered=False,
                old_body_101_requalified=False)
    require(not args.output.exists(),"fresh DATA readback receipt")
    args.output.write_bytes(encoded(result))
    print(json.dumps({key:result[key]for key in("status","cases","complete_lane_runs","original_runs","native_observed_runs","native_unobserved_runs")},sort_keys=True))


if __name__=="__main__":main()
