#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete read-only comparison of retained real calls, buffers and parent ownership."""
from pathlib import Path
import gzip,hashlib,struct
from common import canonical,decode,owned,pin,require,source_evidence,SCOPE
from cases import domain,group,wire
from buffer_store import Reader
from read_journal import Journal,U,invocation,result,stat_reply
from mappings import mapped
from read_observations import setup,snapshots,hooks,compare_view,original_binding,meta
def load(root,name):return decode(owned(root,name).read_bytes())
def query(roles,role):return roles.get("shared",roles.get(role))
def process_identity(root,receipt,native):
    stem="carrier"if native else"original"
    require(receipt["returncode"]==0 and receipt["parent_pgid"]==receipt["child_pgid"]
        and receipt["elapsed_ns"]>0 and receipt["fixed_notify_fd"]==4 and receipt["fixed_ack_fd"]==5,
        "actual process/port custody differs")
    for name in("stdin","stderr")if native else("stdin","stdout","stderr"):
        require(receipt["streams"][name]==pin(owned(root,stem+"."+name)),"complete process stream differs")
    require(owned(root,stem+".stderr").read_bytes()==b"","process stderr changed")
def reference(source,root,name,queries):
    summary=load(root,"CAPTURE.json");rows=load(root,"cases.json");selected=group(name)
    identity=source_evidence(source);receipt=load(root,"original-process.json")
    require(summary["status"]=="ORIGINAL_BORROWED_PARENT_DOMAIN_COMPLETE"and summary["source"]==identity
        and summary["group"]==name and summary["cases"]==len(selected)
        and summary["exact_original_functions"]is True and summary["private_branch_exact"]is True
        and [r["id"]for r in rows]==[c["id"]for c in selected]and summary["process"]==receipt,
        "complete original domain/custody differs")
    process_identity(root,receipt,False)
    require(len(receipt["argv"])==6 and receipt["argv"][1:4]==["-I","-S","-B"],"original worker command differs")
    reader=Reader(root/"buffers");exchanges=[decode(v)for v in owned(root,"exchanges.jsonl").read_bytes().splitlines()]
    require(len(exchanges)==summary["exchanges"]==3*len(rows)
        and [r["exchange"]for r in exchanges]==list(range(1,len(exchanges)+1)),"original exchange domain differs")
    parsed={}
    with owned(root,"original.stdin").open("rb")as incoming,owned(root,"original.stdout").open("rb")as outgoing:
        for e in exchanges:
            request=reader.get(e["input"]);reply=reader.get(e["output"])
            require(incoming.read(len(request))==request and outgoing.read(len(reply))==reply
                and canonical(decode(request))==request and canonical(decode(reply))==reply
                and 0<=e["elapsed_ns"]<61_000_000_000,"complete original transport bytes differ")
            parsed[e["exchange"]]=(decode(request),decode(reply))
        require(not incoming.read(1)and not outgoing.read(1),"unread original transport suffix")
    binding=original_binding(source);results={}
    for ordinal,(case,row)in enumerate(zip(selected,rows)):
        q=query(queries[case["id"]],"original");chain=row["chain"];first=ordinal*3+1
        require(row["input"]==q and row["before"]==q["snapshot"]and 0<=row["elapsed_ns"]<60_000_000_000
            and(chain["first_exchange"],chain["run_exchange"],chain["last_exchange"])==(first,first+1,first+2),
            "original query or case range differs")
        snapshots(row["before"],reader);snapshots(row["after"],reader)
        if not q["mutation"]:require(row["before"]==row["after"],"read-only original changed the actual fixture")
        held=chain["held"];require(held["status"]=="HELD"and held["binding"]==binding
            and held["parent"]==meta(q["snapshot"]["parent"]),"original held parent/binding differs")
        after=row["after"]["moved"if q["mutation"]=="rename_parent"else"parent"]
        require(chain["returned_parent"]==chain["released_parent"]==meta(after)
            and all(held["parent"][k]==after[k]for k in("dev","inode","mode","uid","gid")),
            "original did not retain the same parent capability")
        require(set(chain["fd"])=={"0","1","2","4","5",str(held["fd"])}
            and held["fd"]not in(0,1,2,4,5),"original leaked a source descriptor")
        expected_path=q["parent"]if q["mutation"]!="rename_parent"else str(Path(q["parent"]).with_name("moved"))
        require(chain["fd"][str(held["fd"])]==expected_path,"original retained a different parent directory")
        require(parsed[first]==(dict(command="hold",query=q),held),"original held request/response differs")
        returned=dict(status="RETURNED",result=row["result"],diagnostic=row["original_diagnostic"],parent=chain["returned_parent"])
        require(parsed[first+1]==(dict(command="run"),returned)
            and parsed[first+2]==(dict(command="release"),dict(status="RELEASED",parent=chain["released_parent"])),
            "actual original return/release differs")
        value=row["result"]
        if value["ok"]:
            require(set(value)=={"ok","value","canonical"}and canonical(value["value"])[:-1].decode()==value["canonical"]
                and row["original_diagnostic"]is None,"original success representation differs")
        else:
            require(set(value)=={"ok","error"}and set(value["error"])=={"type","errno","filename","message"}
                and type(row["original_diagnostic"])is str,"original complete exception differs")
        hooks(row,reader,case,False,q["id"],receipt["pid"])
        results[case["id"]]=row
    counts=reader.finish()
    require(counts["complete_images"]==summary["buffer_images"]and counts["logical_buffer_bytes"]==summary["logical_buffer_bytes"],
        "original full buffer inventory differs")
    return results,dict(cases=len(rows),exchanges=len(exchanges),buffers=counts,exact_private_branch=binding)

def native(source,root,name,queries,expected,observer):
    summary=load(root,"CAPTURE.json");rows=load(root,"cases.json");selected=group(name);identity=source_evidence(source)
    require(summary["status"]=="NATIVE_BORROWED_PARENT_DOMAIN_COMPLETE"and summary["source"]==identity
        and summary["group"]==name and summary["cases"]==len(selected)
        and summary["observer_enabled"]is observer and summary["original_outputs_read"]is False
        and summary["runtime_python_required"]is False and summary["runtime_libc_required"]is False
        and [r["id"]for r in rows]==[c["id"]for c in selected],"complete native case domain differs")
    receipt=load(root,"carrier-process.json");require(receipt==summary["native_process"]
        and receipt["binary"]==load(source,"BUILD_REUSE.json")["elf"]and receipt["fixed_journal_fd"]==3
        and receipt["same_outer_process_group"]is True and len(receipt["argv"])==1,"native executable/process differs")
    process_identity(root,receipt,True);reader=Reader(root/"buffers");prepared={}
    for case,row in zip(selected,rows):
        q=query(queries[case["id"]],"native");chain=row["chain"]
        require(row["input"]==q and row["before"]==q["snapshot"]and 0<=row["elapsed_ns"]<60_000_000_000,
            "native input/initial actual fixture differs")
        before=snapshots(row["before"],reader);snapshots(row["after"],reader)
        if not q["mutation"]:require(row["before"]==row["after"],"native changed immutable actual files")
        decoded=hooks(row,reader,case,True,chain["generation"],receipt["pid"])
        require(observer or not decoded,"observer-off emitted notifications")
        fixture={q["fixture"]if n=="."else q["fixture"]+"/"+n:v for n,v in before.items()}
        require(compare_view(row)==compare_view(expected[case["id"]]),"complete actual original/native result differs")
        prepared[chain["first_exchange"]]=(row,fixture,decoded)
    exchanges=[decode(v)for v in owned(root,"exchanges.jsonl").read_bytes().splitlines()]
    require(len(exchanges)==summary["exchanges"]and [r["exchange"]for r in exchanges]==list(range(1,len(exchanges)+1)),
        "native exchange ordinal set differs")
    require(receipt["stdout"]["compressed"]==pin(root/"carrier.stdout.gz"),"compressed stdout identity differs")
    journal=Journal(root/"carrier.journal.gz");parsed={};finals={};workspaces={}
    stdout_digest=hashlib.sha256();stdout_count=0
    with owned(root,"carrier.stdin").open("rb")as incoming,gzip.open(root/"carrier.stdout.gz","rb")as outgoing:
        for e in exchanges:
            request=reader.get(e["input"]);reply=reader.get(e["output"])
            require(incoming.read(len(request))==request and outgoing.read(len(reply))==reply,"complete native transport differs")
            stdout_digest.update(reply);stdout_count+=len(reply)
            require(len(request)>=72 and U(request,0)==len(request)-8 and request[8:16]==b"HBRDFQ01"
                and U(request,16)==e["command"]and U(request,24)==e["session"]and U(request,32)==len(request)-72
                and request[40:72]==bytes(32),"native fixture input frame differs")
            require(len(reply)>=64 and reply[:8]==b"HBRDFR01"and U(reply,16)==len(reply)-64
                and 0<=e["elapsed_ns"]<61_000_000_000 and e["session"]in(0,1),"complete native fixture reply differs")
            require(e["journal_begin"]==journal.position,"journal exchange start differs")
            command,session=e["command"],e["session"];body=request[72:];code=U(reply,8)
            if command in(1,11)and code==64:
                require(e["exchange"]in prepared and U(reply,24)==2 and U(reply,40)==0,"unowned native invocation")
                row,fixture,decoded=prepared[e["exchange"]];q=row["input"];start=bytearray(body);borrowed=None
                require(body==wire(q),"actual invoked packet differs")
                if command==11:
                    parent=row["chain"]["parent_fd"];struct.pack_into("<Q",start,32,parent);borrowed=(parent,q["parent"])
                if observer:
                    final=invocation(journal,bytes(start),reply[64:],U(reply,32),fixture,workspaces.get(session),borrowed,decoded)
                    finals[e["exchange"]]=final;workspaces[session]=final["workspace"]
                else:require(e["journal_begin"]==e["journal_end"],"observer-off emitted journal bytes")
            elif command==3 and code==0:workspaces.pop(session,None)
            require(e["journal_end"]==journal.position,"journal exchange end differs")
            parsed[e["exchange"]]=(e,body,reply)
        require(not incoming.read(1)and not outgoing.read(1),"unread native transport suffix")
    require(dict(bytes=stdout_count,sha256=stdout_digest.hexdigest())==receipt["stdout"]["raw"],"complete native stdout identity differs")
    journal_stats=journal.finish(receipt["journal"]);used=set();refusals=0
    if not observer:
        require(journal_stats["events"]==0,"observer-off journal not empty")
        for n,session in enumerate((0,1),1):
            e,b,r=parsed[n];require(e["command"]==9 and e["session"]==session and not b and U(r,8)==0,"observer-off constructor")
            used.add(n)
    for case,row in zip(selected,rows):
        q=row["input"];chain=row["chain"];begin=chain["begin_exchange"];first=chain["first_exchange"];last=chain["last_exchange"]
        session=case["id"]%2;control=observer and case["id"]in(1,2);destroy=observer and case["id"]%3==0
        commands=[10,13]+([8,4,11,4,4,1,4]if control else[])+[11 if q["entry"]=="at"else 1,4,5,6,7]
        commands+=([4,11,4,4,3,4]if control else[])+[13,2,13]+([3,13]if destroy else[])+[12]
        require([parsed[n][0]["command"]for n in range(begin,last+1)]==commands
            and all(parsed[n][0]["session"]==session for n in range(begin,last+1))
            and chain["session"]==session and chain["hold_exchange"]==begin
            and first==begin+2+(7 if control else 0),"complete per-case fixture sequence differs")
        require(not used.intersection(range(begin,last+1)),"overlapping native case");used.update(range(begin,last+1))
        e,b,r=parsed[begin];parent=chain["parent_fd"]
        require(b==q["parent"].encode()+b"\0"and U(r,8)==parent<2147483648 and U(r,16)==0,"actual fixture held FD binding")
        e,payload,response=parsed[first]
        require(payload==wire(q)and result(response[64:])==row["result"]and U(response,32)==chain["generation"],
            "actual native result binding differs")
        arenas={}
        for n,(command,key)in enumerate(((4,"context"),(5,"workspace"),(6,"output"),(7,"input")),first+1):
            e,b,r=parsed[n];saved=chain["snapshots"][key];raw=reader.get(saved["bytes"])
            require(saved["exchange"]==n and e["command"]==command and not b and U(r,8)==0 and U(r,24)==2
                and r[64:]==raw,"complete final borrowed arena differs")
            arenas[key]=raw
        ctx=arenas["context"];mapped(ctx,reader.get(chain["process"]["maps"]))
        require(U(ctx,344)==U(ctx,352)==0,"borrowed parent capability retained past publication")
        expected_input=bytearray(payload)
        if q["entry"]=="at":struct.pack_into("<Q",expected_input,32,parent)
        require(U(ctx,80)==len(payload)and arenas["input"][:len(payload)]==expected_input
            and len(arenas["input"])==U(ctx,72)and len(arenas["workspace"])==U(ctx,96)
            and len(arenas["output"])==U(ctx,112)and U(ctx,168)==len(response)-64
            and arenas["output"][:U(ctx,168)]==response[64:],"complete arena/input/loan binding differs")
        require(U(arenas["workspace"],88)==(1<<64)-1,"completed body retained a parent close obligation")
        if observer:
            final=finals[first];require(arenas["workspace"]==final["workspace"]and arenas["output"]==final["output"]
                and U(ctx,248)==final["body_calls"],"journal differs from actually borrowed arenas")
        fdset=chain["process"]["fd"];parent_path=q["parent"]if q["mutation"]!="rename_parent"else str(Path(q["parent"]).with_name("moved"))
        require(set(fdset)=={"0","1","2","3","4","5",str(parent)}and parent not in range(6)
            and fdset[str(parent)]==parent_path
            and all(fdset[str(n)].startswith("pipe:[")for n in(0,1,3,4,5)),"native leaked or duplicated a descriptor")
        labels=["before","after-result","after-release"]+(["after-destroy"]if destroy else[])
        require([p["label"]for p in chain["parents"]]==labels,"parent observation sequence differs")
        for item in chain["parents"]:
            e,b,r=parsed[item["exchange"]];raw=reader.get(item["bytes"])
            require(e["command"]==13 and not b and U(r,8)==0 and len(raw)==144 and r[64:]==raw,
                "actual borrowed parent stat differs")
            expected_parent=q["snapshot"]["parent"]if item["label"]=="before"else row["after"]["moved"if q["mutation"]=="rename_parent"else"parent"]
            stat_reply(raw,expected_parent)
            require(U(raw,0)==q["snapshot"]["parent"]["dev"]and U(raw,8)==q["snapshot"]["parent"]["inode"],
                "caller parent identity changed")
        release=chain["release_exchange"];e,b,r=parsed[release]
        require(e["command"]==2 and not b and U(r,8)==0 and U(r,16)==0 and U(r,24)==0 and U(r,40)==0,
            "actual final response release differs")
        if destroy:
            e,b,r=parsed[chain["destroy_exchange"]];require(e["command"]==3 and not b and U(r,8)==0 and r[16:]==bytes(48),
                "context destructor lost parent or left live context")
        else:require("destroy_exchange"not in chain,"undeclared destructor")
        e,b,r=parsed[last];require(e["command"]==12 and not b and U(r,8)==0 and U(r,16)==0,"caller parent release differs")
        controls=chain["controls"];refusals+=len(controls)
        require([c["name"]for c in controls]==(["caller-selected-fd","at-packet-through-path-entry",
            "invoke-with-live-result-loan","destroy-with-live-result-loan"]if control else[]),"refusal domain differs")
        if control:
            e,b,r=parsed[chain["explicit_create"]];require(e["command"]==8 and not b and U(r,8)==0,"explicit constructor")
        for c in controls:
            n=c["exchange"];e,b,r=parsed[n];expected_code=0xffffffff if c["name"]in("caller-selected-fd","at-packet-through-path-entry")else 0xfffffffd
            require(e["command"]==c["command"]and U(r,8)==c["code"]==expected_code,"actual refusal differs")
            expected_payload=bytearray(payload)
            if c["name"]=="caller-selected-fd":struct.pack_into("<Q",expected_payload,32,123)
            elif c["name"]=="destroy-with-live-result-loan":expected_payload=bytearray()
            require(b==expected_payload,"refusal input differs")
            contexts=[]
            for key in("before","after"):
                saved=c[key];ee,bb,rr=parsed[saved["exchange"]];raw=reader.get(saved["bytes"])
                require(ee["command"]==4 and not bb and rr[64:]==raw and U(rr,8)==0,"full refusal context observation differs")
                contexts.append(raw)
            require(contexts[0]==contexts[1],"refusal changed an unrelated context byte")
    require(used==set(parsed)and refusals==summary["private_refusals"]==(8 if name=="g00"and observer else 0),
        "unread fixture exchanges or refusal domain differs")
    counts=reader.finish()
    require(counts["complete_images"]==summary["buffer_images"]and counts["logical_buffer_bytes"]==summary["logical_buffer_bytes"],
        "native full buffer inventory differs")
    return dict(cases=len(rows),refusals=refusals,exchanges=len(exchanges),buffers=counts,journal=journal_stats,
        observer_enabled=observer,same_parent_after_result_release_and_destroy=True,complete_actual_mutations_checked=True)
def verify(source,capture):
    source,capture=Path(source),Path(capture);identity=source_evidence(source)
    queries,fixtures,setup_counts=setup(source,capture/"setup")
    original={};references=[];native_rows=[]
    for g in domain()["groups"]:
        name=g["name"];values,count=reference(source,capture/"original"/name,name,queries)
        require(not(set(original)&set(values)),"duplicate original case");original.update(values);references.append(count)
        native_rows.append(native(source,capture/"native"/name,name,queries,values,True))
    require(len(original)==59,"incomplete original domain")
    unobserved=native(source,capture/"native/unobserved","unobserved",queries,original,False)
    return dict(status="COMPLETE_BINARY_READ_AT_COMPARISON_PASS",source=identity,original_cases=59,native_cases=59,
        borrowed_parent_cases=52,actual_mutation_pairs=21,one_free_fd_pairs=2,observer_off_cases=8,
        private_refusals=8,groups=8,setup_buffers=setup_counts,reference=references,native=native_rows,
        unobserved=unobserved,scope=SCOPE)
