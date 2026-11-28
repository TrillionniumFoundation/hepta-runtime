#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every frozen paired filesystem result and every retained native byte."""
from pathlib import Path
from types import SimpleNamespace
import gzip,hashlib,stat,struct
from common import canonical,decode,owned,pin,require,source_evidence,SCOPE
from cases import domain,group,validate,wire
from filesystem import data,describe
from buffer_store import Reader
from read_journal import Journal,U,invocation,result

def load(root,name):return decode(owned(root,name).read_bytes())
def fixture_rows(snapshot,store,case):
    require("."in snapshot and snapshot["."]["kind"]=="directory","fixture root missing")
    expected=data(case);rows={}
    for name,row in snapshot.items():
        require(type(name)is str and (name=="."or not name.startswith("/")and".."not in name.split("/")),
            "fixture path outside owned root")
        require(row["kind"]in("directory","file","symlink","fifo"),"fixture kind")
        actual_kind=stat.S_IFMT(row["mode"])
        require(actual_kind=={"directory":stat.S_IFDIR,"file":stat.S_IFREG,"symlink":stat.S_IFLNK,"fifo":stat.S_IFIFO}[row["kind"]],
            "fixture kind/mode mismatch")
        if row["kind"]=="file":
            raw=store.get(row["content"])
            require(raw==expected and row["size"]==len(raw)and stat.S_IMODE(row["mode"])==case.get("permissions",0o644),
                "complete fixture bytes/mode differ from frozen input")
            rows[name]=dict(row,raw=raw)
        else:rows[name]=row
    return rows

def setup(source,root):
    validate();identity=source_evidence(source);queries=load(root,"inputs.json");summary=load(root,"SETUP.json")
    require([q["id"]for q in queries]==list(range(1,115))and summary["status"]=="FROZEN_INPUTS_CREATED"
        and summary["source"]==identity and summary["cases"]==114
        and summary["original_or_native_application_calls"]==0,"input setup domain or custody")
    reader=Reader(root/"buffers");fixtures={}
    for case,q in zip(domain()["cases"],queries):
        require(q["id"]==case["id"],"setup input ordinal differs")
        rows=fixture_rows(q["snapshot"],reader,case)
        names=domain()["fixtures"];long=[]
        if case["path"]=="long-path":
            long=["d"*(names["long_path_component_bytes"]-4)+str(n).zfill(4)for n in range(names["long_path_components"])]
        expected=describe(Path(q["fixture"]),case,SimpleNamespace(**q["input_selected_stat"]),long)
        require({k:v for k,v in q.items()if k!="snapshot"}==expected,"input-only request construction differs")
        if case["path"]=="hardlink":selected=rows["hard.bin"]
        elif case["path"]=="nested-sidecar":selected=rows["dir/.hepta-hidden"]
        elif case["path"]in("unicode","control"):selected=rows[names[case["path"]]]
        elif case["path"]=="sidecar":selected=rows[".hepta-hidden"]
        elif case["path"]=="long-path":selected=rows["/".join(long)+"/leaf.bin"]
        else:selected=rows["data.bin"]
        require(q["input_selected_stat"]==dict(st_dev=selected["dev"],st_ino=selected["inode"],
            st_size=selected["size"],st_mtime_ns=selected["mtime_ns"],st_ctime_ns=selected["ctime_ns"]),
            "input version source stat differs")
        fixtures[q["id"]]={q["fixture"]if name=="."else q["fixture"]+"/"+name:value for name,value in rows.items()}
    stats=reader.finish()
    require(stats["complete_images"]==summary["images"]and stats["logical_buffer_bytes"]==summary["logical_bytes"],
        "setup complete buffer inventory differs")
    return queries,fixtures,stats

def reference(source,root,name,queries):
    identity=source_evidence(source);summary=load(root,"CAPTURE.json");rows=load(root,"cases.json")
    ids=[r["id"]for r in group(name)];selected={q["id"]:q for q in queries};cases={c["id"]:c for c in group(name)}
    require(summary["status"]=="ORIGINAL_BINARY_READ_DOMAIN_COMPLETE"and summary["cases"]==len(ids)
        and summary["group"]==name and summary["source"]==identity and summary["exact_original_functions"]is True
        and summary["original_source"]==pin(source/"trusted-build/target/binary_file.py")
        and [r["id"]for r in rows]==ids,"complete original domain/custody differs")
    reader=Reader(root/"buffers")
    for row in rows:
        q=selected[row["id"]]
        require(row["input"]==q and row["before"]==row["after"]==q["snapshot"]
            and 0<=row["elapsed_ns"]<60_000_000_000,"reference input/filesystem/elapsed differs")
        fixture_rows(row["before"],reader,cases[row["id"]]);fixture_rows(row["after"],reader,cases[row["id"]])
        value=row["result"]
        if value["ok"]:
            require(set(value)=={"ok","value","canonical"}and canonical(value["value"])[:-1].decode()==value["canonical"],
                "original complete JSON result differs")
        else:
            require(set(value)=={"ok","error"}and set(value["error"])=={"type","errno","filename","message"}
                and type(row.get("original_diagnostic"))is str,"complete original structured exception differs")
    stats=reader.finish()
    require(stats["complete_images"]==summary["buffer_images"]and stats["logical_buffer_bytes"]==summary["logical_buffer_bytes"],
        "original complete buffer inventory differs")
    return {r["id"]:r["result"]for r in rows},stats

def mapped(context,maps):
    require(len(context)==4096 and context[:8]==b"HBRDCI01"and U(context,8)==4096
        and U(context,56)==2 and U(context,176)==64 and U(context,184)==0
        and context[256:320]==b"\xff"*64,"context state or complete descriptor ledger differs")
    entries=[]
    for line in maps.decode().splitlines():
        columns=line.split();begin,end=(int(x,16)for x in columns[0].split("-"))
        require(begin<end and len(columns)>=5,"process mapping record")
        entries.append((begin,end,columns[1]," ".join(columns[5:])))
    require(not any(".so"in row[3]or"python"in row[3].lower()for row in entries),"native process mapped a host runtime")
    for at,cap in((64,72),(88,96),(104,112),(120,128)):
        address,size=U(context,at),U(context,cap)
        require(address%4096==size%4096==0 and size>=4096
            and any(lo<=address and address+size<=hi and flags[:3]=="rw-"for lo,hi,flags,_ in entries)
            and any(lo<=address+size and address+size+4096<=hi and flags[:3]=="---"for lo,hi,flags,_ in entries),
            "owned arena/guard mapping differs")
    for at,size in((136,1400832),(144,4096)):
        address=U(context,at)
        require(any(lo<=address and address+size<=hi and flags[:3]=="rw-"for lo,hi,flags,_ in entries)
            and any(lo<=address+size and address+size+4096<=hi and flags[:3]=="---"for lo,hi,flags,_ in entries),
            "child arena/guard mapping differs")

def native(source,root,name,queries,fixtures,expected,observer):
    identity=source_evidence(source);summary=load(root,"CAPTURE.json");rows=load(root,"cases.json")
    ids=[c["id"]for c in group(name)];qs={q["id"]:q for q in queries};cs={c["id"]:c for c in group(name)}
    require(summary["status"]=="NATIVE_BINARY_READ_DOMAIN_COMPLETE"and summary["cases"]==len(ids)
        and summary["group"]==name and summary["source"]==identity and summary["observer_enabled"]is observer
        and summary["original_outputs_read"]is False and summary["runtime_python_required"]is False
        and summary["runtime_libc_required"]is False and [r["id"]for r in rows]==ids,
        "native domain or execution ownership differs")
    reader=Reader(root/"buffers")
    exchanges=[decode(line)for line in owned(root,"exchanges.jsonl").read_bytes().splitlines()]
    require([r["exchange"]for r in exchanges]==list(range(1,len(exchanges)+1))
        and len(exchanges)==summary["exchanges"],"complete exchange ordinal set")
    native_process=load(root,"carrier-process.json")
    require(native_process==summary["native_process"]and native_process["binary"]==load(source,"BUILD_REUSE.json")["elf"]
        and native_process["returncode"]==0 and native_process["same_outer_process_group"]is True
        and native_process["parent_pgid"]==native_process["child_pgid"]and native_process["fixed_journal_fd"]==3
        and len(native_process["argv"])==1 and native_process["elapsed_ns"]>0,"native process custody differs")
    require(owned(root,"carrier.stderr").read_bytes()==b"","native stderr not empty")
    for key in("stdin","stderr"):require(native_process["streams"][key]==pin(root/("carrier."+key)),"carrier stream pin differs")
    require(native_process["stdout"]["compressed"]==pin(root/"carrier.stdout.gz"),"compressed stdout pin differs")
    observed_stdout=hashlib.sha256();stdout_count=0
    journal=Journal(root/"carrier.journal.gz");parsed={};finals={};workspaces={};byfirst={r["chain"]["first_exchange"]:r for r in rows}
    with owned(root,"carrier.stdin").open("rb")as incoming,gzip.open(root/"carrier.stdout.gz","rb")as outgoing:
        for row in exchanges:
            request=reader.get(row["input"]);response=reader.get(row["output"])
            require(incoming.read(len(request))==request and outgoing.read(len(response))==response,
                "complete captured transport bytes differ")
            observed_stdout.update(response);stdout_count+=len(response)
            require(len(request)>=72 and U(request,0)==len(request)-8 and request[8:16]==b"HBRDFQ01"
                and U(request,16)==row["command"]and U(request,24)==row["session"]
                and U(request,32)==len(request)-72 and request[40:72]==bytes(32),
                "fixture input envelope differs")
            require(len(response)>=64 and response[:8]==b"HBRDFR01"and U(response,16)==len(response)-64
                and 0<=row["elapsed_ns"]<61_000_000_000 and row["session"]in(0,1),
                "fixture output envelope or deadline differs")
            require(row["journal_begin"]==journal.position,"journal exchange prefix differs")
            command,session=row["command"],row["session"];body=request[72:];code=U(response,8)
            if command==1 and code==64:
                require(U(response,24)==2 and U(response,40)==0,"native borrowed result state differs")
                result(response[64:])
                if observer:
                    entry=byfirst.get(row["exchange"]);fixture=fixtures[entry["id"]]if entry else None
                    final=invocation(journal,body,response[64:],U(response,32),fixture,workspaces.get(session))
                    finals[row["exchange"]]=final;workspaces[session]=final["workspace"]
                else:require(row["journal_begin"]==row["journal_end"],"observer-off emitted bytes")
            elif command==3 and code==0:workspaces.pop(session,None)
            require(row["journal_end"]==journal.position,"journal exchange suffix differs")
            parsed[row["exchange"]]=(row,body,response)
        require(not incoming.read(1)and not outgoing.read(1),"unread carrier stream suffix")
    require(dict(bytes=stdout_count,sha256=observed_stdout.hexdigest())==native_process["stdout"]["raw"],
        "full stdout custody differs")
    journal_stats=journal.finish(native_process["journal"]);used=set()
    if not observer:
        require(journal_stats["events"]==0,"observer-off journal is not empty")
        for n,session in enumerate((0,1),1):
            row,body,response=parsed[n]
            require(row["command"]==9 and row["session"]==session and not body and U(response,8)==0
                and U(response,24)==0,"observer-off constructor differs");used.add(n)
    for row in rows:
        q=qs[row["id"]];chain=row["chain"];first,last=chain["first_exchange"],chain["last_exchange"];session=row["id"]%2
        require(chain["session"]==session and last==first+5 and row["input"]==q
            and row["before"]==row["after"]==q["snapshot"]and row["result"]==expected[row["id"]]
            and 0<=row["elapsed_ns"]<60_000_000_000,"paired original/native result or complete filesystem differs")
        for side in("before","after"):fixture_rows(row[side],reader,cs[row["id"]])
        entry,payload,response=parsed[first]
        require(entry["command"]==1 and entry["session"]==session and payload==wire(q)
            and result(response[64:])==row["result"]and U(response,32)==chain["generation"],"actual native query/result binding")
        arenas={}
        for n,(command,key)in enumerate(((4,"context"),(5,"workspace"),(6,"output"),(7,"input")),first+1):
            e,body,out=parsed[n];snapshot=chain["snapshots"][key];raw=reader.get(snapshot["bytes"])
            require(snapshot["exchange"]==n and e["command"]==command and e["session"]==session and not body
                and U(out,8)==0 and U(out,24)==2 and out[64:]==raw,"complete final arena observation differs")
            arenas[key]=raw
        ctx=arenas["context"];mapped(ctx,reader.get(chain["process"]["maps"]))
        require(set(chain["process"]["fd"])=={"0","1","2","3"}
            and chain["process"]["fd"]["0"].startswith("pipe:[")and chain["process"]["fd"]["1"].startswith("pipe:[")
            and chain["process"]["fd"]["3"].startswith("pipe:["),"native retained a filesystem descriptor")
        require(U(ctx,80)==len(payload)and arenas["input"][:len(payload)]==payload
            and len(arenas["input"])==U(ctx,72)and len(arenas["workspace"])==U(ctx,96)
            and len(arenas["output"])==U(ctx,112)and U(ctx,168)==len(response)-64
            and arenas["output"][:U(ctx,168)]==response[64:],"complete final arena/context binding")
        if observer:
            final=finals[first]
            require(arenas["workspace"]==final["workspace"]and arenas["output"]==final["output"]
                and U(ctx,248)==final["body_calls"],"journal differs from actual held response arena")
        e,body,out=parsed[last]
        require(e["command"]==2 and e["session"]==session and not body and U(out,8)==0
            and U(out,16)==0 and U(out,24)==0 and U(out,40)==0,"final response borrow not released")
        require(not used.intersection(range(first,last+1)),"overlapping native case exchanges")
        used.update(range(first,last+1))
    controls=load(root,"controls.json")if name=="g00"and observer else[]
    require(len(controls)==summary["private_controls"]==(30 if name=="g00"and observer else 0),"private control domain differs")
    for row in controls:
        n=row["exchange"];e,payload,response=parsed[n]
        require(e["command"]==row["command"]and e["session"]==row["session"]
            and payload==reader.get(row["input"])and response==reader.get(row["response"])
            and U(response,8)==row["expected_code"]
            and(row["expected_state"]is None or U(response,24)==row["expected_state"]),"private refusal/borrow control differs")
        used.add(n)
        if "before_context"in row:
            before=[]
            for key in("before_context","after_context"):
                saved=row[key];index=saved["exchange"];ee,bb,oo=parsed[index];raw=reader.get(saved["bytes"])
                require(ee["command"]==4 and ee["session"]==row["session"]and not bb and oo[64:]==raw,
                    "complete refusal context binding");before.append(raw);used.add(index)
            expected_context=bytearray(before[0])
            if row["name"].startswith("release-"):
                for at in(56,168,176):struct.pack_into("<Q",expected_context,at,0)
            require(bytes(expected_context)==before[1],"refusal/release changed an unrelated context byte")
    require(used==set(parsed),"unread or unexplained private exchange")
    stats=reader.finish()
    require(stats["complete_images"]==summary["buffer_images"]and stats["logical_buffer_bytes"]==summary["logical_buffer_bytes"],
        "native complete buffer inventory differs")
    return dict(cases=len(ids),controls=len(controls),exchanges=len(exchanges),buffers=stats,journal=journal_stats,
        observer_enabled=observer,paired_results=True,complete_filesystem_unchanged=True)

def verify(source,capture):
    source,capture=Path(source),Path(capture);identity=source_evidence(source)
    queries,fixtures,setup_stats=setup(source,capture/"setup")
    all_reference={};reference_stats=[];native_stats=[]
    for row in domain()["groups"]:
        values,stats=reference(source,capture/"original"/row["name"],row["name"],queries)
        require(not(set(values)&set(all_reference)),"duplicate reference input");all_reference.update(values);reference_stats.append(stats)
        native_stats.append(native(source,capture/"native"/row["name"],row["name"],queries,fixtures,values,True))
    require(len(all_reference)==114,"incomplete original domain")
    unobserved=native(source,capture/"native/unobserved","unobserved",queries,fixtures,all_reference,False)
    return dict(status="COMPLETE_BINARY_READ_BODY_COMPARISON_PASS",source=identity,original_cases=114,native_cases=114,
        observer_off_cases=15,controls=30,groups=15,setup_buffers=setup_stats,reference_buffers=reference_stats,
        native=native_stats,unobserved=unobserved,scope=SCOPE)
