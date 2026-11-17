#!/usr/bin/env python3
"""Pure admission of complete actual multi-read process, FD and filesystem captures."""
from pathlib import Path
import argparse,json,struct,sys
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SOURCE/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from cases import group,actual_query
from protocol import U,result,wire
from read_evidence import rows,stream_custody,open_buffers,reference_binding,references,setup,hooks,original_journal,walk,file_snapshot
from read_resources import pool,mappings,mapped,guarded_mapping
from read_trace import Journal
from read_body import invocation
from read_compare import compare
PYTHON=dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
MASK=(1<<64)-1
def context(raw,observer,state):
    require(len(raw)==4096 and raw[:8]==b"HMRDCI01"and U(raw,8)==4096 and U(raw,56)==state
        and U(raw,184)==0 and raw[256:320]==b"\xff"*64 and U(raw,344)==U(raw,352)==0,
        "whole drained actual body controller")
    require((U(raw,40)==0)==(not observer),"actual null/observed callback")
    require(U(raw,376)>0 and U(raw,384)>0 and U(raw,392)>0 and U(raw,384)!=U(raw,392),"real fixed children and shared pool")
def idle_parent(raw,observer):
    require(len(raw)==4096 and raw[:8]==b"HPDRCI01"and U(raw,8)==4096 and U(raw,56)==0
        and U(raw,168)==U(raw,176)==U(raw,184)==U(raw,344)==U(raw,352)==U(raw,360)==0
        and raw[256:320]==b"\xff"*64 and ((U(raw,40)==0)==(not observer)),"entire released parent child")
def arena_mappings(ctx,maps):
    for at in(64,88,104,120):
        address,capacity=U(ctx,at),U(ctx,at+8)
        if not capacity:
            require(at==64 and address==0 and U(ctx,80)==0,"only a never-invoked parent may have no input arena");continue
        require(address>0 and address%4096==capacity%4096==0 and capacity>=4096
            and mapped(maps,address,capacity,"rw-p")and mapped(maps,address+capacity,4096,"---p"),
            "actual complete controller-owned guarded arena")
def retired(ctx,parents,maps):
    for owner in[ctx,*parents]:
        for at in(64,88,104,120):
            require(not mapped(maps,U(owner,at),U(owner,at+8)),"context destruction retained an owned arena")
    require(not mapped(maps,U(ctx,384),4096)and not mapped(maps,U(ctx,392),4096),"parent contexts survived owner retirement")
def read_role(source,data,role,name):
    folder=data/role;report=decode((folder/"CAPTURE.json").read_bytes());queries=group(name)
    require(report["status"]=="PASS"and report["role"]==role and report["group"]==name
        and report["source"]==source_evidence(source)and report["cases"]==len(queries)
        and report["actual_inputs_only"]is True and report["expected_values_generated"]is False
        and report["actual_python"]["binary"]==PYTHON,"complete source-owned actual capture")
    values=rows(folder,report);require([v["input"]for v in values]==queries,"all exact frozen input bytes")
    reader,producer_buffers=open_buffers(folder,report);build=decode((source/"BUILD_REUSE.json").read_bytes())
    require(pin(data/"production/multi-read-body-callable.elf")==build["elf"]and (data/"production/multi-read-body-callable.elf").stat().st_mode&0o777==0o500,"same actual executable retained")
    require({p.name for p in folder.iterdir()}=={"CAPTURE.json","buffer-index.jsonl","buffers","carriers","cases.jsonl.gz"}
        and {p.name for p in(folder/"carriers").iterdir()}=={str(q["id"])for q in queries},"complete actual role inventory")
    binding=reference_binding(source);require(len(report["processes"])==len(values),"one process for each frozen input")
    counts=dict(entry_invocations=0,body_calls=0,parent_calls=0,child_calls=0,formatter_calls=0,os_calls=0,
        journal_bytes=0,full_buffer_bytes=0,events=0,private_controls=0,orphans=0,eof_witnesses=0,observer_off_inputs=0)
    for case,process_pin in zip(values,report["processes"]):
        walk(case,reader);q=case["input"];setup(case);chain=case["actual"]["chain"];where=folder/case["process_path"]
        query=actual_query(q,Path(case["fixture_root"]));require(chain["actual_query"]==query,"actual request path binds owned fixture")
        for name_file in("before","after"):file_snapshot(chain[name_file])
        file_snapshot(case["after_exit"])
        receipt=decode((where/"carrier-process.json").read_bytes())
        require(process_pin==dict(id=q["id"],path=case["process_path"],receipt=pin(where/"carrier-process.json"))
            and receipt==case["process"]and receipt["binary"]==(build["elf"]if role=="native"else PYTHON)
            and case["whole_process_exited"]is True,"complete natural process receipt")
        require({p.name for p in where.iterdir()}=={"carrier-process.json","carrier.stdin","carrier.stderr","carrier.stdout.gz","carrier.journal.gz","exchanges.jsonl"},"complete actual process file set")
        exchanges=[decode(r)for r in(where/"exchanges.jsonl").read_bytes().splitlines()]
        for r in exchanges:walk(r,reader)
        stream_custody(where,receipt,exchanges,reader)
        require(sorted(references(case["actual"]))==list(range(1,len(exchanges)+1)),"every actual exchange is owned exactly once")
        def exchange(number,command,slot):
            require(type(number)is int and 1<=number<=len(exchanges),"owned exchange number")
            row=exchanges[number-1];require(row["command"]==command and row["session"]==slot,"actual command/slot")
            return row,reader.get(row["input"])[72:],reader.get(row["output"])
        def snapshot(row,command,slot):
            _,request,reply=exchange(row["exchange"],command,slot);raw=reader.get(row["bytes"])
            require(not request and U(reply,8)==0 and reply[64:]==raw,"whole physical controller snapshot")
            return raw
        slots=[0,1]if q["attempts"]==2 and not q["reuse_context"]else[q["id"]%2]
        used=slots if len(slots)==q["attempts"]else[slots[0]]*q["attempts"]
        require(chain["slots"]==slots and chain["invocation_slots"]==used and len(chain["creates"])==len(slots),"exact distinct/reused context domain")
        for c,slot in zip(chain["creates"],slots):
            _,request,reply=exchange(c["exchange"],8 if q["observer"]else 9,slot)
            require(c["slot"]==slot and not request and U(reply,8)==U(reply,24)==U(reply,32)==0,"fresh actual context")
        if q["control_fd0"]:
            _,request,reply=exchange(chain["control_move_exchange"],17,slots[0])
            require(not request and U(reply,8)==0 and"0"not in chain["fds_before"],"only caller-owned control pipe moved")
        else:require("control_move_exchange"not in chain,"undeclared FD0 setup")
        events=hooks(case,reader);case["_hooks"]=events
        controls=chain["controls"]
        require(len(controls)==(14 if role=="native"and q["native_protocol_controls"]else 0),"complete native private control domain")
        for c in controls:
            _,payload,reply=exchange(c["exchange"],c["command"],slots[0])
            require(U(reply,8)==c["code"]and snapshot(c["before"],4,slots[0])==snapshot(c["after"],4,slots[0]),
                "private refusal changed full context")
            for cmd,key in((5,"workspace"),(6,"output"),(7,"input"),(15,"parents")):
                require(snapshot(c["arenas_before"][key],cmd,slots[0])==snapshot(c["arenas_after"][key],cmd,slots[0]),
                    "private refusal changed complete workspace/output/input/parent buffers")
            counts["private_controls"]+=1
        pools=[];states={};last_contexts={};context_addresses={};orphans=set()
        if role=="native":
            for p in chain["pool_snapshots"]:
                raw=snapshot(p,11,slots[0]);value=pool(raw)
                require(value["pid"]==receipt["pid"],"pool bound to actual OS producer")
                pools.append(dict(label=p["label"],raw=raw,value=value))
            require(pools and pools[0]["label"]=="fresh"and not pools[0]["value"]["records"]
                and len({p["value"]["address"]for p in pools})==1
                and len({p["label"]for p in pools})==len(pools),"one empty process-wide pool")
            require(set(chain["fresh_snapshots"])==set(map(str,slots)),"all fresh contexts retained")
            for slot in slots:
                fresh=chain["fresh_snapshots"][str(slot)]
                ctx=snapshot(fresh["context"],4,slot);context(ctx,q["observer"],0)
                work=snapshot(fresh["workspace"],5,slot);output=snapshot(fresh["output"],6,slot)
                raw_parents=snapshot(fresh["parents"],15,slot);require(len(raw_parents)==8192,"both full fresh parents")
                require(work==bytes(4096)and output==bytes(4096)and U(ctx,192)==U(ctx,400)==0
                    and U(ctx,376)==pools[0]["value"]["address"],"complete empty actual arenas")
                parents=[]
                for i in range(2):
                    pc=raw_parents[i*4096:(i+1)*4096];idle_parent(pc,q["observer"])
                    require(U(pc,192)==0,"fresh parent generation")
                    parents.append(dict(work=bytes(4096),call=0,fds={},generation=0,ctx=pc))
                states[slot]=dict(work=work,owned={},generation=0,parents=parents)
            journal=Journal(where/"carrier.journal.gz",events)
        else:
            require(not chain["pool_snapshots"]and not chain["fresh_snapshots"],"original does not invent native controllers")
            case["_original_events"]=original_journal(where,receipt["journal"],events)
            counts["journal_bytes"]+=receipt["journal"]["raw"]["bytes"]
        case["_native_invocations"]=[];baseline=set(chain["fds_before"]);previous=set(baseline);orphan_fds=[]
        require(len(chain["invocations"])==q["attempts"],"all original/native entry calls")
        for attempt,row in enumerate(chain["invocations"],1):
            slot=used[attempt-1];generation=attempt if q["reuse_context"]else 1
            require((row["attempt"],row["slot"],row["generation"])==(attempt,slot,generation),"actual request generation")
            x,packet,reply=exchange(row["exchange"],1,slot);frame=reader.get(row["frame"])
            require(packet==reader.get(row["packet"])==(wire(query)if role=="native"else encoded(query))
                and frame==reply[64:]and U(reply,8)==(64 if role=="native"else 0)
                and U(reply,24)==2 and U(reply,40)==0,"same complete actual packet/result loan")
            if q["fault"]:
                _,arm,armed=exchange(row["arm_exchange"],18,slot)
                require(arm==struct.pack("<2Q",q["fault"]["phase"],q["fault"]["role"])
                    and U(armed,8)==0,"real source-owned kernel fault armed")
            else:require(row["arm_exchange"]is None,"undeclared fault")
            if role=="native":
                value=result(frame);require(value==row["result"],"complete native result decoded from actual bytes")
                captures={key:snapshot(row["snapshots"][key],cmd,slot)for cmd,key in
                    ((4,"context"),(5,"workspace"),(6,"output"),(7,"input"),(15,"parents"))}
                ctx=captures["context"];context(ctx,q["observer"],2)
                require(U(ctx,168)==len(frame)and U(ctx,176)==64 and U(ctx,192)==generation
                    and U(ctx,248)>0 and U(ctx,80)==len(packet),"complete actual invocation counters")
                require(len(captures["input"])==U(ctx,72)and captures["input"][:len(packet)]==packet
                    and captures["input"][len(packet):]==bytes(len(captures["input"])-len(packet)),"whole original input arena")
                require(len(captures["workspace"])==U(ctx,96)and len(captures["output"])==U(ctx,112)
                    and captures["output"][:len(frame)]==frame and captures["output"][len(frame):]==b"\xa5"*(len(captures["output"])-len(frame)),
                    "complete actual output and untouched suffix")
                require(len(captures["parents"])==8192,"whole two parent contexts")
                parent_contexts=[captures["parents"][i*4096:(i+1)*4096]for i in range(2)]
                for pc in parent_contexts:idle_parent(pc,q["observer"])
                if q["observer"]:
                    require(journal.position==x["journal_begin"],"full application journal start")
                    parsed=invocation(journal,packet,frame,generation,states[slot],orphans)
                    require(journal.position==x["journal_end"]and parsed["work"]==captures["workspace"]
                        and parsed["output"]==captures["output"]and U(ctx,248)==parsed["body_calls"]
                        and captures["parents"]==b"".join(p["ctx"]for p in states[slot]["parents"]),
                        "all final physical buffers equal the complete call journal")
                    case["_native_invocations"].append(parsed)
                else:
                    require(x["journal_begin"]==x["journal_end"]==0 and not q["fault"],"observer-off actual calls have no hidden capture")
                    parsed=dict(orphaned=[]);case["_native_invocations"].append(dict(effects=[]))
                if not value["ok"]:
                    dx,dpacket,dreply=exchange(row["diagnostic_exchange"],13,slot);diagnostic=reader.get(row["diagnostic"])
                    require(not dpacket and U(dreply,8)==len(diagnostic)and dreply[64:]==diagnostic,"complete actual formatter output")
                    if q["observer"]:
                        require(journal.position==dx["journal_begin"],"actual formatter journal start");journal.formatter(frame,diagnostic)
                        require(journal.position==dx["journal_end"],"actual formatter journal end")
                    else:require(dx["journal_begin"]==dx["journal_end"]==0,"observer-off formatter journal")
                    value["_diagnostic"]=diagnostic.decode("utf-8");row["result"]["_diagnostic"]=value["_diagnostic"]
                current=next(p for p in pools if p["label"]=="after-result-"+str(attempt));records=current["value"]["records"]
                expected_orphans=attempt if q["fault"]and q["fault"]["phase"]==23 else 0
                require(len(records)==expected_orphans and U(ctx,376)==current["value"]["address"]
                    and U(ctx,400)==(generation if expected_orphans else 0),"actual shared process pool transition")
                require(len(parsed["orphaned"])==int(expected_orphans>0),"only first regular fstat transfers to orphan pool")
                if expected_orphans:
                    newest=records[-1];require(newest["generation"]==generation and newest["fd"]==parsed["orphaned"][0]["fd"],"exact actual orphan generation/token")
                    if slot in context_addresses:require(context_addresses[slot]==newest["context"],"same reused context")
                    else:
                        require(newest["context"]not in context_addresses.values(),"distinct actual originating contexts")
                        context_addresses[slot]=newest["context"]
                    orphan_fds.append(str(newest["fd"]))
                require([str(r["fd"])for r in records]==orphan_fds,"complete append-only actual orphan inventory")
                maps=mappings(reader.get(row["process_with_result"]["maps"]));arena_mappings(ctx,maps)
                for pc in parent_contexts:arena_mappings(pc,maps)
                require(guarded_mapping(maps,current["value"]["address"])
                    and all(guarded_mapping(maps,p)for p in current["value"]["pages"])
                    and all(guarded_mapping(maps,r["context"])for r in records),"all actual shared pool and live context guard pages")
                last_contexts[slot]=(ctx,parent_contexts)
                if q["cleanup"]!="eof-borrow":
                    released=snapshot(row["released_context"],4,slot);expected=bytearray(ctx)
                    for at in(56,168,176):struct.pack_into("<Q",expected,at,0)
                    require(released==expected and snapshot(row["released_parents"],15,slot)==captures["parents"],"release only retires the result loan")
                    after=next(p for p in pools if p["label"]=="after-release-"+str(attempt))
                    require(after["raw"]==current["raw"],"release changed process-lifetime inventory")
            else:
                value=decode(frame);require(value==row["result"]and value["binding"]==binding,"actual unmodified original target result")
                require(value["actual_seccomp_filters"]==(attempt if q["fault"]else 0),"complete real original EIO injection count")
                current=set(row["fds_with_result"]);new=current-previous
                require(len(new)==int(q["fault"]is not None and q["fault"]["phase"]==23),"original first-fstat leak extent")
                orphan_fds+=sorted(new);previous=current
            live=baseline|set(orphan_fds)
            require(set(row["fds_with_result"])==live and row["process_with_result"]["fd"]==
                {k:v["target"]for k,v in row["fds_with_result"].items()},"actual result leaves only original process orphans")
            if q["fault"]:require(not value["ok"]and value["error"]["type"]=="OSError"and value["error"]["errno"]==5
                and value["error"]["filename"]is None,"actual real-kernel EIO envelope")
            for fd in orphan_fds:
                require(fd in row["fds_with_result"]and row["fds_with_result"][fd]["stat"]["st_mode"]&61440==32768,
                    "orphan remains an actual regular file")
            if q["cleanup"]!="eof-borrow":
                _,payload,released=exchange(row["release_exchange"],2,slot)
                require(not payload and U(released,8)==U(released,24)==U(released,40)==0
                    and set(row["fds_after_release"])==live,"actual release preserves all process orphans")
            else:require("release_exchange"not in row,"actual EOF with live result was prematurely released")
            counts["entry_invocations"]+=1
        if q["control_fd0"]:
            body_opens=[e for e in(case["_original_events"]if role=="original"else case["_native_invocations"][0]["effects"])
                if e["owner"]=="body"and e["operation"]==1]
            require(body_opens and (body_opens[0]["value"]if role=="original"else body_opens[0]["raw_result"])==0,"actual source file uses FD zero")
        live=baseline|set(orphan_fds)
        if q["cleanup"]=="explicit":
            require([d["slot"]for d in chain["destroys"]]==slots,"all actual context destructions")
            for d in chain["destroys"]:
                _,payload,reply=exchange(d["exchange"],3,d["slot"])
                require(not payload and U(reply,8)==U(reply,24)==0 and set(d["fds"])==live,"context destroy did not close process orphans")
                if role=="native":
                    observed=next(p for p in pools if p["label"]=="after-destroy-"+str(d["slot"]))
                    require(observed["raw"]==pools[-1]["raw"],"context destroy changed orphan pool bytes")
                    maps=mappings(reader.get(d["process"]["maps"]));retired(*last_contexts[d["slot"]],maps)
                    if d["slot"]in context_addresses:require(not mapped(maps,context_addresses[d["slot"]],4096),"orphan-origin context survived destroy")
        else:require(not chain["destroys"],"EOF cleanup was replaced by explicit destruction")
        require(set(chain["before_eof"])==live,"all actual FDs before EOF")
        witness=case["actual"]["hooks"]["eof"][0];eofraw=reader.get(witness["raw"])
        moved=baseline-{"0","1","2","3","4","5"}if q["control_fd0"]else set()
        require(len(moved)==int(q["control_fd0"])and set(witness["fds"])==live-moved,"actual EOF retains exact original orphan FDs")
        if role=="native":
            final=pools[-1]["value"];maps=mappings(reader.get(witness["maps"]))
            require(U(eofraw,8)==len(orphan_fds)and U(eofraw,16)==len(final["pages"])
                and guarded_mapping(maps,final["address"])and all(guarded_mapping(maps,p)for p in final["pages"]),"actual EOF preserves guarded process pool")
            for slot in slots:retired(*last_contexts[slot],maps)
            for address in context_addresses.values():require(not mapped(maps,address,4096),"EOF retained originating context")
            if q["native_protocol_controls"]:
                _,payload,reply=exchange(chain["foreign_pid_exchange"],20,slots[0])
                require(not payload and U(reply,8)==0,"actual distinct-PID pool rejection")
                before=next(p for p in pools if p["label"]=="before-foreign-pid")
                after=next(p for p in pools if p["label"]=="after-foreign-pid")
                require(before["raw"]==after["raw"],"foreign PID modified shared pool");counts["private_controls"]+=1
            measured=journal.finish(receipt["journal"])
            for k,v in measured.items():counts[k]+=v
        else:require(eofraw[8:]==bytes(56),"original has no invented native pool")
        case["_orphan_fds"]=orphan_fds;counts["orphans"]+=len(orphan_fds);counts["eof_witnesses"]+=1
        counts["observer_off_inputs"]+=not q["observer"]
    counts["producer_buffers"]=producer_buffers;counts["buffer_read"]=reader.finish()
    require(counts["buffer_read"]["blocks"]==report["buffers"]["blocks"]
        and counts["entry_invocations"]==report["entry_invocations"],"all original recorded buffers and invocations")
    return values,counts,report
def verify(source,data,name):
    source=Path(source).resolve(strict=True);data=Path(data).resolve(strict=True)
    require({p.name for p in data.iterdir()}=={"original","native","production"}and {p.name for p in(data/"production").iterdir()}=={"multi-read-body-callable.elf"},"complete actual application inventory")
    a,ac,ar=read_role(source,data,"original",name);b,bc,br=read_role(source,data,"native",name)
    require(ar["platform"]==br["platform"],"same actual OS/Python fixture environment")
    pairs=[compare(x,y)for x,y in zip(a,b)]
    return dict(status="COMPLETE_ORIGINAL_NATIVE_MULTI_FILESYSTEM_PASS",group=name,cases=len(pairs),pairs=pairs,original=ac,native=bc,
        public_routes_qualified=False,whole_runtime_replaced=False,actual_application_replays=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--data",type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args();print(encoded(verify(a.source,a.data,a.group)).decode(),end="")
if __name__=="__main__":main()
