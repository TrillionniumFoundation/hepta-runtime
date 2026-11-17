#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Consume every native journal byte and prove actual job/borrow/reap custody."""
import struct
from common import require,sha
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
def words(raw):return struct.unpack("<%dQ"%(len(raw)//8),raw)
def pool_state(raw):
    require(len(raw)>=192 and len(raw)%4096==0 and raw[:8]==b"HPTWS001","whole allocated worker state")
    h=words(raw[:192]);used=h[15]
    require(h[2] in (0,1) and h[3]>0 and 192<=used<=len(raw) and (used-192)%128==0
        and not any(raw[152:192]) and not any(raw[used:]),"full pool reserved/tail bytes")
    records={}
    for at in range(192,used,128):
        r=words(raw[at:at+128])
        if r[0]==0:require(not any(r),"retired record not wholly zero");continue
        require(r[0] not in records and 0<r[0]<=h[1] and r[1] in range(1,6)
            and r[2] in range(4) and r[3] in (0,1) and r[8] in (0,1) and r[9] in (0,1)
            and not any(r[10:]),"complete live record shape")
        require(not (r[1]==5 and r[3]==1 and r[2] in (1,3)),"eligible record was not retired")
        records[r[0]]=(at,r)
    rows=[r for _,r in records.values()]
    require(h[5]==len(rows)==h[1]-h[14] and h[4]==sum(r[1] in (2,3,4) for r in rows)<=h[3],"actual live/active conservation")
    require(h[9]==h[1]-h[4]-sum(r[1]==1 for r in rows) and h[6]==h[1]-sum(r[1]==1 for r in rows),"queue/complete conservation")
    require(h[13]==h[14]+sum(r[3] for r in rows),"actual reap conservation")
    require(h[10]+h[11]==h[14]+sum(r[2]!=0 for r in rows)
        and h[11]-h[12]==sum(r[2]==2 for r in rows)
        and h[10]+h[12]==h[14]+sum(r[2] in (1,3) for r in rows),"Drop/borrow/release conservation")
    require(not any(h[16:19]),"ordinary domain contains no synthetic clone/worker failure")
    return h,records
def verify(path,case,commands,expected_jobs,parent_pid):
    frames=0;total=0;logical=0;last_ordinal=0;pool_address=None;previous=None
    clones={};reaps={};starts={};finishes={};drops=set();takes=set();releases=set();enqueued=[]
    reservations=[];bodies={};mutations=0;growth=0;before_growth=None
    with path.open("rb") as stream:
        def read_frame():
            nonlocal frames,total
            head=stream.read(64)
            if not head:return None
            require(len(head)==64 and head[:8]==b"HPTWJR01" and U(head,56)==0,"full private native journal header")
            length=U(head,24);require(length<=256<<20,"owned complete journal span bound")
            raw=stream.read(length);require(len(raw)==length,"complete native journal span")
            frames+=1;total+=64+length
            require(U(head,40)==parent_pid,"journal creator identity")
            return head,raw
        while True:
            frame=read_frame()
            if frame is None:break
            head,raw=frame;event=U(head,8);sequence=U(head,16);address=U(head,32);pid=U(head,48)
            if pool_address is None:pool_address=address
            require(address==pool_address and address>0,"single actual pool capability")
            if event==1:
                require(len(raw)==64 and raw[:8]==b"HPTWQ001" and not any(raw[40:]),"complete actual HIA input")
                bundle=[frame]
                for want in (2,3,4):
                    item=read_frame();require(item is not None,"complete HIA four-frame transaction")
                    h,data=item
                    require(U(h,8)==want and U(h,16)==sequence and U(h,32)==address and U(h,48)==pid,"uninterleaved HIA transaction")
                    bundle.append(item)
                require(sequence==last_ordinal+1,"all actual HIA calls preserved in order");last_ordinal=sequence
                req=raw;out=bundle[1][1];state=bundle[2][1];ret=bundle[3][1]
                require(len(out)==320 and len(ret)==8,"complete HIA output and raw return")
                rc=U(ret,0);command=U(req,8);job=U(req,16);now=U(req,24);arg=U(req,32)
                require(command<=14,"fixed actual HIA operation")
                old=previous if previous is not None else bytes(len(state))
                require(len(state)>=len(old),"pool workspace may not shrink")
                if len(state)>len(old):
                    require(before_growth is not None and req==before_growth[0] and command==1
                        and len(state)>=before_growth[1] and before_growth[1]==U(old,120)+128,
                        "growth retry belongs to one real unchanged request")
                    expanded=old+bytes(len(state)-len(old));at=U(old,120)
                    allowed=((8,16),(40,48),(120,128),(at,at+128))
                    cursor=0
                    for left,right in allowed:
                        require(state[cursor:left]==expanded[cursor:left],"growth changed bytes outside exact enqueue fields")
                        cursor=right
                    require(state[cursor:]==expanded[cursor:],"growth extension not zero outside the actual new record")
                if rc==0xffffffd0:
                    require(out[:8]==b"HGRWS002" and U(out,8)==1 and U(out,16)>len(state)
                        and not any(out[24:]) and state==old,"growth preserves complete state")
                    before_growth=(req,U(out,16));growth+=1;previous=state;continue
                before_growth=None
                if rc==0xffffffff:
                    require(state==old and not any(out),"raw lifecycle refusal preserves all HIA buffers")
                    previous=state;continue
                require(rc==320 and out[:8]==b"HPTWR001" and U(out,8)==320 and U(out,24)==command
                    and not any(out[120:128]),"real HIA success envelope")
                h,records=pool_state(state);status=U(out,16)
                require(out[128:]==state[:192],"complete post-transition HIA header is delivered")
                require(pid==parent_pid if command not in (4,5) else job in clones and pid==clones[job]["pid"],
                    "parent and actual clone mutation ownership")
                if command==1 and status==0:
                    issued=U(out,32);require(issued==len(enqueued)+1,"unique monotonic actual generation")
                    enqueued.append(issued);require(records[issued][1][1:4]==(1,0,0),"real queued record")
                if command==2 and status==0:
                    issued=U(out,32);oldh,oldrecords=pool_state(old)
                    queued=[j for j,(_,r) in oldrecords.items() if r[1]==1]
                    require(queued and issued==min(queued),"actual FIFO admission")
                    reservations.append(issued)
                if command==3:
                    require(job in clones and job not in starts and status==0,"clone ACK precedes BEGIN")
                    clones[job]["ack"]=sequence
                if command==4:
                    require(job in clones and "ack" in clones[job] and job not in starts and status==0,"BEGIN has one acknowledged clone")
                    starts[job]=dict(sequence=sequence,now=now)
                if command==5:
                    require(job in starts and job not in finishes and now>=starts[job]["now"] and status==0,"one monotonic real COMPLETE")
                    require(job in bodies and bodies[job].get("terminal") is not None and arg==64
                        and bodies[job]["terminal_context_open_fds"]==0,"COMPLETE follows actual closed-FD body return")
                    finishes[job]=dict(sequence=sequence,now=now,raw=arg)
                if command==6:
                    require(status==0 and job in enqueued and job not in takes,"Drop only awaiting actual issued job")
                    drops.add(job)
                if command==8 and status==0:
                    require(job in finishes and job not in takes and job not in drops,"TAKE follows COMPLETE and retains owner")
                    takes.add(job)
                if command==9:
                    require(status==0 and job in takes and job not in releases,"release follows one actual borrow")
                    releases.add(job)
                if command==10:
                    require(job in reaps and job in finishes and status==0,"HIA reap follows actual wait4")
                previous=state;mutations+=1
            elif event in (5,6):
                require(len(raw)==32 and pid==parent_pid,"actual clone/wait4 record")
                job,tag,child,outcome=words(raw)
                require(job in expected_jobs and expected_jobs[job]["tag"]==tag and child>0,"native process belongs to exact submitted job")
                if event==5:
                    require(job not in clones and outcome==0 and job in reservations,"single successful actual clone")
                    clones[job]=dict(pid=child,sequence=sequence)
                else:
                    require(job in clones and clones[job]["pid"]==child and job not in reaps and outcome==0,"single actual successful wait4")
                    reaps[job]=dict(sequence=sequence,pid=child)
            elif event==7:
                require(len(raw)==56,"complete body observation identity")
                job,tag,context,body_event,extent,effect_sequence,opcode=words(raw)
                require(job in clones and clones[job]["pid"]==pid and job in starts and job not in finishes
                    and expected_jobs[job]["tag"]==tag,"body owned by actually begun clone")
                items=[]
                for want in (8,9):
                    value=read_frame();require(value is not None,"complete body event bundle")
                    h,data=value
                    require(U(h,8)==want and U(h,16)==sequence and U(h,32)==address and U(h,48)==pid,"uninterleaved complete body spans")
                    items.append(data)
                span,ctx=items
                require(len(span)==extent and len(ctx)==4096 and ctx[:8]==b"HTPCCI01" and U(ctx,8)==4096
                    and U(ctx,216)==effect_sequence and U(ctx,224)==opcode,"full actual body context and extent")
                body=bodies.setdefault(job,dict(context=context,input_seen=False,last_output=None,pending=None,terminal=None,
                    events=0,bytes=0,initial=expected_jobs[job]["input"]))
                require(body["context"]==context,"body context not replaced within job")
                body["events"]+=1;body["bytes"]+=len(span)+len(ctx);logical+=len(span)+len(ctx)
                require(body_event in (1,2,3,4,5,6,7,8,9,18,19),"fixed body observer event")
                if body_event==1:
                    require(span[:8]==b"HTPBQ001" and len(span)==U(ctx,208),"complete actual HIA body input")
                    if not body["input_seen"]:
                        require(span==body["initial"],"worker copied exact full submitted input")
                        body["input_seen"]=True
                    elif U(span,8)==2:require(span==body.get("ack"),"next body invocation consumes exact effect ACK")
                    else:require(span==body["initial"],"growth retry preserves original full input")
                elif body_event==2:
                    require(len(span)==U(ctx,112) and span[:8]==b"HTPBS001" and U(ctx,176)==64
                        and U(span,8)<=5 and U(span,56)<=len(span)-64,"complete actual body output")
                    body["last_output"]=span
                    kind=U(span,8)
                    if kind in (0,3):
                        require(not any(span[24:56]) and U(ctx,184)==0,"terminal body has closed every owned descriptor")
                        body["terminal"]=span[:64+U(span,56)];body["terminal_context_open_fds"]=U(ctx,184)
                    elif kind in (1,2):
                        require(body["pending"] is None,"effect duplicated without actual ACK")
                        body["pending"]=(U(span,16),U(span,24),kind)
                elif body_event==8:
                    require(body["last_output"] is not None and span==body["last_output"][:64+U(body["last_output"],56)]
                        and U(span,8)==1 and body["pending"]==(effect_sequence,opcode,1),"actual native effect from HIA action")
                elif body_event==9:
                    require(body["pending"] is not None and span[:8]==b"HTPBQ001" and U(span,8)==2
                        and U(span,16)==body["pending"][0] and not any(span[32:56])
                        and len(span)==64+U(span,56),"complete matching effect ACK")
                    body["ack"]=span;body["pending"]=None
                elif body_event==3:body["growth_before"]=span
                elif body_event==4:
                    before=body.pop("growth_before")
                    require(len(span)>len(before) and span[:len(before)]==before and not any(span[len(before):]),
                        "complete body growth prefix and zero extension")
            else:raise ValueError("unknown native journal event")
    if not case["observer"]:
        require(frames==0 and total==0,"observer-disabled execution wrote journal bytes")
        return dict(status="OBSERVER_DISABLED_JOURNAL_EMPTY",frames=0,bytes=0)
    require(previous is not None and before_growth is None,"complete initialized HIA journal")
    header,records=pool_state(previous)
    require(header[4]==header[5]==0 and header[1]==header[9]==header[13]==header[14]
        and not records and header[2]==1,"closed, completed, actually reaped and retired entire pool")
    require(set(expected_jobs)==set(enqueued)==set(clones)==set(starts)==set(finishes)==set(reaps)==set(bodies),
        "every actual enqueued job has complete clone/body/OS-reap custody")
    require(takes==releases and takes.isdisjoint(drops) and takes|drops==set(expected_jobs),"complete caller borrow/Drop disposition")
    for job,b in bodies.items():
        require(b["input_seen"] and b["terminal"] is not None and b["pending"] is None,"complete body input/effects/terminal")
        expected_jobs[job]["terminal"]=b["terminal"]
    if case["name"]=="fifo_growth":require(growth>=1,"full queue domain must exercise real HIA workspace growth")
    return dict(status="COMPLETE_NATIVE_WORKER_JOURNAL_PASS",frames=frames,bytes=total,hia_calls=last_ordinal,
        valid_transitions=mutations,jobs=len(clones),growth=growth,drop=sorted(drops),take=sorted(takes),
        reservations=reservations,body_events=sum(x["events"] for x in bodies.values()),
        complete_body_logical_bytes=logical,final_header=list(header))
