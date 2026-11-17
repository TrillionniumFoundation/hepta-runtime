"""Actual body calls, fixed child snapshots, one process pool and EOF ownership."""
import struct
from evidence_common import encoded,decode,require
from protocol import U,result,wire,proc_fds
from hooks import Hooks
from cases import actual_query
def run(carrier,q,fixture,store,native):
    slots=[0,1]if q["attempts"]==2 and not q["reuse_context"]else[q["id"]%2]
    used=slots if len(slots)==q["attempts"]else[slots[0]]*q["attempts"]
    query=actual_query(q,fixture.root)
    chain=dict(slots=slots,invocation_slots=used,creates=[],controls=[],invocations=[],
        destroys=[],pool_snapshots=[],actual_query=query,fresh_snapshots={})
    for slot in slots:
        raw,n=carrier.exchange(8 if q["observer"]else 9,slot)
        require(U(raw,8)==0 and U(raw,24)==0,"fresh actual context")
        chain["creates"].append(dict(slot=slot,exchange=n))
    if q["control_fd0"]:
        raw,n=carrier.exchange(17,slots[0]);require(U(raw,8)==0,"actual control relocation")
        chain["control_move_exchange"]=n
    hooks=Hooks(q,carrier.pid,fixture,store,reference=not native);carrier.hooks=hooks
    def snapshot(command,slot):
        raw,n=carrier.exchange(command,slot);require(U(raw,8)==0,"complete native snapshot")
        return dict(exchange=n,bytes=store.put(raw[64:]))
    def pool(label):
        row=snapshot(11,slots[0]);row["label"]=label;chain["pool_snapshots"].append(row);return row
    if native:
        pool("fresh")
        for slot in slots:
            chain["fresh_snapshots"][str(slot)]={key:snapshot(cmd,slot)for cmd,key in
                ((4,"context"),(5,"workspace"),(6,"output"),(15,"parents"))}
    chain["before"]=fixture.all();chain["fds_before"]=proc_fds(carrier.pid)
    if native and q["native_protocol_controls"]:
        slot=slots[0]
        def refuse(label,command,payload,code):
            before=snapshot(4,slot);raw,n=carrier.exchange(command,slot,payload);after=snapshot(4,slot)
            require(U(raw,8)==code and before["bytes"]==after["bytes"],"physical refusal changed context")
            chain["controls"].append(dict(label=label,command=command,exchange=n,code=code,before=before,after=after))
        packet=wire(query)
        refuse("short-body-header",1,packet[:95],0xffffffff)
        bad=bytearray(packet);bad[0]^=1;refuse("body-magic",1,bytes(bad),0xffffffff)
        for at,value in((8,2),(16,1),(56,1),(64,1),(72,1),(80,1),(88,len(packet))):
            bad=bytearray(packet);struct.pack_into("<Q",bad,at,value)
            refuse("private-word-"+str(at),1,bytes(bad),0xffffffff)
        refuse("release-without-loan",2,b"",0xffffffff)
        refuse("unowned-orphan-token",19,b"",0xffffffff)
        refuse("duplicate-create",8,b"",0xfffffffd)
        before=pool("before-foreign-pid");raw,n=carrier.exchange(20,slot)
        require(U(raw,8)==0,"actual distinct PID refusal")
        after=pool("after-foreign-pid");require(before["bytes"]==after["bytes"],"foreign PID changed pool")
        chain["foreign_pid_exchange"]=n
    for attempt,slot in enumerate(used,1):
        hooks.begin(attempt)
        if q["fault"]:
            raw,n=carrier.exchange(18,slot,struct.pack("<2Q",q["fault"]["phase"],q["fault"]["role"]))
            require(U(raw,8)==0,"actual kernel fault arm");armed=n
        else:armed=None
        packet=wire(query)if native else encoded(query)
        hooks.limit_enter()
        try:raw,n=carrier.exchange(1,slot,packet)
        finally:hooks.limit_leave()
        require(U(raw,8)==(64 if native else 0) and U(raw,24)==2 and U(raw,40)==0,
            "actual body did not publish a complete terminal response")
        frame=raw[64:];value=result(frame)if native else decode(frame);captures={}
        row=dict(attempt=attempt,slot=slot,exchange=n,generation=U(raw,32),arm_exchange=armed,
            packet=store.put(packet),frame=store.put(frame),result=value,snapshots=captures)
        chain["invocations"].append(row)
        if native:
            if not value["ok"]:
                diagnostic,index=carrier.exchange(13,slot)
                require(U(diagnostic,8)==len(diagnostic)-64,"complete actual diagnostic")
                row["diagnostic_exchange"]=index;row["diagnostic"]=store.put(diagnostic[64:])
            for command,name in((4,"context"),(5,"workspace"),(6,"output"),(7,"input"),(15,"parents")):
                captures[name]=snapshot(command,slot)
            pool("after-result-"+str(attempt))
            if q["native_protocol_controls"]:
                for label,command,payload in(("live-invoke",1,packet),("live-destroy",3,b"")):
                    before=snapshot(4,slot);bad,index=carrier.exchange(command,slot,payload);after=snapshot(4,slot)
                    require(U(bad,8)==0xfffffffd and before["bytes"]==after["bytes"],"live loan was modified")
                    chain["controls"].append(dict(label=label,command=command,exchange=index,code=0xfffffffd,before=before,after=after))
        row["fds_with_result"]=proc_fds(carrier.pid);row["process_with_result"]=carrier.observed_process()
        if q["cleanup"]!="eof-borrow":
            released,index=carrier.exchange(2,slot)
            require(U(released,8)==0 and U(released,24)==0 and U(released,40)==0,"actual result release")
            row["release_exchange"]=index;row["fds_after_release"]=proc_fds(carrier.pid)
            row["process_after_release"]=carrier.observed_process()
            if native:
                row["released_context"]=snapshot(4,slot);row["released_parents"]=snapshot(15,slot)
                pool("after-release-"+str(attempt))
    chain["after"]=fixture.all()
    if q["cleanup"]=="explicit":
        for slot in slots:
            raw,n=carrier.exchange(3,slot)
            require(U(raw,8)==0 and U(raw,24)==0,"actual context destruction")
            chain["destroys"].append(dict(slot=slot,exchange=n,fds=proc_fds(carrier.pid),
                process=carrier.observed_process()))
            if native:pool("after-destroy-"+str(slot))
    chain["before_eof"]=proc_fds(carrier.pid);chain["process"]=carrier.observed_process()
    return dict(chain=chain,hooks=hooks.result())
