"""Actual borrowed-parent invocations and complete lifetime observations."""
import struct,time
from evidence_common import encoded,decode,require
from protocol import U,I,result,wire,proc_fds
from hooks import Hooks
def run(carrier,q,fixture,store,native):
    slots=[0,1]if q["attempts"]==2 else[q["id"]%2]
    chain=dict(slots=slots,creates=[],parents={},borrows=[],controls=[],invocations=[],destroys=[],pool_snapshots=[])
    for slot in slots:
        raw,n=carrier.exchange(8 if q["observer"]else 9,slot);require(U(raw,8)==0,"fresh actual context")
        chain["creates"].append(dict(slot=slot,exchange=n))
    def control_move():
        raw,n=carrier.exchange(17,slots[0]);require(U(raw,8)==0,"real control pipe relocation")
        chain["control_move_exchange"]=n
    if q["control_fd0"]=="parent":control_move()
    for slot in slots:
        raw,n=carrier.exchange(10,slot,str(fixture.parent_path).encode()+b"\0")
        fd=U(raw,8);require(fd<=2147483647 and U(raw,16)==0,"actual held parent")
        chain["parents"][str(slot)]=dict(fd=fd,exchange=n)
    if q["control_fd0"]=="file":control_move()
    parents={slot:chain["parents"][str(slot)]["fd"]for slot in slots}
    if q["close_parent_before"]:
        for slot in slots:
            raw,n=carrier.exchange(16,slot);require(U(raw,8)==0,"real negative parent close")
            chain["parents"][str(slot)]["closed_exchange"]=n
    chain["before"]=fixture.all(carrier.pid,parents);chain["fds_before"]=proc_fds(carrier.pid)
    def borrow(label):
        for slot in slots:
            raw,n=carrier.exchange(14,slot)
            require(I(U(raw,8))==(-9 if q["close_parent_before"]else 0)
                and U(raw,16)==(0 if q["close_parent_before"]else 144),"actual held parent lifetime")
            chain["borrows"].append(dict(label=label,slot=slot,exchange=n,stat=store.put(raw[64:])))
    def snapshot(command,slot):
        raw,n=carrier.exchange(command,slot);require(U(raw,8)==0,"full native snapshot")
        return dict(exchange=n,bytes=store.put(raw[64:]))
    def pool(label):
        row=snapshot(11,slots[0]);row["label"]=label;chain["pool_snapshots"].append(row);return row
    if native:pool("fresh")
    if native and q["native_protocol_controls"]:
        slot=slots[0]
        def refusal(label,command,payload,code):
            before=snapshot(4,slot);raw,n=carrier.exchange(command,slot,payload);after=snapshot(4,slot)
            require(U(raw,8)==code and before["bytes"]==after["bytes"],"actual refusal changed context")
            chain["controls"].append(dict(label=label,command=command,exchange=n,code=code,before=before,after=after))
        body=wire(q);bad=bytearray(body);struct.pack_into("<Q",bad,32,123)
        refusal("external-parent-word",1,bytes(bad),0xffffffff)
        bad=bytearray(body);struct.pack_into("<Q",bad,16,1)
        refusal("start-sequence",1,bytes(bad),0xffffffff)
        refusal("release-without-loan",2,b"",0xffffffff)
        refusal("unowned-orphan-token",19,b"",0xffffffff)
        before=pool("before-foreign-pid")
        raw,n=carrier.exchange(20,slot);require(U(raw,8)==0,"actual foreign PID pool refusal")
        after=pool("after-foreign-pid");require(before["bytes"]==after["bytes"],"foreign PID changed pool")
        chain["fork_refusal_exchange"]=n
    borrow("before");time.sleep(q["initial_quiet_seconds"])
    hooks=Hooks(q,carrier.pid,parents,fixture,store,reference=not native);carrier.hooks=hooks
    for attempt,slot in enumerate(slots,1):
        hooks.begin(attempt)
        if q["arm_fstat_error"]:
            raw,n=carrier.exchange(21 if q["fault_owner"]=="read"else 18,slot);require(U(raw,8)==0,"real fstat-filter arm")
            arm=n
        else:arm=None
        packet=wire(q)if native else encoded(q)
        hooks.limit_enter()
        try:raw,n=carrier.exchange(1,slot,packet)
        finally:hooks.limit_leave()
        require(U(raw,8)==(64 if native else 0)and U(raw,24)==2 and U(raw,40)==0,"actual info did not publish")
        frame=raw[64:];value=result(frame)if native else decode(frame);captures={}
        row=dict(attempt=attempt,slot=slot,exchange=n,generation=U(raw,32),arm_exchange=arm,
            packet=store.put(packet),frame=store.put(frame),result=value,snapshots=captures)
        chain["invocations"].append(row)
        if native:
            for command,name in((4,"context"),(5,"workspace"),(6,"output"),(7,"input"),(15,"children")):
                captures[name]=snapshot(command,slot)
            if not value["ok"]:
                formatted,number=carrier.exchange(13,slot)
                require(U(formatted,8)==U(formatted,16),"actual diagnostic formatter complete return")
                row["formatted"]=dict(exchange=number,bytes=store.put(formatted[64:]))
                value["error"]["exact_str"]=formatted[64:].decode()
            pool("after-result-"+str(attempt))
            if q["native_protocol_controls"]:
                for label,command,payload in(("live-invoke",1,packet),("live-destroy",3,b"")):
                    before=snapshot(4,slot);bad,index=carrier.exchange(command,slot,payload);after=snapshot(4,slot)
                    require(U(bad,8)==0xfffffffd and before["bytes"]==after["bytes"],"live loan was modified")
                    chain["controls"].append(dict(label=label,command=command,exchange=index,code=0xfffffffd,before=before,after=after))
        row["fds_with_result"]=proc_fds(carrier.pid);row["process_with_result"]=carrier.observed_process();borrow("after-result-"+str(attempt))
        released,index=carrier.exchange(2,slot);require(U(released,8)==0 and U(released,24)==0 and U(released,40)==0,"actual result release")
        row["release_exchange"]=index;row["fds_after_release"]=proc_fds(carrier.pid);row["process_after_release"]=carrier.observed_process();borrow("after-release-"+str(attempt))
        if native:pool("after-release-"+str(attempt))
    chain["after"]=fixture.all(carrier.pid,parents)
    for slot in slots:
        raw,n=carrier.exchange(3,slot);require(U(raw,8)==0 and U(raw,24)==0,"actual context destruction")
        chain["destroys"].append(dict(slot=slot,exchange=n,fd=proc_fds(carrier.pid),process=carrier.observed_process()));borrow("after-destroy-"+str(slot))
        if native:pool("after-destroy-"+str(slot))
    chain["before_parent_close"]=proc_fds(carrier.pid)
    for slot in slots:
        raw,n=carrier.exchange(12,slot);require(I(U(raw,8))==(-9 if q["close_parent_before"]else 0),"fixture parent owner close")
        chain["parents"][str(slot)]["close_exchange"]=n
    chain["before_eof"]=proc_fds(carrier.pid);chain["process"]=carrier.observed_process()
    carrier.hooks=None
    return dict(chain=chain,hooks=hooks.result())
