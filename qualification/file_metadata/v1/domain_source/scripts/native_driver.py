"""Invoke the fixed HIA/native callable and retain every fixture exchange."""
import struct
import time
from evidence_common import require
from protocol import U,I,result
from cases import snapshot,wire
def run(carrier,query,fixture,store):
    slot=query["id"]%2;chain=dict(slot=slot,files={},borrows=[],controls=[],invocations=[])
    raw,n=carrier.exchange(8 if query["observer"]else 9,slot);require(U(raw,8)==0,"fresh metadata native context")
    chain["create_exchange"]=n
    if query["mode"]!="summary":
        for role,command in(("source",10),("target",11)):
            raw,n=carrier.exchange(command,slot,str(fixture.paths[role]).encode()+b"\0")
            fd=U(raw,8);require(fd<2147483648 and U(raw,16)==0,"actual fixture open")
            chain["files"][role]=dict(fd=fd,exchange=n)
    fds={r:v["fd"]for r,v in chain["files"].items()};fixture.prepare_held()
    for role,command in(("source",16),("target",17)):
        if query.get("close_"+role+"_before"):
            raw,n=carrier.exchange(command,slot);require(I(U(raw,8))==0,"actual negative descriptor close");chain["close_"+role+"_exchange"]=n
    chain["before"]=fixture.all(carrier.pid,fds)
    def borrow(label):
        for role,command in(("source",14),("target",15)):
            if role not in fds:continue
            raw,n=carrier.exchange(command,slot)
            require(I(U(raw,8))==(-9 if query.get("close_"+role+"_before")else 0)
                and U(raw,16)==(0 if query.get("close_"+role+"_before")else 144),"borrowed descriptor lifetime differs")
            chain["borrows"].append(dict(label=label,role=role,exchange=n,stat=store.put(raw[64:])))
    def context():
        raw,n=carrier.exchange(4,slot);require(U(raw,8)==0 and U(raw,16)==4096,"full native context")
        return raw[64:],n
    def refusal(label,command,payload,code):
        before,first=context();raw,n=carrier.exchange(command,slot,payload);after,last=context()
        require(U(raw,8)==code and before==after,"protocol refusal changed complete context: "+label)
        chain["controls"].append(dict(name=label,command=command,exchange=n,code=code,
            before=dict(exchange=first,bytes=store.put(before)),after=dict(exchange=last,bytes=store.put(after))))
    borrow("before")
    time.sleep(query["initial_quiet_seconds"])
    from hooks import Hooks
    hooks=Hooks(query,carrier.pid,fds,fixture,store);carrier.hooks=hooks
    body=wire(query["mode"],snapshot(query["snapshot"])if query["mode"]=="summary"else b"")
    if query["native_protocol_controls"]and query["observer"]:
        bad=bytearray(body);struct.pack_into("<Q",bad,32,123)
        refusal("caller-selected-source-fd",1,bytes(bad),0xffffffff)
        bad=bytearray(body);struct.pack_into("<Q",bad,40,123)
        refusal("caller-selected-target-fd",1,bytes(bad),0xffffffff)
    def invoke(packet,label):
        raw,n=carrier.exchange(1,slot,packet)
        require(U(raw,8)==64 and U(raw,24)==2 and U(raw,40)==0,"actual metadata invocation did not publish")
        frame=raw[64:];value=result(frame);captures={}
        for command,name in((4,"context"),(5,"workspace"),(6,"output"),(7,"input")):
            observed,index=carrier.exchange(command,slot);require(U(observed,8)==0 and U(observed,24)==2,"full borrowed arena")
            captures[name]=dict(exchange=index,bytes=store.put(observed[64:]))
        row=dict(label=label,exchange=n,generation=U(raw,32),packet=store.put(packet),frame=store.put(frame),snapshots=captures,result=value)
        chain["invocations"].append(row)
        if query["native_protocol_controls"]and query["observer"]:
            refusal("invoke-with-live-result-loan-"+label,1,packet,0xfffffffd)
            refusal("destroy-with-live-result-loan-"+label,3,b"",0xfffffffd)
        borrow("after-result-"+label)
        released,index=carrier.exchange(2,slot);require(U(released,8)==0 and U(released,24)==0 and U(released,40)==0,"metadata result release")
        row["release_exchange"]=index;borrow("after-release-"+label)
        return frame,value
    frame,value=invoke(body,"initial")
    if query["mode"]=="capture-summary"and value["ok"]:
        frame,value=invoke(wire("summary",frame[64:]),"summary-of-actual-capture")
    chain["after"]=fixture.all(carrier.pid,fds);chain["process"]=carrier.observed_process()
    destroyed,n=carrier.exchange(3,slot);require(U(destroyed,8)==0 and U(destroyed,24)==0,"metadata context destruction")
    chain["destroy_exchange"]=n;borrow("after-destroy")
    for role,command in(("source",12),("target",13)):
        if role not in fds:continue
        raw,n=carrier.exchange(command,slot)
        require(I(U(raw,8))==(-9 if query.get("close_"+role+"_before")else 0),"fixture caller close")
        chain["files"][role]["close_exchange"]=n
    carrier.hooks=None;return dict(result=value,chain=chain,hooks=hooks.result())
