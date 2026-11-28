"""Actual original metadata function invocations, never predicted responses."""
import time
from evidence_common import encoded,decode,require
from protocol import U,I
def run(carrier,query,fixture,store):
    slot=query["id"]%2;chain=dict(slot=slot,files={},borrows=[],invocations=[])
    raw,n=carrier.exchange(8 if query["observer"]else 9,slot);require(U(raw,8)==0,"fresh original fixture generation");chain["create_exchange"]=n
    if query["mode"]!="summary":
        for role,command in(("source",10),("target",11)):
            raw,n=carrier.exchange(command,slot,str(fixture.paths[role]).encode()+b"\0")
            fd=U(raw,8);require(fd<2147483648 and U(raw,16)==0,"original fixture open")
            chain["files"][role]=dict(fd=fd,exchange=n)
    fds={r:v["fd"]for r,v in chain["files"].items()};fixture.prepare_held()
    for role,command in(("source",16),("target",17)):
        if query.get("close_"+role+"_before"):
            raw,n=carrier.exchange(command,slot);require(I(U(raw,8))==0,"original real negative close");chain["close_"+role+"_exchange"]=n
    chain["before"]=fixture.all(carrier.pid,fds)
    def borrow(label):
        for role,command in(("source",14),("target",15)):
            if role not in fds:continue
            raw,n=carrier.exchange(command,slot)
            require(I(U(raw,8))==(-9 if query.get("close_"+role+"_before")else 0)
                and U(raw,16)==(0 if query.get("close_"+role+"_before")else 144),"original borrowed descriptor lifetime")
            chain["borrows"].append(dict(label=label,role=role,exchange=n,stat=store.put(raw[64:])))
    borrow("before")
    time.sleep(query["initial_quiet_seconds"])
    from hooks import Hooks
    hooks=Hooks(query,carrier.pid,fds,fixture,store,reference=True);carrier.hooks=hooks
    def invoke(mode,label):
        packet=encoded(dict(mode=mode,observer=query["observer"],snapshot=query.get("snapshot")))
        raw,n=carrier.exchange(1,slot,packet);require(U(raw,8)==0,"original carrier invocation")
        value=decode(raw[64:]);chain["invocations"].append(dict(label=label,exchange=n,generation=U(raw,32),
            packet=store.put(packet),frame=store.put(raw[64:]),result=value));borrow("after-result-"+label);return value
    value=invoke(query["mode"],"initial")
    if query["mode"]=="capture-summary"and value["ok"]:value=invoke("summary-held","summary-of-actual-capture")
    chain["after"]=fixture.all(carrier.pid,fds);chain["process"]=carrier.observed_process()
    for role,command in(("source",12),("target",13)):
        if role not in fds:continue
        raw,n=carrier.exchange(command,slot);require(I(U(raw,8))==(-9 if query.get("close_"+role+"_before")else 0),"original fixture close")
        chain["files"][role]["close_exchange"]=n
    carrier.hooks=None;return dict(result=value,chain=chain,hooks=hooks.result())
