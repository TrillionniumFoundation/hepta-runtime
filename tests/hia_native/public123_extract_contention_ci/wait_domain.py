"""Input-only actual lock contention, public cancellation and EOF scenarios."""
from pathlib import Path
import json,struct
def enc(v):return json.dumps(v,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def meta():return {"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"extract-wait-corpus","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}
def message(method,params=None,identifier=None,modern=False):
    v={"jsonrpc":"2.0","method":method}
    if identifier is not None:v["id"]=identifier
    if params is not None or modern:
        v["params"]=dict(params or {})
        if modern:v["params"]["_meta"]=meta()
    return enc(v)+b"\n"
def tool(identifier,source="one",target="target",line=-1,modern=False,arguments=None):
    args={"from_path":source,"from_start":1,"from_end":1,"append_path":target,"append_line":line} if arguments is None else arguments
    return message("tools/call",{"name":"extract_lines","arguments":args},identifier,modern)
def cancel(identifier,modern):
    return message("notifications/cancelled",{"requestId":identifier,"reason":"fixed actual wait fixture"},modern=modern)
def wire(raw,label,identifier=None):return {"kind":"wire","wire_hex":raw.hex(),"label":label,"correlation_id":identifier}
def control(op,slot=0,payload=b"",label="control"):
    return {"kind":"control","operation":op,"slot":slot,"payload_hex":payload.hex(),"label":label}
def wait(path,strong,label):return {"kind":"wait-lock","key_hex":str(path).encode().hex(),"strong":strong,"label":label,"readiness_from_actual_full_state":True}
def write(path,raw,label):return {"kind":"write","path":str(path),"bytes_hex":raw.hex(),"label":label}
def domain(name,work):
    modern=name.endswith("-modern");group=name.rsplit("-",1)[0]
    assert group in ("ordinary-a","ordinary-b","eof") and name.endswith(("-legacy","-modern"))
    work=Path(work);assert work.is_absolute() and ".." not in work.parts
    key=str(work/"target").encode();other=str(work/"other").encode()
    files={"one":b"ONE\n","two":b"TWO\n","three":b"THREE\n","source":b"first\nsecond\nthird\n","target":b"head\ntail\nlast\n","other":b"other\n"}
    opener=[wire(tool("opener",modern=modern,arguments={"from_path":[],"from_start":1,"append_path":"target","append_line":-1}),"modern-opener","opener")] if modern else [wire(message("initialize",{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"extract-wait-corpus","version":"1"}},"initialize"),"initialize","initialize"),wire(message("notifications/initialized"),"initialized")]
    def ping(label):return wire(message("ping",identifier=label,modern=modern),label,label)
    def request(i,source="one",target="target",line=-1):return wire(tool(i,source,target,line,modern),"request-"+str(i))
    def hold(slot=0,path=key):return control(1,slot,path,"hold-"+str(slot))
    def release(slot=0):return control(2,slot,label="release-"+str(slot))
    def observe(label):return control(3,label=label)
    def seed(path,value,label):
        raw=b"HVCACH01"+struct.pack("<5Q",2,0,len(path),len(value),0)+path+value
        return control(4,payload=raw,label=label)
    def done(label="settled"):return wait(work/"target",1,label)
    cases=[]
    def add(name,steps,eof=False):
        cases.append({"name":name,"files":[{"path":n,"bytes_hex":v.hex(),"mode":0o640} for n,v in files.items()],"steps":opener+[ping("ready")]+steps+([] if eof else [ping("final-barrier"),observe("final-state")]),"actual_public_eof":True,"holds_retained_through_runtime_drop":eof})
    add("read-before-lock-target-after-lock",[
        seed(key,b"old-target-cache","seed-target-cache"),seed(str(work/"source").encode(),b"old-source-cache","seed-source-cache"),hold(),
        wire(tool(10,modern=modern,arguments={"from_path":"source","from_start":1,"from_end":2,"append_path":"target","append_line":-1}),"request-10"),
        wait(work/"target",3,"actual-held-and-pending"),
        write(work/"source",b"CHANGED-SOURCE\n","replace-source-while-waiting"),write(work/"target",b"REPLACED-TARGET\n","replace-target-while-waiting"),
        observe("changed-files-still-pending"),release(),done()])
    add("fifo-three-cancel-middle",[
        hold(),request(10,"one"),wait(work/"target",3,"first-pending"),
        request(11,"two"),wait(work/"target",4,"second-pending"),
        request(12,"three"),wait(work/"target",5,"third-pending"),
        wire(cancel(11,modern),"cancel-middle"),ping("cancel-barrier"),observe("after-cancel-before-release"),release(),done()])
    add("independent-and-typed-refusal",[
        seed(other,b"other-cache","seed-other-cache"),hold(),request(10),wait(work/"target",3,"actual-pending"),
        wire(tool(20,"two","other",-1,modern),"independent-request",20),
        wire(tool(21,modern=modern,arguments={"from_path":[],"from_start":1,"append_path":"target","append_line":-1}),"typed-refusal",21),
        ping("independent-barrier"),observe("pending-after-independent"),release(),done()])
    add("numeric-and-string-id-cancel",[
        hold(),request(7,"one"),wait(work/"target",3,"numeric-pending"),
        request("7","two"),wait(work/"target",4,"string-pending"),
        wire(cancel(7,modern),"cancel-numeric"),ping("cancel-barrier"),observe("numeric-cancel-observed"),release(),done()])
    add("unknown-and-pre-cancel",[
        wire(cancel("unknown",modern),"unknown-cancel"),wire(cancel(10,modern),"cancel-before-request"),ping("pre-cancel-barrier"),
        hold(),request(10),wait(work/"target",3,"request-after-pre-cancel"),observe("pre-cancel-has-actual-state"),release(),done()])
    add("duplicate-id-actual-sdk-policy",[
        hold(),request("same","one"),wait(work/"target",3,"first-duplicate-pending"),request("same","two"),
        ping("duplicate-barrier"),observe("both-duplicate-arrivals-observed"),wire(cancel("same",modern),"cancel-duplicate"),
        ping("duplicate-cancel-barrier"),observe("duplicate-cancel-observed"),release(),done()])
    add("post-lock-target-shrinks",[
        hold(),request(10,"one","target",3),wait(work/"target",3,"pending-before-target-change"),
        write(work/"target",b"short\n","shrink-target-after-source-read"),observe("changed-target-still-pending"),release(),done()])
    add("two-complete-hold-wake-cycles",[
        hold(),request(10,"one"),wait(work/"target",3,"first-cycle-pending"),release(),done("first-cycle-settled"),ping("between-cycles"),
        hold(),request(11,"two"),wait(work/"target",3,"second-cycle-pending"),release(),done("second-cycle-settled")])
    add("eof-one-held",[
        hold(),request(10),wait(work/"target",3,"actual-pending-before-eof"),observe("last-live-state")],True)
    add("eof-four-two-keys",[
        hold(),hold(1,other),request(10,"one"),wait(work/"target",3,"pending-one"),request(11,"two"),wait(work/"target",4,"pending-two"),
        request(12,"three"),wait(work/"target",5,"pending-three"),request(13,"one","other"),wait(work/"other",3,"other-key-pending"),observe("last-live-state")],True)
    add("eof-cancelled-held",[
        hold(),request(10),wait(work/"target",3,"pending-before-cancel"),wire(cancel(10,modern),"cancel-held"),ping("cancel-barrier"),observe("cancelled-before-eof")],True)
    add("control-eof-keeps-holder-until-runtime-drop",[
        hold(),request(10),wait(work/"target",3,"pending-before-control-close"),observe("last-live-state"),{"kind":"control-close","label":"close-private-control-channel"}],True)
    pick={"ordinary-a":cases[:4],"ordinary-b":cases[4:8],"eof":cases[8:]}[group]
    return {"schema":"hepta.runtime.actual-extract-public-contention-inputs.v1","name":name,"modern":modern,"fixture":str(work),"cases":pick,"per_exchange_seconds":60,"whole_lane_seconds":180,"job_minutes":15,"expected_wire":None,"runtime_policy_implemented_by_driver":False,"readiness_uses_observed_actual_reference_counts":True,"public_response_count_assumed":None,"target_commit":"d3d75c30719db966b004756f610007a7c723729e","native_source":"e5d701339c16c4b1bd1801252d2357721452687c"}
