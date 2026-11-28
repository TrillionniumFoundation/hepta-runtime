"""Pure complete native export/observation/real-syscall/domain reader."""
from pathlib import Path
import struct
from reader_common import read,loads,require,pin,word,integer
from read_pairs import exact
from read_frames import frames
from read_libc import verify as libc
from read_native_state import N,W,I,O,E,P,U,put,pin_page,slots,context,release_frame,Ledger
from read_native_turn import Turn,response
FILES={"NATIVE.json","ADMISSION.json","LIBC.bin","LIBC-BINDINGS.json","PROCESS-MAPS.txt",
    "RECORDS.json","OBSERVER-ERRORS.json","complete-native-buffers.bin.gz"}
class Cursor:
    def __init__(self,folder):
        self.iterator=iter(frames(folder));self.next=None;self.count=0;self.bytes=0;self.kinds={};self.advance()
    def advance(self):
        try:self.next=next(self.iterator)
        except StopIteration:self.next=None
    def pop(self,kind,label):
        require(self.next is not None,"no omitted physical native call")
        row,raws=self.next
        require(row["kind"]==kind and(row["case"],row["step"],row["operation"])==label,
            "all actual calls exactly follow frozen source domain: "+str((kind,label,row["kind"],row["case"],row["step"],row["operation"])))
        self.count+=1;self.bytes+=sum(map(len,raws));self.kinds[kind]=self.kinds.get(kind,0)+1
        self.advance();return row,raws
def verify(folder,pair,role_index,m,admission,trace):
    name=("native-observed","native-off")[role_index];observed=role_index==0
    report=loads(read(folder/"NATIVE.json"));process=pair["roles"][role_index]["report"]
    require({p.name for p in folder.iterdir()}==FILES,"complete exact native evidence file domain")
    require(set(report)=={"schema","status","role","group","source_manifest_sha256","pid","parent_pid","pgid","uid","gid",
        "source_root","retained_root","output_root","callable","loaded_image","admission","observer","records","errors",
        "native_entry_calls","private_owner_calls","actual_hia_calls","actual_boundaries","original_rust_executions",
        "namespace_version_qualified","public_handler_qualified"},"entire actual native process report")
    require(report["schema"]=="hepta.namespace-watcher.native-role.v1"and report["status"]=="PASS"
        and report["role"]==name and report["group"]==pair["report"]["group"]and report["observer"]is observed
        and report["errors"]==loads(read(folder/"OBSERVER-ERRORS.json"))==[]and
        report["admission"]==admission==loads(read(folder/"ADMISSION.json"))and report["callable"]==admission["image"]
        and report["source_manifest_sha256"]==m["source_manifest_sha256"]and
        report["original_rust_executions"]==0 and report["namespace_version_qualified"]is False
        and report["public_handler_qualified"]is False,"exact private native source and admitted whole build")
    for key in("pid","parent_pid","pgid","uid","gid"):require(type(report[key])is int and report[key]==(process[key]if key in process else m[key]),"actual native process identity")
    require(report["source_root"]==m["source_root"]and report["retained_root"]==m["retained_root"]and
        report["output_root"]==str(Path(pair["report"]["output_root"])/"roles"/name/"capture"),"recorded native roots remain attribution only")
    library=libc(folder);image=report["loaded_image"]
    require(set(image)=={"address","bytes"}and integer(image["address"],1)and image["address"]%4096==0
        and image["bytes"]==admission["image"]["bytes"],"exact actually loaded whole native image")
    owned=[r for r in library["maps"]if r["lo"]<=image["address"]<r["hi"]]
    require(len(owned)==1 and owned[0]["lo"]==image["address"]and owned[0]["hi"]>=image["address"]+image["bytes"]
        and owned[0]["permissions"]=="r-xp"and owned[0]["offset"]==0 and
        owned[0]["path"]=="/memfd:hepta-runtime-native (deleted)","actual retained native mapping is complete sealed-loader RX allocation")
    ledger=Ledger(library["table"],observed);cursor=Cursor(folder);answers=pair["roles"][role_index]["answers"]
    ai=0;turns=[];private_calls=0;outer_kernel=[];active_paths=[];case=None
    def bind(label,ptr,index=None,shared=False):
        row,raws=cursor.pop("bind",label)
        require(row["meta"]==dict(context=ptr,root=index,shared=shared,returned=0)and len(raws)==2
            and raws[0]==ledger.contexts[ptr],"whole actual capability bind input")
        want=bytearray(raws[0]);value=ledger.roots[index]if index is not None else None
        put(want,24,value["fd"]if value else U);put(want,32,value["pointer"]if value and shared else 0)
        require(raws[1]==want,"only actual borrowed root fields change")
        ledger.set_context(ptr,raws[1])
    def open_root(label,index,kernel=None):
        row,raws=cursor.pop("pin-adopt",label);meta=row["meta"]
        require(set(meta)=={"pointer","fd","root","path_hex"}and meta["root"]==index and meta["fd"]==512+index
            and meta["path_hex"]==active_paths[index]and len(raws)==1 and index not in ledger.roots
            and meta["pointer"]not in ledger.pages and pin_page(raws[0],ledger.table)==dict(strong=1,fd=512+index),
            "new actual complete caller File capability")
        ledger.page(meta["pointer"],raws[0]);ledger.roots[index]=dict(pointer=meta["pointer"],fd=meta["fd"])
        if kernel is not None:
            require(len(kernel)==3 and kernel[0]["op"]=="open-root"and kernel[0]["path"]==meta["path_hex"]
                and kernel[0]["directory"]=="AT_FDCWD"and kernel[0]["flags"]=="O_RDONLY|O_CLOEXEC"
                and kernel[0]["errno"]==0 and 32<=kernel[0]["result"]<320,"actual original root open")
            fd=kernel[0]["result"]
            exact(kernel[1],dict(op="root-slot",source=fd,target=512+index,result=512+index,errno=0),"actual FD transfer")
            exact(kernel[2],dict(op="close",fd=fd,result=0,errno=0),"actual transient root close")
        else:outer_kernel.append(dict(kind="adopt",path=meta["path_hex"],fd=meta["fd"]))
    def release(label,index,kernel=None):
        for ptr in list(ledger.wids.values()):bind(label,ptr)
        row,raws=cursor.pop("pin-release",label);root=ledger.roots[index];ptr=root["pointer"]
        require(row["meta"]==dict(root=index,pointer=ptr,fd=root["fd"],returned=0)and len(raws)==4
            and raws[0]==ledger.pages[ptr]and raws[1]==b"\xa5"*80 and len(raws[3])==80
            and raws[3][64:]==b"\xa5"*16,"all complete native caller File release buffers")
        facts=release_frame(raws[0],raws[2],raws[3][:64],ledger.table)
        if raws[2]:ledger.pages[ptr]=raws[2]
        else:del ledger.pages[ptr]
        del ledger.roots[index]
        wanted=[dict(op="close",fd=facts["fd"],result=facts["result"],errno=facts["errno"])]if facts["last"]else[]
        if kernel is not None:exact(kernel,wanted,"actual last caller reference syscall")
        else:outer_kernel.extend(dict(kind="close",**r)for r in wanted)
    def checkpoint(label,answer):
        row,raws=cursor.pop("checkpoint",label)
        if not observed:
            meta=row["meta"];owned={r["pointer"]for r in ledger.roots.values()}
            for ctx in ledger.contexts.values():owned.update(p for p,_ in slots(ctx))
            require(meta["pins"]==sorted(owned),"whole observer-off actually owned page set")
            current={}
            for p,raw in zip(meta["pins"],raws[len(meta["contexts"]):]):
                pin_page(raw,ledger.table)
                if p in{r["pointer"]for r in ledger.roots.values()}:
                    require(raw[:8]==ledger.pages[p][:8]and raw[16:]==ledger.pages[p][16:],"whole caller File stable outside real strong count")
                current[p]=raw
            ledger.pages=current
        ledger.checkpoint(row,raws,answer["state"])
    def dispose(label,ptr):
        row,raws=cursor.pop("dispose",label)
        require(row["meta"]==dict(context=ptr,returned=0)and len(raws)==2 and raws[0]==ledger.contexts[ptr]
            and word(raws[0],96)==U and word(raws[0],104)==0 and raws[1]==bytes(N)+b"\x5a"*16,
            "complete actual context cleared after all native resources are released")
        del ledger.contexts[ptr]
    def invoke(label,op,answer):
        nonlocal private_calls
        ptr=ledger.wids[op["wid"]]if op["op"]!="new"else current_new
        turn=Turn(ledger,ptr,op,label[1]+1,trace["groups"][label[:2]])
        if observed:
            while cursor.next is not None and cursor.next[0]["kind"]=="observation":
                row,raws=cursor.pop("observation",label);turn.feed(row,raws)
        row,raws=cursor.pop("entry",label);frame=turn.finish(row,raws)
        require(frame.hex()==answer["native_frame_hex"],"whole actual terminal equals complete public observer response")
        hia=word(raws[5],64)-word(raws[2],64);boundary=word(raws[5],128)-word(raws[2],128)
        require(hia==boundary+1 and(not observed or(hia,boundary)==(turn.hia,turn.boundaries)),
            "no missing actual HIA/native call including observer-off")
        turns.append(dict(case=label[0],step=label[1],hia=hia,boundaries=boundary))
        return frame
    def private(label,op,answer):
        nonlocal private_calls
        ptr=ledger.wids[op["wid"]];generation=label[1]+1;command=3 if op["root"]is None else 2
        wire=b"HNWQ0001"+struct.pack("<11Q",command,generation,0 if command==3 else 1,
            3 if command==2 and op["shared"]else 0,0,0,0,0,0,0,0)
        at=0
        while True:
            row,raws=cursor.pop("private-owner",label);private_calls+=1
            require(row["meta"]==dict(context=ptr,command=command,generation=generation,returned=128)
                and len(raws)==6 and raws[0]==raws[3]==wire+b"\xc3"*16 and raws[1]==b"\xa5"*144
                and len(raws[4])==144 and raws[4][128:]==b"\xa5"*16
                and raws[2]==ledger.contexts[ptr][W:W+65552]and len(raws[5])==65552
                and raws[5][65536:]==b"\x5a"*16,"all complete explicit original-callback HIA buffers")
            after=bytearray(ledger.contexts[ptr]);after[W:W+65552]=raws[5];ledger.set_context(ptr,after)
            frame=raws[4][:128];response(frame,raws[5][:65536],generation,command)
            if word(frame,8)!=2:
                require(frame.hex()==answer["native_frame_hex"]and at==len(answer["callback"]),
                    "whole private original callback terminal and exact read count");break
            require((word(frame,40),word(frame,48),word(frame,56),word(frame,64))==(2,2,16384,0)
                and at<len(answer["callback"]),"test-owned callback supplies only the original read contract")
            row=answer["callback"][at];item=op["script"]["reads"][row["script_row"]];at+=1
            status=int("errno"in row["result"]);error=row["result"].get("errno",0)
            count=row["result"].get("count",0);payload=b""if status else bytes.fromhex(item["bytes"])
            wire=b"HNWAK001"+struct.pack("<11Q",generation,word(frame,24),2,status,error,count,0,0,
                len(payload),96+len(payload),0)+payload
        require(trace["groups"][label[:2]]==[],"explicit callback domain does not replace any actual kernel effects")
    for case in pair["cases"]:
        ci=case["case"];prepare=(ci,None,"prepare")
        command=pair["commands"][ai];require(command["cmd"]=="prepare","source-order prepare")
        active_paths=[r["path_hex"]for r in command["roots"]]
        require(not ledger.contexts and not ledger.wids and not ledger.roots and not ledger.pages,"complete previous case disposal")
        for i,root in enumerate(case["roots"]):
            if not root["late"]:open_root(prepare,i)
        checkpoint(prepare,answers[ai]);ai+=1
        for si,step in enumerate(case["steps"]):
            op=step["operation"];label=(ci,si,op["op"]);answer=answers[ai];ai+=1;kind=op["op"]
            kernel=trace["groups"][(ci,si)]
            if kind=="new":
                row,raws=cursor.pop("initialize",label);current_new=row["meta"]["context"]
                require(row["meta"]==dict(wid=op["wid"],context=current_new,observer=observed,returned=0)
                    and op["wid"]not in ledger.wids and current_new not in ledger.contexts and len(raws)==4
                    and raws[0]==bytes(N)+b"\x5a"*16 and raws[1]==raws[3]==ledger.table,
                    "whole actual context/table initialization")
                expected=bytearray(raws[0]);expected[:8]=b"HNWCTX01";put(expected,24,U);put(expected,96,U)
                require(bool(word(raws[2],40))==observed,"actual observer on/off pointer")
                put(expected,40,word(raws[2],40));expected[256:320]=ledger.table[:64]
                require(raws[2]==expected,"entire native initialized context")
                ledger.set_context(current_new,raws[2]);frame=invoke(label,op,answer)
                if word(frame,8)==0:ledger.wids[op["wid"]]=current_new
                else:dispose(label,current_new)
            elif kind in("version","drain","changed","drop"):
                ptr=ledger.wids[op["wid"]]
                if kind=="version":bind(label,ptr,op["root"],op["shared"])
                elif kind=="drop":bind(label,ptr)
                invoke(label,op,answer)
                if kind=="drop":dispose(label,ptr);del ledger.wids[op["wid"]]
            elif kind=="seed":
                ptr=ledger.wids[op["wid"]];row,raws=cursor.pop("private-seed",label);value=int(op["next_decimal"])
                require(row["meta"]==dict(context=ptr,next=value,returned=0)and len(raws)==2 and raws[0]==ledger.contexts[ptr],
                    "whole original test-owned epoch seed")
                wanted=bytearray(raws[0]);put(wanted,W+80,value)
                require(raws[1]==wanted and kernel==[],"only exact private epoch scalar changed")
                ledger.set_context(ptr,raws[1])
            elif kind=="callback":private(label,op,answer)
            elif kind=="release-root":release(label,op["root"],kernel)
            elif kind=="open-root":open_root(label,op["root"],kernel)
            elif kind in("limit","restore-limit"):
                require(len(kernel)==1 and kernel[0]["op"]=="limit"and kernel[0]["result"]==0 and kernel[0]["errno"]==0,
                    "actual kernel resource limit operation")
                if kind=="limit":require("rlim_cur="+str(op["soft"])in kernel[0]["request"],"exact input-owned resource limit")
            else:raise ValueError("unknown frozen native operation")
            checkpoint(label,answer)
        finish=(ci,None,"finish")
        require(not ledger.wids and not ledger.contexts,"all actual Watchers already dropped before finish")
        for index in list(ledger.roots):release(finish,index)
        require(not ledger.pages and answers[ai]["command"]=="finish","all actual last caller File holdings released")
        ai+=1
    require(ai==len(answers)and cursor.next is None,"no missing native cases or unclaimed physical records")
    require(report["records"]==cursor.count and report["native_entry_calls"]==len(turns)
        and report["private_owner_calls"]==private_calls and report["actual_hia_calls"]==(sum(t["hia"]for t in turns)if observed else 0)
        and report["actual_boundaries"]==(sum(t["boundaries"]for t in turns)if observed else 0),
        "all actual physical counts independently rebuilt")
    return dict(group=report["group"],role=name,records=cursor.count,full_buffer_bytes=cursor.bytes,kinds=cursor.kinds,
        entries=len(turns),private_owner_calls=private_calls,turns=turns,libc=library["library"],
        image=report["callable"],outer_file_actions=outer_kernel)
