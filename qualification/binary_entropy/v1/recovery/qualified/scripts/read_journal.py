"""Every observed HIA byte and capability transition, without native replay."""
import struct
from evidence_common import require,sha
from protocol import MASK,project,request,result,signed,u
from entropy_model import Model
def context(event,row,start,phase):
    raw=event["context_bytes"];address=row["result"]["context"]
    require(event["context"]==address and len(raw)==4096 and raw[:8]==b"HENTCI01"and u(raw,8)==4096,
        "entire actual private context")
    mapping=start["image_mapping"]
    require(u(raw,16)==mapping["address"]+256+mapping["exports"]["binary_entropy_body_call_displacement"]-1
        and u(raw,40)==mapping["callback"] and u(raw,48)==0 and u(raw,376)==row["result"]["pool"]
        and u(raw,384)==start["pid"],"fixed native code callback pool and process bindings")
    require(raw[24:40]==bytes(16)and raw[136:168]==bytes(32)and raw[320:376]==bytes(56)
        and raw[408:]==bytes(4096-408),"complete unused context bytes")
    pointers=[]
    for offset in(64,88,104,120):
        at=u(raw,offset);require(at and at%4096==0 and u(raw,offset+8)==4096,"fixed mapped arena pair")
        pointers.append(at)
    require(len(set(pointers))==4 and u(raw,376)%4096==0,"independent private arenas")
    slots=[u(raw,256+8*i)for i in range(8)]
    require(sum(fd!=MASK for fd in slots)==u(raw,184)
        and all(fd==MASK or fd<=2147483647 for fd in slots),"complete owned descriptor ledger")
    require(u(raw,56)==phase and u(raw,192)==row["index"]+(0 if event["kind"]==30 else 1),
        "single generation and exact execution phase")
    spans={1:(u(raw,200),u(raw,208)),10:(u(raw,88),4096),12:(u(raw,104),4096),
        2:(u(raw,104),4096),11:(u(raw,88),4096),8:(u(raw,104),64),
        9:(u(raw,120),u(raw,208)),20:(u(raw,88),4096),21:(u(raw,104),4096),
        22:(u(raw,64),4096),23:(u(raw,120),4096),24:(u(raw,376),4096),26:(u(raw,88),4096)}
    if event["kind"]in spans:require((event["pointer"],len(event["data"]))==spans[event["kind"]],"full mapped event span")
    return raw
def pool(events,row,start,expected):
    pool=[e for e in events if e["kind"]==24];pages=[e for e in events if e["kind"]==25]
    require(len(pool)==1,"one full process pool snapshot")
    raw=pool[0]["data"];address=row["result"]["pool"]
    require(raw[:8]==b"HPORP001"and u(raw,8)==4096 and u(raw,16)==start["pid"]
        and u(raw,24)==0 and u(raw,48)==len(expected)and u(raw,56)==len(pages)
        and raw[64:]==bytes(4032),"complete shared process pool header")
    records=[];pointer=u(raw,32)
    for i,e in enumerate(pages):
        p=e["data"]
        require(e["pointer"]==pointer and p[:8]==b"HPORL001"and u(p,8)==address
            and u(p,24)<=126 and u(p,32)==len(records)+1 and p[40:64]==bytes(24),"complete append-only page header")
        count=u(p,24)
        for n in range(count):records.append(struct.unpack_from("<4Q",p,64+32*n))
        require(p[64+32*count:]==bytes(4096-64-32*count),"all unused orphan slots")
        pointer=u(p,16)
    require(pointer==0 and u(raw,40)==(pages[-1]["pointer"]if pages else 0)
        and records==[(fd,row["result"]["context"],generation,i+1)for i,(fd,generation)in enumerate(expected)],
        "all immutable orphan records including descriptor number reuse")
def observed(row,ev,state,start):
    require(ev and ev[0]["kind"]==30 and ev[-1]["kind"]==26,"complete native call event boundaries")
    require(ev[0]["data"]==request(row["mode"]),"actual immutable start packet")
    context(ev[0],row,start,0);before=state.previous;state.start(row["mode"]);at=1;caps=[];hia=0
    reply_arena=getattr(state,"reply_arena",bytes(4096))
    source_packet=request(row["mode"])
    while at<len(ev)and ev[at]["kind"]==1:
        cycle=ev[at:at+5];require([e["kind"]for e in cycle]==[1,10,12,2,11],"all five full HIA observations")
        for e in cycle:context(e,row,start,1)
        entry,w0,o0,o1,w1=cycle
        require(entry["data"]==source_packet and w0["data"]==before and o0["data"]==b"\xa5"*4096,
            "exact input and every before-work/output byte")
        expected=state.response();after=state.workspace()
        require(o1["data"]==expected+b"\xa5"*(4096-len(expected))and w1["data"]==after
            and u(o1["context_bytes"],176)==u(w1["context_bytes"],176)==64,
            "entire actual HIA result and complete persistent workspace")
        before=after;at+=5;hia+=1
        if state.pending is None:break
        pair=ev[at:at+2];require([e["kind"]for e in pair]==[8,9],"one actual fixed capability and resume")
        for e in pair:context(e,row,start,1)
        q,r=pair;require(q["data"]==expected,"actual capability request equals HIA output")
        op,a,b=state.pending;resume=r["data"];value=signed(u(resume,24));body=resume[96:]
        require(q["data"][24:56]==struct.pack("<4Q",op,a,b,0),"fixed requested operation and arguments")
        mutable=bytearray(reply_arena)
        if op==3:mutable[96:240]=bytes(144)
        if op in(1,3,5)and value>=0:mutable[96:96+len(body)]=body
        mutable[:96]=resume[:96];reply_arena=bytes(mutable)
        require(resume==reply_arena[:len(resume)],"whole actual syscall reply buffer")
        caps.append(dict(operation=op,a=a,b=b,return_value=value,payload_hex=body.hex(),sequence=state.sequence))
        state.resume(resume);source_packet=resume;at+=2
    require(state.pending is None and at<len(ev)and ev[at]["kind"]==31,"native application reached one terminal HIA return")
    require(ev[at]["data"]==request(row["mode"])and ev[at]["pointer"]==ev[0]["pointer"],"borrowed input bytes remained unchanged")
    tail=ev[at:];kinds=[e["kind"]for e in tail]
    require(kinds[:6]==[31,20,21,22,23,24]and kinds[6:-1]==[25]*(len(kinds)-7)and kinds[-1]==26,
        "complete final arena and orphan snapshots")
    for e in tail:context(e,row,start,0 if e["kind"]==26 else 2)
    final={e["kind"]:e for e in tail if e["kind"]!=25};response=state.response()
    require(final[20]["data"]==final[26]["data"]==state.workspace()
        and final[21]["data"]==response+b"\xa5"*(4096-len(response))
        and final[22]["data"]==request(row["mode"])+bytes(4000)
        and final[23]["data"]==reply_arena,"every complete final arena and release preservation")
    c=final[20]["context_bytes"];released=final[26]["context_bytes"]
    wanted=[MASK]*8
    if state.cache is not None:wanted[0]=state.cache
    require([u(c,256+8*i)for i in range(8)]==wanted and u(c,184)==int(state.cache is not None)
        and u(c,400)==len(state.orphans)and u(c,168)==len(response)and u(c,176)==64 and u(c,248)==hia,
        "exact terminal native descriptor custody and loan")
    expected_release=bytearray(c)
    for pos in(56,168,176):struct.pack_into("<Q",expected_release,pos,0)
    require(released==expected_release,"release retires only the loan and preserves the process cache")
    require(row["result"]["response_hex"]==response.hex()and row["result"]["native_return"]==64
        and row["result"]["release_return"]==0 and row["result"]["state_before_release"]==2,
        "complete actual callable result")
    pool(tail,row,start,state.orphans)
    state.previous=state.workspace();state.reply_arena=reply_arena
    return dict(result=result(response),hia_calls=hia,actual_hia_calls=hia,total_capabilities=len(caps),capabilities=caps,raw_hex=bytes(state.random).hex())
def unobserved(row,ev,state,start):
    require([e["kind"]for e in ev]==[30,31,20,21,22,23,24,26],"observer-off has only external full snapshots")
    for e in ev:context(e,row,start,0 if e["kind"]in(30,26)else 2)
    require(ev[0]["data"]==ev[1]["data"]==request(row["mode"]),"observer-off unchanged input")
    data={e["kind"]:e["data"]for e in ev};work=data[20];frame=bytes.fromhex(row["result"]["response_hex"])
    require(data[26]==work and work[:8]==b"HENTW001"and u(work,8)==99 and u(work,56)==row["mode"]
        and u(work,96)==u(work,104)==MASK and u(work,112)==16 and work[120:256]==bytes(136)
        and work[272:512]==bytes(240)and work[656:]==bytes(3440),"observer-off entire stable work regions")
    expected=project(work[256:272],row["mode"])
    require(frame==b"HENTR001"+struct.pack("<7Q",0,u(work,16),0,0,0,0,len(expected))+expected
        and data[21]==frame+b"\xa5"*(4096-len(frame))
        and data[22]==request(row["mode"])+bytes(4000),"observer-off exact raw/UUID projection and all output bytes")
    normal=start["case"]["kind"]=="normal";cache=u(work,72)
    require(u(work,64)==int(normal)and (cache==MASK if normal else cache<128)
        and u(work,16)==(1 if normal else 4 if row["index"]==0 else 2)
        and u(work,24)==0 and u(work,32)==u(work,16)and u(work,40)==u(work,48)==16,
        "observer-off persistent fallback and completed sequence")
    require(data[23][:8]==b"HENTQ001"and u(data[23],16)==u(work,16)
        and u(data[23],24)==16 and data[23][32:88]==bytes(56)and u(data[23],88)==16
        and data[23][96:112]==work[256:272]and data[23][240:]==bytes(3856),"full observer-off final real reply")
    c=ev[2]["context_bytes"];released=ev[-1]["context_bytes"];copy=bytearray(c)
    for p in(56,168,176):struct.pack_into("<Q",copy,p,0)
    require(released==copy and u(c,400)==0 and u(c,184)==int(not normal)and u(c,248)==u(work,16)+1
        and [u(c,256+8*i)for i in range(8)]==[cache]+[MASK]*7,"observer-off release and descriptor custody")
    require(row["result"]["native_return"]==64 and row["result"]["release_return"]==0,"observer-off natural owner completion")
    pool(ev,row,start,[])
    state.previous=work
    return dict(result=result(frame),hia_calls=0,actual_hia_calls=u(c,248),total_capabilities=u(work,16),capabilities=[],raw_hex=work[256:272].hex())
