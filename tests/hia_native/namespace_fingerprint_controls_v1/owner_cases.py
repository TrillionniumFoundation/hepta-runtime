"""Source-owned direct ABI cases selected from every complete original native cohort."""
import struct
from common import ROOT,loads,read,require
from callable_contract import word
from protocol import domain
from read_frames import Records
INVALID=0xffffffff
CAPACITY=0xfffffffe
MASK=(1<<64)-1
def changed(raw,at,value):
    result=bytearray(raw);struct.pack_into("<Q",result,at,value);return bytes(result)
def checkpoints(capture):
    selected=[];seen=set();groups=[]
    for group in domain(ROOT)["groups"]:
        folder=capture/("paired-"+group)/"roles/native-observed/capture"
        records=Records(folder)
        bindings={r["case"]:r for r in loads(read(folder/"CONTEXTS.json"))}
        observations={(r["case"],r["step"]):r for r in loads(read(folder/"OBSERVATIONS.json"))}
        while records.position<len(records.rows):
            receipt=records.rows[records.position];ci,si=receipt["case"],receipt["step"]
            record=records.next(ci,si,bindings[ci],observations[(ci,si)]["generation"])
            if record["kind"]!=1:continue
            ni,no,nw=record["ni"],record["no"],record["nw"]
            request=record["before"][0][:ni];work=record["before"][2][:nw];ack=request[:8]==b"HNFACK01"
            key=(group,request[:8],word(work,2056),word(work,2088),
                 word(request,32)if ack else 0,word(request,40)if ack else 0,len(request))
            if key in seen:continue
            seen.add(key)
            require((no,nw)==(128,16384)and request[:8]in(b"HNFRQ001",b"HNFACK01"),
                    "exact original fingerprint checkpoint buffers")
            selected.append(dict(origin=group+"/"+str(record["index"]),case=ci,step=si,
                request=request,work=work,returned=128,output=record["after"][1][:no],
                after_work=record["after"][2][:nw]))
        records.finish();groups.append(group)
    require(len(groups)==10 and {word(r["work"],2088)for r in selected if r["request"][:8]==b"HNFACK01"}=={1,2,3,4,5},
            "all complete actual groups and all five continuation phases")
    return selected
def plans(saved):
    rows=[]
    def add(cp,name,request=None,work=None,no=128,expected=INVALID):
        request=cp["request"]if request is None else request
        work=cp["work"]if work is None else work
        rows.append(dict(name=cp["origin"]+"/"+name,origin=cp["origin"],request=request,work=work,
            output_capacity=no,expected=expected,
            expected_output=cp["output"]+b"\xa5"*(no-128)if expected==128 else None,
            expected_work=cp["after_work"]+work[16384:]if expected==128 else None))
    for cp in saved:
        request,work=cp["request"],cp["work"];ack=request[:8]==b"HNFACK01"
        add(cp,"exact-replay",expected=128)
        add(cp,"extra-output-tail",no=129,expected=128)
        add(cp,"extra-work-tail",work=work+b"\x87",expected=128)
        for at in range(8):
            other=bytearray(request);other[at]^=0x40;add(cp,"magic-%d"%at,request=bytes(other))
        for n in dict.fromkeys((0,1,7,8,63,len(request)-1)):
            add(cp,"truncate-%d"%n,request=request[:n])
        add(cp,"extra-input",request=request+b"\0")
        for no in (0,1,31,32,127):add(cp,"output-%d"%no,no=no,expected=CAPACITY)
        for nw in (0,1,16383):add(cp,"workspace-%d"%nw,work=work[:nw],expected=CAPACITY)
        if ack:
            phase=word(work,2088)
            for at,value in ((8,0),(8,word(request,8)+1),(16,0),(16,word(request,16)+1),
                (24,0),(24,6),(32,3),(40,4096),(56,MASK),(64,MASK),(64,len(request)-1)):
                add(cp,"ack-%d-%d"%(at,value),request=changed(request,at,value))
            for at in (72,80,88):add(cp,"ack-reserved-%d"%at,request=changed(request,at,1))
            for at,value in ((2048,0),(2056,2),(2064,0),(2072,0),(2080,0),(2080,MASK-1),
                (2088,0),(2112,0),(2120,4096),(2128,3),(2136,4096),(2152,4097),(2160,2),(2168,2)):
                add(cp,"pending-work-%d-%d"%(at,value),work=changed(work,at,value))
            for at in range(2176,2304,8):add(cp,"pending-reserved-%d"%at,work=changed(work,at,1))
            if phase==1:
                for at in (2096,2104):add(cp,"unexpected-owned-%d"%at,work=changed(work,at,2))
            elif phase in (2,4):
                add(cp,"missing-fd",work=changed(work,2096,0))
                add(cp,"borrowed-root-as-fd",work=changed(work,2096,word(work,2072)))
                add(cp,"unexpected-dir",work=changed(work,2104,3))
            else:
                add(cp,"unexpected-fd",work=changed(work,2096,2))
                add(cp,"missing-dir",work=changed(work,2104,0))
                add(cp,"borrowed-root-as-dir",work=changed(work,2104,word(work,2072)))
            status=word(request,32)
            if status==1:
                add(cp,"failure-without-errno",request=changed(request,40,0))
                add(cp,"failure-with-value",request=changed(request,48,1))
            elif phase in (1,2):
                add(cp,"success-zero-capability",request=changed(request,48,0))
                add(cp,"success-borrowed-capability",request=changed(request,48,word(work,2072)))
                add(cp,"unexpected-eof",request=changed(request,32,2))
                add(cp,"success-errno",request=changed(request,40,1))
            elif phase==3 and status==0:
                add(cp,"dirent-value-extent",request=changed(request,48,word(request,48)+1))
                other=bytearray(request);other[112]^=1;add(cp,"dirent-reclen",request=bytes(other))
                other=bytearray(request);other[115:]=b"\x41"*(len(other)-115);add(cp,"dirent-no-nul",request=bytes(other))
                add(cp,"success-errno",request=changed(request,40,1))
            elif phase==3:
                add(cp,"eof-value",request=changed(request,48,1))
                add(cp,"eof-errno",request=changed(request,40,1))
            else:
                add(cp,"cleanup-value",request=changed(request,48,1))
                add(cp,"cleanup-eof",request=changed(request,32,2))
        else:
            for at,value in ((8,0),(8,2),(16,0),(24,0)):
                add(cp,"initial-%d-%d"%(at,value),request=changed(request,at,value))
            for at in range(32,64,8):add(cp,"initial-reserved-%d"%at,request=changed(request,at,1))
            if work[2048:2056]==b"HNFWK001":
                for at,value in ((2056,1),(2064,0),(2072,0),(2080,0),(2080,MASK-1),
                    (2088,1),(2096,2),(2104,3),(2112,1),(2120,4096),(2128,3),(2136,4096),
                    (2152,4097),(2160,2),(2168,2),(2176,1),(2296,1)):
                    add(cp,"stable-work-%d-%d"%(at,value),work=changed(work,at,value))
                add(cp,"stale-generation",request=changed(request,16,word(work,2064)))
                add(cp,"backward-generation",request=changed(request,16,max(0,word(work,2064)-1)))
        add(cp,"same-checkpoint-recovery",expected=128)
    require(rows and len({r["name"]for r in rows})==len(rows),"complete unique immutable control corpus")
    return rows
