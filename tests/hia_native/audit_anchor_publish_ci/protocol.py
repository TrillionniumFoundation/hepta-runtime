"""Source-owned anchor publication frames; inert definitions and complete admission."""
import struct
from pathlib import Path
from common import read,loads,require
INVALID=0xffffffff
CAPACITY=0xfffffffe
def word(raw,at):
    require(type(at) is int and 0<=at<=len(raw)-8,"complete word")
    return struct.unpack_from("<Q",raw,at)[0]
def put(raw,at,value):
    require(type(value) is int and 0<=value<1<<64,"exact u64")
    struct.pack_into("<Q",raw,at,value)
def initial(ci,si,case,directory=1):
    raw=bytearray(128);raw[:8]=b"HAPURQ01"
    for at,v in ((8,1),(16,1+ci*100+si),(24,directory)):put(raw,at,v)
    for i,v in enumerate(case["anchor"]):put(raw,32+8*i,int(v))
    return bytes(raw)
def response(raw,result=None):
    require(len(raw)>=128 and raw[:8]==b"HAPURS01","whole publisher result")
    require((result is None or type(result) is int and result==len(raw)) and word(raw,112)==len(raw) and word(raw,120)==0,"whole extent")
    kind,seq,gen,op,a,b,c,p0,n0,p1,n1,family,code=[word(raw,at) for at in range(8,112,8)]
    require(kind<=3 and gen>0,"fixed result identity")
    at=128;payloads=[]
    for pos,size in ((p0,n0),(p1,n1)):
        require((size==0 and pos==0) or (size>0 and pos==at and size<=len(raw)-at),"whole contiguous effect payload")
        payloads.append(raw[at:at+size]);at+=size
    require(at==len(raw),"no hidden payload tail")
    if kind<2:
        require(op==1 and a==b==c==0 and not any(payloads),"complete terminal identity")
        require((kind==0 and family==code==0) or
                (kind==1 and ((family==1 and 1<=code<=4095) or (family in (2,4) and code==1))),
                "actual publisher error projection")
    else:
        require(seq>0 and family==code==0,"pending identity")
        require((kind==2 and op in (1,4,5,6,7,8,9,17,18,19)) or (kind==3 and op==4),"actual owner effects")
        if kind==3:
            p=payloads[0]
            require(a==b==c==0 and not payloads[1] and len(p)==152 and p[:8]==b"HAJRQ001" and
                    word(p,8)==4 and word(p,16)==128 and p[24:32]==b"HAJPR001" and word(p,32)==2,
                    "complete actual qualified anchor serializer request")
    return dict(kind=kind,sequence=seq,generation=gen,operation=op,arguments=(a,b,c),payloads=tuple(payloads),family=family,code=code)
def acknowledgement(effect,*,status=0,errno=0,value=0,payload=b""):
    raw=bytearray(128+len(payload));raw[:8]=b"HAPUACK1"
    for at,v in ((8,effect["generation"]),(16,effect["sequence"]),(24,effect["kind"]),(32,effect["operation"]),
                 (40,status),(48,errno),(56,value),(64,len(payload)),(72,len(raw))):put(raw,at,v)
    raw[128:]=payload
    return bytes(raw)
def semantic(raw):
    state=response(raw);require(state["kind"]<2,"actual terminal")
    out=bytearray(64);out[:8]=b"HAPUOR01"
    for at,v in ((8,state["kind"]),(16,1),(24,state["family"]),(32,state["code"])):put(out,at,v)
    return bytes(out)
def validate_semantic(raw):
    require(len(raw)==64 and raw[:8]==b"HAPUOR01" and word(raw,8) in (0,1) and word(raw,16)==1 and
            raw[40:]==bytes(24),"complete original result")
    require((word(raw,8)==0 and word(raw,24)==word(raw,32)==0) or
            (word(raw,8)==1 and ((word(raw,24)==1 and 1<=word(raw,32)<=4095) or
                                (word(raw,24) in (2,4) and word(raw,32)==1))),"original error categories")
    return raw
def domain(root):
    d=loads(read(Path(root)/"DOMAIN.json"))
    require(d["schema"]=="hepta.audit-anchor-publish.domain.v1" and d["expected_outputs_embedded"] is False,
            "source-owned corpus")
    require(len(d["cases"])==d["case_count"] and len({r["name"] for r in d["cases"]})==d["case_count"] and
            sum(len(r["steps"]) for r in d["cases"])==d["operation_count"],"full original/native domain")
    require(list(dict.fromkeys(r["group"] for r in d["cases"]))==d["groups"],"all actual environment groups")
    return d
def cases(root,group=None):
    d=domain(root)
    require(group is None or group in d["groups"],"source-owned group")
    return [(i,r) for i,r in enumerate(d["cases"]) if group is None or r["group"]==group]
