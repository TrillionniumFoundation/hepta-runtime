"""Fixed private anchor frames and source-owned input corpus; definitions only."""
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
def initial(ci,si,step,directory=1):
    raw=bytearray(128);raw[:8]=b"HAPNRQ01"
    for at,value in ((8,step["operation"]),(16,1+ci*100+si),(24,directory)):put(raw,at,value)
    return bytes(raw)
def response(raw,result=None):
    require(len(raw)>=128 and raw[:8]==b"HAPNRS01","complete anchor response")
    require((result is None or type(result) is int and result==len(raw)) and word(raw,112)==len(raw) and word(raw,120)==0,"full extent")
    kind,seq,gen,op,a,b,c,p0,n0,p1,n1,family,code=[word(raw,at) for at in range(8,112,8)]
    require(kind<=3 and gen>0 and p1==n1==0,"fixed response identity")
    require((n0==0 and p0==0 and len(raw)==128) or (n0>0 and p0==128 and n0==len(raw)-128),"entire contiguous payload")
    payload=raw[128:]
    if kind<2:
        require(op in (1,2,3) and a==b==c==0,"complete terminal fields")
        require((kind==0 and family==code==0) or (kind==1 and family in (1,2,3,4)),"source error family")
        require((kind==0 and op==1 and len(payload)==128) or not payload,"only successful open owns a projection")
    else:
        require(seq>0 and family==code==0,"pending identity")
        require((kind==2 and op in (1,2,3,4,7,15,16)) or (kind==3 and op==2),"fixed actual effects")
        if kind==3:
            require(a==b==c==0 and len(payload)>=24 and payload[:8]==b"HAJRQ001" and word(payload,8)==2 and word(payload,16)==len(payload)-24,"actual qualified Anchor decoder frame")
    return dict(kind=kind,sequence=seq,generation=gen,operation=op,arguments=(a,b,c),payloads=(payload,b""),family=family,code=code)
def acknowledgement(effect,*,status=0,errno=0,value=0,payload=b""):
    raw=bytearray(128+len(payload));raw[:8]=b"HAPNACK1"
    for at,v in ((8,effect["generation"]),(16,effect["sequence"]),(24,effect["kind"]),(32,effect["operation"]),
                 (40,status),(48,errno),(56,value),(64,len(payload)),(72,len(raw))):put(raw,at,v)
    raw[128:]=payload
    return bytes(raw)
def semantic(raw):
    state=response(raw);require(state["kind"]<2,"terminal result")
    payload=state["payloads"][0];out=bytearray(64+len(payload));out[:8]=b"HAPNOR01"
    for at,v in ((8,state["kind"]),(16,state["operation"]),(24,state["family"]),(32,state["code"]),(40,len(payload))):put(out,at,v)
    out[64:]=payload
    return bytes(out)
def cases(root):
    value=loads(read(Path(root)/"DOMAIN.json"))
    require(value["schema"]=="hepta.audit-pinned-anchor.domain.v1" and value["expected_outputs_embedded"] is False,"source-owned corpus")
    rows=value["cases"]
    require(type(rows) is list and len(rows)==value["case_count"] and len({r["name"] for r in rows})==len(rows),"all unique cases")
    require(sum(len(r["steps"]) for r in rows)==value["operation_count"],"every original/native command")
    return rows

def validate_semantic(raw):
    require(len(raw)>=64 and raw[:8]==b"HAPNOR01" and word(raw,8) in (0,1) and word(raw,16) in (1,2,3) and word(raw,40)==len(raw)-64 and word(raw,48)==word(raw,56)==0,"complete original projection")
    require((word(raw,8)==0 and word(raw,24)==word(raw,32)==0) or word(raw,8)==1 and word(raw,24) in (1,2,3,4),"complete original kind")
    if len(raw)>64:require(word(raw,8)==0 and word(raw,16)==1 and len(raw)==192,"complete actual original Anchor")
    return raw
