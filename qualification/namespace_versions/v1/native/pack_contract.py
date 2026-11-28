"""Inert byte composition of the three exact qualified/fresh members."""
import struct
from common import pin,require
MEMBERS=("namespace-versions","namespace-watcher","namespace-fingerprint")
def inputs(images,proof):
    require(tuple(images)==MEMBERS,"exact three image order")
    require({name:pin(raw)for name,raw in images.items()}==proof["members"],"every complete actual image")
    adapter=bytes.fromhex(proof["adapter_hex"]);require(pin(adapter)==proof["adapter"],"every native adapter byte")
    lengths=[len(images[n])for n in MEMBERS];o=proof["offsets"]
    require(o["entry"]==0 and o["owner"]==len(adapter)and o["owner"]%16==0
        and o["watcher"]==len(adapter)+lengths[0]and o["fingerprint"]==len(adapter)+sum(lengths[:2])
        and o["end"]==proof["image_bytes"]==len(adapter)+sum(lengths),"exact complete export/member offsets")
    body=b"".join(images[n]for n in MEMBERS)
    return b"HNVPK001"+struct.pack("<4Q",1,*lengths)+body,adapter+body
def cases(wire,size):
    rows=[("valid",wire,size+64,size),("empty",b"",size+64,0xffffffff),
        ("short",wire[:-1],size+64,0xffffffff),("long",wire+b"\0",size+64,0xffffffff),
        ("magic",b"X"+wire[1:],size+64,0xffffffff),("version",wire[:8]+struct.pack("<Q",2)+wire[16:],size+64,0xffffffff)]
    for at,name in((16,"policy-size"),(24,"watcher-size"),(32,"fingerprint-size")):
        rows.append((name,wire[:at]+struct.pack("<Q",0)+wire[at+8:],size+64,0xffffffff))
    rows.append(("capacity",wire,size-1,0xfffffffe));return rows
def child_inputs(owner,proof,name):
    require(pin(owner)==proof["owner"],"exact fresh qualified child owner")
    adapter=bytes.fromhex(proof["adapter_hex"]);require(pin(adapter)==proof["adapter"],"whole qualified child adapter")
    require(proof["offsets"]["owner"]==len(adapter)and proof["offsets"]["end"]==len(adapter)+len(owner),"child positions")
    magic={"namespace-watcher":b"HNWPK001","namespace-fingerprint":b"HNFPK001"}[name]
    return magic+struct.pack("<2Q",1,len(owner))+owner,adapter+owner
def child_cases(wire,size):
    return [("valid",wire,size+64,size),("empty",b"",size+64,0xffffffff),
        ("short",wire[:-1],size+64,0xffffffff),("long",wire+b"\0",size+64,0xffffffff),
        ("magic",b"X"+wire[1:],size+64,0xffffffff),("version",wire[:8]+struct.pack("<Q",2)+wire[16:],size+64,0xffffffff),
        ("owner-size",wire[:16]+struct.pack("<Q",0)+wire[24:],size+64,0xffffffff),
        ("capacity",wire,size-1,0xfffffffe)]
