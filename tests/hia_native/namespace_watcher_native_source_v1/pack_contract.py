"""Pure exact-byte native callable composition, with no dynamic execution."""
import struct
from common import pin,require
def inputs(owner,composition):
    require(pin(owner)==composition["owner"],"exact semantic HIA image")
    adapter=bytes.fromhex(composition["adapter_hex"])
    require(pin(adapter)==composition["adapter"],"complete mechanical adapter bytes")
    o=composition["offsets"]
    require(o["entry"]==0 and o["owner"]==len(adapter) and
        o["end"]==composition["image_bytes"]==len(adapter)+len(owner) and
        0<o["initialize"]<o["bind"]<o["dispose"]<o["pin_adopt"]<o["pin_clone"]<o["pin_release"]<o["owner"],"all exact native offsets")
    return b"HNWPK001"+struct.pack("<2Q",1,len(owner))+owner,adapter+owner
def cases(wire,size):
    return [
        ("valid",wire,size+64,size),
        ("empty",b"",size+64,0xffffffff),
        ("short",wire[:-1],size+64,0xffffffff),
        ("long",wire+b"\0",size+64,0xffffffff),
        ("magic",b"X"+wire[1:],size+64,0xffffffff),
        ("version",wire[:8]+struct.pack("<Q",2)+wire[16:],size+64,0xffffffff),
        ("owner-size",wire[:16]+struct.pack("<Q",len(wire)-25)+wire[24:],size+64,0xffffffff),
        ("capacity",wire,size-1,0xfffffffe),
    ]
