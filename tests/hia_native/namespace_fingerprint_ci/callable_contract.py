"""Pure fixed real-libc callable layout and inert framing."""
import struct
from common import require
CONTEXT_BYTES=32768
OFFSETS=dict(table=64,owner_in=256,owner_out=4608,observation=4864,owner_work=8192)
FUNCTIONS=("openat","fdopendir","close","readdir","closedir","__errno_location")
def word(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def initial(generation):return b"HNFRQ001"+struct.pack("<7Q",1,generation,1,0,0,0,0)
def response(raw):
    require(len(raw)==128 and raw[:8]==b"HNFRS001","complete native result")
    words=struct.unpack("<16Q",raw)
    require(words[1] in (0,1,2) and words[3]>0,"native kind and generation")
    require(words[7:10]==(0,0,0),"response reserved header")
    if words[1]<2:
        require(words[4]==1 and words[5:10]==(0,)*5,"complete native terminal layout")
        if words[1]==0:require(words[10:12]==(0,0),"fingerprint has no error")
        else:require(words[10]==1 and words[11]<=4095 and raw[96:]==bytes(32),"complete native errno")
    else:require(1<=words[4]<=5 and raw[56:]==bytes(72),"complete native effect layout")
    return dict(kind=words[1],sequence=words[2],generation=words[3],operation=words[4],
                a=words[5],b=words[6],errno=words[11],digest=raw[96:].hex())
def semantic(raw):
    r=response(raw);require(r["kind"]<2,"terminal result")
    return dict(kind=r["kind"],errno=r["errno"],digest=r["digest"])
