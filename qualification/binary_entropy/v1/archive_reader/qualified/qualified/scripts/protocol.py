"""Exact private entropy transport and full retained journal records."""
import struct
from evidence_common import require
MASK=(1<<64)-1
HEADER=struct.Struct("<8s5Q")
def u(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def signed(v):return v-(1<<64)if v>>63 else v
def request(mode):return b"HENTQ001"+struct.pack("<11Q",1,0,mode,0,0,0,0,0,0,0,0)
def exception(e):
    return dict(type=type(e).__name__,module=type(e).__module__,errno=getattr(e,"errno",None),
        filename=getattr(e,"filename",None),filename2=getattr(e,"filename2",None),
        message=str(e),args=list(e.args))
def events(raw):
    result=[];at=0
    while at<len(raw):
        require(len(raw)-at>=HEADER.size,"truncated complete event header")
        magic,kind,context,pointer,n,c=HEADER.unpack_from(raw,at);start=at;at+=HEADER.size
        require(magic==b"HENTEV01"and c in(0,4096)and n<=1048576 and at+c+n<=len(raw),"complete event frame")
        result.append(dict(start=start,end=at+c+n,kind=kind,context=context,pointer=pointer,
            context_bytes=raw[at:at+c],data=raw[at+c:at+c+n]))
        at+=c+n
    return result
def result(raw):
    require(len(raw)>=64 and raw[:8]==b"HENTR001"and u(raw,56)==len(raw)-64,"complete entropy result")
    require(raw[24:56]==bytes(32),"result reserved words")
    kind=u(raw,8)
    if kind==0:return dict(ok=True,payload_hex=raw[64:].hex())
    require(kind==3 and len(raw)>=128 and raw[64:72]==b"HBRDS001"and u(raw,72)==3
        and u(raw,120)==len(raw)-128 and u(raw,80)==u(raw,16),"complete nested entropy error")
    klass,number,message,named=u(raw,88),u(raw,96),u(raw,104),u(raw,112)
    require(message<=len(raw)-128 and named in(0,1),"complete nested error extents")
    literal=raw[128:128+message].decode("utf-8")
    filename=raw[128+message:].decode("utf-8")if named else None
    require(named or len(raw)==128+message,"unclaimed nested error bytes")
    types={2:"PermissionError",3:type(OSError(number,"")).__name__,4:"FileNotFoundError",5:"NotADirectoryError",
        6:"IsADirectoryError",7:"FileExistsError",8:"InterruptedError",9:"BlockingIOError",
        10:"BrokenPipeError",11:"TimeoutError",12:"ConnectionResetError",13:"ConnectionAbortedError",
        14:"ConnectionRefusedError",16:"NotImplementedError",17:"RuntimeError"}
    require(klass in types,"known exact entropy error class")
    return dict(ok=False,error=dict(type=types[klass],errno=number or None,filename=filename,
        literal=literal if klass in(16,17)else None))
def project(raw,mode):
    require(len(raw)==16,"complete sixteen-byte entropy")
    if mode==1:return raw
    value=bytearray(raw);value[6]=(value[6]&15)|64;value[8]=(value[8]&63)|128
    return bytes(value).hex().encode()
