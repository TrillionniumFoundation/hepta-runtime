"""Full fixed info frames, actual errors, and Linux stat observations."""
import os,struct
from evidence_common import decode,require
U=lambda b,o:struct.unpack_from("<Q",b,o)[0]
I=lambda n:n-(1<<64)if n>>63 else n
CLASSES={1:"ValueError",2:"PermissionError",3:"OSError",4:"FileNotFoundError",5:"NotADirectoryError",
6:"IsADirectoryError",7:"FileExistsError",8:"InterruptedError",9:"BlockingIOError",10:"BrokenPipeError",
11:"TimeoutError",12:"ConnectionResetError",13:"ConnectionAbortedError",14:"ConnectionRefusedError"}
def stat_value(s):
    return {k:getattr(s,k)for k in("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size",
        "st_atime_ns","st_mtime_ns","st_ctime_ns","st_rdev","st_blksize","st_blocks")}
def stat_decode(raw):
    require(len(raw)==144,"complete Linux stat")
    return dict(st_dev=U(raw,0),st_ino=U(raw,8),st_nlink=U(raw,16),st_mode=struct.unpack_from("<I",raw,24)[0],
        st_uid=struct.unpack_from("<I",raw,28)[0],st_gid=struct.unpack_from("<I",raw,32)[0],
        st_rdev=U(raw,40),st_size=I(U(raw,48)),st_blksize=I(U(raw,56)),st_blocks=I(U(raw,64)),
        st_atime_ns=I(U(raw,72))*1000000000+U(raw,80),st_mtime_ns=I(U(raw,88))*1000000000+U(raw,96),
        st_ctime_ns=I(U(raw,104))*1000000000+U(raw,112))
def stat_encode(s):
    b=bytearray(144);struct.pack_into("<3Q3I",b,0,s.st_dev,s.st_ino,s.st_nlink,s.st_mode,s.st_uid,s.st_gid)
    struct.pack_into("<4q",b,40,s.st_rdev,s.st_size,s.st_blksize,s.st_blocks)
    for at,v in((72,s.st_atime_ns),(88,s.st_mtime_ns),(104,s.st_ctime_ns)):
        sec,nano=divmod(v,1000000000);struct.pack_into("<qQ",b,at,sec,nano)
    return bytes(b)
def version(st):return ":".join(str(st[k])for k in("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns"))
def exception(e):
    return dict(type=type(e).__name__,errno=getattr(e,"errno",None),filename=getattr(e,"filename",None),
        message=str(e)if getattr(e,"errno",None)is None else"",exact_str=str(e),args_repr=repr(e.args))
def error_frame(raw):
    require(len(raw)>=64 and raw[:8]in(b"HBRDS001",b"HMDSR001")and U(raw,8)==3
        and len(raw)==64+U(raw,56),"complete nested terminal error")
    code,number,message,named=(U(raw,p)for p in(24,32,40,48))
    require(code in CLASSES and number<=4095 and message<=len(raw)-64,"nested exception fields")
    name=None
    if raw[:8]==b"HBRDS001":
        require(named in(0,1)and (named or message==len(raw)-64),"HBRDS filename form")
        if named:name=raw[64+message:].decode("utf-8")
    else:
        require(named in(0,2)and message+(8 if named else 0)==len(raw)-64,"HMDS filename form")
        if named:name=U(raw,64+message)
    cls=CLASSES[code]
    if code==3 and number in(3,10):cls="ProcessLookupError"if number==3 else"ChildProcessError"
    return dict(type=cls,errno=number or None,filename=name,message=raw[64:64+message].decode("utf-8"))
def result(frame):
    require(len(frame)>=64 and frame[:8]==b"HINFR001"and len(frame)==64+U(frame,56)
        and all(U(frame,p)==0 for p in(24,32,40,48)),"terminal info extent")
    if U(frame,8)==0:
        value=decode(frame[64:]);require(isinstance(value,dict),"complete info JSON value")
        return dict(ok=True,value=value)
    require(U(frame,8)==3,"info did not terminate")
    return dict(ok=False,error=error_frame(frame[64:]))
def wire(query):
    name=query["basename"].encode();path=query["original_path"].encode()
    return b"HINFQ001"+struct.pack("<11Q",1,0,1,0,len(name),len(path),0,0,0,0,len(name)+len(path))+name+path
def proc_fds(pid):
    from pathlib import Path
    out={}
    for p in sorted((Path("/proc")/str(pid)/"fd").iterdir(),key=lambda p:int(p.name)):
        target=os.readlink(p)
        try:row=dict(target=target,stat=stat_value(p.stat()))
        except OSError as e:row=dict(target=target,error=exception(e))
        out[p.name]=row
    return out
