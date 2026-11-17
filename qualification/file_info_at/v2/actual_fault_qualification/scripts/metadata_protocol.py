"""Private result decoding; no expected outcome or OS decisions."""
import os,stat,struct
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
    for at,value in((72,s.st_atime_ns),(88,s.st_mtime_ns),(104,s.st_ctime_ns)):
        seconds,nano=divmod(value,1000000000);struct.pack_into("<qQ",b,at,seconds,nano)
    return bytes(b)
def snapshot_decode(raw):
    require(len(raw)>=73856 and raw[:8]==b"HMTSS001"and U(raw,8)==1,"snapshot ABI")
    count,names,values,extent=(U(raw,p)for p in(56,64,72,80))
    require(count<=256 and names<=65536 and values<=4194304 and extent==len(raw)==73856+values
        and U(raw,88)==U(raw,120)==0 and tuple(U(raw,p)for p in(96,104,112))==(128,8320,73856),"snapshot bounds")
    attrs=[];seen=set();names_used=8320;value_used=73856
    for i in range(count):
        no,nl,vo,vl=struct.unpack_from("<4Q",raw,128+32*i)
        require(no==names_used and nl>0 and no+nl<8320+names and raw[no+nl]==0
            and b"\0"not in raw[no:no+nl] and vo==value_used and vo+vl<=len(raw),"snapshot owned spans")
        name=raw[no:no+nl];require(name not in seen,"snapshot duplicate name");seen.add(name)
        attrs.append(dict(name_hex=name.hex(),value_hex=raw[vo:vo+vl].hex()))
        names_used+=nl+1;value_used+=vl
    require(names_used==8320+names and value_used==len(raw),"snapshot complete extents")
    require(raw[128+32*count:8320]==bytes(8320-128-32*count)
        and raw[8320+names:73856]==bytes(65536-names),"snapshot unused fixed region")
    return dict(uid=U(raw,16),gid=U(raw,24),mode=U(raw,32),nlink=U(raw,40),flags=U(raw,48),attributes=attrs,acl_hex=None)
def snapshot_encode(value):
    from cases import snapshot
    return snapshot(dict(uid=value["uid"],gid=value["gid"],mode=value["mode"],nlink=str(value["nlink"]),attributes=value["attributes"]))
def original_snapshot(value):
    return dict(uid=value["uid"],gid=value["gid"],mode=value["mode"],nlink=value["nlink"],flags=value["flags"],
        attributes=[dict(name_hex=os.fsencode(n).hex(),value_hex=v.hex())for n,v in value["xattrs"].items()],
        acl_hex=None if value["acl"]is None else value["acl"].hex())
def exception(e):
    return dict(type=type(e).__name__,errno=getattr(e,"errno",None),filename=getattr(e,"filename",None),
        message=str(e)if getattr(e,"errno",None)is None else getattr(e,"strerror",None),
        exact_str=str(e),args_repr=repr(e.args))
def result(frame):
    require(len(frame)>=64 and frame[:8]==b"HMDSR001"and len(frame)==64+U(frame,56),"terminal result extent")
    kind=U(frame,8)
    if kind==0:
        mode=U(frame,24);require(mode in(1,2,3)and all(U(frame,p)==0 for p in(32,40,48)),"terminal success fields")
        out=dict(ok=True,mode=mode,value=snapshot_decode(frame[64:])if mode==1 else decode(frame[64:]))
        if mode in(2,3):out["value_json"]=frame[64:].decode("ascii")
        return out
    require(kind==3,"metadata did not finish")
    code,number,count,named=(U(frame,p)for p in(24,32,40,48))
    require(code in CLASSES and number<=4095 and named in(0,2)and count+(8 if named else 0)==len(frame)-64,"structured exception")
    return dict(ok=False,error=dict(type=CLASSES[code],errno=number or None,
        filename=U(frame,64+count)if named else None,message=frame[64:64+count].decode("utf-8")))
