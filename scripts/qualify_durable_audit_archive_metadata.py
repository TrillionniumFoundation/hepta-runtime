# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualification: original v12 metadata and real HIA descriptor recovery."""
from pathlib import Path
from contextlib import ExitStack
import argparse,ctypes,errno,fcntl,hashlib,json,os,stat,struct,subprocess,sys,time
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes()
SHA=lambda v:hashlib.sha256(v).hexdigest()
U=lambda v,at:struct.unpack_from("<Q",v,at)[0]
YIELD=0xffffffe0
LEGACY=".request-archive-v11-anchor.json"
NAMES={1:".request-archive-v12-init.json",2:".request-archive-v12-anchor.json"}
PREFIXES={1:".archive-v12-init-",2:".archive-v12-anchor-"}
PATHS=("scripts/qualify_durable_audit_archive_metadata.py","scripts/author_durable_audit_archive_metadata.py",
"scripts/durable_audit_archive_metadata_source.py.txt","native/durable_audit_archive_metadata.hepta","native/durable_audit_archive_metadata_composition.json",
"scripts/author_durable_audit_archive_metadata_packer.py","scripts/durable_audit_archive_metadata_packer_source.py.txt",
"scripts/durable_audit_archive_metadata_code.json","scripts/durable_audit_archive_metadata_engine.S",
"native/durable_audit_archive_metadata_packer.hepta","native/durable_audit_archive_metadata_packer_composition.json",
"native/durable_audit_archive_records.hepta","native/durable_audit_archive_records_composition.json",
"native/durable_audit_record_io.hepta","scripts/author_durable_common.py",
"scripts/prepare_durable_audit_archive_metadata_reference.py","src/mcp/runtime/request_archive_store.rs","src/mcp/runtime/request_audit.rs",
"src/mcp/runtime/request_archive_store_tests.rs","scripts/hia_native_build.py","scripts/hia_native_loader.py")
def pins(root):
 return{n:dict(bytes=len(v),sha256=SHA(v),mode=stat.S_IMODE((root/n).stat().st_mode))for n in PATHS for v in[(root/n).read_bytes()]}
def packet(op):return b"HRAAMQ01"+struct.pack("<QQQ",op,0,0)
def stamp(st):
 return[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,
 st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
def stamp10(st):
 s=stamp(st);return[s[0],s[1],s[6],s[2],s[3],s[5],*s[7:]]
class Engine:
 def __init__(self,raw,record):
  assert raw[:8]==b"HRAMPK01"and len(raw)==U(raw,8)==64+U(raw,16)
  self.flat=raw[64:];assert SHA(self.flat)==record["flat_sha256"]and len(self.flat)==record["flat_bytes"]
  self.exports=dict(zip(("create","step","child_ack","take","destroy"),struct.unpack_from("<5Q",raw,24)))
  assert self.exports==record["exports"]
  self.fd=os.memfd_create("hia-audit-archive-metadata-engine",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
  self.libc=ctypes.CDLL(None,use_errno=True);self.libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long];self.libc.mmap.restype=ctypes.c_void_p
  self.libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];self.libc.munmap.restype=ctypes.c_int
  self.address=None
  try:
   at=0
   while at<len(self.flat):n=os.write(self.fd,self.flat[at:]);assert n>0;at+=n
   fcntl.fcntl(self.fd,fcntl.F_ADD_SEALS,15);assert fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)==15
   assert os.pread(self.fd,len(self.flat),0)==self.flat
   self.address=self.libc.mmap(None,len(self.flat),5,2,self.fd,0);assert self.address not in(None,ctypes.c_void_p(-1).value)
   for name,args in[("create",[ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_int64]),("step",[ctypes.c_void_p]),("child_ack",[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64]),("take",[ctypes.c_void_p,ctypes.c_uint64]),("destroy",[ctypes.c_void_p])]:
    setattr(self,name,ctypes.CFUNCTYPE(ctypes.c_int64,*args)(self.address+self.exports[name]))
  except BaseException:
   if self.address not in(None,ctypes.c_void_p(-1).value):self.libc.munmap(self.address,len(self.flat))
   os.close(self.fd);self.fd=None;raise
 def state(self,ctx):
  v=ctypes.string_at(ctx,224);assert v[:8]==b"HRAAMG01"
  return dict(sequence=U(v,32),pending=U(v,40),owned=U(v,56),fds=list(struct.unpack_from("<6q",v,64)),snapshot=v[160:224].hex())
 def cleanup(self,ctx):
  s=self.state(ctx)
  # This qualification runs private children synchronously. Pending here means
  # the child has not been invoked or has already returned; never unknown work.
  if s["pending"]==2:assert self.child_ack(ctx,0,errno.ECANCELED)==0
  assert self.destroy(ctx)==0
 def close(self):
  if self.fd is not None:
   assert os.pread(self.fd,len(self.flat),0)==self.flat and fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)==15
   assert self.libc.munmap(self.address,len(self.flat))==0;os.close(self.fd);self.fd=None
 def __enter__(self):return self
 def __exit__(self,*args):self.close()

class Metadata:
 def __init__(self,actor,records,engine,root):
  self.actor=actor;self.records=records;self.engine=engine
  self.root=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  self.session=actor.session(output_capacity=4384,workspace_capacity=1048576)
  self.ctx=engine.create(0,ctypes.addressof(self.session._workspace),1048576,self.root);assert self.ctx>0
  self.trace=[];self.owned_seen=[]
 def drive(self,operation,*,before=None,after=None):
  frame=packet(operation)
  for _ in range(1000000):
   code,out,w=self.session.invoke_raw(frame)
   if code!=YIELD:
    assert 160<=code<=4384 and out[:8]==b"HRAAMR01"and U(out,40)==code,(code,self.trace)
    assert self.engine.state(self.ctx)["owned"]==0
    r=dict(diagnostic=U(out,8),errno=U(out,16),point=U(out,24),operation=U(out,32),present=U(out,48),recovered=U(out,56),raw=out[:code].hex())
    if r["diagnostic"]==0 and r["present"]==1:
     wire=out[160:code];assert wire[:8]==b"HRAATR01"and U(wire,24)==len(wire)
     r["stamp"]=list(struct.unpack_from("<10Q",out,64))
     record=dict(format=U(wire,32),root=[U(wire,40),U(wire,48)],legacy=[U(wire,56),U(wire,64)],
       archive=[U(wire,80),U(wire,88)]if U(wire,72)else None,
       shards=[list(struct.unpack_from("<QQ",wire,128+16*i))for i in range(U(wire,96))])
     r["record"]=record;r["record_wire_hex"]=wire.hex()
    else:assert code==160
    return r
   words=struct.unpack_from("<12Q",w,256)
   row=dict(sequence=words[1],kind=words[2],slot=words[3],span=words[4],count=words[5],arg=words[6],capacity=words[7],action_hex=w[256:352].hex())
   assert words[0]==int.from_bytes(b"HRAAMA01","little")and words[8:]==(0,0,0,0)
   if before:before(row,self)
   value=self.engine.step(self.ctx);assert value in(0,1),(value,row,self.engine.state(self.ctx))
   state=self.engine.state(self.ctx);self.owned_seen.extend(fd for fd in state["fds"][1:]if fd>=0)
   if value==1:
    assert row["kind"]==100
    fixed=ctypes.string_at(self.ctx,224)
    assert self.engine.step(self.ctx)==-errno.EBUSY and ctypes.string_at(self.ctx,224)==fixed
    request=ctypes.string_at(ctypes.addressof(self.session._workspace)+row["span"],row["count"])
    payload=self.records.invoke(request,output_capacity=262272,workspace_capacity=512+4*U(request,16))
    assert len(payload)<=262272
    ctypes.memmove(ctypes.addressof(self.session._workspace)+row["arg"],payload,len(payload))
    assert self.engine.child_ack(self.ctx,len(payload),0)==0
    row.update(child_request_hex=request.hex(),child_response_hex=payload.hex())
   current=ctypes.string_at(ctypes.addressof(self.session._workspace)+256,96)
   row.update(result=U(current,72),errno=U(current,80),private=self.engine.state(self.ctx))
   assert U(current,64)==row["sequence"]and U(current,88)==0
   if row["kind"]==2 and row["errno"]==0:
    observed=ctypes.string_at(ctypes.addressof(self.session._workspace)+512,88)
    row["metadata"]=list(struct.unpack("<11Q",observed))
    assert row["metadata"]==stamp(os.fstat(self.engine.state(self.ctx)["fds"][row["slot"]]))
   if row["kind"]in(5,9)and row["errno"]==0:
    row["read_hex"]=ctypes.string_at(ctypes.addressof(self.session._workspace)+row["span"],row["result"]).hex()
   self.trace.append(row)
   if after:after(row,self)
  raise AssertionError("qualification step safety bound exceeded; not a production entry cap")
 def close(self):
  if self.ctx is not None:
   self.engine.cleanup(self.ctx);self.ctx=None
   for fd in set(self.owned_seen):
    try:os.fstat(fd)
    except OSError as e:assert e.errno==errno.EBADF
    else:raise AssertionError("owned metadata descriptor leaked")
   os.fstat(self.root);os.close(self.root);self.root=None;self.session.close()
 def __enter__(self):return self
 def __exit__(self,*args):self.close()

def cases():
 rows=[]
 for op in(1,2):
  base=[("plain",{}),("sequence",{"encoding":"sequence"}),("whitespace-bound",{"padding":65536}),
   ("size-over",{"padding":65537}),("empty",{"raw":"empty"}),("null",{"raw":"null"}),
   ("unknown-field",{"raw":"unknown"}),("duplicate-field",{"raw":"duplicate"}),
   ("unsigned-overflow",{"raw":"overflow"}),("float-format",{"raw":"float"}),("trailing",{"raw":"trailing"}),
   ("missing-format",{"raw":"missing-format"}),("escaped-key",{"raw":"escaped"}),
   ("format11",{"format":11}),("root-mismatch",{"root_bad":True}),("legacy-mismatch",{"legacy_bad":True}),
   ("metadata-missing",{"metadata_kind":"missing"}),("metadata-symlink",{"metadata_kind":"symlink"}),
   ("metadata-directory",{"metadata_kind":"directory"}),("metadata-fifo",{"metadata_kind":"fifo"}),
   ("known-alias",{"alias":"known"}),("unknown-alias",{"alias":"unknown"}),
   ("upper-nonce",{"alias":"uppercase"}),("short-nonce",{"alias":"short"}),
   ("other-prefix",{"alias":"other"}),("missing-suffix",{"alias":"suffix"}),
   ("three-links",{"alias":"three"}),("invalid-record-with-known-alias",{"raw":"unknown","alias":"known"}),
   ("wrong-root-with-known-alias",{"root_bad":True,"alias":"known"}),
   ("wrong-format-with-known-alias",{"format":11,"alias":"known"}),
   ("unknown-before-known",{"alias":"known","other":"unrelated-file"}),
   ("foreign-alias-unsafe-mode",{"alias":"known","other":"unrelated-mode"}),
   ("foreign-alias-directory",{"alias":"known","other":"unrelated-directory"}),
   ("foreign-alias-fifo",{"alias":"known","other":"unrelated-fifo"}),
   ("foreign-alias-symlink",{"alias":"known","other":"unrelated-symlink"}),
   ("bad-utf8-before-known",{"alias":"known","other":"invalid-utf8"}),
   ("bad-utf8-without-scan",{"other":"invalid-utf8"}),
   ("full-directory-scan",{"alias":"known","other":"many-ignored"}),
   ("legacy-missing",{"legacy_kind":"missing"}),("legacy-symlink",{"legacy_kind":"symlink"}),
   ("legacy-fifo",{"legacy_kind":"fifo"}),("legacy-directory",{"legacy_kind":"directory"}),
   ("legacy-linked",{"legacy_kind":"linked"}),("legacy-size-over",{"legacy_raw":"size"}),
   ("legacy-invalid",{"legacy_raw":"invalid"}),("legacy-sequence",{"legacy_raw":"sequence"}),
   ("legacy-invalid-before-recovery",{"legacy_raw":"invalid","alias":"known"}),
   ("legacy-root-mismatch",{"legacy_root_bad":True}),("legacy-id-mismatch",{"legacy_archive_bad":True})]
  for mode in(0,0o400,0o640,0o644,0o660,0o700,0o1600):base.append(("mode-"+oct(mode),{"mode":mode}))
  for mode in(0,0o400,0o644):base.append(("legacy-mode-"+oct(mode),{"legacy_mode":mode}))
  if op==1:
   base.extend([("optional-archive-omitted",{"raw":"omit-archive"}),("bound-empty",{"archive":True}),
     ("bound-first",{"archive":True,"count":1}),("bound-all256",{"archive":True,"count":256}),
     ("too-many-shards",{"archive":True,"count":257}),("absent-archive-with-shard",{"count":1}),
     ("too-many-before-recovery",{"archive":True,"count":257,"alias":"known"})])
  else:base.extend([("count255",{"count":255}),("count257",{"count":257}),("count0",{"count":0}),("null-archive",{"null_archive":True})])
  for label,values in base:rows.append(dict(label=("intent-"if op==1 else"anchor-")+label,operation=op,**values))
 return rows

def make_root(root,case):
 root.mkdir(parents=True,mode=0o700);root.chmod(0o700)
 st=root.stat();identity=[st.st_dev,st.st_ino];op=case["operation"]
 legacy=dict(root_device=identity[0],root_inode=identity[1],archive_device=33,archive_inode=44)
 if case.get("legacy_root_bad"):legacy["root_inode"]+=1
 if case.get("legacy_archive_bad"):legacy["archive_inode"]+=1
 lraw=json.dumps(legacy,separators=(",",":")).encode()
 if case.get("legacy_raw")=="size":lraw+=b" "*(2049-len(lraw))
 if case.get("legacy_raw")=="invalid":lraw=b'{"unknown":1}'
 if case.get("legacy_raw")=="sequence":lraw=json.dumps(list(legacy.values())).encode()
 authored={}
 def file(name,data,mode):
  p=root/name
  with p.open("xb")as f:f.write(data)
  p.chmod(mode);authored[name]=data.hex()
 def member(name,kind,data,mode):
  p=root/name
  if kind=="missing":return
  if kind=="directory":p.mkdir(mode=mode);p.chmod(mode);return
  if kind=="fifo":os.mkfifo(p,mode);p.chmod(mode);return
  if kind=="symlink":file(name+".target",data,mode);os.symlink(name+".target",p);return
  file(name,data,mode)
  if kind=="linked":os.link(p,root/(name+".linked"))
 member(LEGACY,case.get("legacy_kind","file"),lraw,case.get("legacy_mode",0o600))
 count=case.get("count",256 if op==2 else 0)
 archive=[55,66]if op==2 or case.get("archive")else None
 if case.get("null_archive"):archive=None
 data=dict(format=case.get("format",12),root=[identity[0],identity[1]+int(bool(case.get("root_bad")))],
  legacy=[33,44+int(bool(case.get("legacy_bad")))],archive=archive,shards=[[77,i]for i in range(count)])
 raw=json.dumps(list(data.values())if case.get("encoding")=="sequence"else data,separators=(",",":")).encode()
 variant=case.get("raw")
 if variant=="empty":raw=b""
 if variant=="null":raw=b"null"
 if variant=="unknown":raw=raw[:-1]+b',"extra":0}'
 if variant=="duplicate":raw=raw[:-1]+b',"format":12}'
 if variant=="overflow":raw=raw.replace(b'"format":12',b'"format":4294967296')
 if variant=="float":raw=raw.replace(b'"format":12',b'"format":12.0')
 if variant=="trailing":raw+=b"x"
 if variant=="missing-format":d=dict(data);d.pop("format");raw=json.dumps(d).encode()
 if variant=="escaped":raw=raw.replace(b'"format"',b'"for\\u006dat"')
 if variant=="omit-archive":d=dict(data);d.pop("archive");raw=json.dumps(d).encode()
 if "padding"in case:assert len(raw)<=case["padding"];raw+=b" "*(case["padding"]-len(raw))
 name=NAMES[op];member(name,case.get("metadata_kind","file"),raw,case.get("mode",0o600))
 other=case.get("other");other_name=PREFIXES[op]+"0"*64+".tmp"
 if other=="unrelated-file":file(other_name,b"other",0o600)
 if other=="unrelated-mode":file(other_name,b"other",0o755)
 if other=="unrelated-directory":(root/other_name).mkdir(mode=0o700)
 if other=="unrelated-fifo":os.mkfifo(root/other_name,0o600)
 if other=="unrelated-symlink":os.symlink(LEGACY,root/other_name)
 if other=="invalid-utf8":file(os.fsdecode(b"unrelated-\xff"),b"ignored",0o600)
 if other=="many-ignored":
  for i in range(4097):file("ignored-"+str(i).zfill(5),b"x",0o600)
 alias=case.get("alias")
 if alias:
  alias_name=PREFIXES[op]+"a"*64+".tmp"
  if alias=="unknown":alias_name="unrecognized-alias"
  if alias=="uppercase":alias_name=PREFIXES[op]+"A"*64+".tmp"
  if alias=="short":alias_name=PREFIXES[op]+"a"*63+".tmp"
  if alias=="other":alias_name=PREFIXES[3-op]+"a"*64+".tmp"
  if alias=="suffix":alias_name=PREFIXES[op]+"a"*64+".tmpX"
  os.link(root/name,root/alias_name)
  if alias=="three":os.link(root/name,root/(PREFIXES[op]+"b"*64+".tmp"))
 return dict(root_identity=identity,authored=authored,raw_hex=raw.hex(),legacy_hex=lraw.hex(),requested_record=data)

def snapshot(root,authored):
 rows={};objects={}
 for p in sorted(root.iterdir()):
  st=p.lstat();name=p.name;key=(st.st_dev,st.st_ino);objects.setdefault(key,[]).append(name)
  row=dict(mode=stat.S_IMODE(st.st_mode),kind=stat.S_IFMT(st.st_mode),links=st.st_nlink,stamp=stamp(st))
  if stat.S_ISREG(st.st_mode):
   try:
    raw=p.read_bytes();row.update(bytes=len(raw),sha256=SHA(raw),raw_hex=raw.hex())
    assert raw.hex()in authored.values(),(name,"unexpected content mutation")
   except PermissionError as e:row["read_error"]=e.errno
  if stat.S_ISLNK(st.st_mode):row["target"]=os.readlink(p)
  rows[name]=row
 for names in objects.values():
  for name in names:rows[name]["same_inode_as"]=min(names)
 return rows
def normalized_snapshot(rows):
 return{n:{k:r[k]for k in("mode","kind","links","same_inode_as","target","read_error")if k in r}for n,r in rows.items()}
def normalize_record(value,identity):
 result=dict(value);r=list(result["root"])
 if r==identity:result["root"]=["actual-root-device","actual-root-inode"]
 return result
def original_category(value,op):
 if value["accepted"]:return("ok",None)
 error=value["error"]
 if error["io_errno"]is not None:return("io",error["io_errno"])
 text=error["text"]
 exact={
 "request archive initialization intent refused":"private",
 "request archive layout anchor refused":"private",
 "request archive initialization intent changed":"changed-read",
 "request archive layout anchor changed":"changed-read",
 "private request audit inode refused":"legacy-private",
 "request archive anchor size refused":"legacy-size",
 "request archive initialization intent binding changed":"binding",
 "request archive layout anchor binding changed":"binding",
 "request archive initialization metadata refused":"recovery-private",
 "request archive initialization hard-link binding refused":"recovery-binding",
 "request archive initialization intent link count changed":"final-link",
 "request archive layout anchor link count changed":"final-link"}
 if text in exact:return(exact[text],None)
 if "utf-8"in text.lower():return("utf8",None)
 return("typed",None)
def native_category(result):
 if result["diagnostic"]==0:return("ok",None)
 p,e=result["point"],result["errno"]
 if e:return("io",e)
 return({3:"private",5:"changed-read",7:"typed",10:"legacy-private",12:"legacy-size",14:"typed",16:"binding",
  18:"recovery-private",22:"directory-format",23:"utf8",26:"recovery-binding",30:"final-link"}.get(p,"unknown"),None)

def controls(actor,records,packer,engine,q):
 q.mkdir(parents=True,exist_ok=False);rows=[]
 def yes(label,condition):assert condition,label;rows.append(dict(label=label,passed=True))
 good=b"HRAMPQ01"+struct.pack("<QQ",1,0)
 expected=packer.invoke(good,output_capacity=2928,workspace_capacity=16)
 for n in(0,1,7,8,16,23,25,32):
  with packer.session(output_capacity=2928,workspace_capacity=16)as s:
   code,_,_=s.invoke_raw(good[:n]if n<=24 else good+b"x"*(n-24));yes("packer-length-"+str(n),code==0xffffffff)
 for index in range(24):
  bad=bytearray(good);bad[index]^=1
  with packer.session(output_capacity=2928,workspace_capacity=16)as s:
   code,_,_=s.invoke_raw(bytes(bad));yes("packer-byte-"+str(index),code==0xffffffff)
 for cap in(0,63,64,2927):
  with packer.session(output_capacity=cap,workspace_capacity=16)as s:
   code,_,_=s.invoke_raw(good);yes("packer-capacity-"+str(cap),code==0xfffffffe)
 yes("emitter-whole-code",expected[64:]==engine.flat)
 frame=packet(1)
 for n in(0,1,7,8,16,24,31,33,64):
  with actor.session(output_capacity=4384,workspace_capacity=1048576)as s:
   code,_,_=s.invoke_raw(frame[:n]if n<=32 else frame+b"x"*(n-32));yes("actor-length-"+str(n),code==0xffffffff)
 for index in list(range(8))+list(range(16,32)):
  bad=bytearray(frame);bad[index]^=1
  with actor.session(output_capacity=4384,workspace_capacity=1048576)as s:
   code,_,_=s.invoke_raw(bytes(bad));yes("actor-byte-"+str(index),code==0xffffffff)
 for op in(0,3,2**64-1):
  with actor.session(output_capacity=4384,workspace_capacity=1048576)as s:
   code,_,_=s.invoke_raw(packet(op));yes("actor-operation-"+str(op),code==0xffffffff)
 for out,work in[(4383,1048576),(4384,1048575)]:
  with actor.session(output_capacity=out,workspace_capacity=work)as s:
   code,_,_=s.invoke_raw(frame);yes("actor-capacity-"+str(out)+"-"+str(work),code==0xfffffffe)
 for offset in(0,8,224,232,4096,73728,409600,1048575):
  with actor.session(output_capacity=4384,workspace_capacity=1048576)as s:
   ctypes.c_ubyte.from_address(ctypes.addressof(s._workspace)+offset).value=1
   code,_,_=s.invoke_raw(frame);yes("actor-initial-state-"+str(offset),code==0xffffffff)
 root=q/"private";case=dict(operation=1);fixture=make_root(root,case)
 with Metadata(actor,records,engine,root)as runner:
  code,_,w=runner.session.invoke_raw(frame);yes("first-action-yields",code==YIELD)
  ptr=ctypes.addressof(runner.session._workspace)
  frozen=ctypes.string_at(runner.ctx,224)
  yes("descriptor-export-refused",engine.take(runner.ctx,0)==-errno.EPERM)
  for offset in range(256,320,8):
   old=ctypes.string_at(ptr+offset,8);ctypes.memmove(ptr+offset,struct.pack("<Q",U(old,0)^2**63),8)
   result=engine.step(runner.ctx)
   yes("closed-effect-boundary-"+str(offset),result==-errno.EINVAL and ctypes.string_at(runner.ctx,224)==frozen)
   ctypes.memmove(ptr+offset,old,8)
  yes("real-fixed-open",engine.step(runner.ctx)==0)
  state=engine.state(runner.ctx);runner.owned_seen.extend(x for x in state["fds"][1:]if x>=0)
  oldreq=ctypes.string_at(ptr+1536,32);ctypes.c_ubyte.from_address(ptr+1536).value^=1
  code,_,_=runner.session.invoke_raw(frame);yes("whole-request-late-change",code==0xffffffff)
  ctypes.memmove(ptr+1536,oldreq,32)
  oldack=ctypes.string_at(ptr+320,8);ctypes.memmove(ptr+320,b"\0"*8,8)
  code,_,_=runner.session.invoke_raw(frame);yes("missing-ack-refused",code==0xffffffff)
  ctypes.memmove(ptr+320,oldack,8)
  result=runner.drive(1);yes("resumed-real-read",result["diagnostic"]==0 and result["present"]==1)
  code,_,_=runner.session.invoke_raw(frame);yes("terminal-replay-refused",code==0xffffffff)
 # Two genuine outstanding typed children, each cancelled only before dispatch.
 for operation in(1,2):
  private=q/("pending-"+str(operation));make_root(private,dict(operation=operation))
  with Metadata(actor,records,engine,private)as runner:
   ptr=ctypes.addressof(runner.session._workspace);frame=packet(operation)
   while True:
    code,_,w=runner.session.invoke_raw(frame);assert code==YIELD
    kind=U(w,272);step=engine.step(runner.ctx);assert step in(0,1)
    runner.owned_seen.extend(x for x in engine.state(runner.ctx)["fds"][1:]if x>=0)
    if step==1:break
   yes("actual-child-pending-"+str(operation),kind==100)
   frozen=ctypes.string_at(runner.ctx,224)
   yes("pending-no-effect-"+str(operation),engine.step(runner.ctx)==-errno.EBUSY and ctypes.string_at(runner.ctx,224)==frozen)
   yes("pending-no-destroy-"+str(operation),engine.destroy(runner.ctx)==-errno.EBUSY and ctypes.string_at(runner.ctx,224)==frozen)
   for offset in(1536,1544,73728,73736,73744,73752,73760):
    old=ctypes.string_at(ptr+offset,1);ctypes.c_ubyte.from_address(ptr+offset).value^=1
    yes("child-late-input-"+str(operation)+"-"+str(offset),engine.child_ack(runner.ctx,0,errno.ECANCELED)==-errno.EINVAL and ctypes.string_at(runner.ctx,224)==frozen)
    ctypes.memmove(ptr+offset,old,1)
   yes("known-undispatched-cancel-"+str(operation),engine.child_ack(runner.ctx,0,errno.ECANCELED)==0)
   yes("child-ack-no-replay-"+str(operation),engine.child_ack(runner.ctx,0,errno.ECANCELED)==-errno.EINVAL)
   result=runner.drive(operation);yes("cancel-owned-cleanup-"+str(operation),result["diagnostic"]==1 and result["errno"]==errno.ECANCELED and engine.state(runner.ctx)["owned"]==0)
 (q/"controls.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
 return rows

def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--actor",type=Path,required=True);p.add_argument("--records",type=Path,required=True);p.add_argument("--packer",type=Path,required=True);p.add_argument("--oracle",type=Path);p.add_argument("--provenance",type=Path);p.add_argument("--controls-only",action="store_true");p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 q=a.output;q.mkdir(parents=True,exist_ok=False);assert SELF==a.source/"scripts/qualify_durable_audit_archive_metadata.py"and SELF.read_bytes()==EXECUTED
 before=pins(a.source);proof_raw=b"";binary=b""
 if not a.controls_only:
  proof_raw=a.provenance.read_bytes();proof=json.loads(proof_raw);binary=a.oracle.read_bytes()
  assert proof["state"]=="PASS"and proof["original_release_profile"]is True and proof["original_default_features"]is True and proof["locked_registry_archives"]==360
  assert proof["binary_record"]["sha256"]==SHA(binary)and proof["original_archive_store_methods"]==29
 manifests={str(path):path.read_bytes()for path in(a.actor,a.records,a.packer)}
 record_raw=(a.source/"scripts/durable_audit_archive_metadata_code.json").read_bytes();code_record=json.loads(record_raw)
 assert code_record["source_sha256"]==SHA((a.source/"scripts/durable_audit_archive_metadata_engine.S").read_bytes())
 sys.path.insert(0,str(a.source/"scripts"));from hia_native_loader import NativeModule
 cases_=cases();(q/"cases.json").write_text(json.dumps(cases_,sort_keys=True,indent=2)+"\n")
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 results=[];failures=[];start=time.monotonic()
 with ExitStack()as stack:
  actor=stack.enter_context(NativeModule(a.actor,manifest_sha256=SHA(manifests[str(a.actor)])))
  records=stack.enter_context(NativeModule(a.records,manifest_sha256=SHA(manifests[str(a.records)])))
  packer=stack.enter_context(NativeModule(a.packer,manifest_sha256=SHA(manifests[str(a.packer)])))
  produced=packer.invoke(b"HRAMPQ01"+struct.pack("<QQ",1,0),output_capacity=2928,workspace_capacity=16)
  (q/"actual-hia-engine.pack").write_bytes(produced);engine=stack.enter_context(Engine(produced,code_record))
  extra=controls(actor,records,packer,engine,q/"controls")
  for i,case in enumerate([]if a.controls_only else cases_):
   cq=q/("case-"+str(i).zfill(3));cq.mkdir();original_root=cq/"original";native_root=cq/"native"
   original_fixture=make_root(original_root,case);native_fixture=make_root(native_root,case)
   initial={"original":snapshot(original_root,original_fixture["authored"]),"native":snapshot(native_root,native_fixture["authored"])}
   (cq/"fixtures.json").write_text(json.dumps(dict(original=original_fixture,native=native_fixture),sort_keys=True,indent=2)+"\n")
   command=json.dumps(dict(root=str(original_root),operation="read_intent"if case["operation"]==1 else"read_anchor"),separators=(",",":")).encode()+b"\n"
   (cq/"original-input.json").write_bytes(command);run_start=time.monotonic()
   reference=subprocess.run([str(a.oracle)],input=command,capture_output=True,timeout=10)
   (cq/"original.stdout").write_bytes(reference.stdout);(cq/"original.stderr").write_bytes(reference.stderr)
   (cq/"original-terminal.json").write_text(json.dumps(dict(exit_code=reference.returncode,elapsed_seconds=time.monotonic()-run_start))+"\n")
   assert reference.returncode==0 and not reference.stderr,(i,case,reference.returncode,reference.stderr)
   original=json.loads(reference.stdout)
   with Metadata(actor,records,engine,native_root)as runner:observed=runner.drive(case["operation"]);trace=runner.trace
   terminal={"original":snapshot(original_root,original_fixture["authored"]),"native":snapshot(native_root,native_fixture["authored"])}
   category=original_category(original,case["operation"]);observed_category=native_category(observed)
   equal=original["accepted"]==(observed["diagnostic"]==0)and category==observed_category
   equal=equal and normalized_snapshot(terminal["original"])==normalized_snapshot(terminal["native"])
   if original["accepted"]:
    value=original["value"];equal=equal and value["present"]==bool(observed["present"])
    if value["present"]:
     equal=equal and normalize_record(value["record"],original_fixture["root_identity"])==normalize_record(observed["record"],native_fixture["root_identity"])
     if case["operation"]==2:assert value["stamp"]==stamp10((original_root/NAMES[2]).stat())
     assert observed["stamp"]==stamp10((native_root/NAMES[case["operation"]]).stat())
   result=dict(ordinal=i,label=case["label"],equal=equal,original=original,native=observed,
    original_category=category,native_category=observed_category,initial=initial,terminal=terminal,trace=trace)
   (cq/"result.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");results.append(dict(ordinal=i,label=case["label"],equal=equal))
   if not equal:failures.append(dict(ordinal=i,label=case["label"],original_category=category,native_category=observed_category))
 after=pins(a.source)
 if not a.controls_only:assert a.oracle.read_bytes()==binary and a.provenance.read_bytes()==proof_raw
 assert all(Path(path).read_bytes()==v for path,v in manifests.items())and(a.source/"scripts/durable_audit_archive_metadata_code.json").read_bytes()==record_raw
 (q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
 report=dict(schema="hepta.runtime.durable-archive-metadata-qualification.v1",passed=not failures and before==after,cases=len(results),controls=extra,results=results,failures=failures,
 source_before=before,source_after=after,source_unchanged=before==after,original_binary_sha256=SHA(binary)if binary else None,original_provenance_sha256=SHA(proof_raw)if proof_raw else None,
 actual_hia_engine_sha256=SHA(produced),elapsed_seconds=time.monotonic()-start,public_archive_qualified=False,redb_qualified=False,python_is_qualification_transport_only=True)
 (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps(dict(passed=report["passed"],cases=len(results),controls=len(extra),failures=failures,elapsed_seconds=report["elapsed_seconds"],source_unchanged=before==after),sort_keys=True),flush=True)
 if not report["passed"]:raise SystemExit(1)
if __name__=="__main__":main()
