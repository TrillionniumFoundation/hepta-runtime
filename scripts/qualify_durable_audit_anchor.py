# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualification only: original retained anchor versus actual HIA and syscalls."""
from pathlib import Path
from contextlib import ExitStack
import argparse,ctypes,errno,fcntl,hashlib,json,os,stat,struct,subprocess,sys,time
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes()
SHA=lambda v:hashlib.sha256(v).hexdigest()
U=lambda v,at:struct.unpack_from("<Q",v,at)[0]
YIELD=0xffffffe0
NAME=".request-archive-v11-anchor.json"
PATHS=("scripts/qualify_durable_audit_anchor.py","scripts/author_durable_audit_anchor.py",
 "scripts/durable_audit_anchor_source.py.txt","native/durable_audit_anchor.hepta","native/durable_audit_anchor_composition.json",
 "scripts/author_durable_audit_anchor_packer.py","scripts/durable_audit_anchor_packer_source.py.txt",
 "scripts/durable_audit_anchor_code.json","scripts/durable_audit_anchor_engine.S",
 "native/durable_audit_anchor_packer.hepta","native/durable_audit_anchor_packer_composition.json",
 "native/durable_audit_archive_records.hepta","native/durable_audit_archive_records_composition.json",
 "native/durable_audit_record_io.hepta","scripts/author_durable_common.py",
 "scripts/prepare_durable_audit_anchor_reference.py","src/mcp/runtime/request_archive_store.rs",
 "src/mcp/runtime/request_archive_store_tests.rs","scripts/hia_native_build.py","scripts/hia_native_loader.py")
def pins(root):
 return{n:dict(bytes=len(v),sha256=SHA(v),mode=stat.S_IMODE((root/n).stat().st_mode))for n in PATHS for v in[(root/n).read_bytes()]}
def packet(op):return b"HRAANQ01"+struct.pack("<QQQ",op,0,0)
def stamp(st):
 return[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,
 st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
class Engine:
 def __init__(self,raw,record):
  assert raw[:8]==b"HRAAPK01"and len(raw)==U(raw,8)==64+U(raw,16)
  self.flat=raw[64:];assert SHA(self.flat)==record["flat_sha256"]and len(self.flat)==record["flat_bytes"]
  self.exports=dict(zip(("create","step","child_ack","take","destroy"),struct.unpack_from("<5Q",raw,24)))
  assert self.exports==record["exports"]
  self.fd=os.memfd_create("hia-audit-anchor-engine",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
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
  v=ctypes.string_at(ctx,224);assert v[:8]==b"HRAANG01"
  return dict(sequence=U(v,32),pending=U(v,40),owned=U(v,56),root=struct.unpack_from("<q",v,64)[0],anchor=struct.unpack_from("<q",v,72)[0],snapshot=v[160:224].hex())
 def cleanup(self,ctx):
  s=self.state(ctx)
  if s["pending"]==2:assert self.child_ack(ctx,0,errno.ECANCELED)==0
  assert self.destroy(ctx)==0
 def close(self):
  if self.fd is not None:
   assert os.pread(self.fd,len(self.flat),0)==self.flat and fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)==15
   assert self.libc.munmap(self.address,len(self.flat))==0;os.close(self.fd);self.fd=None
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
def mutate(root,mode,original):
 path=root/NAME;alias=root/"qualification-held-anchor"
 def write(raw):
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
  try:
   os.fchmod(fd,0o600);at=0
   while at<len(raw):n=os.write(fd,raw[at:]);assert n>0;at+=n
   os.fsync(fd)
  finally:os.close(fd)
 def changed():
  raw=bytearray(original);i=next(i for i in range(len(raw)-1,-1,-1)if 48<=raw[i]<=57);raw[i]=50 if raw[i]==49 else 49;return bytes(raw)
 if mode=="none":pass
 elif mode=="replace":os.rename(path,alias);write(original)
 elif mode=="different_replace":os.rename(path,alias);write(changed())
 elif mode=="missing":path.unlink()
 elif mode=="mode":path.chmod(0o644)
 elif mode=="link":os.link(path,alias)
 elif mode=="symlink":os.rename(path,alias);os.symlink(alias,path)
 elif mode=="rewrite":write(changed())
 elif mode=="rewrite_restore_mtime":
  st=path.stat();write(changed());os.utime(path,ns=(st.st_atime_ns,st.st_mtime_ns))
 elif mode=="truncate":write(b"{")
 elif mode=="touch":
  st=path.stat();os.utime(path,ns=(st.st_atime_ns,st.st_mtime_ns+10**9))
 elif mode=="rename_back":os.rename(path,alias);write(original);path.unlink();os.rename(alias,path)
 elif mode=="root_replace":
  held=root.with_suffix(".qualification-held-root");os.rename(root,held);root.mkdir(mode=0o700);write(original)
 else:raise AssertionError(mode)
def make_root(root,case):
 root.mkdir(parents=True,mode=0o700);root.chmod(0o700);p=root/NAME;kind=case.get("kind","file")
 if kind=="missing":return
 if kind=="directory":p.mkdir(mode=0o600);p.chmod(0o600);return
 if kind=="fifo":os.mkfifo(p,0o600);return
 target=root/"original-target"if kind=="symlink"else p
 target.write_bytes(bytes.fromhex(case["raw_hex"]));target.chmod(case.get("mode",0o600))
 if kind=="symlink":os.symlink(target,p)
 if kind=="hardlink":os.link(p,root/"original-hardlink")
def snapshot(root):
 result={}
 for p in sorted(root.parent.rglob("*")):
  if not p.is_relative_to(root)and not p.is_relative_to(root.with_suffix(".qualification-held-root")):continue
  st=p.lstat();row=dict(stamp=stamp(st),path=p.relative_to(root.parent).as_posix())
  if stat.S_ISREG(st.st_mode):
   try:
    raw=p.read_bytes();row.update(bytes=len(raw),sha256=SHA(raw),raw_hex=raw.hex())
   except OSError as error:row["read_error"]={"errno":error.errno,"text":str(error)}
  if stat.S_ISLNK(st.st_mode):row["target"]=os.readlink(p)
  result[row["path"]]=row
 return result
def categories(original):
 if original["accepted"]:return("ok",None)
 e=original["error"];text=e["text"]
 if e["io_kind"]=="UnexpectedEof":return("eof",None)
 if e["io_errno"]is not None:return("io",e["io_errno"])
 exact={"private request archive legacy anchor refused":"private",
 "request archive legacy anchor binding changed":"binding",
 "request archive legacy anchor changed while reading":"changed-read",
 "request archive legacy anchor bytes changed":"bytes",
 "request archive legacy anchor disappeared":"disappeared"}
 return(exact.get(text,"typed"),None)
def native_category(result):
 if result["diagnostic"]==0:return("ok",None)
 p,e=result["point"],result["errno"]
 if p in(4,8,13,17)and e==errno.ENOENT:return("disappeared",None)
 if e:return("io",e)
 return({3:"private",4:"binding",6:"changed-read",7:"changed-read",8:"changed-read",10:"typed",11:"private",12:"binding",13:"binding",14:"eof",15:"bytes",16:"changed-read",17:"changed-read"}.get(p,"unknown"),None)
class Anchor:
 def __init__(self,actor,records,engine,root):
  self.actor=actor;self.records=records;self.engine=engine;self.root=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  self.session=actor.session(output_capacity=192,workspace_capacity=16384);self.ctx=engine.create(0,ctypes.addressof(self.session._workspace),16384,self.root);assert self.ctx>0
  self.trace=[];self.owned_seen=[]
 def drive(self,operation,*,before=None,after=None):
  frame=packet(operation)
  for _ in range(10000):
   code,out,w=self.session.invoke_raw(frame)
   if code!=YIELD:
    assert code==192 and out[:8]==b"HRAANR01"and U(out,40)==192,(code,self.trace)
    r=dict(diagnostic=U(out,8),errno=U(out,16),point=U(out,24),operation=U(out,32),state=U(out,48),raw=out[:code].hex())
    if r["diagnostic"]==0 and r["state"]==1:r["record_wire_hex"]=out[64:192].hex()
    return r
   words=struct.unpack_from("<12Q",w,256);row=dict(operation=operation,sequence=words[1],kind=words[2],slot=words[3],span=words[4],count=words[5],arg=words[6],capacity=words[7],action_hex=w[256:352].hex())
   assert words[0]==int.from_bytes(b"HRAANA01","little")and words[8:]==(0,0,0,0)
   if before:before(row,self)
   value=self.engine.step(self.ctx);assert value in(0,1),(value,row,self.engine.state(self.ctx))
   state=self.engine.state(self.ctx)
   if state["anchor"]>=0:self.owned_seen.append(state["anchor"])
   if value==1:
    assert row["kind"]==100
    fixed=ctypes.string_at(self.ctx,224);assert self.engine.step(self.ctx)==-errno.EBUSY and ctypes.string_at(self.ctx,224)==fixed
    request=ctypes.string_at(ctypes.addressof(self.session._workspace)+row["span"],row["count"])
    payload=self.records.invoke(request,output_capacity=128,workspace_capacity=8704)
    assert len(payload)<=128
    ctypes.memmove(ctypes.addressof(self.session._workspace)+row["arg"],payload,len(payload))
    assert self.engine.child_ack(self.ctx,len(payload),0)==0
    row.update(child_request_hex=request.hex(),child_response_hex=payload.hex())
   current=ctypes.string_at(ctypes.addressof(self.session._workspace)+256,96)
   row.update(result=U(current,72),errno=U(current,80),private=self.engine.state(self.ctx))
   assert U(current,64)==row["sequence"]and U(current,88)==0
   if row["kind"]in(2,4)and row["errno"]==0:
    observed=ctypes.string_at(ctypes.addressof(self.session._workspace)+512,88)
    row["metadata"]=list(struct.unpack("<11Q",observed))
    fd=self.engine.state(self.ctx)["anchor"]
    actual=os.fstat(fd)if row["kind"]==2 else os.stat(NAME,dir_fd=self.root,follow_symlinks=False)
    assert row["metadata"]==stamp(actual)
   if row["kind"]in(5,6)and row["errno"]==0:row["read_hex"]=ctypes.string_at(ctypes.addressof(self.session._workspace)+row["span"],row["result"]).hex()
   self.trace.append(row)
   if after:after(row,self)
  raise AssertionError("qualification step bound exceeded")
 def close(self):
  if self.ctx is not None:
   before=self.engine.state(self.ctx)
   if before["owned"]==2:
    result=self.drive(3);assert result["state"]==2 and self.engine.state(self.ctx)["owned"]==0
   self.engine.cleanup(self.ctx);self.ctx=None
   for fd in set(self.owned_seen):
    try:os.fstat(fd)
    except OSError as e:assert e.errno==errno.EBADF
    else:raise AssertionError("owned anchor descriptor leaked")
   os.fstat(self.root);os.close(self.root);self.root=None;self.session.close()
 def __enter__(self):return self
 def __exit__(self,*args):
  if self.ctx is not None:
   # Synchronous private child has completed or was never started here.
   self.engine.cleanup(self.ctx);self.ctx=None;os.fstat(self.root);os.close(self.root);self.root=None;self.session.close()
def cases():
 raw=b'{"root_device":1,"root_inode":2,"archive_device":3,"archive_inode":4}'
 rows=[]
 def add(label,**kw):rows.append(dict(label=label,raw_hex=raw.hex(),before="none",during="none",**kw))
 add("unchanged");add("eight-positional-fences",repeats=8)
 for label,value in[("sequence",b"[1,2,3,4]"),("padded2048",raw+b" "*(2048-len(raw))),("over2048",raw+b" "*(2049-len(raw))),("empty",b""),("null",b"null"),("missing-field",b'{"root_device":1}'),("unknown",raw[:-1]+b',"extra":1}'),("duplicate",raw[:-1]+b',"root_device":1}'),("float",raw.replace(b'"root_device":1',b'"root_device":1.0')),("unsigned-overflow",raw.replace(b'"root_device":1',b'"root_device":18446744073709551616')),("trailing",raw+b"x")]:
  row=dict(label=label,raw_hex=value.hex(),before="none",during="none");rows.append(row)
 for mode in[0o000,0o400,0o644,0o660,0o700,0o4600]:add("mode-"+oct(mode),mode=mode)
 for kind in["missing","directory","fifo","symlink","hardlink"]:add("initial-"+kind,kind=kind)
 for action in["replace","different_replace","missing","mode","link","symlink","rewrite","rewrite_restore_mtime","truncate","touch","rename_back","root_replace"]:
  row=dict(label="before-"+action,raw_hex=raw.hex(),before=action,during="none");rows.append(row)
 for action in["before_read_truncate","after_read_replace","after_read_rewrite","after_read_mode","after_read_link","after_read_missing"]:
  rows.append(dict(label=action,raw_hex=raw.hex(),before="none",during=action))
 rows.append(dict(label="same-metadata-byte-projection",raw_hex=raw.hex(),before="rewrite",during="none",refresh_stamp=True))
 return rows
def native_case(actor,records,engine,root,case):
 with Anchor(actor,records,engine,root)as anchor:
  result=anchor.drive(1)
  if result["diagnostic"]:
   observed=dict(phase="open",accepted=False,category=native_category(result),native=result,trace=anchor.trace);anchor.close();return observed
  original=bytes.fromhex(case["raw_hex"]);fd=engine.state(anchor.ctx)["anchor"];position=os.lseek(fd,0,os.SEEK_CUR);assert position==len(original)
  assert engine.take(anchor.ctx,1)==-errno.EPERM
  mutate(root,case["before"],original)
  if case.get("refresh_stamp"):
   ctypes.memmove(ctypes.addressof(anchor.session._workspace)+640,struct.pack("<11Q",*stamp(os.fstat(fd))),88)
  completed=callbacks=0;fired=False;read_bytes=0
  def before(row,owner):
   nonlocal fired,callbacks
   if row["operation"]==2 and row["kind"]==6 and not fired and case["during"]=="before_read_truncate":
    fired=True;callbacks+=1;mutate(root,"truncate",original)
  def after(row,owner):
   nonlocal fired,callbacks,read_bytes
   if row["operation"]==2 and row["kind"]==6 and row["errno"]==0:
    read_bytes+=row["result"]
    if not fired and case["during"].startswith("after_read_")and read_bytes==len(original):
     fired=True;callbacks+=1;mutate(root,case["during"].removeprefix("after_read_"),original)
  for _ in range(case.get("repeats",1)):
   result=anchor.drive(2,before=before,after=after)
   if result["diagnostic"]:break
   completed+=1
  position_after=os.lseek(fd,0,os.SEEK_CUR)
  observed=dict(phase="fence",accepted=result["diagnostic"]==0,category=native_category(result),
   record_wire_hex=None,
   original_bytes_hex=original.hex(),cursor_before=position,cursor_after=position_after,completed=completed,read_callbacks=callbacks,native=result,trace=anchor.trace)
  # Use the saved record bytes, not an additional fence, for failed outcomes too.
  observed["record_wire_hex"]=ctypes.string_at(ctypes.addressof(anchor.session._workspace)+10752,128).hex()
  anchor.close();return observed

def child_controls(actor,records,engine,root):
 rows=[];counter=0
 def prepared(label):
  nonlocal counter
  directory=root/("child-"+str(counter)+"-"+label);counter+=1;directory.mkdir(mode=0o700)
  p=directory/NAME;p.write_bytes(b"[1,2,3,4]");p.chmod(0o600)
  return Anchor(actor,records,engine,directory)
 def pending(a):
  for _ in range(32):
   code,out,w=a.session.invoke_raw(packet(1));assert code==YIELD
   words=struct.unpack_from("<12Q",w,256)
   r=engine.step(a.ctx);assert r in(0,1)
   state=engine.state(a.ctx)
   if state["anchor"]>=0:a.owned_seen.append(state["anchor"])
   if r==1:
    assert words[2]==100
    request=ctypes.string_at(ctypes.addressof(a.session._workspace)+words[4],words[5])
    return request,state["anchor"]
  raise AssertionError("typed child was not reached")
 def payload(a,request):
  value=records.invoke(request,output_capacity=128,workspace_capacity=8704)
  assert len(value)==128
  ctypes.memmove(ctypes.addressof(a.session._workspace)+10496,value,len(value))
  return value
 with prepared("pending")as a:
  request,fd=pending(a);whole=ctypes.string_at(ctypes.addressof(a.session._workspace),16384);context=ctypes.string_at(a.ctx,224)
  assert engine.step(a.ctx)==-errno.EBUSY and engine.destroy(a.ctx)==-errno.EBUSY
  assert ctypes.string_at(a.ctx,224)==context and ctypes.string_at(ctypes.addressof(a.session._workspace),16384)==whole
  os.fstat(fd);os.fstat(a.root);rows.append(dict(kind="pending-child-retains-both-descriptors"))
  for result,error in[(129,0),(0,4096),(1,errno.EIO)]:
   assert engine.child_ack(a.ctx,result,error)==-errno.EINVAL
   assert ctypes.string_at(a.ctx,224)==context and ctypes.string_at(ctypes.addressof(a.session._workspace),16384)==whole
   rows.append(dict(kind="child-ack-bounds",result=result,error=error))
  for offset in range(256,352,8):
   bad=bytearray(whole);struct.pack_into("<Q",bad,offset,U(bad,offset)^1);ctypes.memmove(ctypes.addressof(a.session._workspace),bytes(bad),16384)
   assert engine.child_ack(a.ctx,128,0)==-errno.EINVAL
   assert ctypes.string_at(a.ctx,224)==context and ctypes.string_at(ctypes.addressof(a.session._workspace),16384)==bytes(bad)
   ctypes.memmove(ctypes.addressof(a.session._workspace),whole,16384)
   rows.append(dict(kind="child-ack-full-action-binding",offset=offset))
  for op in[2,3]:
   code,out,w=a.session.invoke_raw(packet(op));assert code==0xffffffff and w==whole
   os.fstat(fd);rows.append(dict(kind="pending-child-public-op-refused",operation=op))
  for slot in[0,1,2,2**64-1]:
   assert engine.take(a.ctx,slot)==-errno.EPERM
   rows.append(dict(kind="retained-descriptor-never-exported",slot=slot))
  payload(a,request);assert engine.child_ack(a.ctx,128,0)==0
  acknowledged=ctypes.string_at(a.ctx,224);ack_workspace=ctypes.string_at(ctypes.addressof(a.session._workspace),16384)
  assert engine.child_ack(a.ctx,128,0)==-errno.EINVAL and engine.step(a.ctx)==-errno.EINVAL
  assert ctypes.string_at(a.ctx,224)==acknowledged and ctypes.string_at(ctypes.addressof(a.session._workspace),16384)==ack_workspace
  result=a.drive(1);assert result["diagnostic"]==0 and result["state"]==1
  rows.append(dict(kind="child-ack-one-shot-and-no-effect-replay"));a.close()
 for offset in[8192,8200,8208,8216,8224]:
  with prepared("late-input")as a:
   request,fd=pending(a);payload(a,request)
   target=ctypes.addressof(a.session._workspace);value=ctypes.string_at(target+offset,8)
   ctypes.memmove(target+offset,struct.pack("<Q",U(value,0)^1),8)
   assert engine.child_ack(a.ctx,128,0)==0
   code,out,w=a.session.invoke_raw(packet(1));assert code==0xffffffff
   os.fstat(fd);rows.append(dict(kind="typed-child-late-input-refused",offset=offset))
  try:os.fstat(fd)
  except OSError as e:assert e.errno==errno.EBADF
  else:raise AssertionError("late-input failure leaked its anchor")
 for offset in[0,8,16,24,32,72,120]:
  with prepared("late-response")as a:
   request,fd=pending(a);value=bytearray(payload(a,request))
   struct.pack_into("<Q",value,offset,U(value,offset)^1)
   ctypes.memmove(ctypes.addressof(a.session._workspace)+10496,bytes(value),len(value))
   assert engine.child_ack(a.ctx,128,0)==0
   code,out,w=a.session.invoke_raw(packet(1));assert code==0xffffffff
   os.fstat(fd);rows.append(dict(kind="typed-child-response-refused",offset=offset))
  try:os.fstat(fd)
  except OSError as e:assert e.errno==errno.EBADF
  else:raise AssertionError("bad-response failure leaked its anchor")
 with prepared("known-cancelled")as a:
  request,fd=pending(a)
  # This qualification has not dispatched the typed child. Cancellation is
  # confirmed here; an unconfirmed child must keep the pending context held.
  assert engine.child_ack(a.ctx,0,errno.ECANCELED)==0
  result=a.drive(1);assert result["diagnostic"]==1 and result["point"]==9 and result["errno"]==errno.ECANCELED and result["state"]==2
  assert engine.state(a.ctx)["owned"]==0 and engine.state(a.ctx)["anchor"]==-1
  try:os.fstat(fd)
  except OSError as e:assert e.errno==errno.EBADF
  else:raise AssertionError("confirmed cancellation retained an owned anchor")
  root_fd=a.root;os.fstat(root_fd);rows.append(dict(kind="confirmed-child-cancel-closes-owned-only"));a.close()
 return rows

def controls(actor,records,packer,engine,root):
 rows=[]
 request=b"HRAAPQ01"+struct.pack("<QQ",1,0)
 for bad in[request[:i]for i in range(24)]+[request+b"x",b"X"+request[1:],request[:8]+struct.pack("<QQ",0,0),request[:16]+struct.pack("<Q",1)]:
  code,out,w=packer.invoke_raw(bad,output_capacity=2214,workspace_capacity=16,output_fill=0x6d)
  assert code==0xffffffff and out==bytes([0x6d])*len(out);rows.append(dict(kind="packer-invalid",input_sha256=SHA(bad)))
 for n in[0,63,2213]:
  code,out,w=packer.invoke_raw(request,output_capacity=n,workspace_capacity=16,output_fill=0x6d)
  assert code==0xfffffffe and out==bytes([0x6d])*n;rows.append(dict(kind="packer-capacity",bytes=n))
 for bad in[packet(1)[:i]for i in range(32)]+[packet(0),packet(4),packet(1)+b"x",b"X"+packet(1)[1:],packet(1)[:16]+struct.pack("<QQ",1,0)]:
  code,out,w=actor.invoke_raw(bad,output_capacity=192,workspace_capacity=16384,output_fill=0x6d)
  assert code==0xffffffff and out==bytes([0x6d])*len(out);rows.append(dict(kind="actor-invalid",input_sha256=SHA(bad)))
 for oc,wc in[(191,16384),(192,16383),(0,0)]:
  code,out,w=actor.invoke_raw(packet(1),output_capacity=oc,workspace_capacity=wc,output_fill=0x6d)
  assert code==0xfffffffe and out==bytes([0x6d])*oc;rows.append(dict(kind="actor-capacity",output=oc,workspace=wc))
 code,out,w=actor.invoke_raw(packet(1),output_capacity=192,workspace_capacity=16384,output_fill=0x6d,workspace_fill=1)
 assert code==0xffffffff and out==bytes([0x6d])*192;rows.append(dict(kind="nonzero-initial-workspace"))
 root.mkdir(mode=0o700);path=root/NAME;path.write_bytes(b"[1,2,3,4]");path.chmod(0o600)
 with Anchor(actor,records,engine,root)as a:
  code,out,w=a.session.invoke_raw(packet(1));assert code==YIELD;original=w;ctx_before=ctypes.string_at(a.ctx,224)
  for offset in[256,264,272,280,288,296,304,312,320,328,336,344]:
   bad=bytearray(original);struct.pack_into("<Q",bad,offset,U(bad,offset)^1);ctypes.memmove(ctypes.addressof(a.session._workspace),bytes(bad),len(bad))
   assert engine.step(a.ctx)==-errno.EINVAL and ctypes.string_at(a.ctx,224)==ctx_before
   rows.append(dict(kind="effect-frame-refusal",offset=offset))
  ctypes.memmove(ctypes.addressof(a.session._workspace),original,len(original))
  assert engine.step(a.ctx)==0
  actual=ctypes.string_at(ctypes.addressof(a.session._workspace),16384);fd=engine.state(a.ctx)["anchor"];assert fd>=0
  for offset in[256,264,272,280,288,296,304,312,320,344]:
   bad=bytearray(actual);struct.pack_into("<Q",bad,offset,U(bad,offset)^1);ctypes.memmove(ctypes.addressof(a.session._workspace),bytes(bad),len(bad))
   code,out,w=a.session.invoke_raw(packet(1));assert code==0xffffffff and w==bytes(bad)
   os.fstat(fd);rows.append(dict(kind="actor-bad-ack",offset=offset))
  ctypes.memmove(ctypes.addressof(a.session._workspace),actual,len(actual))
  # Finish the already opened action without executing open again.
  result=a.drive(1);assert result["diagnostic"]==0;a.close()
 rows.extend(child_controls(actor,records,engine,root))
 return rows
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--actor",type=Path,required=True);p.add_argument("--records",type=Path,required=True);p.add_argument("--packer",type=Path,required=True);p.add_argument("--oracle",type=Path,required=True);p.add_argument("--provenance",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 q=a.output;q.mkdir(parents=True,exist_ok=False);assert SELF==a.source/"scripts/qualify_durable_audit_anchor.py"and SELF.read_bytes()==EXECUTED
 before=pins(a.source);proof_raw=a.provenance.read_bytes();proof=json.loads(proof_raw);binary=a.oracle.read_bytes()
 assert proof["state"]=="PASS"and proof["original_release_profile"]is True and proof["original_default_features"]is True and proof["locked_registry_archives"]==360
 assert proof["binary_record"]["sha256"]==SHA(binary)and proof["original_pinned_methods"]==9
 manifests={str(p):p.read_bytes()for p in(a.actor,a.records,a.packer)}
 code_record=json.loads((a.source/"scripts/durable_audit_anchor_code.json").read_bytes())
 assert code_record["source_sha256"]==SHA((a.source/"scripts/durable_audit_anchor_engine.S").read_bytes())
 sys.path.insert(0,str(a.source/"scripts"));from hia_native_loader import NativeModule
 cases_=cases();(q/"cases.json").write_text(json.dumps(cases_,sort_keys=True,indent=2)+"\n")
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n");results=[];failures=[];start=time.monotonic()
 with ExitStack()as stack:
  actor=stack.enter_context(NativeModule(a.actor,manifest_sha256=SHA(manifests[str(a.actor)])))
  records=stack.enter_context(NativeModule(a.records,manifest_sha256=SHA(manifests[str(a.records)])))
  packer=stack.enter_context(NativeModule(a.packer,manifest_sha256=SHA(manifests[str(a.packer)])))
  produced=packer.invoke(b"HRAAPQ01"+struct.pack("<QQ",1,0),output_capacity=2214,workspace_capacity=16)
  (q/"actual-hia-engine.pack").write_bytes(produced);engine=stack.enter_context(Engine(produced,code_record))
  extra=controls(actor,records,packer,engine,q/"controls-root")
  for i,case in enumerate(cases_):
   cq=q/("case-"+str(i).zfill(3));cq.mkdir();original_root=cq/"original"/"root";native_root=cq/"native"/"root"
   make_root(original_root,case);make_root(native_root,case)
   initial={"original":snapshot(original_root),"native":snapshot(native_root)}
   command=json.dumps({**case,"root":str(original_root)},separators=(",",":")).encode()+b"\n";(cq/"original-input.json").write_bytes(command)
   run_start=time.monotonic();reference=subprocess.run([str(a.oracle)],input=command,capture_output=True,timeout=10)
   (cq/"original.stdout").write_bytes(reference.stdout);(cq/"original.stderr").write_bytes(reference.stderr)
   (cq/"original-terminal.json").write_text(json.dumps(dict(exit_code=reference.returncode,elapsed_seconds=time.monotonic()-run_start))+"\n")
   assert reference.returncode==0 and not reference.stderr,(i,case,reference.returncode,reference.stderr)
   original=json.loads(reference.stdout);observed=native_case(actor,records,engine,native_root,case)
   equal=original["phase"]==observed["phase"]and original["accepted"]==observed["accepted"]and categories(original)==tuple(observed["category"])
   if original["phase"]=="fence":
    equal=equal and all(original[k]==observed[k]for k in["record_wire_hex","original_bytes_hex","cursor_before","cursor_after","completed","read_callbacks"])
   result=dict(ordinal=i,label=case["label"],equal=equal,original=original,native=observed,initial=initial,terminal={"original":snapshot(original_root),"native":snapshot(native_root)})
   (cq/"result.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");results.append(dict(ordinal=i,label=case["label"],equal=equal))
   if not equal:failures.append(result)
 after=pins(a.source);assert a.oracle.read_bytes()==binary and a.provenance.read_bytes()==proof_raw and all(Path(p).read_bytes()==v for p,v in manifests.items())
 (q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
 report=dict(schema="hepta.runtime.durable-pinned-anchor-qualification.v1",passed=not failures and before==after,
  cases=len(cases_),controls=extra,results=results,failures=failures,source_before=before,source_after=after,source_unchanged=before==after,
  original_binary_sha256=SHA(binary),original_provenance_sha256=SHA(proof_raw),actual_hia_engine_sha256=SHA(produced),
  elapsed_seconds=time.monotonic()-start,public_archive_qualified=False,redb_qualified=False,python_is_qualification_transport_only=True)
 (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps(dict(passed=report["passed"],cases=len(cases_),controls=len(extra),failures=len(failures),elapsed_seconds=report["elapsed_seconds"],source_unchanged=before==after),sort_keys=True),flush=True)
 if not report["passed"]:raise SystemExit(1)
if __name__=="__main__":main()
