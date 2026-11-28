# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Original v12 publication comparisons with actual HIA actors and descriptors."""
from pathlib import Path
from contextlib import ExitStack
import argparse,ctypes,errno,fcntl,hashlib,json,os,stat,struct,subprocess,sys,time,types
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes()
SHA=lambda v:hashlib.sha256(v).hexdigest()
U=lambda v,at:struct.unpack_from("<Q",v,at)[0]
YIELD=0xffffffe0
LEGACY=".request-archive-v11-anchor.json"
NAMES={1:".request-archive-v12-init.json",2:".request-archive-v12-init.json",3:".request-archive-v12-anchor.json"}
OPS={1:"persist_initial",2:"persist_next",3:"publish_anchor"}
OWN=("scripts/qualify_durable_audit_archive_publication.py","scripts/author_durable_audit_archive_publication.py",
"scripts/durable_audit_archive_publication_source.py.txt","native/durable_audit_archive_publication.hepta","native/durable_audit_archive_publication_composition.json",
"scripts/author_durable_audit_archive_publication_packer.py","scripts/durable_audit_archive_publication_packer_source.py.txt",
"scripts/durable_audit_archive_publication_code.json","scripts/durable_audit_archive_publication_engine.S",
"native/durable_audit_archive_publication_packer.hepta","native/durable_audit_archive_publication_packer_composition.json",
"native/durable_audit_archive_publication_abi.md")
def typed(record,kind):
 count=len(record["shards"]);out=bytearray(128+16*count);out[:8]=b"HRAATR01"
 struct.pack_into("<QQQQ",out,8,0,kind,len(out),record["format"])
 struct.pack_into("<4Q",out,40,*record["root"],*record["legacy"])
 struct.pack_into("<QQQ",out,72,int(record["archive"]is not None),*(record["archive"]or[0,0]))
 struct.pack_into("<Q",out,96,count)
 for i,pair in enumerate(record["shards"]):struct.pack_into("<QQ",out,128+16*i,*pair)
 return bytes(out)
def packet(op,record):
 body=typed(record,2 if op==3 else 3)
 return b"HRAAWQ01"+struct.pack("<QQQ",op,len(body),0)+body
def simple_record():
 return dict(format=12,root=[0,0],legacy=[33,44],archive=None,shards=[])
def captured_metadata_module(root):
 path=root/"scripts/qualify_durable_audit_archive_metadata.py";raw=path.read_bytes()
 assert SHA(raw)=="dc6b6b35ef4a7343b7f1585aeead7694f3297a27b383468efa7a1263895bdce8"
 module=types.ModuleType("_captured_v12_metadata_qualification");module.__file__=str(path)
 exec(compile(raw,str(path),"exec"),module.__dict__)
 assert module.EXECUTED==raw and path.read_bytes()==raw
 return module,raw
class Engine:
 def __init__(self,raw,record):
  assert raw[:8]==b"HRAWPK01"and len(raw)==U(raw,8)==64+U(raw,16)
  self.flat=raw[64:];assert SHA(self.flat)==record["flat_sha256"]and len(self.flat)==record["flat_bytes"]
  self.exports=dict(zip(("create","step","child_ack","take","destroy"),struct.unpack_from("<5Q",raw,24)))
  assert self.exports==record["exports"]
  self.fd=os.memfd_create("hia-audit-archive-publication-engine",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
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
  v=ctypes.string_at(ctx,224);assert v[:8]==b"HRAAWG01"
  return dict(sequence=U(v,32),pending=U(v,40),owned=U(v,56),fds=list(struct.unpack_from("<2q",v,64)),snapshot=v[160:224].hex())
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


def borrowed_reader_type(metadata):
 class BorrowedMetadata(metadata.Metadata):
  def __init__(self,actor,records,engine,root_fd):
   self.actor=actor;self.records=records;self.engine=engine;self.root=root_fd
   self.session=actor.session(output_capacity=4384,workspace_capacity=1048576)
   self.ctx=engine.create(0,ctypes.addressof(self.session._workspace),1048576,self.root);assert self.ctx>0
   self.trace=[];self.owned_seen=[]
  def close(self):
   if self.ctx is not None:
    self.engine.cleanup(self.ctx);self.ctx=None
    for fd in set(self.owned_seen):
     try:os.fstat(fd)
     except OSError as e:assert e.errno==errno.EBADF
     else:raise AssertionError("owned nested metadata descriptor leaked")
    os.fstat(self.root);self.session.close()
 return BorrowedMetadata

class Publication:
 def __init__(self,actor,engine,metadata_actor,records,metadata_engine,reader_type,root,frame):
  self.actor=actor;self.engine=engine;self.metadata_actor=metadata_actor;self.records=records
  self.metadata_engine=metadata_engine;self.reader_type=reader_type;self.frame=frame
  self.root=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  self.capacity=max(1048576,524288+len(frame))
  self.session=actor.session(output_capacity=128,workspace_capacity=self.capacity)
  self.ctx=engine.create(0,ctypes.addressof(self.session._workspace),self.capacity,self.root);assert self.ctx>0
  self.trace=[];self.owned_seen=[]
 def drive(self):
  for _ in range(1000000):
   code,out,w=self.session.invoke_raw(self.frame)
   if code!=YIELD:
    assert code==128 and out[:8]==b"HRAAWR01"and U(out,40)==128,(code,self.trace)
    assert self.engine.state(self.ctx)["owned"]==0
    return dict(diagnostic=U(out,8),errno=U(out,16),point=U(out,24),operation=U(out,32),
     serialized_bytes=U(out,48),created=U(out,56),child_diagnostic=U(out,64),child_point=U(out,72),
     cleanup_attempted=U(out,80),temporary_name_bytes=U(out,88),raw=out[:128].hex())
   words=struct.unpack_from("<12Q",w,256)
   row=dict(sequence=words[1],kind=words[2],slot=words[3],span=words[4],count=words[5],arg=words[6],capacity=words[7],action_hex=w[256:352].hex())
   assert words[0]==int.from_bytes(b"HRAAWA01","little")and words[8:]==(0,0,0,0)
   value=self.engine.step(self.ctx);assert value in(0,1),(value,row,self.engine.state(self.ctx))
   state=self.engine.state(self.ctx);self.owned_seen.extend(fd for fd in state["fds"][1:]if fd>=0)
   if value==1:
    assert row["kind"]==100
    fixed=ctypes.string_at(self.ctx,224)
    assert self.engine.step(self.ctx)==-errno.EBUSY and self.engine.destroy(self.ctx)==-errno.EBUSY
    assert ctypes.string_at(self.ctx,224)==fixed
    request=ctypes.string_at(ctypes.addressof(self.session._workspace)+row["span"],row["count"])
    assert request==b"HRAAMQ01"+struct.pack("<QQQ",1,0,0)
    with self.reader_type(self.metadata_actor,self.records,self.metadata_engine,self.root)as child:
     result=child.drive(1);payload=bytes.fromhex(result["raw"]);child_trace=child.trace
    assert len(payload)<=4384
    ctypes.memmove(ctypes.addressof(self.session._workspace)+row["arg"],payload,len(payload))
    assert self.engine.child_ack(self.ctx,len(payload),0)==0
    root_identity=os.fstat(self.root)
    row.update(child_request_hex=request.hex(),child_response_hex=payload.hex(),metadata_result=result,metadata_trace=child_trace,borrowed_root_identity=[root_identity.st_dev,root_identity.st_ino])
   current=ctypes.string_at(ctypes.addressof(self.session._workspace)+256,96)
   row.update(result=U(current,72),errno=U(current,80),private=self.engine.state(self.ctx))
   assert U(current,64)==row["sequence"]and U(current,88)==0
   if row["kind"]==12 and row["errno"]==0:
    row["entropy_hex"]=ctypes.string_at(ctypes.addressof(self.session._workspace)+row["span"],row["result"]).hex()
   if row["kind"]==13:
    row["write_input_hex"]=ctypes.string_at(ctypes.addressof(self.session._workspace)+row["span"],row["count"]).hex()
   if row["kind"]in(1,10,14,15):
    row["temporary_hex"]=ctypes.string_at(ctypes.addressof(self.session._workspace)+1024,row["count"]).hex()
   self.trace.append(row)
  raise AssertionError("qualification safety loop exhausted, not an application entry cap")
 def close(self):
  if self.ctx is not None:
   self.engine.cleanup(self.ctx);self.ctx=None
   for fd in set(self.owned_seen):
    try:os.fstat(fd)
    except OSError as e:assert e.errno==errno.EBADF
    else:raise AssertionError("owned publication descriptor leaked")
   os.fstat(self.root);os.close(self.root);self.root=None;self.session.close()
 def __enter__(self):return self
 def __exit__(self,*args):self.close()

def cases():
 rows=[]
 for op in(1,3):
  base=[("plain",{}),("count1",{"count":1}),("count255",{"count":255}),("count256",{"count":256}),
   ("count257",{"count":257}),("format0",{"format":0}),("format11",{"format":11}),("format-u32-max",{"format":2**32-1}),
   ("all-u64-max",{"maximum":True,"count":3}),("target-file",{"target":"file"}),("target-readonly",{"target":"readonly"}),
   ("target-directory",{"target":"directory"}),("target-symlink",{"target":"symlink"}),("target-fifo",{"target":"fifo"}),
   ("parent-readonly",{"root_mode":0o500}),("invalid-legacy-ignored",{"legacy_invalid":True})]
  if op==1:base.extend([("optional-archive-none-with-shard",{"count":1}),("bound-archive",{"archive":True})])
  for size in(65535,65536,65537):base.append(("size-"+str(size),{"serialized_size":size}))
  base.extend([("oversize-with-existing-target",{"serialized_size":65537,"target":"file"}),
   ("oversize-parent-readonly",{"serialized_size":65537,"root_mode":0o500}),
   ("large-typed-vector16385",{"count":16385}),("large-typed-vector65536",{"count":65536}),
   ("large-vector-parent-readonly",{"count":65536,"root_mode":0o500})])
  for label,extra in base:rows.append(dict(operation=op,label=OPS[op]+"-"+label,**extra))
 updates=[
 ("same-empty",{}),("bind-root",{"new_archive":[55,66]}),("one-shard",{"new_archive":[55,66],"count":1}),
 ("new-none-with-one-shard",{"count":1}),("new-format11",{"format":11}),("new-format-u32-max",{"format":2**32-1}),
 ("same-first",{"old":{"archive":True,"count":1},"count":1}),
 ("append-second",{"old":{"archive":True,"count":1},"count":2}),
 ("append257",{"old":{"archive":True,"count":256},"count":257}),
 ("same256",{"old":{"archive":True,"count":256},"count":256}),
 ("shrink",{"old":{"archive":True,"count":1},"count":0}),
 ("jump-two",{"old":{"archive":True,"count":1},"count":3}),
 ("changed-prefix",{"old":{"archive":True,"count":1},"count":1,"prefix_bad":True}),
 ("changed-archive",{"old":{"archive":True},"new_archive":[55,67]}),
 ("drop-archive",{"old":{"archive":True},"new_archive":None}),
 ("changed-root",{"root_bad":True}),("changed-legacy",{"legacy_bad":True}),
 ("old-missing",{"old":{"metadata_kind":"missing"}}),
 ("old-malformed",{"old":{"raw":"empty"}}),("old-unknown-field",{"old":{"raw":"unknown"}}),
 ("old-format11",{"old":{"format":11}}),("old-wrong-root",{"old":{"root_bad":True}}),
 ("old-wrong-legacy",{"old":{"legacy_bad":True}}),
 ("old257",{"old":{"archive":True,"count":257}}),
 ("old-none-with-shard",{"old":{"count":1}}),
 ("old-mode400",{"old":{"mode":0o400}}),("old-mode000",{"old":{"mode":0}}),
 ("old-symlink",{"old":{"metadata_kind":"symlink"}}),("old-fifo",{"old":{"metadata_kind":"fifo"}}),
 ("old-directory",{"old":{"metadata_kind":"directory"}}),
 ("legacy-missing",{"old":{"legacy_kind":"missing"}}),
 ("legacy-invalid",{"old":{"legacy_raw":"invalid"}}),
 ("legacy-mode",{"old":{"legacy_mode":0o644}}),
 ("known-hard-link",{"old":{"alias":"known"},"new_archive":[55,66],"count":1}),
 ("unknown-hard-link",{"old":{"alias":"unknown"}}),
 ("three-links",{"old":{"alias":"three"}}),
 ("recovery-before-new-binding",{"old":{"alias":"known"},"root_bad":True}),
 ("recovery-denied",{"old":{"alias":"known"},"root_mode":0o500}),
 ("parent-readonly",{"root_mode":0o500}),
 ("oversize-new-rejected-before-create",{"count":65536}),
 ("oversize-old-before-create",{"old":{"padding":65537}})]
 for label,extra in updates:rows.append(dict(operation=2,label="persist_next-"+label,**extra))
 return rows

def canonical(record):return json.dumps(record,separators=(",",":"),ensure_ascii=False).encode()
def make_root(root,case,metadata):
 op=case["operation"];authored={}
 if op==2:
  old=dict(operation=1,**case.get("old",{}));fixture=metadata.make_root(root,old)
  identity=fixture["root_identity"];authored=fixture["authored"]
  data=dict(format=case.get("format",12),root=list(identity),legacy=[33,44],
   archive=[55,66]if old.get("archive")else None,shards=[[77,i]for i in range(case.get("count",old.get("count",0)))])
  if "new_archive"in case:data["archive"]=case["new_archive"]
  if case.get("prefix_bad"):data["shards"][0][1]+=1
 else:
  root.mkdir(parents=True,mode=0o700);root.chmod(0o700);st=root.stat();identity=[st.st_dev,st.st_ino]
  data=dict(format=case.get("format",12),root=list(identity),legacy=[33,44],
   archive=[55,66]if op==3 or case.get("archive")else None,shards=[[77,i]for i in range(case.get("count",0))])
  if case.get("maximum"):
   data["root"]=[2**64-1]*2;data["legacy"]=[2**64-1]*2;data["archive"]=[2**64-1]*2
   data["shards"]=[[2**64-1,2**64-1]for _ in data["shards"]]
  if "serialized_size"in case:
   target=case["serialized_size"];data.update(root=[0,0],legacy=[0,0],shards=[])
   base=len(canonical(data));n=max(1,(target-base)//6)
   data["shards"]=[[0,0]for _ in range(n)]
   gap=target-len(canonical(data));assert 0<=gap<=19
   if gap:data["shards"][0][0]=10**gap
   assert len(canonical(data))==target
  if case.get("legacy_invalid"):
   (root/LEGACY).write_bytes(b"not json");(root/LEGACY).chmod(0o600);authored[LEGACY]=b"not json".hex()
  target=case.get("target");p=root/NAMES[op]
  if target in("file","readonly"):
   p.write_bytes(b"existing original");p.chmod(0o400 if target=="readonly"else 0o600);authored[p.name]=p.read_bytes().hex()
  if target=="directory":p.mkdir(mode=0o700)
  if target=="fifo":os.mkfifo(p,0o600)
  if target=="symlink":
   other=root/"original-target";other.write_bytes(b"original referent");other.chmod(0o600)
   authored[other.name]=other.read_bytes().hex();os.symlink(other.name,p)
 if case.get("root_bad"):data["root"][1]+=1
 if case.get("legacy_bad"):data["legacy"][1]+=1
 if "root_mode"in case:root.chmod(case["root_mode"])
 return dict(root_identity=identity,record=data,authored=authored,packet_hex=packet(op,data).hex())

def snapshot(root):
 rows={};groups={}
 for p in sorted(root.iterdir()):
  st=p.lstat();name=p.name;key=(st.st_dev,st.st_ino);groups.setdefault(key,[]).append(name)
  row=dict(mode=stat.S_IMODE(st.st_mode),kind=stat.S_IFMT(st.st_mode),uid=st.st_uid,gid=st.st_gid,links=st.st_nlink,
   physical=[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns])
  if stat.S_ISREG(st.st_mode):
   try:raw=p.read_bytes();row.update(bytes=len(raw),sha256=SHA(raw),raw_hex=raw.hex())
   except PermissionError as e:row["read_error"]=e.errno
  if stat.S_ISLNK(st.st_mode):row["target"]=os.readlink(p)
  rows[name]=row
 for group in groups.values():
  for name in group:rows[name]["same_inode_as"]=min(group)
 return rows
def normalized(rows,identity,declared_wrong_root=None):
 if declared_wrong_root is not None:assert declared_wrong_root==[identity[0],identity[1]+1]
 result={}
 for name,row in rows.items():
  item={k:row[k]for k in("mode","kind","uid","gid","links","same_inode_as","target","read_error")if k in row}
  if "raw_hex"in row:
   raw=bytes.fromhex(row["raw_hex"])
   try:value=json.loads(raw)
   except(ValueError,UnicodeError):item["bytes_hex"]=raw.hex()
   else:
    if isinstance(value,dict):
     if value.get("root")==identity:value={**value,"root":["actual-root-device","actual-root-inode"]}
     elif name==NAMES[2] and declared_wrong_root is not None and value.get("root")==declared_wrong_root:
      value={**value,"root":["actual-root-device","declared-invalid-inode-plus-one"]}
     if [value.get("root_device"),value.get("root_inode")]==identity:value={**value,"root_device":"actual-root-device","root_inode":"actual-root-inode"}
    item["json"]=value
  result[name]=item
 return result

def reference_category(value,metadata):
 if value["accepted"]:return("ok",None)
 error=value["error"]
 if error["io_errno"]is not None:return("io",error["io_errno"])
 text=error["text"]
 exact={"request archive initialization intent disappeared":"missing-old",
  "request archive initialization intent size refused":"size",
  "request archive layout anchor size refused":"size",
  "request identity entropy unavailable":"entropy",
  "failed to write whole buffer":"write-zero"}
 if text in exact:return(exact[text],None)
 result=metadata.original_category(value,1)
 if result[0]=="typed":assert text=="EOF while parsing a value at line 1 column 0" or any(k in text for k in("expected","missing field","unknown field","duplicate field","invalid type","invalid value","out of range","trailing characters")),text
 return result
def native_category(value,metadata):
 if value["diagnostic"]==0:return("ok",None)
 point,error=value["point"],value["errno"]
 if point==4:return("entropy",None)
 if error:return("io",error)
 if point==1:
  return metadata.native_category(dict(diagnostic=value["child_diagnostic"],point=value["child_point"],errno=error))
 return({2:"missing-old",3:"binding",6:"size",8:"write-zero"}.get(point,"unknown"),None)

def protocol_faults(actor,q):
 rows=[]
 specs=[("entropy-error",12,None,errno.EIO,4),("write-zero",13,0,0,8),
 ("write-error",13,None,errno.ENOSPC,7),("file-sync-error",11,1,errno.EIO,9),
 ("link-error",14,None,errno.EEXIST,10),("unlink-error",10,None,errno.EPERM,11),
 ("root-sync-error",11,0,errno.EIO,13)]
 for label,kind,selector,error,point in specs:
  frame=packet(1,simple_record());trace=[];failed=False
  with actor.session(output_capacity=128,workspace_capacity=1048576)as session:
   ptr=ctypes.addressof(session._workspace)
   for _ in range(100):
    code,out,w=session.invoke_raw(frame)
    if code!=YIELD:
     assert code==128 and U(out,8)==1 and U(out,24)==point
     assert U(out,80)==int(point!=4)
     if point==8:assert U(out,16)==0
     else:assert U(out,16)==error
     break
    words=struct.unpack_from("<12Q",w,256);k,slot=words[2],words[3];ret=0;err=0
    if k==12:
     ctypes.memset(ptr+words[4],0,words[5]);ret=words[5]
    if k==13:ret=words[5]
    match=(not failed and k==kind and(kind!=11 or slot==selector))
    if match:
     failed=True;err=error;ret=0
    elif failed and k in(7,10):err=errno.EACCES
    struct.pack_into("<QQQ",session._workspace,320,words[1],ret,err)
    trace.append(dict(kind=k,slot=slot,result=ret,errno=err))
   else:raise AssertionError("protocol-control loop")
  assert failed
  row=dict(label=label,passed=True,scope="actual HIA policy with explicit effect-result inputs; no kernel-effect claim",trace=trace)
  rows.append(row)
 (q/"protocol-faults.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
 return rows

def controls(actor,packer,engine,metadata_actor,records,metadata_engine,reader_type,q):
 q.mkdir(parents=True,exist_ok=False);rows=[]
 def yes(label,condition):assert condition,label;rows.append(dict(label=label,passed=True))
 # These four controls validate only the qualification's declared fixture
 # correspondence. They never grant an application or filesystem operation.
 def sample(pair,legacy=44):
  data=dict(format=12,root=pair,legacy=[33,legacy],archive=None,shards=[])
  return {NAMES[2]:dict(mode=0o600,kind=stat.S_IFREG,raw_hex=canonical(data).hex())}
 left=normalized(sample([10,21]),[10,20],[10,21])
 right=normalized(sample([30,41]),[30,40],[30,41])
 for label,condition in[
  ("declared-invalid-root-correspondence",left==right),
  ("different-invalid-root-not-hidden",left!=normalized(sample([30,42]),[30,40],[30,41])),
  ("valid-root-not-hidden-as-invalid",left!=normalized(sample([30,40]),[30,40],[30,41])),
  ("other-fields-not-hidden",left!=normalized(sample([30,41],45),[30,40],[30,41]))]:
  assert condition,label;rows.append(dict(label=label,passed=True,scope="qualification comparator only"))

 good=b"HRAWPQ01"+struct.pack("<QQ",1,0);output_size=64+len(engine.flat)
 expected=packer.invoke(good,output_capacity=output_size,workspace_capacity=16)
 yes("emitted-whole-native-code",expected[64:]==engine.flat)
 for size in(0,1,7,8,16,23,25,32):
  with packer.session(output_capacity=output_size,workspace_capacity=16)as s:
   code,_,_=s.invoke_raw(good[:size]if size<=24 else good+b"x"*(size-24));yes("packer-length-"+str(size),code==0xffffffff)
 for index in range(24):
  bad=bytearray(good);bad[index]^=1
  with packer.session(output_capacity=output_size,workspace_capacity=16)as s:
   code,_,_=s.invoke_raw(bytes(bad));yes("packer-byte-"+str(index),code==0xffffffff)
 for cap in(0,63,64,output_size-1):
  with packer.session(output_capacity=cap,workspace_capacity=16)as s:
   code,_,_=s.invoke_raw(good);yes("packer-capacity-"+str(cap),code==0xfffffffe)
 frame=packet(1,simple_record())
 for size in(0,1,7,8,32,127,159,161,176):
  bad=frame[:size]if size<=len(frame)else frame+b"\0"*(size-len(frame))
  with actor.session(output_capacity=128,workspace_capacity=1048576)as s:
   code,_,_=s.invoke_raw(bad);yes("actor-length-"+str(size),code==0xffffffff)
 for index in list(range(8))+list(range(24,32))+[40,48,56,68,128,136,144,152]:
  bad=bytearray(frame);bad[index]^=1
  with actor.session(output_capacity=128,workspace_capacity=1048576)as s:
   code,_,_=s.invoke_raw(bytes(bad));yes("actor-byte-"+str(index),code==0xffffffff)
 for out,work in[(127,1048576),(128,1048575)]:
  with actor.session(output_capacity=out,workspace_capacity=work)as s:
   code,_,_=s.invoke_raw(frame);yes("actor-capacity-"+str(out)+"-"+str(work),code==0xfffffffe)
 for offset in(0,8,224,232,1024,524288,1048575):
  with actor.session(output_capacity=128,workspace_capacity=1048576)as s:
   ctypes.c_ubyte.from_address(ctypes.addressof(s._workspace)+offset).value=1
   code,_,_=s.invoke_raw(frame);yes("actor-dirty-"+str(offset),code==0xffffffff)
 root=q/"fixed-effects";root.mkdir(mode=0o700)
 with Publication(actor,engine,metadata_actor,records,metadata_engine,reader_type,root,frame)as runner:
  code,_,w=runner.session.invoke_raw(frame);yes("first-entropy-yield",code==YIELD and U(w,272)==12)
  yes("real-entropy-effect",engine.step(runner.ctx)==0)
  code,_,w=runner.session.invoke_raw(frame);yes("create-only-open-yield",code==YIELD and U(w,272)==1)
  ptr=ctypes.addressof(runner.session._workspace);frozen=ctypes.string_at(runner.ctx,224)
  yes("no-descriptor-export",engine.take(runner.ctx,0)==-errno.EPERM)
  for offset in range(256,320,8):
   previous=ctypes.string_at(ptr+offset,8);ctypes.memmove(ptr+offset,struct.pack("<Q",U(previous,0)^2**63),8)
   result=engine.step(runner.ctx);stable=ctypes.string_at(runner.ctx,224)==frozen
   ctypes.memmove(ptr+offset,previous,8);yes("closed-effect-"+str(offset),result==-errno.EINVAL and stable)
  previous=ctypes.string_at(ptr+524288+len(frame)-1,1);ctypes.c_ubyte.from_address(ptr+524288+len(frame)-1).value^=1
  result=engine.step(runner.ctx);ctypes.memmove(ptr+524288+len(frame)-1,previous,1)
  yes("whole-captured-record-before-effect",result==-errno.EINVAL and ctypes.string_at(runner.ctx,224)==frozen)
  yes("real-create-only-open",engine.step(runner.ctx)==0)
  runner.owned_seen.extend(fd for fd in engine.state(runner.ctx)["fds"][1:]if fd>=0)
  result=runner.drive();yes("actual-publication-completes",result["diagnostic"]==0)
  yes("actual-canonical-byte-result",(root/NAMES[1]).read_bytes()==canonical(simple_record()))
  code,_,_=runner.session.invoke_raw(frame);yes("terminal-replay",code==0xffffffff)
 for count in(0,2,65536):
  private=q/("pending-"+str(count));private.mkdir(mode=0o700)
  data=simple_record();data["shards"]=[[0,0]for _ in range(count)];frame=packet(2,data)
  with Publication(actor,engine,metadata_actor,records,metadata_engine,reader_type,private,frame)as runner:
   code,_,w=runner.session.invoke_raw(frame);yes("metadata-child-yield-"+str(count),code==YIELD and U(w,272)==100)
   yes("metadata-child-dispatch-"+str(count),engine.step(runner.ctx)==1)
   ptr=ctypes.addressof(runner.session._workspace);frozen=ctypes.string_at(runner.ctx,224)
   yes("child-busy-no-effect-"+str(count),engine.step(runner.ctx)==-errno.EBUSY and ctypes.string_at(runner.ctx,224)==frozen)
   yes("child-busy-no-destroy-"+str(count),engine.destroy(runner.ctx)==-errno.EBUSY and ctypes.string_at(runner.ctx,224)==frozen)
   for offset in(1536,1544,1552,1560,524288,524304,524288+len(frame)-1,256,312):
    previous=ctypes.string_at(ptr+offset,1);ctypes.c_ubyte.from_address(ptr+offset).value^=1
    result=engine.child_ack(runner.ctx,0,errno.ECANCELED);stable=ctypes.string_at(runner.ctx,224)==frozen
    ctypes.memmove(ptr+offset,previous,1);yes("child-late-"+str(count)+"-"+str(offset),result==-errno.EINVAL and stable)
   yes("child-known-undispatched-cancel-"+str(count),engine.child_ack(runner.ctx,0,errno.ECANCELED)==0)
   yes("child-no-replay-"+str(count),engine.child_ack(runner.ctx,0,errno.ECANCELED)==-errno.EINVAL)
   result=runner.drive();yes("child-cancel-before-creation-"+str(count),result["diagnostic"]==1 and result["point"]==1 and result["errno"]==errno.ECANCELED and not list(private.iterdir()))
 rows.extend(protocol_faults(actor,q))
 (q/"controls.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n");return rows

def main():
 p=argparse.ArgumentParser()
 for name in("source","actor","packer","metadata","metadata-packer","records","output"):p.add_argument("--"+name,type=Path,required=True)
 p.add_argument("--oracle",type=Path);p.add_argument("--provenance",type=Path);p.add_argument("--controls-only",action="store_true")
 a=p.parse_args();a.source=a.source.resolve(strict=True);q=a.output;q.mkdir(parents=True,exist_ok=False)
 metadata,metadata_source=captured_metadata_module(a.source)
 names=tuple(dict.fromkeys((*OWN,*metadata.PATHS)))
 def pins():
  return{n:dict(bytes=len(raw),sha256=SHA(raw),mode=stat.S_IMODE((a.source/n).stat().st_mode))for n in names for raw in[(a.source/n).read_bytes()]}
 before=pins();assert (a.source/OWN[0]).read_bytes()==EXECUTED
 binary=proof_raw=None
 if not a.controls_only:
  assert a.oracle and a.provenance;binary=a.oracle.read_bytes();proof_raw=a.provenance.read_bytes();proof=json.loads(proof_raw)
  assert proof["state"]=="PASS"and proof["original_release_profile"]is True and proof["original_default_features"]is True
  assert proof["locked_registry_archives"]==360 and proof["original_archive_store_methods"]==29 and proof["binary_record"]["sha256"]==SHA(binary)
 paths=(a.actor,a.packer,a.metadata,a.metadata_packer,a.records);manifests={str(path):path.read_bytes()for path in paths}
 record_raw=(a.source/"scripts/durable_audit_archive_publication_code.json").read_bytes();record=json.loads(record_raw)
 assert record["source_sha256"]==SHA((a.source/"scripts/durable_audit_archive_publication_engine.S").read_bytes())
 previous_code=json.loads((a.source/"scripts/durable_audit_archive_metadata_code.json").read_bytes())
 sys.path.insert(0,str(a.source/"scripts"));from hia_native_loader import NativeModule
 all_cases=cases();(q/"cases.json").write_text(json.dumps(all_cases,sort_keys=True,indent=2)+"\n")
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 results=[];failures=[];start=time.monotonic()
 with ExitStack()as stack:
  actor,packer,meta_actor,meta_packer,records=[stack.enter_context(NativeModule(path,manifest_sha256=SHA(manifests[str(path)])))for path in paths]
  produced=packer.invoke(b"HRAWPQ01"+struct.pack("<QQ",1,0),output_capacity=64+record["flat_bytes"],workspace_capacity=16)
  (q/"actual-hia-engine.pack").write_bytes(produced);engine=stack.enter_context(Engine(produced,record))
  meta_produced=meta_packer.invoke(b"HRAMPQ01"+struct.pack("<QQ",1,0),output_capacity=2928,workspace_capacity=16)
  (q/"actual-hia-metadata-engine.pack").write_bytes(meta_produced);meta_engine=stack.enter_context(metadata.Engine(meta_produced,previous_code))
  reader_type=borrowed_reader_type(metadata)
  extra=controls(actor,packer,engine,meta_actor,records,meta_engine,reader_type,q/"controls")
  for i,case in enumerate([]if a.controls_only else all_cases):
   cq=q/("case-"+str(i).zfill(3));cq.mkdir();original_root=cq/"original";native_root=cq/"native"
   original_fixture=make_root(original_root,case,metadata);native_fixture=make_root(native_root,case,metadata)
   initial={"original":snapshot(original_root),"native":snapshot(native_root)}
   (cq/"fixtures.json").write_text(json.dumps(dict(original=original_fixture,native=native_fixture),sort_keys=True,indent=2)+"\n")
   command=json.dumps(dict(root=str(original_root),operation=OPS[case["operation"]],record=original_fixture["record"]),separators=(",",":")).encode()+b"\n"
   (cq/"original-input.json").write_bytes(command);t=time.monotonic()
   reference=subprocess.run([str(a.oracle)],input=command,capture_output=True,timeout=10)
   (cq/"original.stdout").write_bytes(reference.stdout);(cq/"original.stderr").write_bytes(reference.stderr)
   (cq/"original-terminal.json").write_text(json.dumps(dict(exit_code=reference.returncode,elapsed_seconds=time.monotonic()-t))+"\n")
   assert reference.returncode==0 and not reference.stderr,(i,case,reference.returncode,reference.stderr)
   original=json.loads(reference.stdout);frame=packet(case["operation"],native_fixture["record"])
   with Publication(actor,engine,meta_actor,records,meta_engine,reader_type,native_root,frame)as runner:
    observed=runner.drive();trace=runner.trace
   terminal={"original":snapshot(original_root),"native":snapshot(native_root)}
   (cq/"native-output.json").write_text(json.dumps(observed,sort_keys=True,indent=2)+"\n")
   (cq/"native-trace.json").write_text(json.dumps(trace,sort_keys=True,indent=2)+"\n")
   (cq/"original-result.json").write_text(json.dumps(original,sort_keys=True,indent=2)+"\n")
   (cq/"filesystem-before-after.json").write_text(json.dumps(dict(initial=initial,terminal=terminal),sort_keys=True,indent=2)+"\n")
   category=reference_category(original,metadata);seen_category=native_category(observed,metadata)
   same=original["accepted"]==(observed["diagnostic"]==0)and category==seen_category
   declared_wrong=case["operation"]==2 and case.get("old",{}).get("root_bad",False)
   if declared_wrong:
    assert terminal["original"]==initial["original"] and terminal["native"]==initial["native"],"refused old-root metadata changed"
    assert category==("binding",None) and observed["point"]==1 and observed["child_point"]==16
   original_wrong=[original_fixture["root_identity"][0],original_fixture["root_identity"][1]+1]if declared_wrong else None
   native_wrong=[native_fixture["root_identity"][0],native_fixture["root_identity"][1]+1]if declared_wrong else None
   same=same and normalized(terminal["original"],original_fixture["root_identity"],original_wrong)==normalized(terminal["native"],native_fixture["root_identity"],native_wrong)
   if original["accepted"]:
    assert original["value"]=={"written":True}
    for root,fixture in[(original_root,original_fixture),(native_root,native_fixture)]:
     assert(root/NAMES[case["operation"]]).read_bytes()==canonical(fixture["record"])
    assert observed["serialized_bytes"]==len(canonical(native_fixture["record"]))
   if observed["point"]in(1,2,3):assert not any(r["kind"]in(1,12,13,14,15)for r in trace)
   if observed["point"]==6:
    assert observed["created"]==1 and observed["cleanup_attempted"]==1
    assert any(r["kind"]==1 and r["errno"]==0 for r in trace)and not any(r["kind"]==13 for r in trace)
   result=dict(ordinal=i,label=case["label"],equal=same,original=original,native=observed,
    original_category=category,native_category=seen_category,initial=initial,terminal=terminal,trace=trace)
   (cq/"result.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
   results.append(dict(ordinal=i,label=case["label"],equal=same))
   if not same:failures.append(dict(ordinal=i,label=case["label"],original_category=category,native_category=seen_category))
 after=pins()
 if not a.controls_only:assert a.oracle.read_bytes()==binary and a.provenance.read_bytes()==proof_raw
 assert all(Path(path).read_bytes()==raw for path,raw in manifests.items())
 assert(a.source/"scripts/qualify_durable_audit_archive_metadata.py").read_bytes()==metadata_source
 assert(a.source/"scripts/durable_audit_archive_publication_code.json").read_bytes()==record_raw
 (q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
 report=dict(schema="hepta.runtime.durable-archive-publication-qualification.v1",passed=not failures and before==after,
  cases=len(results),controls=extra,results=results,failures=failures,source_before=before,source_after=after,source_unchanged=before==after,
  original_binary_sha256=SHA(binary)if binary else None,original_provenance_sha256=SHA(proof_raw)if proof_raw else None,
  actual_hia_engine_sha256=SHA(produced),actual_hia_metadata_engine_sha256=SHA(meta_produced),elapsed_seconds=time.monotonic()-start,
  public_archive_qualified=False,redb_qualified=False,python_is_qualification_transport_only=True)
 (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps(dict(passed=report["passed"],cases=len(results),controls=len(extra),failures=failures,elapsed_seconds=report["elapsed_seconds"],source_unchanged=before==after),sort_keys=True),flush=True)
 if not report["passed"]:raise SystemExit(1)
if __name__=="__main__":main()
