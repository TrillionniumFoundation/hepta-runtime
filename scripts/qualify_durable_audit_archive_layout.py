# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual HIA layout, retained directory capabilities, and frozen original oracle."""
from pathlib import Path
from contextlib import ExitStack
import argparse,ctypes,errno,fcntl,hashlib,json,os,selectors,stat,struct,subprocess,sys,time,types
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes()
SHA=lambda v:hashlib.sha256(v).hexdigest()
U=lambda v,at:struct.unpack_from("<Q",v,at)[0]
YIELD=0xffffffe0
ROOT="request-archive-v12";LEGACY="request-archive-v11"
ANCHOR=".request-archive-v12-anchor.json";INTENT=".request-archive-v12-init.json"
LEGACY_ANCHOR=".request-archive-v11-anchor.json"
OWN=("scripts/qualify_durable_audit_archive_layout.py","scripts/author_durable_audit_archive_layout.py",
 "scripts/durable_audit_archive_layout_source.py.txt","native/durable_audit_archive_layout.hepta","native/durable_audit_archive_layout_composition.json",
 "scripts/author_durable_audit_archive_layout_packer.py","scripts/durable_audit_archive_layout_packer_source.py.txt",
 "scripts/durable_audit_archive_layout_code.json","scripts/durable_audit_archive_layout_engine.S",
 "native/durable_audit_archive_layout_packer.hepta","native/durable_audit_archive_layout_packer_composition.json",
 "scripts/prepare_durable_audit_archive_layout_reference.py","native/durable_audit_archive_layout_abi.md")
def captured(root,name,expected):
 path=root/name;raw=path.read_bytes();assert SHA(raw)==expected,(name,SHA(raw),expected)
 module=types.ModuleType("_captured_"+path.stem);module.__file__=str(path)
 exec(compile(raw,str(path),"exec"),module.__dict__)
 assert module.EXECUTED==raw and path.read_bytes()==raw
 return module,raw
def identity(path):
 s=path.stat();return[s.st_dev,s.st_ino]
def put_file(path,raw,mode=0o600):
 with path.open("wb")as f:f.write(raw)
 path.chmod(mode)
def canonical(v):return json.dumps(v,separators=(",",":"),ensure_ascii=False).encode()
def create_root(root,complete=False):
 root.mkdir(parents=True,mode=0o700);root.chmod(0o700)
 legacy=root/LEGACY;legacy.mkdir(mode=0o700);legacy.chmod(0o700)
 ri=identity(root);li=identity(legacy)
 put_file(root/LEGACY_ANCHOR,canonical(dict(root_device=ri[0],root_inode=ri[1],archive_device=li[0],archive_inode=li[1])))
 put_file(legacy/("1"*64+".json"),b'{"qualification":"original legacy bytes"}')
 if complete:
  shards=root/ROOT;shards.mkdir(mode=0o700)
  for i in range(256):(shards/format(i,"02x")).mkdir(mode=0o700)
  record=dict(format=12,root=ri,legacy=li,archive=identity(shards),shards=[identity(shards/format(i,"02x"))for i in range(256)])
  put_file(root/ANCHOR,canonical(record))
 return dict(root=ri,legacy=li)
def stamp(st):
 return[st.st_dev,st.st_ino,st.st_size,st.st_mode,st.st_uid,st.st_nlink,
 st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
def snapshot(root):
 rows={}
 for p in [root,*sorted(root.rglob("*"))]:
  st=p.lstat();name="."if p==root else p.relative_to(root).as_posix()
  row=dict(identity=[st.st_dev,st.st_ino],mode=stat.S_IMODE(st.st_mode),kind=stat.S_IFMT(st.st_mode),
   uid=st.st_uid,gid=st.st_gid,links=st.st_nlink,stamp=stamp(st))
  if stat.S_ISREG(st.st_mode):
   try:raw=p.read_bytes();row.update(raw_hex=raw.hex(),bytes=len(raw),sha256=SHA(raw))
   except OSError as e:row["read_errno"]=e.errno
  if stat.S_ISLNK(st.st_mode):row["target"]=os.readlink(p)
  rows[name]=row
 return rows
def normalized(rows):
 byid={}
 for n,r in rows.items():byid.setdefault(tuple(r["identity"]),[]).append(n)
 def pair(v):return["physical",min(byid[tuple(v)])]if tuple(v)in byid else v
 result={}
 for n,r in rows.items():
  row={k:r[k]for k in("mode","kind","uid","gid","links","read_errno","target")if k in r}
  row["same_inode_as"]=min(byid[tuple(r["identity"])])
  if "raw_hex"in r:
   raw=bytes.fromhex(r["raw_hex"])
   if n in(ANCHOR,INTENT,LEGACY_ANCHOR):
    try:data=json.loads(raw)
    except(ValueError,UnicodeError):row["bytes_hex"]=raw.hex()
    else:
     if isinstance(data,dict)and n in(ANCHOR,INTENT):
      for key in("root","legacy","archive"):
       if isinstance(data.get(key),list)and len(data[key])==2:data[key]=pair(data[key])
      if isinstance(data.get("shards"),list):data["shards"]=[pair(v)if isinstance(v,list)and len(v)==2 else v for v in data["shards"]]
     elif isinstance(data,dict)and n==LEGACY_ANCHOR:
      for a,b in(("root_device","root_inode"),("archive_device","archive_inode")):
       if a in data and b in data:data[a],data[b]=pair([data[a],data[b]])
     row["json"]=data
     row["canonical"]=raw==canonical(json.loads(raw))
   else:row["bytes_hex"]=raw.hex()
  result[n]=row
 return result
def decode_record(raw):
 assert raw[:8]==b"HRAATR01"and U(raw,8)==0 and U(raw,24)==len(raw)
 count=U(raw,96);assert len(raw)==128+16*count and not any(raw[104:128])
 return dict(format=U(raw,32),root=list(struct.unpack_from("<2Q",raw,40)),legacy=list(struct.unpack_from("<2Q",raw,56)),
  archive=list(struct.unpack_from("<2Q",raw,80))if U(raw,72)else None,
  shards=[list(struct.unpack_from("<2Q",raw,128+16*i))for i in range(count)])
def borrowed_anchor_type(old):
 class Borrowed(old.Anchor):
  def __init__(self,actor,records,engine,rootfd):
   self.actor=actor;self.records=records;self.engine=engine;self.root=rootfd
   self.session=actor.session(output_capacity=192,workspace_capacity=16384)
   self.ctx=engine.create(0,ctypes.addressof(self.session._workspace),16384,rootfd);assert self.ctx>0
   self.trace=[];self.owned_seen=[]
  def close(self):
   if self.ctx is not None:
    self.engine.cleanup(self.ctx);self.ctx=None;os.fstat(self.root);self.session.close()
  def __exit__(self,*args):self.close()
 return Borrowed
def borrowed_publication_type(old):
 class Borrowed(old.Publication):
  def __init__(self,actor,engine,metadata_actor,records,metadata_engine,reader_type,rootfd,frame):
   self.actor=actor;self.engine=engine;self.metadata_actor=metadata_actor;self.records=records
   self.metadata_engine=metadata_engine;self.reader_type=reader_type;self.frame=frame;self.root=rootfd
   self.capacity=max(1048576,524288+len(frame));self.session=actor.session(output_capacity=128,workspace_capacity=self.capacity)
   self.ctx=engine.create(0,ctypes.addressof(self.session._workspace),self.capacity,rootfd);assert self.ctx>0
   self.trace=[];self.owned_seen=[]
  def close(self):
   if self.ctx is not None:
    self.engine.cleanup(self.ctx);self.ctx=None;os.fstat(self.root);self.session.close()
  def __exit__(self,*args):self.close()
 return Borrowed
class Cut(Exception):pass
class Engine:
 def __init__(self,raw,record):
  assert raw[:8]==b"HRALPK01"and len(raw)==U(raw,8)==64+U(raw,16)
  self.flat=raw[64:];assert SHA(self.flat)==record["flat_sha256"]and len(self.flat)==record["flat_bytes"]
  self.exports=dict(zip(("create","step","child_ack","take","destroy"),struct.unpack_from("<5Q",raw,24)))
  assert self.exports==record["exports"]
  self.fd=os.memfd_create("hia-audit-archive-layout-engine",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
  self.libc=ctypes.CDLL(None,use_errno=True);self.libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long];self.libc.mmap.restype=ctypes.c_void_p
  self.libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];self.libc.munmap.restype=ctypes.c_int
  self.address=None
  try:
   at=0
   while at<len(self.flat):n=os.write(self.fd,self.flat[at:]);assert n>0;at+=n
   fcntl.fcntl(self.fd,fcntl.F_ADD_SEALS,15);assert fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)==15
   assert os.pread(self.fd,len(self.flat),0)==self.flat
   self.address=self.libc.mmap(None,len(self.flat),5,2,self.fd,0);assert self.address not in(None,ctypes.c_void_p(-1).value)
   for name,args in[("create",[ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_int64,ctypes.c_int64]),("step",[ctypes.c_void_p]),("child_ack",[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64]),("take",[ctypes.c_void_p,ctypes.c_uint64]),("destroy",[ctypes.c_void_p])]:
    setattr(self,name,ctypes.CFUNCTYPE(ctypes.c_int64,*args)(self.address+self.exports[name]))
  except BaseException:
   if self.address not in(None,ctypes.c_void_p(-1).value):self.libc.munmap(self.address,len(self.flat))
   os.close(self.fd);self.fd=None;raise
 def state(self,ctx):
  v=ctypes.string_at(ctx,4360);assert v[:8]==b"HRAALG01"
  fds=list(struct.unpack_from("<264q",v,64));owned=[i for i in range(264)if v[4096+i]]
  return dict(sequence=U(v,32),pending=U(v,40),fds=fds,owned=owned,
   query=ctypes.string_at(ctx+2368,32).hex(),snapshot=ctypes.string_at(ctx+2304,64).hex())
 def cleanup(self,ctx):
  s=self.state(ctx)
  # Qualification children are synchronous and have completed or were never started.
  if s["pending"]==1:assert self.child_ack(ctx,0,errno.ECANCELED)==0
  assert self.destroy(ctx)==0
 def close(self):
  if self.fd is not None:
   assert os.pread(self.fd,len(self.flat),0)==self.flat and fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)==15
   assert self.libc.munmap(self.address,len(self.flat))==0;os.close(self.fd);self.fd=None
 def __enter__(self):return self
 def __exit__(self,*args):self.close()

class Layout:
 def __init__(self,components,root,trace_path):
  self.c=components;self.root_path=root
  self.root=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:self.legacy=os.open(LEGACY,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root)
  except BaseException:os.close(self.root);raise
  self.session=components["layout"].session(output_capacity=4480,workspace_capacity=1048576)
  self.engine=components["layout_engine"];self.ctx=self.engine.create(0,ctypes.addressof(self.session._workspace),1048576,self.root,self.legacy);assert self.ctx>0
  self.anchor=components["anchor_type"](components["anchor"],components["records"],components["anchor_engine"],self.root)
  initial=self.anchor.drive(1);assert initial["diagnostic"]==0,initial
  self.query=0;self.checkpoints=[];self.trace_path=trace_path;self.trace=trace_path.open("x")
  self.trace.write(json.dumps(dict(event="actual-retained-anchor-open",result=initial,trace=self.anchor.trace),sort_keys=True)+"\n")
  self.anchor.trace.clear();self.steps=0;self.last=None
 def child(self,row,request):
  c=self.c;kind=row["kind"]
  if kind==100:
   assert request[:8]==b"HRAAMQ01"and len(request)==32
   with c["metadata_type"](c["metadata"],c["records"],c["metadata_engine"],self.root)as child:
    result=child.drive(U(request,8));trace=child.trace
  elif kind==101:
   assert request==b"HRAANQ01"+struct.pack("<QQQ",2,0,0)
   result=self.anchor.drive(2);trace=list(self.anchor.trace);self.anchor.trace.clear()
  elif kind==102:
   assert request[:8]==b"HRAAWQ01"
   with c["publication_type"](c["publication"],c["publication_engine"],c["metadata"],c["records"],c["metadata_engine"],c["metadata_type"],self.root,request)as child:
    result=child.drive();trace=child.trace
  else:raise AssertionError(kind)
  return bytes.fromhex(result["raw"]),dict(result=result,trace=trace)
 def drive(self,op,*,cut=None,before=None,after=None):
  self.query+=1;frame=b"HRAALQ01"+struct.pack("<QQQ",op,self.query,0);checkpoints=[]
  for _ in range(1000000):
   code,out,w=self.session.invoke_raw(frame)
   if code!=YIELD:
    if code not in(256,4480):
     self.trace_path.with_suffix(".invalid.workspace.bin").write_bytes(w)
     self.trace_path.with_suffix(".invalid.output.bin").write_bytes(out)
     self.trace_path.with_suffix(".invalid.input.bin").write_bytes(frame)
     self.trace.flush();raise AssertionError(dict(code=code,last=self.last,phase=U(w,0),request=frame.hex()))
    assert out[:8]==b"HRAALR01"and U(out,32)==op and U(out,40)==code and U(out,56)==self.query
    assert U(out,48)==(code==4480)
    result=dict(diagnostic=U(out,8),errno=U(out,16),point=U(out,24),operation=op,loaded=bool(U(out,48)),
     root=list(struct.unpack_from("<2Q",out,64)),legacy=list(struct.unpack_from("<2Q",out,80)),
     child_diagnostic=U(out,96),child_point=U(out,104),exclusive=bool(U(out,112)),raw=out[:code].hex(),checkpoints=checkpoints)
    if code==4480:
     result["anchor"]=decode_record(out[256:4480]);result["anchor_stamp"]=list(struct.unpack_from("<10Q",out,128))
     state=self.engine.state(self.ctx)
     assert state["owned"]==[2,*range(8,264)]
     result["held_root"]=[os.fstat(state["fds"][2]).st_dev,os.fstat(state["fds"][2]).st_ino]
     result["held_shards"]=[[os.fstat(state["fds"][i]).st_dev,os.fstat(state["fds"][i]).st_ino]for i in range(8,264)]
    else:assert self.engine.state(self.ctx)["owned"]==[]
    self.trace.write(json.dumps(dict(event="terminal",value=result),sort_keys=True)+"\n");self.trace.flush()
    return result
   words=struct.unpack_from("<12Q",w,256)
   assert words[0]==int.from_bytes(b"HRAALA01","little")and words[8:]==(0,0,0,0)
   row=dict(sequence=words[1],kind=words[2],slot=words[3],span=words[4],count=words[5],arg=words[6],capacity=words[7],action_hex=w[256:352].hex(),phase=U(w,0))
   self.last=row
   if before:before(row,self)
   v=self.engine.step(self.ctx);assert v in(0,1),(v,row,self.engine.state(self.ctx))
   if v==1:
    request=ctypes.string_at(ctypes.addressof(self.session._workspace)+row["span"],row["count"])
    pending=self.engine.state(self.ctx);assert pending["pending"]==1
    assert self.engine.step(self.ctx)==-errno.EBUSY and self.engine.destroy(self.ctx)==-errno.EBUSY
    assert self.engine.state(self.ctx)==pending
    payload,details=self.child(row,request);assert len(payload)<=row["capacity"]
    ctypes.memmove(ctypes.addressof(self.session._workspace)+row["arg"],payload,len(payload))
    assert self.engine.child_ack(self.ctx,len(payload),0)==0
    row.update(child_request_hex=request.hex(),child_response_hex=payload.hex(),child=details)
   action=ctypes.string_at(ctypes.addressof(self.session._workspace)+256,96)
   assert U(action,64)==row["sequence"]and U(action,88)==0
   row.update(result=U(action,72),errno=U(action,80),ack_hex=action.hex())
   if row["kind"]in(2,4)and row["errno"]==0:row["stat_hex"]=ctypes.string_at(ctypes.addressof(self.session._workspace)+512,88).hex()
   if row["kind"]==9 and row["errno"]==0:row["directory_entries_hex"]=ctypes.string_at(ctypes.addressof(self.session._workspace)+row["span"],row["result"]).hex()
   if row["kind"]==21:
    k=row["arg"];n=row["capacity"]
    label={1:"Intent",2:"RootCreated",3:"RootBound",4:"ShardCreated("+str(n)+")",5:"ShardBound("+str(n)+")",6:"Anchor",7:"IntentRemoved"}[k]
    assert row["errno"]==0 and row["result"]==0
    checkpoints.append(label);self.checkpoints.append(label);row["checkpoint"]=label
   self.trace.write(json.dumps(row,sort_keys=True)+"\n");self.steps+=1
   if after:after(row,self)
   if cut is not None and row.get("checkpoint")==cut:
    self.trace.flush();raise Cut(dict(checkpoints=checkpoints,point=cut))
  raise AssertionError("qualification loop exhausted; no application directory cap added")
 def close(self):
  if self.ctx is not None:
   state=self.engine.state(self.ctx);fds=[state["fds"][i]for i in state["owned"]]
   self.engine.cleanup(self.ctx);self.ctx=None
   for fd in fds:
    try:os.fstat(fd)
    except OSError as e:assert e.errno==errno.EBADF
    else:raise AssertionError("owned layout descriptor leaked")
   os.fstat(self.root);os.fstat(self.legacy);self.anchor.close();self.session.close()
   os.close(self.legacy);os.close(self.root);self.trace.close()
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
class Original:
 def __init__(self,path,q):
  self.q=q;q.mkdir();self.err=(q/"stderr").open("xb");self.input=(q/"stdin.jsonl").open("xb");self.output=(q/"stdout.jsonl").open("xb")
  self.p=subprocess.Popen([str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,bufsize=0)
  self.selector=selectors.DefaultSelector();self.selector.register(self.p.stdout,selectors.EVENT_READ);self.buffer=b""
 def step(self,operation,**kw):
  raw=canonical(dict(operation=operation,**kw))+b"\n";self.input.write(raw);self.input.flush()
  self.p.stdin.write(raw);self.p.stdin.flush();deadline=time.monotonic()+10
  while b"\n"not in self.buffer:
   left=deadline-time.monotonic();assert left>0,"original command exceeded qualification 10-second ceiling"
   assert self.selector.select(left),"original command timed out"
   part=os.read(self.p.stdout.fileno(),65536);assert part,"original terminated without reply";self.buffer+=part
  raw,self.buffer=self.buffer.split(b"\n",1);self.output.write(raw+b"\n");self.output.flush();return json.loads(raw)
 def close(self):
  self.p.stdin.close()
  try:code=self.p.wait(timeout=3)
  except subprocess.TimeoutExpired:self.p.kill();self.p.wait();raise
  self.selector.close();self.p.stdout.close();self.err.close();self.input.close();self.output.close()
  assert code==0 and not self.buffer and not(self.q/"stderr").read_bytes(),(code,(self.q/"stderr").read_bytes())
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
def verify_success(reference,native,root):
 assert reference["accepted"]and native["diagnostic"]==0
 value=reference["value"]
 if "layout"in value:
  assert value["root"]==identity(root)and value["legacy"]==identity(root/LEGACY)
  assert (value["layout"]is not None)==native["loaded"]
 if native["loaded"]:
  actual=json.loads((root/ANCHOR).read_bytes())
  # Caller supplies each lane separately; compare topology to its actual named objects.
  assert actual["format"]==12 and actual["root"]==identity(root)and actual["legacy"]==identity(root/LEGACY)
  assert actual["archive"]==identity(root/ROOT)
  assert actual["shards"]==[identity(root/ROOT/format(i,"02x"))for i in range(256)]
 if "exclusive"in value:assert value["exclusive"]==native["exclusive"]
def native_topology(value,root):
 assert value["root"]==identity(root)and value["legacy"]==identity(root/LEGACY)
 if value["loaded"]:
  actual=json.loads((root/ANCHOR).read_bytes())
  assert value["anchor"]==actual and value["held_root"]==actual["archive"]and value["held_shards"]==actual["shards"]
  assert value["anchor_stamp"]==stamp((root/ANCHOR).stat())
def compare_files(original,native):
 a=snapshot(original);b=snapshot(native);return normalized(a)==normalized(b),dict(original=a,native=b)
def single_case(c,oracle,q,label,complete,operations,cut=None,fixtures=None):
 cq=q/label;cq.mkdir()
 fq=cq if fixtures is None else fixtures/label
 if fq!=cq:fq.mkdir(mode=0o700)
 ro=fq/"original";rn=fq/"native";create_root(ro,complete);create_root(rn,complete)
 results=[]
 with Original(oracle,cq/"oracle")as old:
  observed=None
  with Layout(c,rn,cq/"native-trace.jsonl")as new:
   ref=old.step("open",root=str(ro));observed=new.drive(1)
   assert ref["accepted"]and observed["diagnostic"]==0,(ref,observed)
   native_topology(observed,rn);verify_success(ref,observed,ro)
   same,files=compare_files(ro,rn);assert same,(label,"initial",files)
   results.append(dict(operation="open",original=ref,native=observed))
   for op in operations:
    if op==1:
     ref=old.step("open",root=str(ro),handle=1)
     assert old.step("drop",handle=1)["value"]=={"dropped":True}
    else:
     ref=old.step({2:"initialize",3:"fence",4:"full_layout",5:"exclusive"}[op],**({"cut":cut}if cut and op==2 else{}))
    try:observed=new.drive(op,cut=cut if op==2 else None)
    except Cut as e:
     assert not ref["accepted"]and ref["error"]["text"]=="injected initialization interruption"
     assert e.args[0]["checkpoints"]==ref["checkpoints"]
     observed=dict(interrupted=True,checkpoints=e.args[0]["checkpoints"]);results.append(dict(operation=op,original=ref,native=observed));break
    assert ref["accepted"]and observed["diagnostic"]==0,(label,ref,observed)
    assert observed["checkpoints"]==ref["checkpoints"],(label,ref["checkpoints"],observed["checkpoints"])
    native_topology(observed,rn);verify_success(ref,observed,ro)
    same,files=compare_files(ro,rn);assert same,(label,op,files)
    results.append(dict(operation=op,original=ref,native=observed))
  assert old.step("drop")["value"]=={"dropped":True}
  same,before_restart=compare_files(ro,rn);assert same,(label,"before-restart")
  with Layout(c,rn,cq/"restart-native-trace.jsonl")as new:
   ref=old.step("open",root=str(ro));observed=new.drive(1)
   assert ref["accepted"]and observed["diagnostic"]==0,(label,"restart",ref,observed)
   native_topology(observed,rn);verify_success(ref,observed,ro)
   same,files=compare_files(ro,rn);assert same,(label,"restart",files)
   results.append(dict(operation="restart",original=ref,native=observed))
  assert old.step("drop")["value"]=={"dropped":True}
 result=dict(label=label,passed=True,fixture_paths=dict(original=str(ro),native=str(rn)),results=results,before_restart=before_restart,terminal=files)
 (cq/"result.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 return dict(label=label,passed=True,calls=len(results))

def main():
 p=argparse.ArgumentParser()
 for name in("source","layout","layout-packer","anchor","anchor-packer","metadata","metadata-packer","publication","publication-packer","records","oracle","provenance","output"):
  p.add_argument("--"+name,type=Path,required=True)
 p.add_argument("--smoke",action="store_true");p.add_argument("--fixtures",type=Path);a=p.parse_args();a.source=a.source.resolve(strict=True)
 q=a.output;q.mkdir(parents=True,exist_ok=False)
 if a.fixtures is not None:
  assert a.fixtures.is_absolute();a.fixtures.parent.resolve(strict=True)
  a.fixtures.mkdir(mode=0o700,exist_ok=False);a.fixtures=a.fixtures.resolve(strict=True)
 pub,pubraw=captured(a.source,"scripts/qualify_durable_audit_archive_publication.py","dca32d7674518ac0a3ffef164459a56aa076239f475eb964767f1b9cf0c710e2")
 anchor,anchorraw=captured(a.source,"scripts/qualify_durable_audit_anchor.py","efdf5180ee7bac264e4cf561bf3ecbd82c8c61ffbb6777a909fc1929258ac012")
 metadata,metaraw=pub.captured_metadata_module(a.source)
 names=tuple(dict.fromkeys((*OWN,*pub.OWN,*metadata.PATHS,*anchor.PATHS)))
 def pins():
  return{n:dict(bytes=len(raw),sha256=SHA(raw),mode=stat.S_IMODE((a.source/n).stat().st_mode))for n in names for raw in[(a.source/n).read_bytes()]}
 before=pins();assert(a.source/OWN[0]).read_bytes()==EXECUTED
 binary=a.oracle.read_bytes();proof_raw=a.provenance.read_bytes();proof=json.loads(proof_raw)
 assert proof["state"]=="PASS"and proof["original_release_profile"]is True and proof["original_default_features"]is True
 assert proof["locked_registry_archives"]==360 and proof["original_archive_store_methods"]==29 and proof["binary_record"]["sha256"]==SHA(binary)
 paths={n:getattr(a,n.replace("-","_"))for n in("layout","layout-packer","anchor","anchor-packer","metadata","metadata-packer","publication","publication-packer","records")}
 manifests={n:path.read_bytes()for n,path in paths.items()}
 sys.path.insert(0,str(a.source/"scripts"));from hia_native_loader import NativeModule
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 start=time.monotonic();results=[];failed=None
 try:
  with ExitStack()as stack:
   c={n:stack.enter_context(NativeModule(path,manifest_sha256=SHA(manifests[n])))for n,path in paths.items()}
   config=[("layout","HRALPQ01","durable_audit_archive_layout",Engine),
    ("anchor","HRAAPQ01","durable_audit_anchor",anchor.Engine),
    ("metadata","HRAMPQ01","durable_audit_archive_metadata",metadata.Engine),
    ("publication","HRAWPQ01","durable_audit_archive_publication",pub.Engine)]
   for key,magic,stem,cls in config:
    record=json.loads((a.source/("scripts/"+stem+"_code.json")).read_bytes())
    assert record["source_sha256"]==SHA((a.source/("scripts/"+stem+"_engine.S")).read_bytes())
    out=c[key+"-packer"].invoke(magic.encode()+struct.pack("<QQ",1,0),output_capacity=64+record["flat_bytes"],workspace_capacity=16)
    (q/("actual-hia-"+key+"-engine.pack")).write_bytes(out)
    c[key+"_engine"]=stack.enter_context(cls(out,record))
   c["anchor_type"]=borrowed_anchor_type(anchor);c["metadata_type"]=pub.borrowed_reader_type(metadata);c["publication_type"]=borrowed_publication_type(pub)
   cases=[("flat-open-fence",False,[5,3,1,4,5],None),("initialize-all-256",False,[2,5,3,4,2],None),("preexisting-all-256",True,[5,3,4,1,2],None)]
   if not a.smoke:
    for cut in["Intent","RootCreated","RootBound","ShardCreated(0)","ShardBound(31)","ShardCreated(255)","ShardBound(255)","Anchor","IntentRemoved"]:
     cases.append(("restart-"+cut.replace("(","-").replace(")",""),False,[2],cut))
   (q/"cases.json").write_text(json.dumps(cases,sort_keys=True,indent=2)+"\n")
   for label,complete,operations,cut in cases:
    row=single_case(c,a.oracle,q,label,complete,operations,cut,a.fixtures);results.append(row);print(json.dumps(row),flush=True)
 except BaseException as error:
  failed=dict(type=type(error).__name__,text=str(error));raise
 finally:
  after=pins();same=before==after
  assert a.oracle.read_bytes()==binary and a.provenance.read_bytes()==proof_raw
  assert all(paths[n].read_bytes()==raw for n,raw in manifests.items())
  (q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
  report=dict(schema="hepta.runtime.durable-archive-layout-qualification.v1",passed=failed is None and same,results=results,failed=failed,
   source_before=before,source_after=after,source_unchanged=same,original_binary_sha256=SHA(binary),original_provenance_sha256=SHA(proof_raw),
   elapsed_seconds=time.monotonic()-start,fixture_root=str(q if a.fixtures is None else a.fixtures),physical_layout_only=True,shared_registry_qualified=False,content_watch_qualified=False,redb_qualified=False,public_archive_qualified=False)
  (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
  print(json.dumps(dict(passed=report["passed"],cases=len(results),elapsed_seconds=report["elapsed_seconds"],source_unchanged=same,failed=failed)),flush=True)
  assert same
if __name__=="__main__":main()
