#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual current original/native binary write, decoder, ownership and wire gates."""
from __future__ import annotations
import argparse,ast,base64,fcntl,gzip,hashlib,itertools,json,os,resource,signal,socket,stat,struct,subprocess,sys,time,unittest
from pathlib import Path
sys.dont_write_bytecode=True
A=ROOT=OUT=BUILD=SOURCE=REFERENCE=None
ROWS=[];PAIRS=[];JOURNALS=[];DECODER=None
def pin(path):
 p=Path(path)
 with p.open("rb") as f:digest=hashlib.file_digest(f,"sha256").hexdigest()
 return dict(path=str(p),bytes=p.stat().st_size,sha256=digest)
def u64(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def wire(root,path,prior,data):
 parts=[x.encode() for x in (root,path,prior,data)]
 return b"HBWRQ001"+struct.pack("<11Q",1,0,1,*map(len,parts),0,0,0,sum(map(len,parts)))+b"".join(parts)
def injected(block):
 marker="if __name__ == '__main__':";at=SOURCE.rfind(marker);assert at>0
 text=SOURCE[:at]+block+"\n"+SOURCE[at:]
 assert text.replace(block+"\n","",1)==SOURCE
 return text
def snapshot(root):
 rows={}
 for p in sorted(root.rglob("*")):
  st=p.lstat();row=dict(mode=stat.S_IMODE(st.st_mode),kind=stat.S_IFMT(st.st_mode),uid=st.st_uid,gid=st.st_gid,nlink=st.st_nlink)
  if stat.S_ISREG(st.st_mode):
   try:row["content"]=dict(bytes=st.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
   except PermissionError:row["content"]="not-readable"
   row["xattrs"]={k:os.getxattr(p,k,follow_symlinks=False).hex() for k in sorted(os.listxattr(p,follow_symlinks=False))}
  if stat.S_ISLNK(st.st_mode):row["target"]=os.readlink(p)
  rows[p.relative_to(root).as_posix()]=row
 return rows
def run(name,argv,data,observe=False,fsize=None):
 folder=OUT/"runs";folder.mkdir(exist_ok=True);prefix=folder/name
 journal=None
 if observe:
  journal=prefix.with_suffix(".journal")
  fd=os.open(journal,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  if fd!=3:
   os.close(fd);raise AssertionError(("controlled journal FD3 unavailable",fd))
 def limit():
  resource.setrlimit(resource.RLIMIT_FSIZE,(fsize,fsize))
 start=time.monotonic()
 try:
  p=subprocess.run([str(x) for x in argv],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
   pass_fds=(3,) if observe else (),preexec_fn=limit if fsize is not None else None)
 finally:
  if observe:os.close(3)
 prefix.with_suffix(".input").write_bytes(data);prefix.with_suffix(".stdout").write_bytes(p.stdout);prefix.with_suffix(".stderr").write_bytes(p.stderr)
 row=dict(name=name,argv=[str(x) for x in argv],returncode=p.returncode,seconds=time.monotonic()-start,timeout_seconds=30,
  fsize_limit=fsize,input=pin(prefix.with_suffix(".input")),stdout=pin(prefix.with_suffix(".stdout")),stderr=pin(prefix.with_suffix(".stderr")))
 if journal:row["journal"]=pin(journal)
 ROWS.append(row)
 return p,journal
def setup(root,kind,name,data):
 target=root/name
 if kind in ("existing","metadata","hardlink","unreadable"):
  target.write_bytes(b"original bytes");target.chmod(0o640)
 if kind=="metadata":
  os.setxattr(target,"user.hia.empty",b"");os.setxattr(target,"user.hia.binary",bytes(range(256)))
  os.setxattr(target,"user.hia.中文","π".encode())
 if kind=="hardlink":os.link(target,root/"alias")
 if kind=="unreadable":target.chmod(0)
 if kind=="directory":target.mkdir()
 if kind=="symlink":
  (root/"source").write_bytes(b"symlink target unchanged");target.symlink_to("source")
 if kind=="fifo":os.mkfifo(target,0o600)
 if kind=="parent-symlink":
  (root/"real").mkdir();(root/"parent").symlink_to("real",target_is_directory=True)
 if kind=="parent-file":(root/"parent").write_bytes(b"regular parent")
 if kind=="parent-denied":(root/"parent").mkdir();(root/"parent").chmod(0)
 lock=root/(".hepta-lock-"+hashlib.sha256(name.encode()).hexdigest()[:24])
 if kind in ("lock-public","lock-hardlink","lock-symlink","lock-directory","lock-fifo"):
  if kind=="lock-directory":lock.mkdir()
  elif kind=="lock-fifo":os.mkfifo(lock,0o600)
  elif kind=="lock-symlink":
   (root/"side-target").write_bytes(b"unchanged");lock.symlink_to("side-target")
  else:
   lock.write_bytes(b"");lock.chmod(0o600)
   if kind=="lock-public":lock.chmod(0o644)
   else:os.link(lock,root/"lock-alias")
 return target
def compare(case,kind="absent",name="target",data="eA==",prior="absent",variant="production",path_tail=None,root_mode=None,original_source=None,fsize=None):
 parent=OUT/"cases"/case;parent.mkdir(parents=True)
 results=[];journals=[]
 row=dict(case=case,kind=kind,variant=variant,implementations={})
 for implementation in ("native","original"):
  root=parent/implementation;root.mkdir()
  target=setup(root,kind,name,data)
  configured=str(root);path=str(target) if path_tail is None else str(root)+path_tail
  if root_mode=="relative":configured="relative"
  elif root_mode=="empty":configured=""
  elif root_mode=="outside":configured=str(root)+"-other"
  elif root_mode=="root":path=configured
  elif root_mode=="sidecar":path=configured+"/.hepta-private"
  elif root_mode=="relative-path":path="relative"
  elif root_mode=="double-anchor":configured="/"+configured;path="/"+path
  elif root_mode=="normalized":configured+="/.";path=str(root)+"/./"+name+"/"
  actual_prior=REFERENCE["version"](target.stat()) if prior=="current" else prior
  q=dict(op="write",root=configured,path=path,expected_version=actual_prior,data_base64=data)
  before=snapshot(root)
  source=SOURCE if original_source is None else original_source
  argv=[A.build/variant/"public-binary-write.elf"] if implementation=="native" else [sys.executable,"-I","-B","-c",source]
  raw=wire(configured,path,actual_prior,data) if implementation=="native" else json.dumps(q,ensure_ascii=False).encode()
  p,j=run(case+"-"+implementation,argv,raw,implementation=="native" and variant!="production",fsize)
  after=snapshot(root)
  result=dict(returncode=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex(),before=before,after=after)
  if p.returncode==0:
   value=json.loads(p.stdout);st=target.stat();actual=REFERENCE["version"](st)
   result.update(value=value,actual_version=actual,stat=dict(dev=st.st_dev,ino=st.st_ino,size=st.st_size,mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns))
   assert value["version"]==actual,(case,implementation,value,actual)
   expected_data=base64.b64decode(data,validate=True)
   assert target.read_bytes()==expected_data
   assert value["written"]==len(expected_data) and value["size"]==len(expected_data)
   assert value["sha256"]==hashlib.sha256(expected_data).hexdigest() and value["mode"]==stat.S_IMODE(st.st_mode)
   assert set(value)=={"written","size","version","sha256","mode"}
  row["implementations"][implementation]=result
  results.append(p);journals.append(j)
  if kind=="parent-denied":(root/"parent").chmod(0o700)
  if kind=="unreadable":target.chmod(0o640)
 PAIRS.append(row)
 n,p=results
 assert n.returncode==p.returncode,(case,n.returncode,p.returncode,n.stderr,p.stderr)
 assert n.stderr==p.stderr,(case,n.stderr,p.stderr)
 if p.returncode==0:
  nv=dict(row["implementations"]["native"]["value"]);pv=dict(row["implementations"]["original"]["value"])
  # These measured OS identities are checked independently against each actual
  # final stat before replacing them with the same role for cross-process equality.
  nv["version"]=pv["version"]="<actual-final-file-version>"
  assert nv==pv,(case,nv,pv)
  assert n.stdout.endswith(b"\n") and p.stdout.endswith(b"\n")
 else:assert n.stdout==p.stdout==b""
 assert row["implementations"]["native"]["after"]==row["implementations"]["original"]["after"],case
 assert not any(".hepta-write-" in path for path in row["implementations"]["native"]["after"]),case
 return row,journals[0]
def read_journal(path):
 selected={};rows=[]
 with Path(path).open("rb") as f:
  at=0
  while True:
   head=f.read(64)
   if not head:break
   assert len(head)==64 and head[:8]==b"HBWLJR01"
   family,event,identity,z1,z2,size,z3=struct.unpack_from("<7Q",head,8)
   assert family in (1,2,3) and z1==z2==z3==0
   data=f.read(size);assert len(data)==size
   rows.append(dict(offset=at,family=family,event=event,producer_identity=identity,bytes=size,sha256=hashlib.sha256(data).hexdigest()))
   if family==1 and event in (8,9,10,11,12,13,14):selected.setdefault(event,[]).append(data)
   at+=64+size
  assert at==Path(path).stat().st_size
 JOURNALS.append(dict(file=pin(path),entries=rows))
 return selected,rows
class Controls(unittest.TestCase):
 def test_01_complete_write_results_and_metadata(self):
  cases=[("empty",b""),("one",b"x"),("all-bytes",bytes(range(256))),("hash-boundary",bytes(range(256))*16+b"x"),
   ("one-mib",bytes(range(256))*4096)]
  for name,data in cases:compare("value-"+name,data=base64.b64encode(data).decode())
  for kind in ("existing","metadata","hardlink"):
   row,_=compare("overwrite-"+kind,kind=kind,prior="current",data=base64.b64encode(bytes(range(256))*3).decode())
   for result in row["implementations"].values():
    self.assertEqual(result["before"]["target"]["mode"],result["after"]["target"]["mode"])
    self.assertEqual(result["before"]["target"]["xattrs"],result["after"]["target"]["xattrs"])
  for i,name in enumerate(("unicode-中文-π-😀","quote'\"slash\\tab\tline\nreturn\rcontrol\x01",".ordinary-dotfile")):
   compare("name-"+str(i),name=name,data="YWJjZA==")
  compare("normalization",root_mode="normalized",data="eHl6")
  compare("double-anchor",root_mode="double-anchor",data="eHl6")
 def test_02_original_error_precedence_and_cleanup(self):
  for kind in ("directory","symlink","fifo","unreadable","lock-public","lock-hardlink","lock-symlink","lock-directory","lock-fifo"):
   compare("target-"+kind,kind=kind,prior="absent")
  compare("stale-existing",kind="existing",prior="absent",data="!")
  compare("stale-absent",prior="wrong",data="!")
  compare("nul-final",name="nu\x00l")
  compare("nul-parent",path_tail="/nu\x00l/target")
  compare("long-name",name="q"*70000)
  compare("long-unicode-name",name="😀"*18000)
  for kind in ("parent-symlink","parent-file","parent-denied"):
   compare(kind,kind=kind,path_tail="/parent/leaf")
  compare("missing-parent",path_tail="/missing/leaf")
  compare("traversal",path_tail="/dir/../target")
  for mode in ("relative","empty","outside","root","sidecar","relative-path"):compare("root-"+mode,root_mode=mode)
  values=["!","A","AAAA=","YQ===","AA==!","AA==A","AA=A","=AAA","A===","AAA","é","😀","AA==\x00"]
  for i,value in enumerate(values):compare("decode-error-"+str(i),data=value)
  compare("over-decoded-bound",data=base64.b64encode(b"x"*1048577).decode())
 def test_03_actual_kernel_partial_write_and_fsize_failure(self):
  for size in (0,3):
   row,_=compare("fsize-"+str(size),kind="metadata",prior="current",data=base64.b64encode(b"ten bytes!").decode(),fsize=size)
   for result in row["implementations"].values():
    self.assertEqual(result["returncode"],1)
    self.assertEqual(bytes.fromhex(result["stderr_hex"]),b"OSError: [Errno 27] File too large\n")
    self.assertEqual(result["before"]["target"],result["after"]["target"])
 def test_04_complete_observation_and_parent_fd_zero(self):
  for variant in ("observed","fd-zero"):
   block="\n_original_parent_fd_zero = parent\ndef parent(root,path):\n    os.close(0)\n    return _original_parent_fd_zero(root,path)\n"
   row,path=compare("observe-"+variant,variant=variant,data="YWJj",original_source=injected(block) if variant=="fd-zero" else None)
   selected,rows=read_journal(path)
   self.assertTrue(any(x["family"]==2 for x in rows))
   self.assertEqual(len(selected[10]),1);child=selected[10][0]
   self.assertEqual(child[:8],b"HBWTR001");self.assertEqual(u64(child,8),0);self.assertEqual(u64(child,56),len(child)-64)
   self.assertTrue(all(u64(x,56)==2 and u64(x,184)==0 for x in selected[11]))
   state=selected[12][-1];self.assertEqual(u64(state,104),0);self.assertEqual(u64(state,112),0)
   self.assertEqual(u64(selected[13][-1],48),0)
   if variant=="fd-zero":self.assertEqual(u64(selected[9][0],24),0)
 def test_05_actual_outer_close_error(self):
  block="\nimport ctypes as _ctypes\nclass _Filter(_ctypes.Structure):\n    _fields_=[(\"code\",_ctypes.c_ushort),(\"jt\",_ctypes.c_ubyte),(\"jf\",_ctypes.c_ubyte),(\"k\",_ctypes.c_uint)]\nclass _Program(_ctypes.Structure):\n    _fields_=[(\"len\",_ctypes.c_ushort),(\"filter\",_ctypes.POINTER(_Filter))]\n_libc=_ctypes.CDLL(None,use_errno=True)\n_original_close=os.close\n_close_calls=[]\n_close_armed=False\ndef _actual_close(fd):\n    global _close_armed\n    if not _close_armed:\n        rules=(_Filter*6)(_Filter(0x20,0,0,0),_Filter(0x15,0,3,3),_Filter(0x20,0,0,16),_Filter(0x15,0,1,fd),_Filter(6,0,0,0x00050005),_Filter(6,0,0,0x7fff0000))\n        program=_Program(6,rules)\n        if _libc.prctl(38,1,0,0,0)!=0:raise RuntimeError(\"fixture no_new_privs\")\n        if _libc.syscall(317,1,0,_ctypes.byref(program))!=0:raise RuntimeError(\"fixture seccomp\")\n        _close_armed=True\n    _close_calls.append(fd)\n    return _original_close(fd)\n_original_parent_for_close = parent\ndef parent(root,path):\n    os.close=_actual_close\n    try:\n        return _original_parent_for_close(root,path)\n    finally:\n        os.close=_original_close\n        assert len(_close_calls)==2 and _close_calls[0]==_close_calls[1]\n"
  row,path=compare("outer-close-error",variant="close-error",original_source=injected(block))
  self.assertEqual(bytes.fromhex(row["implementations"]["native"]["stderr_hex"]),b"OSError: [Errno 5] Input/output error\n")
  selected,rows=read_journal(path)
  self.assertNotIn(10,selected)
  self.assertEqual([u64(x,24) for x in selected[8]],[1,2,3,4,5])
  self.assertEqual(u64(selected[8][2],32),u64(selected[8][4],32))
  self.assertEqual(u64(selected[13][-1],48),1)
  self.assertEqual(u64(selected[14][-1],64),u64(selected[9][1],24))
 def test_06_malformed_private_frames_and_owner_capacity(self):
  good=wire("/","/target","absent","eA==")
  cases=[b"",good[:95],b"BADMAGIC"+good[8:],good+b"x",good[:-1]]
  for at,value in ((8,0),(8,3),(16,1),(24,0),(24,2),(32,(1<<64)-1),(40,(1<<64)-1),(48,(1<<64)-1),(56,(1<<64)-1),(64,1),(72,1),(80,1),(88,0)):
   raw=bytearray(good);struct.pack_into("<Q",raw,at,value);cases.append(bytes(raw))
  for at in (96,97,len(good)-1):
   raw=bytearray(good);raw[at]=0xff;cases.append(bytes(raw))
  for i,raw in enumerate(cases):
   p,_=run("bad-wire-"+str(i),[A.build/"production/public-binary-write.elf"],raw)
   self.assertEqual((p.returncode,p.stdout,p.stderr),(111,b"",b""))
  sys.path.insert(0,str(ROOT/"scripts"));from hia_native_loader import NativeModule
  meta=BUILD["members"]["walk"]
  with NativeModule(A.build/meta["manifest"],manifest_sha256=meta["manifest_pin"]["sha256"]) as m:
   for raw in cases:
    code,out,work=m.invoke_raw(raw,output_capacity=512,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0x6b)
    self.assertEqual(code,0xffffffff);self.assertEqual(out,b"\xa5"*512);self.assertEqual(work,b"\x6b"*4096)
   code,out,work=m.invoke_raw(good,output_capacity=63,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0)
   self.assertEqual(code,0xfffffffe);self.assertEqual(out,b"\xa5"*63);self.assertEqual(work,bytes(4096))
   code,out,work=m.invoke_raw(good,output_capacity=512,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0)
   self.assertEqual(code,64);self.assertEqual(out[:8],b"HBWRR001");self.assertEqual(u64(out,8),4);needed=u64(out,32)
   self.assertEqual(out[64:],b"\xa5"*448);self.assertEqual(work,bytes(4096))
   for capacity in (needed-1,needed,needed+1):
    code,out,work=m.invoke_raw(good,output_capacity=512,workspace_capacity=capacity,output_fill=0xa5,workspace_fill=0)
    self.assertEqual(code,64)
    self.assertEqual(u64(out,8),4 if capacity<needed else 1)
    if capacity<needed:self.assertEqual(work,bytes(capacity))
 def test_07_current_decoder_complete_original_pairs(self):
  global DECODER
  sys.path.insert(0,str(ROOT/"scripts"));from hia_native_loader import NativeModule
  meta=BUILD["members"]["base64"];path=OUT/"decoder-complete-buffers.bin.gz"
  cases=["".join(chars) for length in range(7) for chars in itertools.product("A/=!\n",repeat=length)]
  cases += [("AAAA"[:i]+chr(c)+"AAAA"[i+1:]) for c in range(128) for i in range(4)]
  cases += [base64.b64encode(bytes((i*37+j)%256 for j in range(i))).decode() for i in range(514)]
  cases += ["é","😀","AA==é","=😀","A===é","A="*500,"A"*1025,"A"*4097]
  count=0;logical=0;statuses={}
  with NativeModule(A.build/meta["manifest"],manifest_sha256=meta["manifest_pin"]["sha256"]) as m,gzip.open(path,"xb",compresslevel=1) as journal:
   for value in cases:
    raw=value.encode();query=b"HRCODEC1"+struct.pack("<2Q",4,0)+raw;capacity=max(512,len(raw)+96)
    try:
     payload=base64.b64decode(value,validate=True);kind=0;klass=0
    except (ValueError,base64.binascii.Error) as exc:
     payload=str(exc).encode();kind=3;klass=1 if type(exc) is ValueError else 15
    head=bytearray(64);head[:8]=b"HBRDS001";struct.pack_into("<Q",head,8,kind)
    struct.pack_into("<Q",head,24,klass);struct.pack_into("<Q",head,40,len(payload) if kind else 0);struct.pack_into("<Q",head,56,len(payload))
    expected=bytes(head)+payload+b"\xa5"*(capacity-64-len(payload))
    code,out,work=m.invoke_raw(query,output_capacity=capacity,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0x6b)
    journal.write(struct.pack("<5Q",len(query),len(out),len(work),code,len(expected)));journal.write(query);journal.write(out);journal.write(work);journal.write(expected)
    logical+=40+len(query)+len(out)+len(work)+len(expected);count+=1
    self.assertEqual(code,64+len(payload),(value,code,payload))
    self.assertEqual(out,expected,value);self.assertEqual(work,b"\x6b"*4096,value)
    statuses[str(kind)+":"+str(klass)]=statuses.get(str(kind)+":"+str(klass),0)+1
   for value in ("","A","YQ==","YQ===","AAAA=","AA==!","é"):
    raw=b"HRCODEC1"+struct.pack("<2Q",4,0)+value.encode()
    code,out,work=m.invoke_raw(raw,output_capacity=512,workspace_capacity=0,output_fill=0xa5,workspace_fill=0)
    extent=code
    for cap in (extent-1,extent,extent+1):
     ret,small,workspace=m.invoke_raw(raw,output_capacity=cap,workspace_capacity=0,output_fill=0xa5,workspace_fill=0)
     self.assertEqual(workspace,b"")
     if cap<extent:self.assertEqual(ret,0xfffffffe);self.assertEqual(small,b"\xa5"*cap)
     else:self.assertEqual(ret,extent);self.assertEqual(small[:extent],out[:extent]);self.assertEqual(small[extent:],b"\xa5"*(cap-extent))
  DECODER=dict(actual_pairs=count,statuses=statuses,logical_buffer_bytes=logical,complete_capture=pin(path),capacity_controls=21)
 def test_08_real_cooperative_lock_blocks_then_releases(self):
  rows=[]
  for implementation in ("native","original"):
   root=OUT/("lock-contention-"+implementation);root.mkdir();target=root/"target"
   lock=root/(".hepta-lock-"+hashlib.sha256(b"target").hexdigest()[:24]);fd=os.open(lock,os.O_RDWR|os.O_CREAT,0o600)
   fcntl.flock(fd,fcntl.LOCK_EX)
   q=dict(op="write",root=str(root),path=str(target),expected_version="absent",data_base64="eA==")
   raw=wire(str(root),str(target),"absent","eA==") if implementation=="native" else json.dumps(q).encode()
   argv=[A.build/"production/public-binary-write.elf"] if implementation=="native" else [sys.executable,"-I","-B","-c",SOURCE]
   p=subprocess.Popen([str(x) for x in argv],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   try:
    p.stdin.write(raw);p.stdin.close();p.stdin=None
    deadline=time.monotonic()+3;observed=""
    while time.monotonic()<deadline:
     self.assertIsNone(p.poll());observed=Path(f"/proc/{p.pid}/syscall").read_text()
     if observed.split()[0]=="73":break
     time.sleep(0.005)
    self.assertEqual(observed.split()[0],"73")
    self.assertFalse(target.exists())
    fcntl.flock(fd,fcntl.LOCK_UN)
    stdout,stderr=p.communicate(timeout=30)
    self.assertEqual((p.returncode,stderr),(0,b""));self.assertEqual(target.read_bytes(),b"x")
    value=json.loads(stdout);self.assertEqual(value["version"],REFERENCE["version"](target.stat()))
    rows.append(dict(implementation=implementation,pid=p.pid,actual_blocked_syscall=observed,returncode=p.returncode,stdout_hex=stdout.hex(),stderr_hex=stderr.hex()))
   finally:
    os.close(fd)
    if p.poll() is None:p.kill()
    p.wait(timeout=3)
    if p.stdin:p.stdin.close()
    p.stdout.close();p.stderr.close()
  (OUT/"lock-contention.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
 def test_09_parent_death_kills_and_reaps_the_fixed_helper(self):
  import ctypes,signal
  libc=ctypes.CDLL(None,use_errno=True)
  previous=ctypes.c_int()
  self.assertEqual(libc.prctl(37,ctypes.byref(previous),0,0,0),0)
  self.assertEqual(libc.prctl(36,1,0,0,0),0)
  helper=None;middle=None;collected=False
  data_read,data_write=os.pipe()
  start=time.monotonic()
  launcher="import subprocess,sys,time\np=subprocess.Popen([sys.argv[1]],stdin=int(sys.argv[2]),stdout=subprocess.PIPE,stderr=subprocess.PIPE)\nprint(p.pid,flush=True)\ntime.sleep(30)\n"
  try:
   middle=subprocess.Popen([sys.executable,"-I","-B","-c",launcher,str(A.build/"production/public-binary-write.elf"),str(data_read)],
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(data_read,))
   helper=int(middle.stdout.readline().strip())
   os.close(data_read);data_read=None
   deadline=time.monotonic()+3
   observed=""
   while time.monotonic()<deadline:
    observed=Path(f"/proc/{helper}/syscall").read_text()
    if observed.split()[0]=="0":break
    time.sleep(0.005)
   self.assertEqual(observed.split()[0],"0","helper did not reach actual stdin read")
   os.kill(middle.pid,signal.SIGKILL)
   self.assertEqual(middle.wait(timeout=3),-signal.SIGKILL)
   deadline=time.monotonic()+3
   while time.monotonic()<deadline:
    pid,status=os.waitpid(helper,os.WNOHANG)
    if pid:
     collected=True;break
    time.sleep(0.005)
   self.assertTrue(collected,"owned helper was not reaped after parent death")
   row=dict(schema="hepta.runtime.public-binary-write-parent-death.v1",middle_pid=middle.pid,helper_pid=helper,
    actual_blocked_syscall=observed,wait_status=status,signal=os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
    seconds=time.monotonic()-start,helper_reaped=True,original_parent_death=True,stdin_writer_still_held_by_controller=True)
   (OUT/"parent-death.json").write_text(json.dumps(row,sort_keys=True,indent=2)+"\n")
   self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)
  finally:
   if data_read is not None:os.close(data_read)
   os.close(data_write)
   if middle is not None:
    if middle.poll() is None:middle.kill()
    middle.wait(timeout=3)
    middle.stdout.close();middle.stderr.close()
   if helper is not None and not collected:
    try:os.kill(helper,signal.SIGKILL)
    except ProcessLookupError:pass
    try:os.waitpid(helper,0)
    except ChildProcessError:pass
   self.assertEqual(libc.prctl(36,previous.value,0,0,0),0)
def main():
 global A,ROOT,OUT,BUILD,SOURCE,REFERENCE
 p=argparse.ArgumentParser()
 for n in ("source","build","output"):p.add_argument("--"+n,type=Path,required=True)
 A=p.parse_args();ROOT=A.source.resolve(strict=True);A.build=A.build.resolve(strict=True);OUT=A.output.absolute()
 assert not OUT.exists();OUT.mkdir(parents=True)
 assert sys.flags.isolated==1 and sys.flags.optimize==0
 BUILD=json.loads((A.build/"BUILD.json").read_bytes());assert BUILD["status"]=="PASS"
 sources=[ROOT/"src/mcp/runtime"/x for x in ("file_metadata.py","inode_patch.py","binary_file.py")]
 SOURCE="\n".join(p.read_text() for p in sources)
 version_node=next(n for n in ast.parse(SOURCE).body if isinstance(n,ast.FunctionDef) and n.name=="version")
 REFERENCE={"__name__":"hia_write_reference_stat_version"}
 exec(compile(ast.Module(body=[version_node],type_ignores=[]),"original_stat_version","exec"),REFERENCE)
 (OUT/"complete-original.py").write_text(SOURCE)
 paths=[Path(__file__).resolve(),Path(sys.executable).resolve(strict=True),A.build/"BUILD.json"]+sources
 for name,info in BUILD["members"].items():
  manifest=A.build/info["manifest"];meta=json.loads(manifest.read_bytes())
  paths.extend([manifest,manifest.parent/meta["image"],ROOT/info["source_path"]])
 for variant in BUILD["variants"]:paths.append(A.build/variant/"public-binary-write.elf")
 paths=list(dict.fromkeys(paths));before=[pin(p) for p in paths]
 start=time.monotonic()
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
 after=[pin(p) for p in paths]
 report=dict(schema="hepta.runtime.public-binary-write-actual-controls.v1",
  status="PASS" if result.wasSuccessful() and before==after else "FAIL",tests_run=result.testsRun,
  failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
  expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
  seconds=time.monotonic()-start,python_isolated=sys.flags.isolated,python_optimize=sys.flags.optimize,
  inputs=before,all_inputs_unchanged=before==after,actual_processes=ROWS,complete_application_pairs=PAIRS,journals=JOURNALS,decoder=DECODER,
  original_source_complete=True,original_exception_stderr_compared_exactly=True,
  stat_version_function_ast_sha256=hashlib.sha256(ast.dump(version_node,include_attributes=False).encode()).hexdigest(),
  complete_result_versions_verified_against_each_actual_final_stat=True,
  only_cross_process_result_normalization="independently measured final stat version maps to the same final-file role",
  reference_interpreter=dict(version=sys.version,version_info=list(sys.version_info),implementation=sys.implementation.name,executable=sys.executable),
  machine=dict(zip(("sysname","nodename","release","version","machine"),os.uname())),
  synthetic_business_syscall_replies=False,network_ssh_qualified=False,default_public_route_qualified=False,whole_runtime_replaced=False)
 (OUT/"result.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps({k:report[k] for k in ("status","tests_run","failures","errors","skipped","seconds","all_inputs_unchanged")},sort_keys=True))
 raise SystemExit(0 if report["status"]=="PASS" else 1)
if __name__=="__main__":main()
