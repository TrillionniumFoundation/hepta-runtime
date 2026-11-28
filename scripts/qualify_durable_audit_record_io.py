# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual-filesystem qualification broker; not an installed policy fallback."""
from pathlib import Path
import argparse,ctypes,errno,fcntl,hashlib,json,os,stat,struct,subprocess,time
from hia_native_loader import NativeModule
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
WORD=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.openat.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint];LIBC.openat.restype=ctypes.c_int
LIBC.read.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t];LIBC.read.restype=ctypes.c_ssize_t
LIBC.close.argtypes=[ctypes.c_int];LIBC.close.restype=ctypes.c_int
LIBC.unlinkat.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int];LIBC.unlinkat.restype=ctypes.c_int
LIBC.fsync.argtypes=[ctypes.c_int];LIBC.fsync.restype=ctypes.c_int
LIBC.fcntl.restype=ctypes.c_int
LIBC.syscall.restype=ctypes.c_long
YIELD=0xffffffe0
class Broker:
 def __init__(self,native,record):
  self.native=native;self.record=record
 def run(self,directory,operation,filename,*,preseek=False,mutate=None):
  frame=b"HRAIO001"+struct.pack("<QQQ",operation,len(filename),0)+filename
  root=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  fds={0:root};trace=[];seq=0
  try:
   if preseek:
    raw=ctypes.create_string_buffer(32768)
    while True:
     n=LIBC.syscall(217,root,ctypes.c_void_p(ctypes.addressof(raw)),len(raw))
     if n==0:break
     if n<0:raise OSError(ctypes.get_errno(),"preseek")
   with self.native.session(output_capacity=4096,workspace_capacity=65536)as s:
    while True:
     code,out,w=s.invoke_raw(frame)
     if code!=YIELD:
      if code>=0xffff0000:return dict(code=code,raw=out.hex(),trace=trace,owned_after=sorted(fds))
      assert 192<=code<=512 and out[:8]==b"HRADIO01"and WORD(out,32)==code
      result=dict(diagnostic=WORD(out,8),errno=WORD(out,16),record=None,raw=out[:code].hex())
      count=WORD(out,24)
      if count:
       r=out[192:];assert r[:8]==b"HRAJR001"and WORD(r,8)==0 and WORD(r,56)==count
       fields=[r[WORD(r,64+i*16):WORD(r,64+i*16)+WORD(r,72+i*16)].decode()for i in range(3)]
       result["record"]=dict(request_id=fields[0],owner=fields[1],tool_name=fields[2],state=("unknown","completed","failed")[WORD(r,16)],accepted_unix_ms=WORD(r,24)+(WORD(r,32)<<64),elapsed_ms=WORD(r,48)if WORD(r,40)else None)
      assert set(fds)=={0},("native terminal leaked owned descriptor",fds,trace)
      return dict(result,trace=trace,owned_after=sorted(fds))
     action=struct.unpack_from("<12Q",w,256);magic,current,kind,slot,span,count,arg,capacity,ack,value,error,reserved=action
     assert magic==int.from_bytes(b"HRADAS01","little")and current==seq+1 and ack==value==error==reserved==0
     seq=current;assert len(trace)<100000,"qualification harness runaway, not a product limit"
     row=dict(sequence=seq,kind=kind,slot=slot,span=span,count=count,arg=arg,capacity=capacity,action_hex=w[256:352].hex())
     if mutate:mutate(row,fds,s,w)
     value=0;error=0;payload=b""
     try:
      if kind==1:
       assert slot in range(1,6)and slot not in fds and capacity==0
       assert 0<count<=255 and span+count<=65536 and arg in(0xa0800,0xb0000)
       name=w[span:span+count];assert b"/"not in name and b"\0"not in name
       row["name_hex"]=name.hex();fd=LIBC.openat(fds[0],name,arg,0)
       if fd<0:raise OSError(ctypes.get_errno(),"openat")
       fds[slot]=fd
      elif kind==2:
       assert slot in fds and span==512 and count==88 and arg==capacity==0
       st=os.fstat(fds[slot])
       numbers=[st.st_mode,st.st_uid,os.geteuid(),st.st_nlink,st.st_size,st.st_dev,st.st_ino,st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
       payload=struct.pack("<11Q",*(n&((1<<64)-1)for n in numbers))
      elif kind==3:
       assert slot==1 and slot in fds and 40000<=span<=42049 and 0<count<=2049 and span+count<=42049 and arg==capacity==0
       value=LIBC.read(fds[slot],ctypes.addressof(s._workspace)+span,count)
       if value<0:raise OSError(ctypes.get_errno(),"read")
       payload=ctypes.string_at(ctypes.addressof(s._workspace)+span,value)
      elif kind==4:
       assert slot==0 and 0<count<=255 and span+count<=65536 and arg==capacity==0
       name=w[span:span+count];assert b"/"not in name and b"\0"not in name
       row["name_hex"]=name.hex()
       if LIBC.unlinkat(fds[0],name,0)<0:raise OSError(ctypes.get_errno(),"unlinkat")
      elif kind==5:
       assert slot==0 and span==count==arg==capacity==0
       if LIBC.fsync(fds[0])<0:raise OSError(ctypes.get_errno(),"fsync")
      elif kind==6:
       assert slot in range(1,6)and slot in fds and span==count==arg==capacity==0
       fd=fds.pop(slot)
       if LIBC.close(fd)<0:raise OSError(ctypes.get_errno(),"close")
      elif kind==7:
       assert slot==5 and slot not in fds and arg==4 and arg in fds and span==count==capacity==0
       fd=LIBC.fcntl(fds[arg],fcntl.F_DUPFD_CLOEXEC,0)
       if fd<0:raise OSError(ctypes.get_errno(),"dup")
       fds[slot]=fd
      elif kind==8:
       assert slot==5 and slot in fds and span==4096 and count==32768 and arg==capacity==0
       value=LIBC.syscall(217,fds[slot],ctypes.c_void_p(ctypes.addressof(s._workspace)+span),count)
       if value<0:raise OSError(ctypes.get_errno(),"getdents64")
       payload=ctypes.string_at(ctypes.addressof(s._workspace)+span,value)
      elif kind==9:
       assert slot==5 and slot in fds and span==count==arg==capacity==0
       value=LIBC.fcntl(fds[slot],fcntl.F_GETFL)
       if value<0:raise OSError(ctypes.get_errno(),"fcntl getfl")
      elif kind==10:
       assert slot==5 and slot in fds and span==count==capacity==0 and arg==1
       if LIBC.fcntl(fds[slot],fcntl.F_SETFD,fcntl.FD_CLOEXEC)<0:raise OSError(ctypes.get_errno(),"fcntl setfd")
      elif kind==100:
       assert slot==0 and span==44000 and 101<=count<=2149 and arg==48000 and capacity==4096
       payload=self.record.invoke(w[span:span+count],output_capacity=4096,workspace_capacity=16384);value=len(payload);span=arg
      else:raise ValueError("unknown private effect")
     except OSError as e:
      value=0;error=e.errno
     if payload:ctypes.memmove(ctypes.addressof(s._workspace)+span,payload,len(payload))
     row.update(result=value,errno=error,payload_hex=payload.hex());trace.append(row)
     ctypes.memmove(ctypes.addressof(s._workspace)+320,struct.pack("<QQQQ",seq,value,error,0),32)
  finally:
   for fd in fds.values():os.close(fd)

def record_raw(**changes):
 value=dict(request_id="a"*64,owner="b"*64,tool_name="host_list",state="unknown",accepted_unix_ms=17,elapsed_ms=None);value.update(changes)
 return json.dumps(value,separators=(",",":")).encode()
def scenarios():
 cases=[]
 def add(label,**kw):cases.append(dict(label=label,operation=1,filename="a"*64+".json",files=[dict(name="a"*64+".json",kind="file",raw=record_raw().hex(),mode=0o600)],**kw))
 for state in("unknown","completed","failed"):
  for timestamp in(0,17,2**64-1,2**64,2**128-1):
   add(state+"-"+str(timestamp),replace_raw=record_raw(state=state,accepted_unix_ms=timestamp,elapsed_ms=None if timestamp%2 else 7).hex())
 for label,raw in[("json-empty",b""),("json-truncated",b"{"),("json-unknown",record_raw(secret="denied")),("json-duplicate",record_raw()[:-1]+b',"owner":"' +b"b"*64+b'"}'),("wrong-id",record_raw(request_id="c"*64)),("bad-owner",record_raw(owner="B"*64)),("bad-tool",record_raw(tool_name="host\nlist")),("at-2048",record_raw()+b" "*(2048-len(record_raw()))),("at-2049",record_raw()+b" "*(2049-len(record_raw()))),("huge",b"x"*8192)]:
  add(label,replace_raw=raw.hex())
 for mode in(0o400,0o644,0o660,0o1600,0o4600):add("mode-"+oct(mode),replace_mode=mode)
 add("missing",remove_record=True);add("directory",replace_kind="dir");add("fifo",replace_kind="fifo")
 add("symlink",replace_kind="symlink")
 for style in("orphan","linked","wide","oversized","symlink","wrong-binding","missing-published","three-links"):
  add("deterministic-"+style,staging_style=style,staging_nonce="a"*64)
 for style in("linked","bad-nonce","external-link","three-links","invalid-utf8-first","invalid-utf8-last"):
  add("random-"+style,staging_style=style,staging_nonce="c"*64)
 add("fresh-scan-description",staging_style="linked",staging_nonce="c"*64,preseek=True)
 for name in("",".tmp","bad","."+"a"*64+"-"+ "c"*64+".bad","."+"A"*64+"-"+"c"*64+".tmp","."+"a"*64+"-bad.tmp","."+"a"*64+"-"+"c"*64+".tmp"):
  cases.append(dict(label="cleanup-name-"+str(len(cases)),operation=2,filename=name,files=[]))
 for style in("orphan","linked","wide","oversized","wrong-binding","missing-published","three-links"):
  add("cleanup-"+style,staging_style=style,staging_nonce="c"*64,cleanup=True)
 return cases

def materialize(path,case):
 path.mkdir(mode=0o700);outside=path/"outside";outside.mkdir(mode=0o700)
 target=path/("a"*64+".json")
 def file(p,raw=b"orphan",mode=0o600):
  p.write_bytes(raw);p.chmod(mode)
 raw=bytes.fromhex(case.get("replace_raw",record_raw().hex()));mode=case.get("replace_mode",0o600);kind=case.get("replace_kind","file")
 if case.get("files"):
  if kind=="file":file(target,raw,mode)
  elif kind=="dir":target.mkdir(mode=0o700)
  elif kind=="fifo":os.mkfifo(target,0o600)
  elif kind=="symlink":file(outside/"record",raw);target.symlink_to("outside/record")
 if case.get("remove_record"):target.unlink()
 style=case.get("staging_style")
 if style:
  nonce=case["staging_nonce"];name="."+"a"*64+"-"+nonce+".tmp"
  if style=="bad-nonce":name="."+"a"*64+"-bad.tmp"
  staging=path/name
  if style=="invalid-utf8-first":os.close(os.open(os.fsencode(path)+b"/\xff",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600))
  if style in("linked","bad-nonce","three-links","invalid-utf8-first","invalid-utf8-last"):
   os.link(target,staging)
   if style=="three-links":os.link(target,outside/"third")
  elif style=="external-link":os.link(target,outside/"external")
  elif style=="symlink":staging.symlink_to(target.name)
  elif style=="wrong-binding":
   file(staging);os.link(staging,outside/"different")
  elif style=="missing-published":
   target.unlink();file(staging);os.link(staging,outside/"different")
  else:file(staging,b"X"*2049 if style=="oversized"else b"invalid-json-but-private",0o644 if style=="wide"else 0o600)
  if style=="invalid-utf8-last":os.close(os.open(os.fsencode(path)+b"/\xff",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600))
  if case.get("cleanup"):return 2,name
 return case["operation"],case["filename"]

def snapshot(path):
 result={}
 for base,dirs,files in os.walk(os.fsencode(path),followlinks=False):
  for name in sorted(dirs+files):
   p=base+b"/"+name;st=os.lstat(p);relative=os.path.relpath(p,os.fsencode(path)).hex()
   row=dict(mode=st.st_mode,nlink=st.st_nlink,size=st.st_size,uid=st.st_uid)
   if stat.S_ISREG(st.st_mode):row["raw_hex"]=Path(os.fsdecode(p)).read_bytes().hex()
   elif stat.S_ISLNK(st.st_mode):row["target_hex"]=os.readlink(p).hex()
   elif stat.S_ISDIR(st.st_mode):row.pop("size")
   result[relative]=row
 return result

def main():
 p=argparse.ArgumentParser();p.add_argument("--manifest",type=Path,required=True);p.add_argument("--record-manifest",type=Path,required=True);p.add_argument("--original",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();q=a.output;q.mkdir(parents=True,exist_ok=False)
 inputs=[a.manifest,a.record_manifest,a.original,Path(__file__)];before={str(p):SHA(p.read_bytes())for p in inputs}
 rows=[];start=time.monotonic()
 with NativeModule(a.manifest,manifest_sha256=SHA(a.manifest.read_bytes()))as native,NativeModule(a.record_manifest,manifest_sha256=SHA(a.record_manifest.read_bytes()))as record:
  broker=Broker(native,record)
  for index,case in enumerate(scenarios()):
   d=q/f"{index:04d}-{case['label']}";d.mkdir()
   op,name=materialize(d/"original",case);op2,name2=materialize(d/"native",case);assert(op,name)==(op2,name2)
   request=dict(directory=str(d/"original"),operation=op,filename=name,preseek=case.get("preseek",False))
   (d/"case.json").write_text(json.dumps(case,sort_keys=True,indent=2)+"\n");(d/"original-input.json").write_text(json.dumps(request)+"\n")
   old_before=snapshot(d/"original");new_before=snapshot(d/"native");assert old_before==new_before
   r=subprocess.run([str(a.original)],input=(json.dumps(request)+"\n").encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
   (d/"original.stdout").write_bytes(r.stdout);(d/"original.stderr").write_bytes(r.stderr);assert r.returncode==0,(index,r.stderr.decode())
   old=json.loads(r.stdout);old_record=json.loads(old["record_json"])if old["record_json"]is not None else None
   new=broker.run(d/"native",op,name.encode(),preseek=case.get("preseek",False))
   (d/"native.json").write_text(json.dumps(new,sort_keys=True,indent=2)+"\n")
   old_after=snapshot(d/"original");new_after=snapshot(d/"native")
   (d/"original-after.json").write_text(json.dumps(old_after,sort_keys=True,indent=2)+"\n");(d/"native-after.json").write_text(json.dumps(new_after,sort_keys=True,indent=2)+"\n")
   match="code"not in new and(new["diagnostic"],new["errno"],new["record"])==(old["diagnostic"],old["errno"],old_record)and old_after==new_after
   row=dict(index=index,label=case["label"],passed=match,original_diagnostic=old["diagnostic"],native_diagnostic=new.get("diagnostic"),effects=len(new["trace"]));rows.append(row)
   (q/"progress.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
   assert match,("original/native audit I/O differs",row,old,new)
 after={str(p):SHA(p.read_bytes())for p in inputs};assert before==after
 report=dict(state="PASS",cases=len(rows),rows=rows,elapsed_seconds=time.monotonic()-start,source_before=before,source_after=after,source_unchanged=True,public_routing_qualified=False)
 (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n");print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
