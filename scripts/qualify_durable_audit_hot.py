# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Full hot collection against fixed original functions, using actual HIA callees."""
from pathlib import Path
import argparse,ctypes,errno,fcntl,hashlib,json,os,random,stat,struct,subprocess,time
from types import FunctionType
import qualify_durable_audit_record_io as io_qa
from hia_native_loader import NativeModule
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
WORD=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
LIBC=io_qa.LIBC
YIELD=0xffffffe0
class BorrowedOs:
 def __getattr__(self,name):return getattr(os,name)
 def open(self,fd,flags,*args,**kwargs):
  assert type(fd)is int and flags==os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC and not args and not kwargs
  return os.dup(fd)
# Preserve the qualified IO broker's exact function code. Only its initial
# mechanical directory acquisition uses dup on the caller's actual held lease.
IO_RUN=FunctionType(io_qa.Broker.run.__code__,{**io_qa.Broker.run.__globals__,"os":BorrowedOs()},io_qa.Broker.run.__name__,io_qa.Broker.run.__defaults__,io_qa.Broker.run.__closure__)
IO_RUN.__kwdefaults__=dict(io_qa.Broker.run.__kwdefaults__)
class HotBroker:
 def __init__(self,native,io,record):self.native=native;self.io=io_qa.Broker(io,record)
 def run(self,directory,*,preseek=False,mutate=None):
  frame=b"HRAHOT01"+struct.pack("<QQ",512,0)
  root=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds={0:root};trace=[];seq=0
  try:
   if preseek:
    chunk=ctypes.create_string_buffer(32768)
    while True:
     n=LIBC.syscall(217,root,ctypes.c_void_p(ctypes.addressof(chunk)),len(chunk))
     if n==0:break
     if n<0:raise OSError(ctypes.get_errno(),"preseek")
   with self.native.session(output_capacity=131136,workspace_capacity=532480)as s:
    while True:
     code,out,w=s.invoke_raw(frame)
     if code!=YIELD:
      assert code>=64 and code<=131136 and out[:8]==b"HRAHOTR1"and WORD(out,32)==code,(code,trace)
      count=WORD(out,24);assert code==64+count*256 and set(fds)=={0}
      records=[]
      for i in range(count):
       r=out[64+i*256:64+(i+1)*256];tool_len=WORD(r,192);assert 1<=tool_len<=64 and not any(r[128+tool_len:192])and WORD(r,240)==WORD(r,248)==0
       records.append(dict(request_id=r[:64].decode(),owner=r[64:128].decode(),tool_name=r[128:128+tool_len].decode(),state=("unknown","completed","failed")[WORD(r,200)],accepted_unix_ms=WORD(r,208)+(WORD(r,216)<<64),elapsed_ms=WORD(r,232)if WORD(r,224)else None))
      replay,out2,w2=s.invoke_raw(frame);assert replay==0xffffffff and out2==out and w2==w
      return dict(diagnostic=WORD(out,8),errno=WORD(out,16),records=records,raw=out[:code].hex(),trace=trace,owned_after=sorted(fds),terminal_replay_refused=True)
     magic,current,kind,slot,span,count,arg,capacity,ack,value,error,reserved=struct.unpack_from("<12Q",w,256)
     assert magic==int.from_bytes(b"HRAHAS01","little")and current==seq+1 and ack==value==error==reserved==0
     seq=current;assert len(trace)<100000,"qualification runaway only"
     row=dict(sequence=seq,kind=kind,slot=slot,span=span,count=count,arg=arg,capacity=capacity,action_hex=w[256:352].hex())
     if mutate:mutate(row,fds,s,w)
     error=value=0;payload=b""
     try:
      if kind==1:
       assert slot==4 and slot not in fds and span==640 and count==1 and w[span:span+count]==b"."and arg==0xb0000 and capacity==0
       fd=LIBC.openat(fds[0],b".",arg,0)
       if fd<0:raise OSError(ctypes.get_errno(),"openat")
       fds[slot]=fd
      elif kind==2:
       assert slot==5 and slot in fds and span==512 and count==88 and arg==capacity==0
       st=os.fstat(fds[slot]);numbers=[st.st_mode,st.st_uid,os.geteuid(),st.st_nlink,st.st_size,st.st_dev,st.st_ino,st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
       payload=struct.pack("<11Q",*(n&((1<<64)-1)for n in numbers))
      elif kind==6:
       assert slot in(4,5)and slot in fds and span==count==arg==capacity==0
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
       if value<0:raise OSError(ctypes.get_errno(),"getfl")
      elif kind==10:
       assert slot==5 and slot in fds and span==count==capacity==0 and arg==1
       if LIBC.fcntl(fds[slot],fcntl.F_SETFD,fcntl.FD_CLOEXEC)<0:raise OSError(ctypes.get_errno(),"setfd")
      elif kind==100:
       assert set(fds)=={0},"original complete member scan must close before first cleanup/record"
       assert slot==0 and span==524288 and 32<=count<=287 and arg==525312 and capacity==4096
       request=w[span:span+count];assert request[:8]==b"HRAIO001"and WORD(request,16)==len(request)-32 and WORD(request,24)==0
       child=IO_RUN(self.io,fds[0],WORD(request,8),request[32:])
       assert "code"not in child;payload=bytes.fromhex(child["raw"]);value=len(payload);span=arg
       row["child"]=child;row["child_request_hex"]=request.hex()
      else:raise ValueError("unknown private hot effect")
     except OSError as e:error=e.errno;value=0
     if payload:ctypes.memmove(ctypes.addressof(s._workspace)+span,payload,len(payload))
     row.update(errno=error,result=value,payload_hex=payload.hex());trace.append(row)
     ctypes.memmove(ctypes.addressof(s._workspace)+320,struct.pack("<QQQQ",seq,value,error,0),32)
  finally:
   for fd in fds.values():os.close(fd)
def scenarios():
 rows=[]
 for count in(0,1,2,17,64,128,512,513):
  for order in("ascending","descending"):
   rows.append(dict(label=f"records-{count}-{order}",count=count,order=order))
 rows.extend(dict(label=name,count=3,variant=name)for name in("full-u128-sort","same-time-id-sort","mixed-owners-and-states","malformed-json","wrong-identity","wide-record","symlink-record","hardlink-record","fifo-record","unexpected-extension","bad-json-name","invalid-utf8-member","orphan-stage","linked-stage","bad-stage","wide-stage","oversized-stage","wrong-linked-stage","cleanup-before-bad-record","fresh-scan-description"))
 for count,stages in((512,32),(512,33),(0,544),(0,545)):
  rows.append(dict(label=f"record-{count}-staging-{stages}",count=count,stages=stages))
 return rows
def materialize(path,case):
 path.mkdir(mode=0o700);n=case["count"];variant=case.get("variant")
 ids=list(range(1,n+1));created=list(reversed(ids))if case.get("order")=="descending"else ids
 for index in created:
  stamp=index
  if variant=="full-u128-sort":stamp=[2**128-1,2**64,2**64-1][index-1]
  if variant=="same-time-id-sort":stamp=17
  owner="c"*64 if variant=="mixed-owners-and-states"and index%2 else"b"*64
  value=io_qa.record_raw(request_id=f"{index:064x}",owner=owner,accepted_unix_ms=stamp,state=("unknown","completed","failed")[index%3],elapsed_ms=None if index%2 else index)
  p=path/(f"{index:064x}"+".json");p.write_bytes(value);p.chmod(0o600)
 first=path/(f"{1:064x}"+".json")
 stage="."+f"{1:064x}"+"-"+"c"*64+".tmp"
 if variant=="malformed-json":first.write_bytes(b"{")
 if variant=="wrong-identity":first.write_bytes(io_qa.record_raw(request_id="a"*64))
 if variant=="wide-record":first.chmod(0o644)
 if variant=="symlink-record":
  first.unlink();first.symlink_to(f"{2:064x}"+".json")
 if variant=="hardlink-record":os.link(first,path/"unmatched-link")
 if variant=="fifo-record":first.unlink();os.mkfifo(first,0o600)
 if variant=="unexpected-extension":first.rename(path/"unexpected.bin")
 if variant=="bad-json-name":first.rename(path/"bad.json")
 if variant=="invalid-utf8-member":os.close(os.open(os.fsencode(path)+b"/\xff",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600))
 if variant in("orphan-stage","wide-stage","oversized-stage","cleanup-before-bad-record"):
  p=path/stage;p.write_bytes(b"x"*2049 if variant=="oversized-stage"else b"actual orphan");p.chmod(0o644 if variant=="wide-stage"else 0o600)
  if variant=="cleanup-before-bad-record":first.write_bytes(b"{")
 if variant in("linked-stage","fresh-scan-description"):os.link(first,path/stage)
 if variant=="bad-stage":
  p=path/".unknown";p.write_bytes(b"keep");p.chmod(0o600)
 if variant=="wrong-linked-stage":os.link(path/(f"{2:064x}"+".json"),path/stage)
 for index in range(case.get("stages",0)):
  p=path/("."+f"{1000+index:064x}"+"-"+"d"*64+".tmp");p.write_bytes(b"orphan");p.chmod(0o600)
def main():
 p=argparse.ArgumentParser();p.add_argument("--manifest",type=Path,required=True);p.add_argument("--io-manifest",type=Path,required=True);p.add_argument("--record-manifest",type=Path,required=True);p.add_argument("--original",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 manifests=[a.manifest,a.io_manifest,a.record_manifest];bound=[a.original,Path(__file__),Path(io_qa.__file__),Path(__file__).parent/"hia_native_loader.py",*manifests]
 for m in manifests:
  v=json.loads(m.read_bytes());bound.extend([m.parent/v["source"],m.parent/v["image"]])
 before={str(p):SHA(p.read_bytes())for p in bound};rows=[];start=time.monotonic()
 with NativeModule(a.manifest,manifest_sha256=SHA(a.manifest.read_bytes()))as native,NativeModule(a.io_manifest,manifest_sha256=SHA(a.io_manifest.read_bytes()))as io,NativeModule(a.record_manifest,manifest_sha256=SHA(a.record_manifest.read_bytes()))as record:
  broker=HotBroker(native,io,record)
  for index,case in enumerate(scenarios()):
   d=a.output/f"{index:03d}-{case['label']}";d.mkdir();materialize(d/"original",case);materialize(d/"native",case)
   old_before=io_qa.snapshot(d/"original");new_before=io_qa.snapshot(d/"native");assert old_before==new_before
   request=dict(directory=str(d/"original"),preseek=case.get("variant")=="fresh-scan-description")
   (d/"case.json").write_text(json.dumps(case,sort_keys=True,indent=2)+"\n");(d/"original-input.json").write_text(json.dumps(request)+"\n")
   result=subprocess.run([str(a.original)],input=(json.dumps(request)+"\n").encode(),capture_output=True,timeout=30)
   (d/"original.stdout").write_bytes(result.stdout);(d/"original.stderr").write_bytes(result.stderr);assert result.returncode==0,(index,result.stderr.decode())
   old=json.loads(result.stdout);new=broker.run(d/"native",preseek=request["preseek"])
   (d/"native.json").write_text(json.dumps(new,sort_keys=True,indent=2)+"\n")
   old_after=io_qa.snapshot(d/"original");new_after=io_qa.snapshot(d/"native")
   (d/"original-after.json").write_text(json.dumps(old_after,sort_keys=True,indent=2)+"\n");(d/"native-after.json").write_text(json.dumps(new_after,sort_keys=True,indent=2)+"\n")
   old_records=json.loads(old["record_json"])if old["record_json"]is not None else []
   passed=(old["diagnostic"],old["errno"],old_records)==(new["diagnostic"],new["errno"],new["records"])and old_after==new_after
   operations=[WORD(bytes.fromhex(r["child_request_hex"]),8)for r in new["trace"]if r["kind"]==100]
   assert operations==sorted(operations,reverse=True),"staging cleanup must precede all reads"
   row=dict(index=index,label=case["label"],passed=passed,records=len(new["records"]),original_diagnostic=old["diagnostic"],native_diagnostic=new["diagnostic"],effects=len(new["trace"]),child_calls=len(operations));rows.append(row)
   (a.output/"progress.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
   assert passed,(row,old,new["diagnostic"])
 after={str(p):SHA(p.read_bytes())for p in bound};assert before==after
 report=dict(state="PASS",cases=len(rows),rows=rows,elapsed_seconds=time.monotonic()-start,source_before=before,source_after=after,source_unchanged=True,public_routing_qualified=False)
 (a.output/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n");print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
