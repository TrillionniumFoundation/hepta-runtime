# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Original root/hot functions versus actual HIA descriptor policy (QA only)."""
from pathlib import Path
import argparse,ctypes,errno,hashlib,json,os,stat,struct,subprocess,time
from hia_native_loader import NativeModule
import qualify_durable_audit_record_io as record_qa
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
WORD=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.open.argtypes=[ctypes.c_char_p,ctypes.c_int,ctypes.c_uint];LIBC.open.restype=ctypes.c_int
LIBC.openat.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint];LIBC.openat.restype=ctypes.c_int
LIBC.mkdirat.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];LIBC.mkdirat.restype=ctypes.c_int
LIBC.close.argtypes=[ctypes.c_int];LIBC.close.restype=ctypes.c_int
LIBC.fsync.argtypes=[ctypes.c_int];LIBC.fsync.restype=ctypes.c_int
YIELD=0xffffffe0
class RootBroker:
 def __init__(self,native):self.native=native
 def run(self,root_bytes,operation,*,mutate=None):
  frame=b"HRAROOT1"+struct.pack("<QQQ",operation,len(root_bytes),0)+root_bytes
  fds={};trace=[];seq=0;capacity=max(4096,len(frame)+1024)
  try:
   with self.native.session(output_capacity=160,workspace_capacity=capacity)as s:
    while True:
     code,out,w=s.invoke_raw(frame)
     if code!=YIELD:
      assert code==160 and out[:8]==b"HRAROOT1"and WORD(out,32)==160,(code,trace)
      exported=WORD(out,24);assert set(fds)==({exported}if exported else set())
      metadata=list(struct.unpack_from("<11Q",out,64))if exported else None
      if exported:
       st=os.fstat(fds[exported]);actual=[st.st_mode,st.st_uid,os.geteuid(),st.st_nlink,st.st_size,st.st_dev,st.st_ino,st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
       assert metadata==actual
      replay,out2,w2=s.invoke_raw(frame);assert replay==0xffffffff and out2==out and w2==w
      return dict(diagnostic=WORD(out,8),errno=WORD(out,16),present=bool(exported),metadata=metadata,raw=out.hex(),trace=trace,owned_export=[exported]if exported else [],terminal_replay_refused=True)
     magic,current,kind,slot,span,count,arg,parent,ack,value,error,reserved=struct.unpack_from("<12Q",w,256)
     assert magic==int.from_bytes(b"HRARDS01","little")and current==seq+1 and ack==value==error==reserved==0
     seq=current;assert len(trace)<100000,"qualification runaway only"
     row=dict(sequence=seq,kind=kind,slot=slot,span=span,count=count,arg=arg,parent=parent,action_hex=w[256:352].hex())
     if mutate:mutate(row,fds,s,w)
     error=0;payload=b""
     try:
      if kind==11:
       assert not fds and slot==1 and span==768 and count==1 and w[span:span+count]==b"/"and arg==0x2b0000 and parent==0
       fd=LIBC.open(b"/",arg,0)
       if fd<0:raise OSError(ctypes.get_errno(),"open root")
       fds[slot]=fd
      elif kind==1:
       assert slot in(1,2,3)and slot not in fds and parent in fds and 0<count and span+count<=capacity and arg in(0x2b0000,0xb0000)
       name=w[span:span+count];assert b"\0"not in name and b"/"not in name;row["name_hex"]=name.hex()
       fd=LIBC.openat(fds[parent],name,arg,0)
       if fd<0:raise OSError(ctypes.get_errno(),"openat")
       fds[slot]=fd
      elif kind==2:
       assert slot in fds and span==512 and count==88 and arg==parent==0
       st=os.fstat(fds[slot]);values=[st.st_mode,st.st_uid,os.geteuid(),st.st_nlink,st.st_size,st.st_dev,st.st_ino,st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
       payload=struct.pack("<11Q",*(v&((1<<64)-1)for v in values))
      elif kind==12:
       assert slot in fds and span==800 and count==13 and arg==0o700 and parent==0 and w[span:span+count]==b"request-audit"
       if LIBC.mkdirat(fds[slot],b"request-audit",arg)<0:raise OSError(ctypes.get_errno(),"mkdirat")
      elif kind==5:
       assert slot in fds and span==count==arg==parent==0
       if LIBC.fsync(fds[slot])<0:raise OSError(ctypes.get_errno(),"fsync")
      elif kind==6:
       assert slot in fds and span==count==arg==parent==0
       fd=fds.pop(slot)
       if LIBC.close(fd)<0:raise OSError(ctypes.get_errno(),"close")
      else:raise ValueError("unknown private root effect")
     except OSError as e:error=e.errno
     if payload:ctypes.memmove(ctypes.addressof(s._workspace)+span,payload,len(payload))
     row.update(errno=error,payload_hex=payload.hex());trace.append(row)
     ctypes.memmove(ctypes.addressof(s._workspace)+320,struct.pack("<QQQQ",seq,0,error,0),32)
  finally:
   for fd in fds.values():os.close(fd)
def materialize(base,case):
 base.mkdir(mode=0o700);ancestor=base/"ancestor";ancestor.mkdir(mode=0o700);root=ancestor/"root";root.mkdir(mode=0o700)
 variant=case["variant"];operation=case["operation"]
 if variant.startswith("root-mode-"):root.chmod(int(variant.removeprefix("root-mode-"),8))
 if variant.startswith("ancestor-mode-"):ancestor.chmod(int(variant.removeprefix("ancestor-mode-"),8))
 if variant=="root-file":root.rmdir();root.write_bytes(b"actual file");root.chmod(0o600)
 if variant=="root-fifo":root.rmdir();os.mkfifo(root,0o600)
 if variant=="root-symlink":root.rename(ancestor/"actual");root.symlink_to("actual")
 if variant=="ancestor-symlink":
  ancestor.rename(base/"actual");ancestor.symlink_to("actual")
 if variant=="root-missing":root.rmdir()
 if variant.startswith("hot-"):
  hot=root/"request-audit"
  if variant=="hot-file":hot.write_bytes(b"retained");hot.chmod(0o600)
  elif variant=="hot-fifo":os.mkfifo(hot,0o600)
  elif variant=="hot-symlink":
   (root/"actual").mkdir(mode=0o700);hot.symlink_to("actual")
  else:hot.mkdir(mode=0o700);hot.chmod(int(variant.removeprefix("hot-"),8))
 raw=os.fsencode(root)
 if variant=="dot":raw+=b"/."
 if variant=="dotdot":raw+=b"/.."
 if variant=="repeated-slashes":raw=raw.replace(b"/",b"//")
 if variant=="trailing-slashes":raw+=b"///"
 if variant=="relative":raw=b"relative/nonexistent"
 if variant=="empty":raw=b""
 if variant=="slash":raw=b"/"
 if variant=="non-utf8":raw+=b"/\xff"
 if variant=="nul":raw+=b"/ab\0cd"
 if variant=="long-component":raw+=b"/"+b"x"*256
 if variant=="deep":
  for n in range(30):root=root/str(n);root.mkdir(mode=0o700)
  raw=os.fsencode(root)
 return raw
def snapshot(base):
 # Restore only ancestor search for qualified inspection, after its result has
 # been recorded. The actual input mode is preserved in case.json and trace.
 ancestor=base/"ancestor"
 old=os.lstat(ancestor).st_mode
 if stat.S_ISDIR(old):
  ancestor.chmod(0o700)
  try:result=record_qa.snapshot(base)
  finally:ancestor.chmod(stat.S_IMODE(old))
  row=result[os.fsencode("ancestor").hex()];row["mode"]=old
  return result
 return record_qa.snapshot(base)
def cases():
 variants=["private","root-mode-755","root-mode-500","root-mode-1700","root-mode-2700","root-mode-4700","root-mode-777","ancestor-mode-600","ancestor-mode-100","ancestor-mode-111","root-file","root-fifo","root-symlink","ancestor-symlink","root-missing","dot","dotdot","repeated-slashes","trailing-slashes","relative","empty","slash","non-utf8","nul","long-component","deep"]
 rows=[dict(variant=v,operation=o)for o in(1,2,3)for v in variants]
 rows.extend(dict(variant=v,operation=o)for o in(2,3)for v in("hot-700","hot-755","hot-500","hot-1700","hot-file","hot-fifo","hot-symlink"))
 return rows
def main():
 p=argparse.ArgumentParser();p.add_argument("--manifest",type=Path,required=True);p.add_argument("--original",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 metadata=json.loads(a.manifest.read_bytes());inputs=[a.manifest,a.manifest.parent/metadata["image"],a.manifest.parent/metadata["source"],a.original,Path(__file__),Path(record_qa.__file__),Path(__file__).parent/"hia_native_loader.py"]
 before={str(p):SHA(p.read_bytes())for p in inputs};rows=[];start=time.monotonic()
 with NativeModule(a.manifest,manifest_sha256=SHA(a.manifest.read_bytes()))as native:
  broker=RootBroker(native)
  for index,case in enumerate(cases()):
   d=a.output/f"{index:03d}-{case['operation']}-{case['variant']}";d.mkdir()
   old_root=materialize(d/"original",case);new_root=materialize(d/"native",case);op=case["operation"]
   request=dict(operation=op,root_hex=old_root.hex());(d/"case.json").write_text(json.dumps(case,sort_keys=True,indent=2)+"\n");(d/"original-input.json").write_text(json.dumps(request)+"\n")
   old_before=snapshot(d/"original");new_before=snapshot(d/"native");assert old_before==new_before
   r=subprocess.run([str(a.original)],input=(json.dumps(request)+"\n").encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
   (d/"original.stdout").write_bytes(r.stdout);(d/"original.stderr").write_bytes(r.stderr);assert r.returncode==0,(index,r.stderr.decode())
   old=json.loads(r.stdout);new=broker.run(new_root,op)
   (d/"native.json").write_text(json.dumps(new,sort_keys=True,indent=2)+"\n")
   old_after=snapshot(d/"original");new_after=snapshot(d/"native")
   (d/"original-after.json").write_text(json.dumps(old_after,sort_keys=True,indent=2)+"\n");(d/"native-after.json").write_text(json.dumps(new_after,sort_keys=True,indent=2)+"\n")
   match=(old["diagnostic"],old["errno"],old["present"])==(new["diagnostic"],new["errno"],new["present"])and old_after==new_after
   if old["present"]:match=match and old["metadata"][:4]==new["metadata"][:4]
   row=dict(index=index,case=case,passed=match,original_diagnostic=old["diagnostic"],native_diagnostic=new["diagnostic"],effects=len(new["trace"]));rows.append(row)
   (a.output/"progress.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n");assert match,(row,old,new)
 after={str(p):SHA(p.read_bytes())for p in inputs};assert before==after
 report=dict(state="PASS",cases=len(rows),rows=rows,elapsed_seconds=time.monotonic()-start,source_before=before,source_after=after,source_unchanged=True,public_routing_qualified=False)
 (a.output/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n");print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
