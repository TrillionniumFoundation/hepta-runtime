#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual original-Python/native file-info comparisons and private wire controls."""
from __future__ import annotations
import argparse, hashlib, json, os, socket, stat, struct, subprocess, sys, time, unittest
from pathlib import Path
sys.dont_write_bytecode=True
A=None
ROOT=None
OUT=None
BUILD=None
SOURCE=None
ROWS=[]
JOURNALS=[]
def pin(path):
 p=Path(path);b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def u64(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def wire(root,path):
 r=root.encode();p=path.encode()
 return b"HFRDQ001"+struct.pack("<11Q",1,0,1,len(r),len(p),0,0,0,0,0,len(r)+len(p))+r+p
def run(name,argv,data,observe=False):
 folder=OUT/"runs";folder.mkdir(exist_ok=True)
 prefix=folder/name
 journal=None
 if observe:
  journal=prefix.with_suffix(".journal")
  fd=os.open(journal,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  if fd!=3:
   os.close(fd);raise AssertionError(f"controlled observer requires free FD3, obtained {fd}")
 start=time.monotonic()
 try:
  p=subprocess.run([str(x) for x in argv],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
   pass_fds=(3,) if observe else ())
 finally:
  if observe:os.close(3)
 prefix.with_suffix(".input").write_bytes(data)
 prefix.with_suffix(".stdout").write_bytes(p.stdout);prefix.with_suffix(".stderr").write_bytes(p.stderr)
 row=dict(name=name,argv=[str(x) for x in argv],returncode=p.returncode,seconds=time.monotonic()-start,timeout_seconds=30,
  input=pin(prefix.with_suffix(".input")),stdout=pin(prefix.with_suffix(".stdout")),stderr=pin(prefix.with_suffix(".stderr")))
 if journal:row["journal"]=pin(journal)
 ROWS.append(row)
 return p,journal
def compare(case,root,path,variant="production",original_source=None):
 exe=A.build/variant/"public-file-info.elf"
 q=dict(op="info",root=root,path=path)
 n,journal=run(case+"-native",[exe],wire(root,path),variant!="production")
 code=SOURCE if original_source is None else original_source
 source=OUT/"references"/(case+".py");source.parent.mkdir(exist_ok=True);source.write_text(code)
 p,_=run(case+"-original",[sys.executable,"-I","-B","-c",code],json.dumps(q,ensure_ascii=False).encode())
 assert n.returncode==p.returncode,(case,n.returncode,p.returncode,n.stderr,p.stderr)
 assert n.stderr==p.stderr,(case,n.stderr,p.stderr)
 if p.returncode==0:
  assert json.loads(n.stdout)==json.loads(p.stdout),(case,n.stdout,p.stdout)
  assert n.stdout.endswith(b"\n")
 else:assert n.stdout==p.stdout==b"",(case,n.stdout,p.stdout)
 return n,journal
def journal(path):
 rows=[];selected={}
 with Path(path).open("rb") as f:
  at=0
  while True:
   head=f.read(64)
   if not head:break
   assert len(head)==64 and head[:8]==b"HFWLJR01"
   family,event,identity,z1,z2,size,z3=struct.unpack_from("<7Q",head,8)
   assert z1==z2==z3==0 and family in (1,2,3)
   data=f.read(size);assert len(data)==size
   rows.append(dict(offset=at,family=family,event=event,bytes=size,sha256=hashlib.sha256(data).hexdigest()))
   if family==1 and event in (8,9,10,11,12,13,14):selected.setdefault(event,[]).append(data)
   at+=64+size
  assert at==Path(path).stat().st_size
 summary=dict(file=pin(path),entries=rows)
 JOURNALS.append(summary)
 return selected,rows
def injected(block):
 marker="if __name__ == '__main__':"
 at=SOURCE.rfind(marker);assert at>0
 text=SOURCE[:at]+block+"\n"+SOURCE[at:]
 assert text.replace(block+"\n","",1)==SOURCE
 return text
class Controls(unittest.TestCase):
 def test_01_original_complete_values_and_filesystem_errors(self):
  base=OUT/"files";base.mkdir()
  files=[]
  for i,(name,data) in enumerate([
   ("empty",b""),("small",b"abc\n"),("all-bytes",bytes(range(256))),
   ("larger-than-hash-chunk",bytes(range(256))*8193),
   ("unicode-中文-π-😀",b"Unicode"),("quote'\"slash\\tab\tline\nreturn\rcontrol\x01",b"Escapes"),
   (".ordinary-dotfile",b"dot"),("with-xattrs",b"metadata")]):
   p=base/name;p.write_bytes(data);files.append(p)
  os.setxattr(files[-1],"user.public_info.empty",b"")
  os.setxattr(files[-1],"user.public_info.binary",bytes(range(256)))
  os.setxattr(files[-1],"user.public_info.中文","value-π".encode())
  link=base/"hard-link";os.link(files[1],link);files.append(link)
  directory=base/"directory";directory.mkdir()
  symlink=base/"final-link";symlink.symlink_to(files[1].name)
  broken=base/"broken-link";broken.symlink_to("not-present")
  intermediate=base/"middle-link";intermediate.symlink_to(directory.name,target_is_directory=True)
  fifo=base/"fifo";os.mkfifo(fifo,0o600)
  sock=socket.socket(socket.AF_UNIX);sock.bind(str(base/"socket"))
  unreadable=base/"unreadable";unreadable.write_bytes(b"x");unreadable.chmod(0)
  sidecar=base/".hepta-secret";sidecar.write_bytes(b"x")
  denied=base/"denied-directory";denied.mkdir();(denied/"file").write_bytes(b"secret");denied.chmod(0)
  try:
   for i,p in enumerate(files):compare(f"value-{i}",str(base),str(p))
   cases=[
    ("absent",str(base),str(base/"absent")),
    ("missing-parent",str(base),str(base/"missing"/"leaf")),
    ("regular-parent",str(base),str(files[1])+"/leaf"),
    ("directory",str(base),str(directory)),
    ("symlink-final",str(base),str(symlink)),
    ("symlink-broken",str(base),str(broken)),
    ("symlink-parent",str(base),str(intermediate/"leaf")),
    ("fifo",str(base),str(fifo)),
    ("socket",str(base),str(base/"socket")),
    ("unreadable",str(base),str(unreadable)),
    ("denied-parent",str(base),str(denied/"file")),
    ("sidecar",str(base),str(sidecar)),
    ("root-itself",str(base),str(base)),
    ("root-dot-itself",str(base),str(base)+"/."),
    ("root-trailing",str(base)+"/",str(base)+"/"),
    ("outside",str(base),str(base)+"-other/file"),
    ("outside-nul",str(base),"/outside/\x00"),
    ("relative-root","relative",str(files[0])),
    ("relative-path",str(base),"relative"),
    ("empty-root","",str(files[0])),
    ("empty-path",str(base),""),
    ("traversal-path",str(base),str(base)+"/directory/../small"),
    ("traversal-root",str(base)+"/directory/..",str(files[1])),
    ("nul-parent",str(base),str(base)+"/nu\x00l/file"),
    ("nul-basename",str(base),str(base)+"/nu\x00l"),
    ("long-basename",str(base),str(base)+"/"+"q"*70000),
    ("long-unicode",str(base),str(base)+"/"+"😀"*18000),
    ("root-anchor","/","/"),
    ("root-double-anchor","//","//"),
    ("anchor-mismatch","/",str(files[1]).replace("/","//",1)),
    ("double-anchor","//","/"+str(files[1])),
    ("triple-anchor","///","//"+str(files[1])),
    ("repeated-slashes",str(base).replace("/","//"),str(files[1]).replace("/","///")),
    ("normalized-dot",str(base)+"/.",str(base)+"/./small/"),
    ("unicode-absent",str(base),str(base)+"/不存在😀"),
    ("escaping-absent",str(base),str(base)+"/missing'\n\\\""),
   ]
   for name,root,path in cases:compare(name,root,path)
  finally:
   unreadable.chmod(0o600);denied.chmod(0o700);sock.close()
 def test_02_actual_observed_children_and_fd_zero(self):
  base=OUT/"observed-files";base.mkdir();p=base/"payload";p.write_bytes(b"observed complete graph")
  for variant in ("observed","fd-zero"):
   block=""
   if variant=="fd-zero":
    block="\n_original_parent_for_fd_zero = parent\ndef parent(root, path):\n    os.close(0)\n    return _original_parent_for_fd_zero(root, path)\n"
   _,path=compare("observed-"+variant,str(base),str(p),variant,injected(block) if block else SOURCE)
   selected,rows=journal(path)
   self.assertTrue(any(x["family"]==2 for x in rows))
   self.assertEqual(len(selected[10]),1)
   child=selected[10][0]
   self.assertEqual(child[:8],b"HINFR001");self.assertEqual(u64(child,8),0)
   self.assertEqual(u64(child,56),len(child)-64)
   self.assertTrue(all(u64(c,56)==2 and u64(c,184)==0 for c in selected[11]))
   state=selected[12][-1]
   self.assertEqual(u64(state,104),0);self.assertEqual(u64(state,112),0)
   self.assertEqual(u64(selected[13][-1],48),0)
   ops=[u64(x,24) for x in selected[8]]
   self.assertIn(1,ops);self.assertIn(2,ops);self.assertIn(3,ops)
   if variant=="fd-zero":
    replies=selected[9]
    self.assertEqual(u64(replies[0],24),0)
 def test_03_actual_kernel_close_error_keeps_original_second_close(self):
  base=OUT/"close-files";base.mkdir();p=base/"payload";p.write_bytes(b"unchanged")
  block=r'''
import ctypes as _ctypes
class _Filter(_ctypes.Structure):
    _fields_=[("code",_ctypes.c_ushort),("jt",_ctypes.c_ubyte),("jf",_ctypes.c_ubyte),("k",_ctypes.c_uint)]
class _Program(_ctypes.Structure):
    _fields_=[("len",_ctypes.c_ushort),("filter",_ctypes.POINTER(_Filter))]
_libc=_ctypes.CDLL(None,use_errno=True)
_original_close=os.close
_close_calls=[]
_close_armed=False
def _actual_close(fd):
    global _close_armed
    if not _close_armed:
        rules=(_Filter*6)(_Filter(0x20,0,0,0),_Filter(0x15,0,3,3),_Filter(0x20,0,0,16),_Filter(0x15,0,1,fd),_Filter(6,0,0,0x00050005),_Filter(6,0,0,0x7fff0000))
        program=_Program(6,rules)
        if _libc.prctl(38,1,0,0,0)!=0:raise RuntimeError("fixture no_new_privs")
        if _libc.syscall(317,1,0,_ctypes.byref(program))!=0:raise RuntimeError("fixture seccomp")
        _close_armed=True
    _close_calls.append(fd)
    return _original_close(fd)
_original_parent_for_close = parent
def parent(root,path):
    os.close=_actual_close
    try:
        return _original_parent_for_close(root,path)
    finally:
        os.close=_original_close
        assert len(_close_calls)==2 and _close_calls[0]==_close_calls[1]
'''
  n,path=compare("real-kernel-close",str(base),str(p),"close-error",injected(block))
  self.assertEqual(n.returncode,1)
  self.assertEqual(n.stderr,b"OSError: [Errno 5] Input/output error\n")
  selected,rows=journal(path)
  self.assertNotIn(10,selected)
  ops=[u64(x,24) for x in selected[8]]
  self.assertEqual(ops,[1,2,3,4,5])
  closes=[x for x in selected[8] if u64(x,24) in (3,5)]
  self.assertEqual(u64(closes[0],32),u64(closes[1],32))
  replies=selected[9]
  self.assertEqual(u64(replies[2],24),(1<<64)-5)
  self.assertEqual(u64(replies[4],24),(1<<64)-5)
  pool=selected[13][-1]
  self.assertEqual(u64(pool,48),1);self.assertEqual(u64(pool,56),1)
  page=selected[14][-1]
  self.assertEqual(page[:8],b"HPORL001");self.assertEqual(u64(page,24),1)
  child_fd=u64(replies[1],24)
  self.assertEqual(u64(page,64),child_fd)
  self.assertEqual(u64(page,80),1)
  self.assertEqual(p.read_bytes(),b"unchanged")
 def test_04_malformed_private_frames_never_become_business_success(self):
  good=wire("/","/nonexistent")
  cases=[b"",good[:95],b"BADMAGIC"+good[8:],good+b"x",good[:-1]]
  for at,value in ((8,0),(8,3),(16,1),(24,0),(24,2),(32,(1<<64)-1),(40,(1<<64)-1),(48,1),(56,1),(64,1),(72,1),(80,1),(88,0)):
   b=bytearray(good);struct.pack_into("<Q",b,at,value);cases.append(bytes(b))
  bad=bytearray(wire("/","/x"));bad[-1]=0xff;cases.append(bytes(bad))
  for i,b in enumerate(cases):
   p,_=run("bad-wire-"+str(i),[A.build/"production/public-file-info.elf"],b)
   self.assertEqual((p.returncode,p.stdout,p.stderr),(111,b"",b""))
 def test_05_actual_hia_growth_and_replay_boundary(self):
  sys.path.insert(0,str(ROOT/"scripts"))
  from hia_native_loader import NativeModule
  info=BUILD["members"]["walk"]
  manifest=A.build/info["manifest"]
  with NativeModule(manifest,manifest_sha256=info["manifest_pin"]["sha256"]) as m:
   good=wire("/","/absent")
   for bad in (b"",good[:95],b"BADMAGIC"+good[8:],good+b"x",good[:-1]):
    code,out,work=m.invoke_raw(bad,output_capacity=512,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0x6b)
    self.assertEqual(code,0xffffffff);self.assertEqual(out,b"\xa5"*512);self.assertEqual(work,b"\x6b"*4096)
   code,out,work=m.invoke_raw(good,output_capacity=63,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0x6b)
   self.assertEqual(code,0xfffffffe);self.assertEqual(out,b"\xa5"*63);self.assertEqual(work,b"\x6b"*4096)
   code,out,work=m.invoke_raw(good,output_capacity=512,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0)
   self.assertEqual(code,64);self.assertEqual(out[:8],b"HFRDR001");self.assertEqual(u64(out,8),4)
   needed=u64(out,32);self.assertGreater(needed,4096)
   self.assertEqual(out[64:],b"\xa5"*448);self.assertEqual(work,bytes(4096))
   code,out,work=m.invoke_raw(good,output_capacity=512,workspace_capacity=needed,output_fill=0xa5,workspace_fill=0)
   self.assertEqual(code,64);self.assertEqual(u64(out,8),1);self.assertEqual(u64(out,24),1)
   self.assertEqual(out[64:],b"\xa5"*448)
   # The raw loader does not resume saved work. This control deliberately makes
   # no synthetic syscall reply or filesystem completion claim.
   short=wire("","")
   code,out,work=m.invoke_raw(short,output_capacity=512,workspace_capacity=needed,output_fill=0xa5,workspace_fill=0)
   self.assertEqual(code,64);self.assertEqual(u64(out,8),3)
   self.assertEqual(out[64:72],b"HBRDS001")
   extent=64+u64(out,56);self.assertEqual(out[extent:],b"\xa5"*(512-extent))
 def test_06_parent_death_kills_and_reaps_the_fixed_helper(self):
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
   middle=subprocess.Popen([sys.executable,"-I","-B","-c",launcher,str(A.build/"production/public-file-info.elf"),str(data_read)],
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
   row=dict(schema="hepta.runtime.public-file-info-parent-death.v1",middle_pid=middle.pid,helper_pid=helper,
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
 global A,ROOT,OUT,BUILD,SOURCE
 p=argparse.ArgumentParser()
 for n in ("source","build","output"):p.add_argument("--"+n,type=Path,required=True)
 A=p.parse_args();ROOT=A.source.resolve(strict=True);A.build=A.build.resolve(strict=True);OUT=A.output.absolute()
 assert not OUT.exists();OUT.mkdir(parents=True)
 assert sys.flags.isolated==1 and sys.flags.optimize==0
 BUILD=json.loads((A.build/"BUILD.json").read_bytes());assert BUILD["status"]=="PASS"
 source_paths=[ROOT/"src/mcp/runtime"/n for n in ("file_metadata.py","inode_patch.py","binary_file.py")]
 SOURCE="\n".join(p.read_text() for p in source_paths)
 paths=[Path(__file__).resolve(),Path(sys.executable).resolve(strict=True),A.build/"BUILD.json"]+source_paths
 for name,info in BUILD["members"].items():
  manifest=A.build/info["manifest"];meta=json.loads(manifest.read_bytes())
  paths.extend([manifest,manifest.parent/meta["image"],ROOT/info["source_path"]])
 for variant in BUILD["variants"]:paths.append(A.build/variant/"public-file-info.elf")
 paths=list(dict.fromkeys(paths));before=[pin(p) for p in paths]
 start=time.monotonic()
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
 after=[pin(p) for p in paths]
 report=dict(schema="hepta.runtime.public-file-info-walk-actual-controls.v1",
  status="PASS" if result.wasSuccessful() and before==after else "FAIL",tests_run=result.testsRun,
  failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
  expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
  seconds=time.monotonic()-start,python_isolated=sys.flags.isolated,python_optimize=sys.flags.optimize,
  inputs=before,all_inputs_unchanged=before==after,actual_processes=ROWS,journals=JOURNALS,
  original_source_complete=True,original_exception_stderr_compared_exactly=True,
  reference_interpreter=dict(version=sys.version,version_info=list(sys.version_info),implementation=sys.implementation.name,executable=sys.executable,real_executable=str(Path(sys.executable).resolve(strict=True)),platform=sys.platform),
  machine=dict(zip(("sysname","nodename","release","version","machine"),os.uname())),
  successful_complete_json_values_compared=True,synthetic_business_syscall_replies=False,
  network_ssh_qualified=False,default_public_route_qualified=False,whole_runtime_replaced=False)
 (OUT/"result.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps({k:report[k] for k in ("status","tests_run","failures","errors","skipped","seconds","all_inputs_unchanged")},sort_keys=True))
 raise SystemExit(0 if report["status"]=="PASS" else 1)
if __name__=="__main__":main()
