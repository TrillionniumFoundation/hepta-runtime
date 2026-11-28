#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual original/native bounded multi-read processes and terminal frame controls."""
from __future__ import annotations
import argparse,hashlib,json,os,socket,struct,subprocess,sys,time,unittest
from pathlib import Path
sys.dont_write_bytecode=True
A=ROOT=OUT=BUILD=SOURCE=None
ROWS=[]
JOURNALS=[]
def pin(path):
 p=Path(path)
 with p.open("rb") as f:return dict(path=str(p),bytes=p.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def u64(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def query(root,paths,file=65536,response=262144):
 return dict(files=[dict(root=str(root),path=str(p)) for p in paths],max_file_bytes=file,max_response_bytes=response)
def wire(q):
 flags=(1 if "max_file_bytes" in q else 0)|(2 if "max_response_bytes" in q else 0)
 records=b""
 for e in q["files"]:
  r=e["root"].encode();p=e["path"].encode()
  records+=struct.pack("<2Q",len(r),len(p))+r+p
 return b"HMRDQ001"+struct.pack("<11Q",1,0,flags,len(q["files"]),q.get("max_file_bytes",0),
  q.get("max_response_bytes",0),0,0,0,0,len(records))+records
def run(name,argv,data,observe=False):
 folder=OUT/"runs";folder.mkdir(exist_ok=True);prefix=folder/name;journal=None
 if observe:
  journal=prefix.with_suffix(".journal")
  fd=os.open(journal,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  if fd!=3:os.close(fd);raise AssertionError(f"observer requires free FD3, obtained {fd}")
 start=time.monotonic()
 try:
  p=subprocess.run([str(x) for x in argv],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
   pass_fds=(3,) if observe else ())
 finally:
  if observe:os.close(3)
 prefix.with_suffix(".input").write_bytes(data);prefix.with_suffix(".stdout").write_bytes(p.stdout)
 prefix.with_suffix(".stderr").write_bytes(p.stderr)
 row=dict(name=name,argv=[str(x) for x in argv],returncode=p.returncode,seconds=time.monotonic()-start,timeout_seconds=30,
  input=pin(prefix.with_suffix(".input")),stdout=pin(prefix.with_suffix(".stdout")),stderr=pin(prefix.with_suffix(".stderr")))
 if journal:row["journal"]=pin(journal)
 ROWS.append(row);return p,journal
def compare(case,q,variant="production"):
 exe=A.build/variant/"public-multi-read.elf"
 n,journal=run(case+"-native",[exe],wire(q),variant!="production")
 p,_=run(case+"-original",[sys.executable,"-I","-B","-c",SOURCE],json.dumps(q,ensure_ascii=False).encode())
 assert (n.returncode,n.stdout,n.stderr)==(p.returncode,p.stdout,p.stderr),(case,n.returncode,p.returncode,n.stdout,p.stdout,n.stderr,p.stderr)
 if p.returncode==0:
  assert n.stdout.endswith(b"\n") and not n.stderr
  assert json.loads(n.stdout)==json.loads(p.stdout)
 else:
  assert n.returncode==1 and n.stdout==b""
  assert n.stderr.startswith(b"multi-file read rejected: ") and n.stderr.endswith(b"\n")
 return n,journal
def journal(path):
 rows=[];selected={}
 with Path(path).open("rb") as f:
  at=0;sequence=0
  while True:
   head=f.read(64)
   if not head:break
   assert len(head)==64 and head[:8]==b"HPMRJ001"
   source,event,size,state,generation,owned,current=struct.unpack_from("<7Q",head,8)
   sequence+=1;assert current==sequence and source in (1,2,3)
   data=f.read(size);assert len(data)==size
   rows.append(dict(offset=at,source=source,event=event,state=state,generation=generation,owned=owned,bytes=size,sha256=hashlib.sha256(data).hexdigest()))
   if event in (8,9,80,81,95,96):selected.setdefault((source,event),[]).append(data)
   at+=64+size
  assert at==Path(path).stat().st_size
 JOURNALS.append(dict(file=pin(path),entries=rows))
 return selected,rows
class Controls(unittest.TestCase):
 def test_01_complete_values_and_original_filesystem_failures(self):
  base=OUT/"files";base.mkdir();files=[]
  for name,data in [
   ("empty",b""),("small",b"abc\n"),("unicode-中文-π-😀","中文 π 😀\n".encode()),
   ("quote'\"slash\\tab\tline\nreturn\rcontrol\x01",b'quote" slash\\ \x00\x01\t\r\n'),
   (".ordinary-dotfile",b"dot"),("65536-bytes",b"a"*65536)]:
   p=base/name;p.write_bytes(data);files.append(p)
  for i,p in enumerate(files):compare(f"value-{i}",query(base,[p]))
  compare("all-values",query(base,files))
  many=[]
  for i in range(16):
   p=base/("file-"+str(i));p.write_bytes(("item "+str(i)).encode());many.append(p)
  compare("sixteen-files",query(base,many))
  compare("root-anchor",query("/",[files[1]]))
  hard=base/"hard-link";os.link(files[1],hard)
  directory=base/"directory";directory.mkdir()
  link=base/"symlink";link.symlink_to(files[2].name)
  broken=base/"broken";broken.symlink_to("not-present")
  middle=base/"middle";middle.symlink_to(directory.name,target_is_directory=True)
  fifo=base/"fifo";os.mkfifo(fifo,0o600)
  sock=socket.socket(socket.AF_UNIX);sock.bind(str(base/"socket"))
  denied=base/"denied";denied.mkdir();(denied/"file").write_bytes(b"private");denied.chmod(0)
  unreadable=base/"unreadable";unreadable.write_bytes(b"private");unreadable.chmod(0)
  sidecar=base/".hepta-secret";sidecar.write_bytes(b"private")
  try:
   cases=[("hardlinked",hard),("hardlinked-original",files[1]),("directory",directory),
    ("final-symlink",link),("broken-symlink",broken),("parent-symlink",middle/"leaf"),("fifo",fifo),
    ("socket",base/"socket"),("absent",base/"absent"),("missing-parent",base/"absent"/"leaf"),
    ("regular-parent",Path(str(files[2])+"/leaf")),("denied-parent",denied/"file"),
    ("unreadable",unreadable),("sidecar",sidecar),("root-itself",base),
    ("outside",Path(str(base)+"-outside")/"leaf"),("name-256",base/("q"*256)),
    ("name-unicode",base/("😀"*80)),("escaping-absent",base/"missing'\n\\\"")]
   for name,path in cases:compare(name,query(base,[path]))
   secret=base/"first-secret";secret.write_bytes(b"FIRST_FILE_PRIVATE_CONTENT")
   for name,path in cases:
    p,_=compare("later-"+name,query(base,[secret,path]))
    self.assertEqual(p.stdout,b"");self.assertNotIn(b"FIRST_FILE_PRIVATE_CONTENT",p.stderr)
  finally:denied.chmod(0o700);unreadable.chmod(0o600);sock.close()
 def test_02_preflight_order_and_exact_serialized_budget(self):
  base=OUT/"preflight";base.mkdir();p=base/"payload";p.write_bytes(('"\n\\ 中文😀'*400).encode())
  ok,_=compare("budget-large",query(base,[p]))
  result=json.loads(ok.stdout)
  text=json.dumps(result,ensure_ascii=False,sort_keys=True,separators=(",",":"))
  budget=len(json.dumps({"content":[{"type":"text","text":text}],"isError":False},ensure_ascii=False,separators=(",",":")).encode())
  self.assertGreaterEqual(budget,1024)
  for delta in (-1,0,1):
   process,_=compare("budget-"+str(delta+1),query(base,[p],response=budget+delta))
   self.assertEqual(process.returncode,1 if delta<0 else 0)
  size=p.stat().st_size
  for limit in (1,size-1,size,size+1,65536,0,65537):
   compare("file-limit-"+str(limit),query(base,[p],file=limit))
  for limit in (0,1023,1024,262144,262145):
   compare("response-limit-"+str(limit),query(base,[p],response=limit))
  compare("no-files",query(base,[]));compare("seventeen-files",query(base,[base/str(i) for i in range(17)]))
  compare("default-limits",dict(files=[dict(root=str(base),path=str(p))]))
  compare("only-file-limit",dict(files=[dict(root=str(base),path=str(p))],max_file_bytes=65536))
  compare("only-response-limit",dict(files=[dict(root=str(base),path=str(p))],max_response_bytes=262144))
  compare("duplicate-before-missing",query(base,[base/"missing",base/"missing"]))
  invalid_paths=["","relative","/",str(p)+"/",str(base)+"//payload",str(base)+"/./payload",
   str(base)+"/../payload",str(base)+"/nu\0l",str(base)+"/nu\0l/payload",str(base)+"/"+"q"*4096]
  for i,path in enumerate(invalid_paths):
   compare("invalid-path-"+str(i),query(base,[base/"missing",path]))
  for i,root in enumerate(["","relative",str(base)+"/",str(base)+"/.",str(base)+"/..","//",str(base)+"/nu\0l"]):
   q=query(base,[p]);q["files"][0]["root"]=root
   compare("invalid-root-"+str(i),q)
 def test_03_complete_original_utf8_errors_and_no_partial_content(self):
  base=OUT/"utf8";base.mkdir();good=base/"good";good.write_bytes(b"SENSITIVE_EARLIER_FILE")
  values=[b"\x80",b"\xff",b"\xc0\x80",b"\xc2",b"\xe2(\xa1",b"\xe2\x82",b"\xed\xa0\x80",
   b"\xf4\x90\x80\x80",b"\xf0\x9f\x92",b"abc\xf0(\x8c\xbc",bytes(range(256)),b"a"*65535+b"\xc2"]
  for i,data in enumerate(values):
   p=base/str(i);p.write_bytes(data)
   value,_=compare("utf8-"+str(i),query(base,[good,p]))
   self.assertEqual(value.stdout,b"");self.assertIn(b"UnicodeDecodeError: ",value.stderr)
   self.assertNotIn(b"SENSITIVE_EARLIER_FILE",value.stderr)
 def test_04_observed_complete_children_and_actual_fd_zero(self):
  base=OUT/"observed";base.mkdir();p=base/"data";p.write_bytes(b"observed graph")
  for variant in ("observed","fd-zero"):
   native,jpath=compare("observed-"+variant,query(base,[p]),variant)
   selected,rows=journal(jpath)
   self.assertEqual({row["source"] for row in rows},{1,2,3})
   framed=selected[(1,81)][0]
   self.assertEqual(framed[:8],b"HMRFR001");self.assertEqual(u64(framed,8),0)
   size=u64(framed,16);self.assertEqual(framed[32:32+size],native.stdout)
   self.assertEqual(framed[32+size:],b"\xa5"*(len(framed)-32-size))
   context=selected[(1,96)][0];self.assertEqual(u64(context,56),0);self.assertEqual(u64(context,184),0)
   pool=selected[(1,95)][0];self.assertEqual(pool[:8],b"HPORP001");self.assertEqual(u64(pool,48),0)
   self.assertTrue(any(row["source"]==1 and row["event"]==3 for row in rows))
   if variant=="fd-zero":
    first_request=selected[(2,8)][0];first_reply=selected[(2,9)][0]
    self.assertEqual(u64(first_request,24),1);self.assertEqual(u64(first_reply,24),0)
 def test_05_malformed_private_frames_are_private_failures(self):
  valid=wire(query("/",["/absent"]))
  bad=[b"",valid[:95],b"BADMAGIC"+valid[8:],valid+b"x",valid[:-1],b"x"*(1<<20),b"x"*((1<<20)+1)]
  for at,value in [(8,0),(8,2),(16,1),(24,4),(56,1),(64,1),(72,1),(80,1),(88,0)]:
   b=bytearray(valid);struct.pack_into("<Q",b,at,value);bad.append(bytes(b))
  b=bytearray(valid);b[112]=255;bad.append(bytes(b))
  b=bytearray(valid);struct.pack_into("<Q",b,96,(1<<64)-1);bad.append(bytes(b))
  for i,data in enumerate(bad):
   p,_=run("malformed-"+str(i),[A.build/"production/public-multi-read.elf"],data)
   self.assertEqual((p.returncode,p.stdout,p.stderr),(111,b"",b""))
 def test_06_actual_hia_terminal_format_capacities_and_tails(self):
  sys.path.insert(0,str(ROOT/"scripts"))
  from hia_native_loader import NativeModule
  info=BUILD["members"]["result"];manifest=A.build/info["manifest"]
  cases=[(0,b""),(0,b'{"ok":"yes"}'),(0,bytes(range(256))*300),(1,b"ValueError: rejected"),
   (1,"UnicodeDecodeError: \u4e2d\u6587".encode())]
  with NativeModule(manifest,manifest_sha256=info["manifest_pin"]["sha256"]) as module:
   for mode,payload in cases:
    data=b"HMRFQ001"+struct.pack("<2Q",mode,len(payload))+payload
    expected=(b"multi-file read rejected: " if mode else b"")+payload+b"\n"
    required=32+len(expected)
    for capacity in (0,31,required-1,required,required+127):
     code,out,work=module.invoke_raw(data,output_capacity=capacity,workspace_capacity=256,output_fill=0xa5,workspace_fill=0x6b)
     self.assertEqual(work,b"\x6b"*256)
     if capacity<required:
      self.assertEqual(code,0xfffffffe);self.assertEqual(out,b"\xa5"*capacity)
     else:
      self.assertEqual(code,32);self.assertEqual(out[:32],b"HMRFR001"+struct.pack("<3Q",mode,len(expected),0))
      self.assertEqual(out[32:required],expected);self.assertEqual(out[required:],b"\xa5"*(capacity-required))
   good=b"HMRFQ001"+struct.pack("<2Q",0,1)+b"x"
   invalid=[b"",good[:23],b"BADMAGIC"+good[8:],good[:-1],good+b"x",b"HMRFQ001"+struct.pack("<2Q",2,1)+b"x"]
   for data in invalid:
    code,out,work=module.invoke_raw(data,output_capacity=256,workspace_capacity=256,output_fill=0xa5,workspace_fill=0x6b)
    self.assertEqual(code,0xffffffff);self.assertEqual(out,b"\xa5"*256);self.assertEqual(work,b"\x6b"*256)
 def test_07_parent_death_kills_and_reaps_the_fixed_helper(self):
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
   middle=subprocess.Popen([sys.executable,"-I","-B","-c",launcher,str(A.build/"production/public-multi-read.elf"),str(data_read)],
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
   row=dict(schema="hepta.runtime.public-multi-read-parent-death.v1",middle_pid=middle.pid,helper_pid=helper,
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
 source_paths=[ROOT/"src/mcp/runtime"/n for n in ("file_metadata.py","binary_file.py","multi_read_host.py")]
 SOURCE="__name__ = 'hepta_multi_read_helpers'\n"+"\n".join(p.read_text() for p in source_paths)+"\nrun_multi_read()\n"
 (OUT/"original-source.py").write_text(SOURCE)
 (OUT/"test-source.py").write_bytes(Path(__file__).read_bytes())
 paths=[Path(__file__).resolve(),Path(sys.executable).resolve(strict=True),A.build/"BUILD.json",ROOT/"src/mcp/runtime/multi_read.rs"]+source_paths
 for rel in BUILD["source_files"]:paths.append(ROOT/rel)
 for info in BUILD["members"].values():
  manifest=A.build/info["manifest"];meta=json.loads(manifest.read_bytes())
  paths.extend([manifest,manifest.parent/meta["image"],ROOT/info["source_path"]])
 q=ROOT/"qualification/multi_read_body/v1/codec_reserved_native_build"
 paths.extend(p for p in q.rglob("*") if p.is_file())
 for variant in BUILD["variants"]:paths.append(A.build/variant/"public-multi-read.elf")
 paths=list(dict.fromkeys(paths));before=[pin(p) for p in paths]
 start=time.monotonic()
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
 after=[pin(p) for p in paths]
 report=dict(schema="hepta.runtime.public-multi-read-helper.actual-controls.v1",
  status="PASS" if result.wasSuccessful() and before==after else "FAIL",tests_run=result.testsRun,
  failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
  expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
  seconds=time.monotonic()-start,python_isolated=sys.flags.isolated,python_optimize=sys.flags.optimize,
  inputs=before,all_inputs_unchanged=before==after,actual_processes=ROWS,journals=JOURNALS,
  original_source=pin(OUT/"original-source.py"),original_source_complete=True,
  original_success_stdout_error_stderr_and_exit_compared_exactly=True,
  reference_interpreter=dict(version=sys.version,version_info=list(sys.version_info),implementation=sys.implementation.name,
   executable=sys.executable,real_executable=str(Path(sys.executable).resolve(strict=True)),platform=sys.platform),
  machine=dict(zip(("sysname","nodename","release","version","machine"),os.uname())),
  successful_complete_json_values_compared=True,synthetic_business_syscall_replies=False,
  network_ssh_qualified=False,default_public_route_qualified=False,whole_runtime_replaced=False)
 (OUT/"result.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps({k:report[k] for k in ("status","tests_run","failures","errors","skipped","seconds","all_inputs_unchanged")},sort_keys=True))
 raise SystemExit(0 if report["status"]=="PASS" else 1)
if __name__=="__main__":main()
