# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual held-inode changes and explicit private-effect refusal controls."""
from pathlib import Path
import argparse,contextlib,ctypes,errno,hashlib,json,os,struct,time
import qualify_durable_audit_record_io as qa
from hia_native_loader import NativeModule
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--manifest",type=Path,required=True);p.add_argument("--record-manifest",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 bound=[a.manifest,a.record_manifest,Path(qa.__file__),Path(__file__),Path(__file__).parent/"hia_native_loader.py"]
 for manifest in(a.manifest,a.record_manifest):
  data=json.loads(manifest.read_bytes());bound.extend([manifest.parent/data["source"],manifest.parent/data["image"]])
 before={str(p):SHA(p.read_bytes())for p in bound};rows=[];start=time.monotonic()
 with NativeModule(a.manifest,manifest_sha256=SHA(a.manifest.read_bytes()))as native,NativeModule(a.record_manifest,manifest_sha256=SHA(a.record_manifest.read_bytes()))as record:
  broker=qa.Broker(native,record);filename=("a"*64+".json").encode();wire=b"HRAIO001"+struct.pack("<QQQ",1,69,0)+filename
  base=dict(label="baseline",operation=1,filename=filename.decode(),files=[{}])
  def run(label,case=None,hook=None):
   d=a.output/label;d.mkdir();op,name=qa.materialize(d/"files",dict(base,**(case or {})))
   result=broker.run(d/"files",op,name.encode(),mutate=(lambda row,fds,s,w:hook(d/"files",row,fds,s,w))if hook else None)
   (d/"result.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
   (d/"after.json").write_text(json.dumps(qa.snapshot(d/"files"),sort_keys=True,indent=2)+"\n")
   return d,result
  expected=json.loads(qa.record_raw())
  seen=set()
  def retained(path,row,fds,s,w):
   if row["kind"]==2 and row["slot"]==1 and "swap"not in seen:
    seen.add("swap");os.rename(path/filename.decode(),path/"held-original")
    (path/filename.decode()).write_bytes(qa.record_raw(request_id="c"*64));(path/filename.decode()).chmod(0o600)
  d,r=run("held-record-inode-after-path-replacement",hook=retained);assert r["diagnostic"]==0 and r["record"]==expected and seen=={"swap"}
  rows.append(dict(name=d.name,passed=True,kind="actual inode replacement"))
  for label,contents,diagnostic in[("actual-growth-after-validation",b"x"*8192,3),("actual-truncate-after-validation",b"",1)]:
   hit=set()
   def change(path,row,fds,s,w):
    if row["kind"]==3 and not hit:
     hit.add(1);(path/filename.decode()).write_bytes(contents)
   d,r=run(label,hook=change);assert hit and r["diagnostic"]==diagnostic
   assert sum(x["result"]for x in r["trace"]if x["kind"]==3)<=2049
   if diagnostic==3:assert all(x["kind"]!=100 for x in r["trace"])
   rows.append(dict(name=d.name,passed=True,kind="actual inode byte change",diagnostic=diagnostic))
  # Outcomes are deliberately injected at the private syscall boundary; record
  # this separately from genuine OS permission/metadata failures in the 63 cases.
  def injected(label,symbol,error_number,diagnostic,case=None,predicate=None,close_really=False):
   original=getattr(qa.LIBC,symbol);calls=[];injected_calls=[]
   def effect(*args):
    calls.append(tuple(int(x.value)if hasattr(x,"value")and x.value is not None else x for x in args))
    if not injected_calls and(predicate is None or predicate(args)):
     injected_calls.append(len(calls))
     if close_really:original(*args)
     ctypes.set_errno(error_number);return -1
    return original(*args)
   setattr(qa.LIBC,symbol,effect)
   try:d,r=run(label,case)
   finally:setattr(qa.LIBC,symbol,original)
   assert injected_calls and r["diagnostic"]==diagnostic,(label,r)
   rows.append(dict(name=label,passed=True,kind="injected private syscall result",diagnostic=diagnostic,injected_calls=injected_calls,total_calls=len(calls)))
   return d,r
  d,r=injected("known-interrupted-read", "read",errno.EINTR,0);assert r["record"]==expected
  d,r=injected("known-read-io-error","read",errno.EIO,23);assert r["errno"]==errno.EIO
  stage=dict(staging_style="linked",staging_nonce="c"*64)
  d,r=injected("known-interrupted-directory-sync","fsync",errno.EINTR,0,stage);assert r["record"]==expected
  d,r=injected("directory-sync-error-after-unlink","fsync",errno.EIO,23,stage);assert r["errno"]==errno.EIO
  assert not(d/"files"/("."+"a"*64+"-"+"c"*64+".tmp")).exists()
  d,r=injected("close-interrupted-never-replayed","close",errno.EINTR,0,close_really=True)
  assert sum(x["kind"]==6 for x in r["trace"])==1 and r["record"]==expected
  d,r=injected("known-directory-read-interrupted","syscall",errno.EINTR,23,stage);assert r["errno"]==errno.EINTR
  d,r=injected("deleted-directory-enoent-is-end","syscall",errno.ENOENT,16,stage)
  assert(d/"files"/("."+"a"*64+"-"+"c"*64+".tmp")).exists()
  d,r=injected("duplication-error-closes-fresh-scan","fcntl",errno.EMFILE,23,stage,predicate=lambda args:args[1]==qa.fcntl.F_DUPFD_CLOEXEC)
  d,r=injected("getfl-error-closes-both-scan-handles","fcntl",errno.EBADF,23,stage,predicate=lambda args:args[1]==qa.fcntl.F_GETFL)
  d,r=injected("setfd-error-closes-both-scan-handles","fcntl",errno.EPERM,23,stage,predicate=lambda args:args[1]==qa.fcntl.F_SETFD)
  for label,offset,value in[("wrong-action-magic",256,0),("wrong-action-sequence",264,99),("changed-action-kind",272,99),("changed-action-slot",280,99),("changed-action-span",288,0),("changed-action-count",296,0),("changed-action-flags",304,0),("changed-action-capacity",312,99),("wrong-ack-sequence",320,99),("reserved-ack",344,1),("invalid-errno",336,4096),("error-with-nonzero-result",328,1)]:
   with native.session(output_capacity=4096,workspace_capacity=65536)as session:
    code,out,w=session.invoke_raw(wire);assert code==qa.YIELD
    ack=bytearray(struct.pack("<QQQQ",1,0,errno.ENOENT,0));ctypes.memmove(ctypes.addressof(session._workspace)+320,bytes(ack),32)
    ctypes.memmove(ctypes.addressof(session._workspace)+offset,struct.pack("<Q",value),8)
    prior=session._workspace.raw[:65536];before_out=session._output.raw[:4096]
    code,out,w=session.invoke_raw(wire);assert code==0xffffffff and w==prior and out==before_out
    d=a.output/label;d.mkdir();(d/"before.bin").write_bytes(prior);(d/"after.bin").write_bytes(w);(d/"input.bin").write_bytes(wire)
    rows.append(dict(name=label,passed=True,kind="malformed acknowledgement",effects_executed=0))
  with native.session(output_capacity=4096,workspace_capacity=65536)as session:
   code,out,w=session.invoke_raw(wire);assert code==qa.YIELD
   ctypes.memmove(ctypes.addressof(session._workspace)+320,struct.pack("<QQQQ",1,0,2,0),32)
   prior=session._workspace.raw[:65536]
   altered=wire[:-1]+b"x";code,out,w=session.invoke_raw(altered);assert code==0xffffffff and w==prior
   rows.append(dict(name="late-input-change",passed=True,kind="private byte binding",effects_executed=0))
  class TerminalProbe:
   @contextlib.contextmanager
   def session(self,**options):
    with native.session(**options)as actual:
     class Proxy:
      _workspace=actual._workspace
      def invoke_raw(self,request):
       code,out,w=actual.invoke_raw(request)
       if code<0xffff0000:
        code2,out2,w2=actual.invoke_raw(request)
        assert code2==0xffffffff and out2==out and w2==w
        rows.append(dict(name="terminal-cannot-replay-effects",passed=True,kind="actual terminal one-shot",effects_replayed=0))
       return code,out,w
     yield Proxy()
  terminal_dir=a.output/"terminal-cannot-replay-effects";terminal_dir.mkdir()
  op,name=qa.materialize(terminal_dir/"files",base)
  result=qa.Broker(TerminalProbe(),record).run(terminal_dir/"files",op,name.encode())
  assert result["diagnostic"]==0 and result["record"]==expected
  (terminal_dir/"result.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
  with native.session(output_capacity=4096,workspace_capacity=65536)as session:
   bad=wire[:8]+struct.pack("<Q",9)+wire[16:];code,out,w=session.invoke_raw(bad);assert code==0xffffffff and not any(out)and not any(w)
   rows.append(dict(name="unknown-operation-no-effects",passed=True,kind="private operation admission"))
  for output,workspace in[(4095,65536),(4096,65535)]:
   code,out,w=native.invoke_raw(wire,output_capacity=output,workspace_capacity=workspace,output_fill=0x91,workspace_fill=0)
   assert code==0xfffffffe and out==b"\x91"*output and not any(w)
   rows.append(dict(name=f"capacity-{output}-{workspace}",passed=True,kind="capacity before effect"))
 after={str(p):SHA(p.read_bytes())for p in bound};assert before==after
 report=dict(state="PASS",controls=len(rows),rows=rows,elapsed_seconds=time.monotonic()-start,source_before=before,source_after=after,source_unchanged=True,public_routing_qualified=False)
 (a.output/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n");print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
