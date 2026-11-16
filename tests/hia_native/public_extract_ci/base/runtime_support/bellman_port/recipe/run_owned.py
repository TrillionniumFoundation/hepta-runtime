import argparse,hashlib,json,os,pathlib,signal,subprocess,sys,time
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,required=True);p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.output.mkdir()
command=[sys.executable,'-I','-S','-B',str(a.script.resolve()),'--build',str(a.build.resolve()),'--output',str((a.output/'capture').resolve())]
start=time.monotonic_ns();child=None;receipt={'command':command,'timeout_seconds':60,'started':False,'parent_pid':os.getpid()}
try:
 with (a.output/'stdout').open('xb') as out,(a.output/'stderr').open('xb') as err:
  child=subprocess.Popen(command,stdout=out,stderr=err,start_new_session=True);receipt.update(started=True,pid=child.pid,pgid=child.pid)
  try:receipt['returncode']=child.wait(timeout=60);receipt['timed_out']=False
  except subprocess.TimeoutExpired:receipt['timed_out']=True;raise
finally:
 if child is not None:
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  receipt['returncode']=child.wait()
 receipt['elapsed_ns']=time.monotonic_ns()-start
 for name in ['stdout','stderr']:
  b=(a.output/name).read_bytes();receipt[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
 (a.output/'process.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');print(json.dumps(receipt,sort_keys=True),flush=True)
 if receipt['returncode']:sys.stderr.buffer.write((a.output/'stderr').read_bytes())
sys.exit(0 if receipt.get('returncode')==0 and not receipt.get('timed_out') else 1)
