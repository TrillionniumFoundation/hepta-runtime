"""Physical rehashed port evidence refusals; normal verification only reads."""
import argparse,gc,hashlib,json,os,pathlib,shutil,stat,subprocess,sys,time,traceback,signal
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from read_port import verify,read,doc,sha,get,journal_records
CASES=['cancelled-core-clock','cancelled-final-writer-clock','missing-mode1-delivery','caller-workspace-identity','ready-fifo-copy','changed-mechanical-source','changed-domain-claim','missing-final-destroy-attempt']
def encoded(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
def file_pin(path):
 assert stat.S_ISREG(path.lstat().st_mode)
 with path.open('rb') as f:h=hashlib.file_digest(f,'sha256').hexdigest()
 return {'bytes':path.stat().st_size,'sha256':h}
def files(root):
 result={}
 def visit(folder):
  assert stat.S_ISDIR(folder.lstat().st_mode)
  for p in sorted(folder.iterdir()):
   mode=p.lstat().st_mode
   if stat.S_ISDIR(mode):visit(p)
   else:assert stat.S_ISREG(mode);result[p.relative_to(root).as_posix()]=file_pin(p)
 visit(root);return result
def copy_exact(source,target,pins):
 target.mkdir()
 for name,pin in pins.items():
  a=source/name;b=target/name;assert pin==file_pin(a)
  b.parent.mkdir(parents=True,exist_ok=True)
  with a.open('rb') as src,b.open('xb') as dst:
   while chunk:=src.read(1<<20):dst.write(chunk)
  assert file_pin(b)==pin and (a.stat().st_dev,a.stat().st_ino)!=(b.stat().st_dev,b.stat().st_ino)
def jsonl(rows):return b''.join((json.dumps(r,sort_keys=True,separators=(',',':'))+'\n').encode() for r in rows)
def chunks(value):
 if isinstance(value,bytes):yield value;return
 assert set(value)=={'splice','cuts'};path=pathlib.Path(value['splice']);assert stat.S_ISREG(path.lstat().st_mode)
 size=path.stat().st_size;at=0
 with path.open('rb') as stream:
  for begin,end in value['cuts']+[(size,size)]:
   assert at<=begin<=end<=size;remaining=begin-at
   while remaining:
    b=stream.read(min(1<<20,remaining));assert b;remaining-=len(b);yield b
   stream.seek(end);at=end
  assert stream.read(1)==b''
def value_pin(value):
 if value is None:return None
 h=hashlib.sha256();size=0
 for b in chunks(value):h.update(b);size+=len(b)
 return {'bytes':size,'sha256':h.hexdigest()}
def same_content(path,value):
 with path.open('rb') as f:
  for b in chunks(value):assert f.read(len(b))==b
  assert f.read(1)==b''

def mutation(case,run,build):
 capture=run/'capture';rows=[json.loads(line) for line in read(capture/'calls.jsonl').splitlines()]
 result={};details={}
 if case in {'cancelled-core-clock','cancelled-final-writer-clock','missing-mode1-delivery'}:
  cuts=[]
  if case=='missing-mode1-delivery':
   begin=end=None
   for at,m,b in journal_records(capture/'journal.bin'):
    if begin is None and m==b'HBPAC001' and get(b,48)==2 and get(b,56)==1:begin=(at,b)
    elif begin is not None and m==b'HBPAA001':end=(at,b);break
   assert begin is not None and end is not None
   cuts=[(at,at+len(b)) for at,b in [begin,end]]
  else:
   job,owner=(1,1) if case=='cancelled-core-clock' else (4,2)
   last=None
   for at,m,b in journal_records(capture/'journal.bin'):
    if m==b'HBCLOCK1' and get(b,16)==job and get(b,32)==owner:last=(at,b)
   assert last is not None
   at,b=last;cuts=[(at,at+len(b))];details={'job':job,'owner':owner,'descriptor_sha256':sha(b)}
  result['run/capture/journal.bin']={'splice':str(capture/'journal.bin'),'cuts':cuts}
  for row in rows:
   if 'journal_bytes' in row:
    old=row['journal_bytes'];assert not any(a<old<b for a,b in cuts)
    row['journal_bytes']=old-sum(b-a for a,b in cuts if b<=old)
  result['run/capture/calls.jsonl']=jsonl(rows);details['removed_ranges']=cuts
 elif case=='caller-workspace-identity':
  pin=next(row['after']['rows'][0]['buffers']['72'] for row in rows if row['phase']=='end' and row['after']['rows'] and row['after']['rows'][0]['buffers']['72'])
  raw=read(capture/'blobs'/pin['sha256']);assert raw[:8]==b'HBLCST01';changed=b'X'+raw[1:];new={'bytes':len(changed),'sha256':sha(changed)}
  def replace(v):
   if isinstance(v,dict):
    if v==pin:return new
    return {k:replace(x) for k,x in v.items()}
   if isinstance(v,list):return [replace(x) for x in v]
   return v
  result['run/capture/calls.jsonl']=jsonl(replace(rows));result['run/capture/blobs/'+pin['sha256']]=None;result['run/capture/blobs/'+new['sha256']]=changed
  details={'old':pin,'new':new}
 elif case=='ready-fifo-copy':
  ready=[r for r in rows if r['phase']=='ready' and r['code']==32];assert len(ready)==4
  details={'old':ready[0]['event'],'new':ready[1]['event']};ready[0]['event']=ready[1]['event'];result['run/capture/calls.jsonl']=jsonl(rows)
 elif case=='changed-mechanical-source':
  name='source/runtime_mcp_bellman_port.S';result['build/'+name]=read(build/name)+b'\n/* changed source */\n'
 elif case=='missing-final-destroy-attempt':
  value=doc(capture/'RESULT.json');attempts=value['groups'][3]['destroy_attempts']
  assert attempts;details={'removed_actual_destroy_call':attempts.pop()}
  result['run/capture/RESULT.json']=encoded(value)
 elif case=='changed-domain-claim':
  value=doc(capture/'RESULT.json');value['controls'][0]='omitted-empty-control';result['run/capture/RESULT.json']=encoded(value)
 else:raise AssertionError(case)
 return result,details

def one_case(case,run,build,output):
 assert case in CASES;folder=output/case;folder.mkdir();rp=files(run);bp=files(build)
 copy_exact(run,folder/'run',rp);changes,details=mutation(case,run,build);candidate_build=build
 if any(n.startswith('build/') for n in changes):copy_exact(build,folder/'build',bp);candidate_build=folder/'build'
 for name,value in changes.items():
  path=folder/name
  if value is None:path.unlink()
  else:
   path.parent.mkdir(parents=True,exist_ok=True)
   with path.open('wb') as stream:
    for chunk in chunks(value):stream.write(chunk)
 change_pins={name:value_pin(value) for name,value in changes.items()}
 del changes,value
 gc.collect()
 try:verify(candidate_build,folder/'run/capture')
 except AssertionError as exc:failure={'type':'AssertionError','message':str(exc),'traceback':traceback.format_exc()}
 else:raise AssertionError('mutated evidence accepted: '+case)
 row={'case':case,'details':details,'changes':change_pins,'failure':failure,'native_or_rust_executed':False}
 (folder/'REFUSAL.json').write_bytes(encoded(row));return row

def create(run,build,output):
 assert not output.exists();baseline=verify(build,run/'capture');output.mkdir();(output/'processes').mkdir()
 rp=files(run);bp=files(build);observed=[];processes=[];start=time.monotonic()
 for case in CASES:
  command=[sys.executable,'-I','-S','-B',str(pathlib.Path(__file__).resolve()),'--run',str(run),'--build',str(build),'--output',str(output),'--case',case]
  receipt={'command':command,'timeout_seconds':60,'parent_pid':os.getpid(),'started':False};child=None;t0=time.monotonic_ns()
  try:
   with (output/'processes'/(case+'.stdout')).open('xb') as out,(output/'processes'/(case+'.stderr')).open('xb') as err:
    child=subprocess.Popen(command,stdout=out,stderr=err,start_new_session=True);receipt.update(started=True,pid=child.pid,pgid=child.pid)
    try:receipt['returncode']=child.wait(timeout=60);receipt['timed_out']=False
    except subprocess.TimeoutExpired:receipt['timed_out']=True;raise
  finally:
   if child is not None:
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    receipt['returncode']=child.wait()
   receipt['elapsed_ns']=time.monotonic_ns()-t0
   for name in ['stdout','stderr']:
    raw=read(output/'processes'/(case+'.'+name));receipt[name]={'bytes':len(raw),'sha256':sha(raw)}
   (output/'processes'/(case+'.json')).write_bytes(encoded(receipt))
  assert receipt['returncode']==0 and not receipt['timed_out'],(case,receipt)
  row=doc(output/case/'REFUSAL.json');assert json.loads(read(output/'processes'/(case+'.stdout')))==row and read(output/'processes'/(case+'.stderr'))==b''
  observed.append(row);processes.append(receipt)
 report={'status':'PHYSICAL_PORT_REFUSALS_PASS','cases':CASES,'baseline':baseline,'run_origin':str(run),'build_origin':str(build),'output_origin':str(output),'run_files':rp,'build_files':bp,'refusals':observed,'processes':processes,'elapsed_seconds':time.monotonic()-start,'native_or_rust_executed':False}
 (output/'RESULT.json').write_bytes(encoded(report));return report

def verify_controls(run,build,output):
 report=doc(output/'RESULT.json');assert report['status']=='PHYSICAL_PORT_REFUSALS_PASS' and report['cases']==CASES and report['native_or_rust_executed'] is False
 assert report['run_files']==files(run) and report['build_files']==files(build)
 assert report['baseline']==verify(build,run/'capture') and len(report['refusals'])==len(CASES)
 assert len(report['processes'])==len(CASES)
 for case,row,process in zip(CASES,report['refusals'],report['processes']):
  folder=output/case;changes,details=mutation(case,run,build);assert row['case']==case and row['details']==json.loads(json.dumps(details))
  expected_changes={name:value_pin(value) for name,value in changes.items()};assert row['changes']==expected_changes
  for kind,original,pins in [('run',run,report['run_files'])]+([('build',build,report['build_files'])] if any(n.startswith('build/') for n in changes) else []):
   expected=dict(pins)
   for name,pin in expected_changes.items():
    if name.startswith(kind+'/'):
     rel=name[len(kind)+1:]
     if pin is None:expected.pop(rel)
     else:expected[rel]=pin
   assert files(folder/kind)==expected
   for name in expected:
    key=kind+'/'+name;wanted=changes[key] if key in changes else {'splice':str(original/name),'cuts':[]}
    same_content(folder/kind/name,wanted)
  assert doc(folder/'REFUSAL.json')==row and row['failure']['type']=='AssertionError'
  assert doc(output/'processes'/(case+'.json'))==process and process['started'] is True and process['returncode']==0 and process['timed_out'] is False
  assert process['timeout_seconds']==60 and 0<=process['elapsed_ns']<=60_000_000_000 and process['pid']==process['pgid']>0 and process['parent_pid']>0
  command=process['command'];assert len(command)==13 and command[1:4]==['-I','-S','-B'] and pathlib.Path(command[4]).name=='port_reader_controls.py' and command[5:]==['--run',report['run_origin'],'--build',report['build_origin'],'--output',report['output_origin'],'--case',case]
  for name in ['stdout','stderr']:
   raw=read(output/'processes'/(case+'.'+name));assert process[name]=={'bytes':len(raw),'sha256':sha(raw)}
  assert json.loads(read(output/'processes'/(case+'.stdout')))==row and read(output/'processes'/(case+'.stderr'))==b''
  del changes
  gc.collect()
  candidate=folder/'build' if (folder/'build').exists() else build
  try:verify(candidate,folder/'run/capture')
  except AssertionError as exc:assert str(exc)==row['failure']['message']
  else:raise AssertionError('retained mutant now accepted: '+case)
 assert {p.name for p in output.iterdir()}==set(CASES)|{'RESULT.json','processes'}
 assert {p.name for p in (output/'processes').iterdir()}=={case+'.'+suffix for case in CASES for suffix in ['json','stdout','stderr']}
 return {'status':'READ_ONLY_PORT_REFUSALS_PASS','cases':len(CASES),'physical_copies_checked':len(CASES),'complete_bytes_compared':True,'native_or_rust_executed':False,'verified_tree_writes':False}

def main():
 p=argparse.ArgumentParser();p.add_argument('--run',type=pathlib.Path,required=True);p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--verify',action='store_true');p.add_argument('--case',choices=CASES);a=p.parse_args()
 assert not (a.case and a.verify)
 if a.case:r=one_case(a.case,a.run.resolve(),a.build.resolve(),a.output.resolve())
 else:r=(verify_controls if a.verify else create)(a.run.resolve(),a.build.resolve(),a.output.resolve())
 print(json.dumps({k:v for k,v in r.items() if k not in {'run_files','build_files','refusals','processes'}},sort_keys=True))
if __name__=='__main__':main()
