"""Necessary physical/reforged refusals over the frozen Batch public evidence."""
from pathlib import Path
import argparse,copy,gzip,json,os,shutil,struct,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import strict_public as q
import state_comparison as state
import trace_evidence as trace
from capture_format import Files,actual_process,blob,canonical,need,parse_records,pin,same,strict_json,uint
CONTROL_NAMES=(
 ('process-json',('missing-deadline','boolean-pid','changed-deadline','actual-timeout','duplicate-json','overflow-json')),
 ('complete-binding',('native-source-byte','private-elf-byte','original-function-byte','missing-original-stderr','native-input-truncation','causal-native-object')),
 ('complete-record',('record-magic','record-truncation','record-trailing','request-byte','response-byte','transport-error-utf8')),
 ('actual-kernel',('duplicate-marker','missing-marker','missing-fixture-close','pipe-byte','receipt-truncation','negative-elapsed')),
 ('terminal-state',('caller-retained-lock','lock-still-held','context-escaped','scope-still-active','history-body','cache-body')),
 ('lifecycle-order',('fence-after-scope','failed-fence-continued','scope-drop-missing','history-after-write','cache-before-rename','active-context-outside')),
)
def encode_records(raw,rows):
 out=bytearray(b'HBCSO002')
 for row in rows:
  m=canonical(row['metadata'])[:-1];out+=struct.pack('<2Q',len(m),len(row['blobs']))+m
  for i in range(len(row['blobs'])):
   b=blob(raw,row,i);out+=struct.pack('<Q',len(b))+b
 return bytes(out)
def write_new(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb')as f:f.write(raw)
def pinraw(raw):return q.raw_pin(raw)
def main():
 a=argparse.ArgumentParser();a.add_argument('--request',type=Path,required=True);a.add_argument('--baseline',type=Path,required=True);a.add_argument('--output',type=Path,required=True);args=a.parse_args()
 D=args.output.absolute();D.mkdir();request=strict_json(args.request.read_bytes());baseline=strict_json(args.baseline.read_bytes())
 write_new(D/'REQUEST.json',canonical(request));write_new(D/'BASELINE.json',canonical(baseline))
 source={p.name:pin(p)for p in Path(__file__).parent.glob('*.py')};write_new(D/'SOURCE.json',canonical(source))
 write_new(D/'remote-process.json',canonical({'pid':os.getpid(),'argv':sys.argv,'cgroup':Path('/proc/self/cgroup').read_text()}))
 before=time.monotonic_ns();actual=q.evidence(**request);same(actual,baseline,'complete unchanged positive baseline')
 nr={k:request[k]for k in('qualification_source','native_source','native_output','native_receipt','graph','origins')};nr['causal_source']=request['original_source']
 native=q.native_evidence(**nr);write_new(D/'NATIVE-ONLY.json',canonical(native))
 need(native['fresh_original_comparison']is False and not any(Path(request['original_output'])==Path(p)or Path(request['original_output'])in Path(p).parents for p in native['artifact_sha256']),'native-only reads no original captures')
 N=Path(request['native_output']);O=Path(request['original_output']);G=Path(request['graph']);files=Files(request['origins'])
 mirror=D/'mirror';mirror.mkdir()
 for name,expected in baseline['artifact_sha256'].items():
  old=Path(name);rel=old.relative_to('/');p=mirror/rel;p.parent.mkdir(parents=True,exist_ok=True);os.link(files.file(name),p);same(pin(p),expected,'complete physical mirror')
 replay=dict(request,origins=[['/',str(mirror)]])
 # Select existing successful business observations, never synthesize semantics.
 row=q.js(files,N/'scenario-012/RESULT.json')
 raw=q.bound(files,O/'processes/sdk-012/stdout.bin');records=parse_records(raw,b'HBCSO002',counted=False)
 index=next(i for i,r in enumerate(records)if r['metadata'].get('kind')=='case'and any(e['kind']=='note_write_enter'for e in r['metadata']['events']))
 original_case=records[index];meta=original_case['metadata'];native_case=next(x for x in row['steps']if x['input']['case_id']==meta['case_id']);step=next(x for x in row['input']['steps']if x['case_id']==meta['case_id'])
 original_trace=q.bound(files,O/'scenario-012/original.strace');ot=trace.parse_trace(original_trace,markers=True)
 native_trace=q.bound(files,Path(row['process']['trace']['path']));nt=trace.parse_trace(native_trace,markers=False)
 streams={k:q.saved_stream(files,v)for k,v in row['process']['streams'].items()}
 observed={'request':q.saved_blob(files,native_case['observed']['wire']),'body':q.saved_blob(files,native_case['observed']['body']),'mode':native_case['observed']['exchange']['header']['mode']}
 base_process=q.js(files,O/'processes/build/PROCESS.json')
 results=[];current=None;mutations=[]
 def physical(name,data):
  p=current/name;write_new(p,data);mutations.append({'file':str(p.relative_to(D)),**pinraw(data)});return p
 def reject(group,name,fn):
  nonlocal current,mutations
  current=D/name;current.mkdir();mutations=[];started=time.monotonic_ns()
  try:fn()
  except (ValueError,KeyError,FileNotFoundError,UnicodeDecodeError)as error:
   finished=time.monotonic_ns();result={'group':group,'name':name,'status':'REJECTED','exception':type(error).__name__,'message':str(error),'started_monotonic_ns':started,'finished_monotonic_ns':finished,'elapsed_seconds':(finished-started)/1e9,'mutations':mutations};write_new(current/'RESULT.json',canonical(result));results.append(result);return
  raise AssertionError('corrupted evidence admitted: '+name)
 def changed_process(name):
  r=copy.deepcopy(base_process)
  if name=='missing-deadline':r.pop('timeout_seconds')
  elif name=='boolean-pid':r['pid']=True
  elif name=='changed-deadline':r['timeout_seconds']=181
  elif name=='actual-timeout':r['timed_out']=True
  b=canonical(r)
  if name=='duplicate-json':b=b'{"pid":1,'+b[1:]
  if name=='overflow-json':b=b'{"overflow":1e9999,'+b[1:]
  p=physical('process.json',b);value=strict_json(p.read_bytes());actual_process(value,base_process['command'],base_process['cwd'])
 def complete_binding(name):
  if name=='native-source-byte':target=Path(request['native_source'])/'capture_native.py'
  elif name=='private-elf-byte':
   target=Path(q.js(files,N/'RESULT.json')['native_elf']['path'])
  elif name=='original-function-byte':target=Path(request['original_source'])/'oracle/original/text_editing.rs'
  elif name=='missing-original-stderr':target=Path(request['original_receipt']).parent/'stderr.bin'
  elif name=='native-input-truncation':target=Path(q.js(files,N/'scenario-000/RESULT.json')['process']['streams']['stdin']['path'])
  else:target=O/'NATIVE-EVIDENCE.json'
  copy_target=mirror/target.relative_to('/');base=files.raw(str(target))
  if name=='native-input-truncation':data=base[:-1]
  elif name=='causal-native-object':
   v=strict_json(base);v['status']='ALTERED';data=canonical(v)
  else:data=bytes([base[0]^1])+base[1:]if base else b'x'
  if name=='missing-original-stderr':data=None
  physical('mutation.json',canonical({'target':str(target),'before':pinraw(base),'after':None if data is None else pinraw(data),'missing':data is None}))
  if data is not None:physical('replacement.bin',data)
  copy_target.unlink()
  if data is not None:write_new(copy_target,data)
  try:q.evidence(**replay)
  finally:
   if copy_target.exists()or copy_target.is_symlink():copy_target.unlink()
   os.link(files.file(str(target)),copy_target)
 def record_control(name):
  if name=='transport-error-utf8':
   b=q.bound(files,O/'processes/sdk-011/stdout.bin');rr=parse_records(b,b'HBCSO002',counted=False);r=next(x for x in rr if x['metadata'].get('result',{}).get('transport')=='write-error')
   at=r['blobs'][r['metadata']['result']['error']['short_blob']]['offset'];b=b[:at]+b'\xff'+b[at+1:]
   p=physical('original.bin',b);b=p.read_bytes();r=next(x for x in parse_records(b,b'HBCSO002',counted=False)if x['metadata'].get('case_id')==90103)
   q.actual_response(r['metadata'],{'request':blob(b,r,r['metadata']['result']['request_blob']),'body':b'','mode':3},lambda i:blob(b,r,i));return
  b=raw
  if name=='record-magic':b=b'X'+b[1:]
  elif name=='record-truncation':b=b[:-1]
  elif name=='record-trailing':b+=b'X'
  else:
   key='request_blob'if name=='request-byte'else'response_blob';at=original_case['blobs'][meta['result'][key]]['offset'];b=b[:at]+bytes([b[at]^1])+b[at+1:]
  p=physical('original.bin',b);b=p.read_bytes();rr=parse_records(b,b'HBCSO002',counted=False)
  if name in('request-byte','response-byte'):
   r=rr[index];q.actual_response(r['metadata'],observed,lambda i:blob(b,r,i))
 def kernel_control(name):
  if name in('duplicate-marker','missing-marker'):
   mark=next(x for x in ot['records']if x['name']=='getpgid');seg=mark['segments'][0];at,n=seg['offset'],seg['bytes'];part=original_trace[at:at+n]
   b=original_trace[:at]+(part+part if name=='duplicate-marker'else b'')+original_trace[at+n:]
   trace.parse_trace(physical('trace.txt',b).read_bytes(),markers=True);return
  if name=='missing-fixture-close':
   candidates=[]
   for r in nt['records']:
    if r['name']=='close'and r['return']==0:
     try:fd,path=trace.fd_target(r['args'])
     except ValueError:continue
     if path and path.startswith(os.fsencode(N/'files')+b'/'):candidates.append(r)
   need(candidates,'actual fixture close selected');r=candidates[-1]
   b=native_trace
   for s in sorted(r['segments'],key=lambda x:x['offset'],reverse=True):b=b[:s['offset']]+b[s['offset']+s['bytes']:]
   parsed=trace.parse_trace(physical('trace.txt',b).read_bytes(),markers=False);trace.descriptor_lifetimes(parsed,os.fsencode(N/'files'));return
  if name=='pipe-byte':
   b=streams['stdout'];b=bytes([b[0]^1])+b[1:];b=physical('stdout.bin',b).read_bytes();trace.stream_evidence(nt,stdin=streams['stdin'],stdout=b,stderr=streams['stderr']);return
  if name=='receipt-truncation':
   trace.native_receipts(physical('stderr.bin',streams['stderr'][:-1]).read_bytes());return
  r=next(x for x in nt['records']if x['name']=='openat'and len(x['segments'])==1);s=r['segments'][0];part=native_trace[s['offset']:s['offset']+s['bytes']]
  import re
  changed=re.sub(rb' <([0-9.]+)>\n$',rb' <-\1>\n',part);need(changed!=part,'actual elapsed span changed')
  b=native_trace[:s['offset']]+changed+native_trace[s['offset']+s['bytes']:]
  trace.parse_trace(physical('trace.txt',b).read_bytes(),markers=False)
 def state_control(name):
  n=copy.deepcopy(native_case);key=n['input']['session'];state_view=n['after_state'][key];section={'caller-retained-lock':'caller','lock-still-held':'locks','context-escaped':'context','scope-still-active':'scope','history-body':'history'}.get(name)
  def save_descriptor(d,data):
   p=physical('state.bin',data);compressed=gzip.compress(data,mtime=0);pp=physical('state.bin.gz',compressed)
   return {'path':str(pp),'bytes':len(data),'sha256':q.sha(data),'compressed':pinraw(compressed)}
  if name=='cache-body':
   d=state_view['view']['sections']['cache'];data=bytearray(q.saved_blob(files,d));struct.pack_into('<Q',data,32,1);state_view['view']['sections']['cache']=save_descriptor(d,bytes(data))
  else:
   d=state_view['batch']['sections'][section];data=bytearray(q.saved_blob(files,d))
   if name=='caller-retained-lock':struct.pack_into('<Q',data,120,1)
   elif name=='lock-still-held':
    head=state.word(bytes(data),32);need(head>0,'actual completed lock node');struct.pack_into('<Q',data,head+48,1)
   elif name=='context-escaped':data[0]=1
   elif name=='scope-still-active':struct.pack_into('<Q',data,24,1)
   else:
    kn,vn=struct.unpack_from('<2Q',data,64);need(vn>0,'actual History body');data[80+kn]^=1
   state_view['batch']['sections'][section]=save_descriptor(d,bytes(data))
  p=physical('native-step.json',canonical(n));nf=Files([['/','/']])
  q.compare_state(nf,strict_json(p.read_bytes()),meta,lambda i:blob(raw,original_case,i),row['input'],[],[])
 def order_control(name):
  r=copy.deepcopy(original_case);m=r['metadata'];events=m['events'];kinds=[e['kind']for e in events]
  def swap(a,b):i,j=kinds.index(a),kinds.index(b);events[i],events[j]=events[j],events[i]
  if name=='fence-after-scope':swap('effect_fence_enter','scope_enter')
  elif name=='failed-fence-continued':events[kinds.index('effect_fence_exit')]['data']['ok']=False
  elif name=='scope-drop-missing':events.pop(kinds.index('scope_future_drop_complete'))
  elif name=='history-after-write':swap('history_exit','tokio_write_enter')
  elif name=='cache-before-rename':swap('note_write_enter','tokio_rename_enter')
  else:events[0]['request_context']['present']=True
  rr=copy.deepcopy(records);rr[index]=r;b=encode_records(raw,rr);p=physical('original-resigned.bin',b);b=p.read_bytes();r=parse_records(b,b'HBCSO002',counted=False)[index]
  physical('resigned-record.json',canonical(r));trace.public_lifecycle(r['metadata'],step,lambda i:blob(b,r,i),ot)
 handlers={'process-json':changed_process,'complete-binding':complete_binding,'complete-record':record_control,'actual-kernel':kernel_control,'terminal-state':state_control,'lifecycle-order':order_control}
 for group,names in CONTROL_NAMES:
  for name in names:reject(group,name,lambda name=name,group=group:handlers[group](name))
 same(len(results),36,'all necessary controls');same({p.name:pin(p)for p in Path(__file__).parent.glob('*.py')},source,'test/reader source unchanged')
 for name,expected in baseline['artifact_sha256'].items():same(pin(files.file(name)),expected,'all original artifacts unchanged')
 result={'schema':'hepta.runtime.batch-public-evidence-controls.v1','status':'PASS','groups':6,'controls':36,'baseline':pin(D/'BASELINE.json'),'source':pin(D/'SOURCE.json'),'native_only':pin(D/'NATIVE-ONLY.json'),'rows':results,'elapsed_seconds':(time.monotonic_ns()-before)/1e9,'new_native_calls':0,'new_rust_processes':0}
 write_new(D/'RESULT.json',canonical(result));print(json.dumps({k:v for k,v in result.items()if k!='rows'}),flush=True)
if __name__=='__main__':main()
