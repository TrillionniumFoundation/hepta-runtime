"""Consume the actual physical/reforged reader-control records without mutation."""
from pathlib import Path
import copy,gzip,os,re,struct
from capture_format import Files,actual_process,blob,canonical,fields,need,parse_records,pin,same,strict_json,uint
import strict_public as q
import trace_evidence as trace

def controls_evidence(*,request,controls,receipt,origins):
 files=Files(origins);D=Path(controls);P=Path(receipt);request=dict(request,origins=origins)
 same(Path(__file__).read_bytes(),q.bound(files,Path(request['qualification_source'])/'qualification/consumer.py'),'actual executed aggregate consumer')
 base=q.evidence(**request);saved=q.js(files,D/'BASELINE.json');same(saved,base,'entire original-qualified baseline')
 wanted=q.js(files,D/'REQUEST.json');same({k:v for k,v in wanted.items()if k!='origins'},{k:v for k,v in request.items()if k!='origins'},'actual control source/input roots')
 test=q.load(files,Path(request['qualification_source'])/'test_evidence.py','_batch_public_control_source')
 expected_names=[name for group,names in test.CONTROL_NAMES for name in names]
 result=q.js(files,D/'RESULT.json');same([x['name']for x in result['rows']],expected_names,'all source-declared36 physical controls')
 same(result['baseline'],q.raw_pin(q.bound(files,D/'BASELINE.json')),'complete baseline pin')
 sources=q.js(files,D/'SOURCE.json');same(sorted(sources),sorted(('capture_format.py','trace_evidence.py','state_comparison.py','strict_public.py','test_evidence.py')),'actual control source closure')
 for name,expected in sources.items():q.bound(files,Path(request['qualification_source'])/name,expected)
 same(result['source'],q.raw_pin(q.bound(files,D/'SOURCE.json')),'complete control source table')
 process=q.js(files,P);cmd=process['command']
 same(len(cmd),10,'actual source-owned control invocation')
 same(cmd[1:5],['-I','-B',str(Path(request['qualification_source'])/'test_evidence.py'),'--request'],'actual control test')
 same(cmd[6::2],['--baseline','--output'],'actual control named inputs')
 same(cmd[9],str(D),'actual control output')
 same(q.js(files,Path(cmd[5])),wanted,'actual request input bytes');same(q.js(files,Path(cmd[7])),base,'actual baseline input bytes')
 actual_process(process,cmd,Path(request['native_output']).parent)
 stdout=q.bound(files,P.parent/'stdout.bin',process['stdout']);same(q.bound(files,P.parent/'stderr.bin',process['stderr']),b'','actual control stderr')
 same(strict_json(stdout),{k:v for k,v in result.items()if k!='rows'},'whole actual control stdout')
 remote=q.js(files,D/'remote-process.json');same(remote['pid'],process['pid'],'actual control PID');same(remote['argv'],cmd[3:],'actual control argv');need(type(remote['cgroup'])is str,'actual control cgroup')
 nr={k:request[k]for k in('qualification_source','native_source','native_output','native_receipt','graph','origins')};nr['causal_source']=request['original_source']
 native=q.native_evidence(**nr);same(q.js(files,D/'NATIVE-ONLY.json'),native,'complete independently admitted native-only object');same(result['native_only'],q.raw_pin(q.bound(files,D/'NATIVE-ONLY.json')),'native-only whole pin')
 N=Path(request['native_output']);O=Path(request['original_output']);G=Path(request['graph'])
 source_case=q.js(files,N/'scenario-012/RESULT.json');raw=q.bound(files,O/'processes/sdk-012/stdout.bin');records=parse_records(raw,b'HBCSO002',counted=False)
 index=next(i for i,r in enumerate(records)if r['metadata'].get('kind')=='case'and any(e['kind']=='note_write_enter'for e in r['metadata']['events']))
 record=records[index];meta=record['metadata'];native_case=next(x for x in source_case['steps']if x['input']['case_id']==meta['case_id']);step=native_case['input']
 observed={'request':q.saved_blob(files,native_case['observed']['wire']),'body':q.saved_blob(files,native_case['observed']['body']),'mode':native_case['observed']['exchange']['header']['mode']}
 ot=trace.parse_trace(q.bound(files,O/'scenario-012/original.strace'),markers=True);nt=trace.parse_trace(q.bound(files,Path(source_case['process']['trace']['path'])),markers=False)
 streams={k:q.saved_stream(files,v)for k,v in source_case['process']['streams'].items()}
 original_process=q.js(files,O/'processes/build/PROCESS.json')
 def expected_mutations(group,name):
  """Rebuild the named corruption from admitted complete source observations.

  A generic parse failure cannot stand in for a different semantic control.
  Paths inside resigned descriptors remain the recorded execution origins.
  """
  c=D/name
  if group=='process-json':
   changed=copy.deepcopy(original_process)
   if name=='missing-deadline':changed.pop('timeout_seconds')
   elif name=='boolean-pid':changed['pid']=True
   elif name=='changed-deadline':changed['timeout_seconds']=181
   elif name=='actual-timeout':changed['timed_out']=True
   data=canonical(changed)
   if name=='duplicate-json':data=b'{"pid":1,'+data[1:]
   elif name=='overflow-json':data=b'{"overflow":1e9999,'+data[1:]
   return {'process.json':data}
  if group=='complete-binding':
   targets={'native-source-byte':Path(request['native_source'])/'capture_native.py',
    'private-elf-byte':Path(q.js(files,N/'RESULT.json')['native_elf']['path']),
    'original-function-byte':Path(request['original_source'])/'oracle/original/text_editing.rs',
    'missing-original-stderr':Path(request['original_receipt']).parent/'stderr.bin',
    'native-input-truncation':Path(q.js(files,N/'scenario-000/RESULT.json')['process']['streams']['stdin']['path']),
    'causal-native-object':O/'NATIVE-EVIDENCE.json'}
   target=targets[name];before=q.bound(files,target)
   if name=='missing-original-stderr':after=None
   elif name=='native-input-truncation':after=before[:-1]
   elif name=='causal-native-object':
    value=strict_json(before);value['status']='ALTERED';after=canonical(value)
   else:after=bytes([before[0]^1])+before[1:]if before else b'x'
   result={'mutation.json':canonical({'target':str(target),'before':q.raw_pin(before),
    'after':None if after is None else q.raw_pin(after),'missing':after is None})}
   if after is not None:result['replacement.bin']=after
   return result
  if group=='complete-record':
   data=raw
   if name=='transport-error-utf8':
    data=q.bound(files,O/'processes/sdk-011/stdout.bin')
    original_records=parse_records(data,b'HBCSO002',counted=False)
    selected=next(r for r in original_records if r['metadata'].get('result',{}).get('transport')=='write-error')
    at=selected['blobs'][selected['metadata']['result']['error']['short_blob']]['offset']
    data=data[:at]+b'\xff'+data[at+1:]
   elif name=='record-magic':data=b'X'+data[1:]
   elif name=='record-truncation':data=data[:-1]
   elif name=='record-trailing':data+=b'X'
   else:
    key='request_blob'if name=='request-byte'else'response_blob'
    at=record['blobs'][meta['result'][key]]['offset'];data=data[:at]+bytes([data[at]^1])+data[at+1:]
   return {'original.bin':data}
  if group=='actual-kernel':
   if name=='pipe-byte':
    data=streams['stdout'];return {'stdout.bin':bytes([data[0]^1])+data[1:]}
   if name=='receipt-truncation':return {'stderr.bin':streams['stderr'][:-1]}
   if name in('duplicate-marker','missing-marker'):
    data=q.bound(files,O/'scenario-012/original.strace')
    marker=next(r for r in ot['records']if r['name']=='getpgid');segment=marker['segments'][0]
    at,size=segment['offset'],segment['bytes'];part=data[at:at+size]
    return {'trace.txt':data[:at]+(part+part if name=='duplicate-marker'else b'')+data[at+size:]}
   data=q.bound(files,Path(source_case['process']['trace']['path']))
   if name=='missing-fixture-close':
    candidates=[]
    for event in nt['records']:
     if event['name']=='close'and event['return']==0:
      try:fd,path=trace.fd_target(event['args'])
      except ValueError:continue
      if path and path.startswith(os.fsencode(N/'files')+b'/'):candidates.append(event)
    need(candidates,'source-selected fixture close exists')
    for segment in sorted(candidates[-1]['segments'],key=lambda x:x['offset'],reverse=True):
     data=data[:segment['offset']]+data[segment['offset']+segment['bytes']:]
   else:
    event=next(r for r in nt['records']if r['name']=='openat'and len(r['segments'])==1)
    segment=event['segments'][0];at,size=segment['offset'],segment['bytes'];part=data[at:at+size]
    changed=re.sub(rb' <([0-9.]+)>\n$',rb' <-\1>\n',part)
    need(changed!=part,'source-selected elapsed span changed');data=data[:at]+changed+data[at+size:]
   return {'trace.txt':data}
  if group=='terminal-state':
   changed=copy.deepcopy(native_case);view=changed['after_state'][changed['input']['session']]
   section={'caller-retained-lock':'caller','lock-still-held':'locks','context-escaped':'context',
    'scope-still-active':'scope','history-body':'history'}.get(name)
   descriptor=view['view']['sections']['cache']if name=='cache-body'else view['batch']['sections'][section]
   data=bytearray(q.saved_blob(files,descriptor))
   if name=='cache-body':struct.pack_into('<Q',data,32,1)
   elif name=='caller-retained-lock':struct.pack_into('<Q',data,120,1)
   elif name=='lock-still-held':
    head=q.states.word(bytes(data),32);need(head>0,'source-selected completed lock node');struct.pack_into('<Q',data,head+48,1)
   elif name=='context-escaped':data[0]=1
   elif name=='scope-still-active':struct.pack_into('<Q',data,24,1)
   else:
    key_size,value_size=struct.unpack_from('<2Q',data,64);need(value_size>0,'source-selected History body');data[80+key_size]^=1
   data=bytes(data);compressed=gzip.compress(data,mtime=0)
   descriptor={'path':str(c/'state.bin.gz'),'bytes':len(data),'sha256':q.sha(data),'compressed':q.raw_pin(compressed)}
   if name=='cache-body':view['view']['sections']['cache']=descriptor
   else:view['batch']['sections'][section]=descriptor
   return {'state.bin':data,'state.bin.gz':compressed,'native-step.json':canonical(changed)}
  need(group=='lifecycle-order','source-selected control group')
  changed=copy.deepcopy(record);events=changed['metadata']['events'];kinds=[event['kind']for event in events]
  def swap(a,b):i,j=kinds.index(a),kinds.index(b);events[i],events[j]=events[j],events[i]
  if name=='fence-after-scope':swap('effect_fence_enter','scope_enter')
  elif name=='failed-fence-continued':events[kinds.index('effect_fence_exit')]['data']['ok']=False
  elif name=='scope-drop-missing':events.pop(kinds.index('scope_future_drop_complete'))
  elif name=='history-after-write':swap('history_exit','tokio_write_enter')
  elif name=='cache-before-rename':swap('note_write_enter','tokio_rename_enter')
  else:events[0]['request_context']['present']=True
  changed_records=copy.deepcopy(records);changed_records[index]=changed
  data=test.encode_records(raw,changed_records)
  resigned=parse_records(data,b'HBCSO002',counted=False)[index]
  return {'original-resigned.bin':data,'resigned-record.json':canonical(resigned)}
 control_artifacts={}
 for group,names in test.CONTROL_NAMES:
  for name in names:
   c=D/name;row=q.js(files,c/'RESULT.json');same(row,next(x for x in result['rows']if x['name']==name),'complete physical refusal result')
   same(row['group'],group,'exact source-owned control group');same(row['status'],'REJECTED','actual refusal')
   need(row['exception']in('ValueError','KeyError','FileNotFoundError','UnicodeDecodeError')and type(row['message'])is str and row['message'],'actual complete refusal')
   start=uint(row['started_monotonic_ns'],'actual control start');end=uint(row['finished_monotonic_ns'],'actual control end');need(process['started_monotonic_ns']<=start<end<=process['finished_monotonic_ns'],'actual control interval');same(row['elapsed_seconds'],(end-start)/1e9,'actual control elapsed')
   seen=set()
   for item in row['mutations']:
    fields(item,('file','bytes','sha256'),'complete physical changed file')
    rel=Path(item['file']);need(not rel.is_absolute()and '..'not in rel.parts and rel.parts[0]==name and str(rel)not in seen,'owned control mutation');seen.add(str(rel));q.bound(files,D/rel,{k:item[k]for k in('bytes','sha256')})
   need(seen,'actual physical corruption required')
   def raw_control(filename):need(name+'/'+filename in seen,'complete named mutation');return q.bound(files,c/filename)
   expected=expected_mutations(group,name)
   same(row['mutations'],[{'file':name+'/'+filename,**q.raw_pin(data)}for filename,data in expected.items()],
        'exact source-derived named mutation set')
   physical_case=files.path(str(c/'RESULT.json')).parent
   same(sorted(child.name for child in physical_case.iterdir()),sorted(('RESULT.json',*expected)),
        'complete physical named control file set')
   for filename,data in expected.items():same(raw_control(filename),data,'complete source-derived control bytes: '+name+'/'+filename)
   def expect_refusal(fn):
    try:fn()
    except (ValueError,KeyError,FileNotFoundError,UnicodeDecodeError)as error:
     same(type(error).__name__,row['exception'],'same actual refusal exception type');return
    raise ValueError('retained corruption no longer refused: '+name)
   if group=='process-json':
    expect_refusal(lambda:actual_process(strict_json(raw_control('process.json')),original_process['command'],original_process['cwd']))
   elif group=='complete-binding':
    mutation=strict_json(raw_control('mutation.json'));target=Path(mutation['target']);base_bytes=q.bound(files,target)
    same(mutation['before'],q.raw_pin(base_bytes),'actual complete preimage')
    allowed={'native-source-byte':Path(request['native_source'])/'capture_native.py','original-function-byte':Path(request['original_source'])/'oracle/original/text_editing.rs','missing-original-stderr':Path(request['original_receipt']).parent/'stderr.bin','native-input-truncation':Path(q.js(files,N/'scenario-000/RESULT.json')['process']['streams']['stdin']['path']),'causal-native-object':O/'NATIVE-EVIDENCE.json'}
    if name=='private-elf-byte':same(str(target),q.js(files,N/'RESULT.json')['native_elf']['path'],'actual selected private ELF');need(str(target)in base['artifact_sha256'],'admitted private ELF artifact')
    else:same(str(target),str(allowed[name]),'exact fixed full-binding target')
    if name=='missing-original-stderr':same(mutation['after'],None,'actual removed complete stderr');same(mutation['missing'],True,'actual missing control')
    else:
     data=raw_control('replacement.bin')
     if name=='native-input-truncation':expected=base_bytes[:-1]
     elif name=='causal-native-object':v=strict_json(base_bytes);v['status']='ALTERED';expected=canonical(v)
     else:expected=bytes([base_bytes[0]^1])+base_bytes[1:]if base_bytes else b'x'
     same(data,expected,'exact source-selected complete physical mutation');same(mutation['after'],q.raw_pin(data),'complete replacement pin');same(mutation['missing'],False,'actual replacement control')
    replacement=c/('absent.bin'if name=='missing-original-stderr'else'replacement.bin')
    if name=='missing-original-stderr':
     mapped=next(Path(new)/replacement.relative_to(Path(old))for old,new in sorted(origins,key=lambda x:len(Path(x[0]).parts),reverse=True)if replacement.is_relative_to(Path(old)))
     need(not mapped.exists()and not mapped.is_symlink(),'retained missing artifact must remain absent')
    else:mapped=files.file(str(replacement))
    altered=dict(request,origins=[[str(target),str(mapped)],*origins])
    expect_refusal(lambda:q.evidence(**altered))
   elif group=='complete-record':
    b=raw_control('original.bin')
    def check():
     rr=parse_records(b,b'HBCSO002',counted=False)
     if name in('request-byte','response-byte'):
      r=rr[index];q.actual_response(r['metadata'],observed,lambda i:blob(b,r,i))
     elif name=='transport-error-utf8':
      r=next(x for x in rr if x['metadata'].get('case_id')==90103);q.actual_response(r['metadata'],{'request':blob(b,r,r['metadata']['result']['request_blob']),'body':b'','mode':3},lambda i:blob(b,r,i))
    expect_refusal(check)
   elif group=='actual-kernel':
    if name=='pipe-byte':expect_refusal(lambda:trace.stream_evidence(nt,stdin=streams['stdin'],stdout=raw_control('stdout.bin'),stderr=streams['stderr']))
    elif name=='receipt-truncation':expect_refusal(lambda:trace.native_receipts(raw_control('stderr.bin')))
    else:
     def check():
      t=trace.parse_trace(raw_control('trace.txt'),markers=name in('duplicate-marker','missing-marker'))
      if name=='missing-fixture-close':trace.descriptor_lifetimes(t,bytes(str(N/'files'),'utf-8'))
     expect_refusal(check)
   elif group=='terminal-state':
    n=strict_json(raw_control('native-step.json'));expect_refusal(lambda:q.compare_state(files,n,meta,lambda i:blob(raw,record,i),source_case['input'],[],[]))
   else:
    b=raw_control('original-resigned.bin');rr=parse_records(b,b'HBCSO002',counted=False);r=rr[index]
    same(strict_json(raw_control('resigned-record.json')),r,'complete resigned metadata/blob index')
    expect_refusal(lambda:trace.public_lifecycle(r['metadata'],step,lambda i:blob(b,r,i),ot))
 for key,value in {'schema':'hepta.runtime.batch-public-evidence-controls.v1','status':'PASS','groups':6,'controls':36,'new_native_calls':0,'new_rust_processes':0}.items():same(result[key],value,'complete actual control scope '+key)
 artifacts={**base['artifact_sha256'],**native['artifact_sha256'],**files.artifacts}
 return {**base,'evidence_controls':{'result':result,'process':process,'native_only':native},'artifact_sha256':dict(sorted(artifacts.items()))}
