"""Pure admission of complete native-first Batch public capture."""
from pathlib import Path
import gzip,hashlib,importlib.util,json,os,stat,struct,sys
SOURCES={"HELPER-PROVENANCE.json":{"bytes":1594,"sha256":"85b3640e76417fa049d1d5dc6b301a0ac7475bc4126dc1d84bf44abcce70aa71"},"capture_common.py":{"bytes":21471,"sha256":"bae751774d2eb31125bfdf2ae1290022bb892ab3231a3c47c1769b6e56a464ab"},"capture_fixture.py":{"bytes":13691,"sha256":"876eb1991f4f7823e4021fb6ee7be27c117a44d5a492ff3ed67b50891d09327c"},"capture_native.py":{"bytes":14224,"sha256":"511a745a748f9b8da351043b910612ae1c639b50b6eec8313b0201b0ed5cc9f6"},"installation.py":{"bytes":774,"sha256":"44329cb2390edcce74d5b209148977a587aa00934c792192bd5c7aa59682f48b"},"public_cases.py":{"bytes":10335,"sha256":"dff26bd6a93b5dc2e0e5743f4f94831acd2fe9786a56d8528c77426240b64912"}}
def need(x,m):
 if not x:raise ValueError('batch public native: '+m)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def canonical(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
def same(x,y,m):
 if isinstance(x,bytes) or isinstance(y,bytes):need(type(x)is bytes and type(y)is bytes and x==y,m)
 else:need(canonical(x)==canonical(y),m)
def strict_json(raw):
 def pairs(values):
  d={}
  for k,v in values:need(k not in d,'duplicate JSON key');d[k]=v
  return d
 def bad(x):raise ValueError('nonfinite JSON '+x)
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=bad)
class Files:
 def __init__(self,origins):self.origins=sorted([(Path(a),Path(b)) for a,b in origins],key=lambda x:len(str(x[0])),reverse=True);self.artifacts={}
 def logical(self,p):
  p=Path(p);need(p.is_absolute() and '..'not in p.parts,'absolute mapped artifact path')
  for old,new in sorted(self.origins,key=lambda pair:len(pair[1].parts),reverse=True):
   if old!=new and (p==new or new in p.parents):return old/p.relative_to(new)
  return p
 def physical(self,p):
  p=self.logical(p);need(p.is_absolute() and '..' not in p.parts,'absolute logical path')
  for old,new in self.origins:
   if p==old or old in p.parents:return new/p.relative_to(old)
  raise ValueError('unmapped input '+str(p))
 def raw(self,p,expected=None):
  p=self.logical(p);actual=self.physical(p);s=actual.lstat();need(stat.S_ISREG(s.st_mode),'regular retained file')
  for parent in [actual,*actual.parents]:need(not parent.is_symlink(),'no source/artifact symlink')
  raw=actual.read_bytes();v=pin(raw)
  if expected is not None:same(v,expected,'complete bytes changed '+str(p))
  self.artifacts[str(p)]=v;return raw
 def json(self,p,expected=None):return strict_json(self.raw(p,expected))
 def blob(self,row):
  raw=self.raw(row['path'],row['compressed']);full=gzip.decompress(raw);same(pin(full),{k:row[k] for k in ('bytes','sha256')},'complete blob');return full
 def stream(self,row):raw=gzip.decompress(self.raw(row['path'],row['compressed']));same(pin(raw),row['uncompressed'],'complete process stream');return raw
def load_source(files,source):
 raw={}
 for n,p in SOURCES.items():raw[n]=files.raw(Path(source)/n,p)
 modules={}
 def run(n):
  if n in modules:return modules[n]
  from types import ModuleType
  m=ModuleType('_batch_public_'+n);m.__file__=str(files.physical(Path(source)/(n+'.py')));modules[n]=m
  exec(compile(raw[n+'.py'],m.__file__,'exec'),m.__dict__);return m
 # The producer is never executed. These are input and mechanical span helpers.
 return run('public_cases'),run('installation'),run('capture_common'),run('capture_fixture')
def proc(files,row,pid,expected_exe=None):
 need(type(row['pid'])is int and row['pid']==pid,'actual proc PID')
 need(type(row['read_started_monotonic_ns'])is int and row['read_finished_monotonic_ns']>=row['read_started_monotonic_ns'],'actual proc interval')
 for n in ('status','cmdline','cgroup','stat'):files.blob(row[n])
 status=files.blob(row['status']).decode();parsed=dict(line.split(':',1) for line in status.splitlines() if ':' in line)
 need(int(parsed['Pid'].strip())==pid and parsed['Umask'].strip()=='0077','actual proc identity and inherited umask')
 if expected_exe is not None:need(row['exe']==str(expected_exe),'actual selected native exe')
def native_evidence(*,source,output,graph,receipt,origins):
 source,output,graph,receipt=map(Path,(source,output,graph,receipt));f=Files(origins);cases,installation,common,carrier=load_source(f,source)
 result=f.json(output/'RESULT.json');need(result['status']=='NATIVE_CAPTURE_COMPLETE' and result['fresh_original_comparison'] is False and result['original_processes']==0,'complete native-first status')
 graphraw=f.raw(graph/'GRAPH.json');binding=strict_json(graphraw)
 same(sorted(binding),sorted(('schema','runtime_root','source_files','public_manifest','private_manifest')),'complete normal graph binding fields')
 same(binding['schema'],'hepta.runtime.batch-public-main-graph.v1','normal graph binding schema')
 runtime=Path(binding['runtime_root']);need(runtime.is_absolute() and '..'not in runtime.parts,'actual runtime source origin')
 graphpins=binding['source_files'];same(result['graph_source_sha256'],graphpins,'entire graph source inventory')
 same(f.json(output/'GRAPH-BINDING.json'),{'path':str(graph/'GRAPH.json'),**pin(graphraw)},'actual selected graph binding')
 for n,v in graphpins.items():
  rel=Path(n);need(not rel.is_absolute() and '..'not in rel.parts and rel.as_posix()==n,'relative normal graph source')
  f.raw(runtime/rel,v)
 same(result['source_sha256'],{str(source/n):v for n,v in SOURCES.items()},'exact producer closure')
 same(f.json(output/'SOURCE-PINS.json'),result['source_sha256'],'source receipt')
 pp=Path(binding['public_manifest']['path']);pm=Path(binding['private_manifest']['path'])
 for path,name in ((pp,'public_manifest'),(pm,'private_manifest')):
  same({'path':str(path),**pin(f.raw(path))},binding[name],'actual normal selected manifest bytes')
 sys.path.insert(0,str(f.physical(runtime/'scripts')))
 try:
  p=f.physical(runtime/'scripts/hia_native_filesystem_public_build.py');spec=importlib.util.spec_from_file_location('_batch_public_actual_dual',p);dual=importlib.util.module_from_spec(spec);spec.loader.exec_module(dual)
  # adapter_source reads source-owned boundary files directly.  It receives
  # the explicit retained source root; all reported artifacts use origin names.
  build=dual.dual_build_evidence(f.physical(runtime),pp,pm,read_bytes=f.raw)
  for field in ('artifacts','artifact_sha256'):
   normalized={}
   for path,value in build[field].items():
    origin=str(f.logical(path))
    if origin in normalized:same(normalized[origin],value,'ambiguous relocated artifact')
    normalized[origin]=value
   build[field]=dict(sorted(normalized.items()))
 finally:sys.path.pop(0)
 same(f.json(output/'BUILD-EVIDENCE.json'),build,'full actual71 source/compiler/image/link/pack proof')
 binary=pm.parent/f.json(pm)['elf'];binarypin=pin(f.raw(binary));same({k:result['native_elf'][k] for k in ('bytes','sha256')},binarypin,'actual native ELF')
 data=f.json(output/'INPUTS.json');same(data,cases.materialized(output/'files'),'regenerated complete133 inputs')
 installed={k:installation.installed_policy(v) for k,v in data['policies'].items()};same(f.json(output/'INSTALLED-POLICIES.json'),installed,'exact companion startup envelope')
 scenarios=sorted((s for g in data['groups'] for s in g['scenarios']),key=lambda s:s['scenario_id']);need(len(scenarios)==15,'all15 scenarios')
 parent=f.json(output/'PARENT-IDENTITY.json');proc(f,parent,parent['pid'])
 outer=f.json(receipt);selected=f.json(output/'SELECTED-STRACE.json');f.raw(output/selected['captured_file'],{k:selected[k]for k in ('bytes','sha256')})
 vr=f.json(output/'strace-version/PROCESS.json');need(vr['timeout_seconds']==180 and vr['timed_out']is False and vr['start_error']is None and vr['exit_code']==0,'actual tracer version process');f.raw(output/'strace-version/stdout.bin',vr['stdout']);need(f.raw(output/'strace-version/stderr.bin',vr['stderr'])==b'','actual tracer stderr')
 command=[outer['command'][0],'-I','-B',str(source/'capture_native.py'),'--source',str(source),'--graph',str(graph),'--output',str(output),'--strace',selected['path']]
 same(outer['command'],command,'actual native producer command')
 need(outer['pid']==parent['pid'] and outer['cwd']==str(source) and outer['timeout_seconds']==180 and outer['exit_code']==0 and outer['timed_out'] is False and outer['start_error'] is None,'actual native producer process')
 need(0<outer['elapsed_seconds']<=180 and outer['finished_monotonic_ns']>outer['started_monotonic_ns'],'actual producer interval')
 stdout=f.raw(receipt.parent/'stdout.bin',outer['stdout']);need(f.raw(receipt.parent/'stderr.bin',outer['stderr'])==b'','actual producer stderr')
 same([r['scenario_id']for r in result['scenario_results']],[s['scenario_id']for s in scenarios],'complete actual scenario result inventory')
 final_path=output/'FINAL-FIXTURES.json';descriptor=result['final_fixtures']
 same(sorted(descriptor),['bytes','path','sha256'],'complete final fixture descriptor');same(descriptor['path'],str(final_path),'actual complete final fixture location')
 final=f.json(final_path,{k:descriptor[k]for k in('bytes','sha256')})
 same(sorted(final),sorted(('schema','stage','producer_pid','started_monotonic_ns','finished_monotonic_ns','trees')),'complete final fixture observation fields')
 same([final['schema'],final['stage'],final['producer_pid']],['hepta.runtime.batch-public-final-fixture-observation.v1','native',outer['pid']],'actual final fixture producer')
 same([tree['root_hex']for tree in final['trees']],[os.fsencode(output/'files').hex()],'complete owned native fixture root')
 need(type(final['started_monotonic_ns'])is int and type(final['finished_monotonic_ns'])is int and outer['started_monotonic_ns']<=final['started_monotonic_ns']<final['finished_monotonic_ns']<=result['finished_monotonic_ns']<=outer['finished_monotonic_ns'],'actual complete final fixture capture interval')
 logs=[strict_json(line)for line in stdout.split(b'\n')if line]
 expected_logs=[{'stage':'native-scenario','id':s['scenario_id'],'steps':len(s['steps']),'status':'NATIVE_CAPTURE_COMPLETE'}for s in scenarios]
 expected_logs.append({'status':'NATIVE_CAPTURE_COMPLETE','steps':133,'scenario_count':15,'public_attempts':123,'private_fixture_steps':10,'actual_native_processes':15,'fresh_original_comparison':False,'result':pin(f.raw(output/'RESULT.json'))})
 same(logs,expected_logs,'complete actual native stdout and final result commitment')
 same(f.json(output/'PROCESSES.json'),[f.json(output/('scenario-%03d'%s['scenario_id'])/'process/process.json') for s in scenarios],'all15 actual process receipts')
 publicrows=[];allrecords=[];ids=[];frames=0;tracebytes=0
 for scenario,record in zip(scenarios,result['scenario_results']):
  d=output/('scenario-%03d'%scenario['scenario_id']);row=f.json(d/'RESULT.json',{k:record[k] for k in ('bytes','sha256')})
  same(row['input'],scenario,'complete scenario input');need(row['status']=='NATIVE_CAPTURE_COMPLETE','scenario completion')
  need(type(row['finished_monotonic_ns'])is int and row['finished_monotonic_ns']<=final['started_monotonic_ns'],'all real native processes ended before complete root capture')
  sessions={s['id']:i for i,s in enumerate(scenario['sessions'])}
  process=f.json(d/'process/process.json');same(row['process'],process,'actual process preserved');same(process['binary'],binarypin,'process ELF binding')
  need(process['exit_code']==0 and process['timed_out'] is False and process['wait_timed_out'] is False and process['start_error'] is None and process['cleanup_error'] is None and process['failure_cleanup_requested'] is False and process['kill_requested'] is False,'successful real process')
  same(process['pipe_eof'],{'stdout':True,'stderr':True},'both actual EOF')
  same(process['unconsumed_stdout'],pin(b''),'no unclaimed public/fixture bytes')
  need(process['cwd']==str(output/'files') and process['drain_deadline_seconds']==60 and process['wait_deadline_seconds']==5,'unchanged actual process contract')
  config=None if installed[scenario['policy_id']]is None else d/'runtime-config.json'
  if config is not None:same(f.json(config),installed[scenario['policy_id']],'actual installed config fullbytes')
  argv=[str(binary)]+([]if config is None else ['--runtime-config',str(config)]);same(process['native_argv'],argv,'actual native argv')
  same(process['environment'],{'PATH':'','LC_ALL':'C',**data['fence_environments'][scenario['fence_id']]},'actual fence environment')
  for ident in (row['process_identity'],row['process_identity_before_eof']):
   proc(f,ident['tracer'],process['pid']);np=ident['native']['pid'];proc(f,ident['native'],np,binary);same(f.blob(ident['children']).decode().split(),[str(np)],'actual native child')
  streams={n:f.stream(v) for n,v in process['streams'].items()};same(streams['stdin'],streams['attempted-stdin'],'all declared bytes actually written')
  trace=f.raw(process['trace']['path'],{k:process['trace'][k]for k in ('bytes','sha256')});tracebytes+=len(trace)
  need(trace.endswith(b'\n') and b'execve(' in trace and b'exit(0)' in trace,'complete actual kernel trace')
  exchanges=f.json(d/'process/exchanges.json');need(len(exchanges)==process['exchanges'],'all actual exchanges');cursor=[0,0,0]
  def exchange(session,slot,payload,declared,body_blob=None):
   i,ip,op=cursor;need(i<len(exchanges),'missing actual exchange');r=exchanges[i];same(r,declared,'exchange full receipt')
   need(r['index']==i and r['session']==session and r['slot']==slot and r['deadline_seconds']==60 and r['timed_out'] is False and r['error']is None and r['transport']=='private-frame' and 0<=r['elapsed_seconds']<60,'actual per-exchange identity/deadline')
   request=carrier.request_frame(session,slot,payload);same(streams['stdin'][ip:ip+len(request)],request,'complete raw actual request')
   same(r['attempted_input'],{'offset':ip,**pin(request)},'attempted full request');same(r['accepted_input'],r['attempted_input'],'accepted complete request')
   rr=r['response'];need(rr['offset']==op,'contiguous complete output');raw=streams['stdout'][op:op+rr['bytes']];same(pin(raw),{k:rr[k]for k in ('bytes','sha256')},'complete actual response')
   header,body=carrier.decode_response(raw,session,slot);same(header,r['header'],'decoded actual wireheader')
   same(r['body'],{'offset':op+header['header_bytes'],**pin(body)},'complete raw body offset')
   if body_blob is not None:same(f.blob(body_blob),body,'saved body is actual pipe output')
   cursor[:]=[i+1,ip+len(request),op+len(raw)];return body,header
  def observed(states):
   same(sorted(states),sorted(sessions),'all actual declared Session snapshots')
   for ident,slot in sessions.items():
    state=states[ident];need(state['session']==slot,'same real Session slot')
    view=state['view'];raw,_=exchange(slot,33,b'',view['exchange'],view['full_body']);sections,_=carrier.observer_spans(raw)
    same(carrier.state_projection(raw),view['projection'],'complete actual Session/cache projection')
    for n,b in sections.items():same(f.blob(view['sections'][n]),b,'complete actual View section')
    batch=state['batch'];raw,_=exchange(slot,35,b'',batch['exchange'],batch['full_body']);need(raw[:8]==b'HBCOBS03','actual192B Batch observer')
    values=struct.unpack_from('<23Q',raw,8);keys=('flags','binding_phase','retired','worker_pid','global_borrowers','session_borrowers','caller_capacity','history_capacity','locks_capacity','caller_used','history_used','locks_used','clone_epoch','clone_ticket','view_epoch','view_ticket','pending_target','caller_phase','reserved0','context_bytes','scope_bytes','lease_bytes','reserved1')
    same(dict(zip(keys,values)),batch['fields'],'complete native Batch observer fields');need(values[18]==values[22]==0 and len(raw)==192+sum(values[6:9])+sum(values[19:22]),'full Batch state capacities')
    at=192
    for n,z in zip(('caller','history','locks','context','scope','lease'),(*values[6:9],*values[19:22])):
     same(f.blob(batch['sections'][n]),raw[at:at+z],'complete actual Batch state span');at+=z
    need(at==len(raw),'no dropped Batch state bytes')
  same([x['action']for x in row['common_setup']],data['common_setup'],'all actual common setup actions')
  same([x['action']for x in row['setup']],scenario['setup'],'all actual setup actions')
  for inp,init in zip(scenario['sessions'],row['initialization']):
   slot=sessions[inp['id']];raw=bytes.fromhex(inp['root_hex']);same(init['root_hex'],inp['root_hex'],'exactraw Session root')
   exchange(slot,36,b'HBCNEW02'+struct.pack('<Q',len(raw))+raw,init['exchange'],init['body'])
   same(len(init['public']),len(inp['initial_messages']),'all SDK initialization exchanges')
   for msg,rec in zip(inp['initial_messages'],init['public']):
    wire=canonical(msg);same(f.blob(rec['wire']),wire,'full initialization input');exchange(slot,34,wire[:-1],rec['exchange'],rec['body'])
  observed(row['initial_state']);same(len(row['steps']),len(scenario['steps']),'all scenario steps')
  lines=[strict_json(x)for x in f.raw(d/'steps.jsonl').split(b'\n')if x];same(lines,row['steps'],'complete incrementally retained step stream')
  for inp,step in zip(scenario['steps'],row['steps']):
   same(step['input'],inp,'entire actual step input');ids.append(inp['case_id']);observed(step['before_state']);a=inp['action'];slot=sessions[inp['session']]
   if a['kind']=='public':
    wire=common.wire(a);r=step['observed'];same(f.blob(r['wire']),wire,'full public input');body,header=exchange(slot,34,wire[:-1],r['exchange'],r['body'])
    publicrows.append({'case_id':inp['case_id'],'body_sha256':pin(body),'mode':header['mode']})
   elif a['kind']=='cache_seed':r=step['observed'];exchange(slot,23,carrier.cache_seed(a['entries']),r['exchange'],r['body'])
   else:same([x['action']for x in step['observed']['actions']],a['actions'],'all real external fixture actions')
   observed(step['after_state'])
   need(type(step['started_monotonic_ns'])is int and step['finished_monotonic_ns']>=step['started_monotonic_ns'],'actual step interval')
  observed(row['final_state']);same(cursor,[len(exchanges),len(streams['stdin']),len(streams['stdout'])],'complete all input/output frames with no gaps')
  frames+=len(exchanges);allrecords.append({'scenario_id':scenario['scenario_id'],'steps':len(row['steps']),'frames':len(exchanges),'trace':pin(trace),'process_pid':process['pid'],'native_pid':row['process_identity']['native']['pid']})
 need(ids==list(range(90000,90133)),'all133 exactordered actual attempts')
 return {'schema':'hepta.runtime.batch-public-native-predecessor.v1','status':'PASS','steps':133,'public_attempts':len(publicrows),'private_fixture_steps':133-len(publicrows),'actual_native_processes':len(allrecords),'mechanical_frames':frames,'trace_bytes':tracebytes,'public_rows':publicrows,'processes':allrecords,'artifact_sha256':dict(sorted(f.artifacts.items())),'source_sha256':SOURCES,'original_execution_started':False,'original_processes':0,'production_handler_complete':False,'whole_runtime_replaced':False,'transient_fixture_directories':[str(output/'files')]}
