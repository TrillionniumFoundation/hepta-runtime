"""Capture the frozen native public Batch path; no Rust or expected replies."""
from pathlib import Path
import argparse,gzip,hashlib,importlib.util,json,os,struct,sys,time,traceback
sys.dont_write_bytecode=True
def module(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def need(x,m):
 if not x:raise ValueError(m)
def canonical(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def save(p,x):p.write_bytes(canonical(x));return pin(p.read_bytes())
def append(path,value):
 with path.open('ab') as stream:stream.write(canonical(value));stream.flush()
def blob(root,raw):
 h=hashlib.sha256(raw).hexdigest();p=root/'blobs'/(h+'.bin.gz');p.parent.mkdir(exist_ok=True)
 if not p.exists():p.write_bytes(gzip.compress(raw,mtime=0))
 else:need(gzip.decompress(p.read_bytes())==raw,'complete deduplicated blob')
 return {'path':str(p),**pin(raw),'compressed':pin(p.read_bytes())}
def actions(fixture,rows):
 out=[]
 for action in rows:
  result=fixture.actions([action])[0]
  if action['kind']=='write' and 'mode' in action:
   target=fixture.owned(bytes.fromhex(action['path_hex']));need(not target.is_symlink(),'fixture write mode through link')
   target.chmod(action['mode']);result['actual_mode_after']=target.stat().st_mode
  out.append(result)
 return out
BFIELDS=('flags','binding_phase','retired','worker_pid','global_borrowers','session_borrowers','caller_capacity','history_capacity','locks_capacity','caller_used','history_used','locks_used','clone_epoch','clone_ticket','view_epoch','view_ticket','pending_target','caller_phase','reserved0','context_bytes','scope_bytes','lease_bytes','reserved1')
def batch_observe(p,s,out):
 rec,raw=p.call(s,35,b'');need(raw[:8]==b'HBCOBS03' and len(raw)>=192,'full Batch observer v3')
 v=struct.unpack_from('<23Q',raw,8);need(v[18]==v[22]==0 and len(raw)==192+sum(v[6:9])+sum(v[19:22]),'Batch observer full extent')
 at=192;sections={}
 for n,z in zip(('caller','history','locks','context','scope','lease'),(*v[6:9],*v[19:22])):
  sections[n]=blob(out,raw[at:at+z]);at+=z
 need(at==len(raw),'complete Batch state')
 return {'exchange':rec,'full_body':blob(out,raw),'fields':dict(zip(BFIELDS,v)),'sections':sections}
def observe(p,sessions,out,carrier):
 rows={}
 for ident,slot in sessions.items():
  rec,raw,parts,pairs=p.observe(slot)
  rows[ident]={'session':slot,'view':{'exchange':rec,'full_body':blob(out,raw),'projection':carrier.state_projection(raw),'sections':{n:blob(out,b) for n,b in parts.items()}},'batch':batch_observe(p,slot,out)}
 return rows
def proc_record(pid,out,label):
 result={'pid':pid,'read_started_monotonic_ns':time.monotonic_ns()}
 for name in ('status','cmdline','cgroup','stat'):
  result[name]=blob(out,(Path('/proc')/str(pid)/name).read_bytes())
 result['exe']=os.readlink('/proc/'+str(pid)+'/exe')
 result['read_finished_monotonic_ns']=time.monotonic_ns()
 return result
def identities(p,out):
 tracer=p.process.pid;children=(Path('/proc')/str(tracer)/'task'/str(tracer)/'children').read_bytes()
 pids=[int(v) for v in children.split()];need(len(pids)==1,'actual one native child of tracer')
 rows={'tracer':proc_record(tracer,out,'tracer'),'native':proc_record(pids[0],out,'native'),'children':blob(out,children)}
 need(Path(rows['native']['exe']).samefile(p.binary),'actual observed executable is selected native ELF')
 return rows
def tool_version(executable,out):
 import subprocess
 d=out/'strace-version';d.mkdir();command=[str(executable),'--version'];start=time.monotonic_ns()
 p=subprocess.Popen(command,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE);stdout,stderr=p.communicate(timeout=180);end=time.monotonic_ns()
 (d/'stdout.bin').write_bytes(stdout);(d/'stderr.bin').write_bytes(stderr)
 row={'name':'strace-version','command':command,'cwd':str(out),'pid':p.pid,'timeout_seconds':180,'started_monotonic_ns':start,'finished_monotonic_ns':end,'elapsed_seconds':(end-start)/1e9,'exit_code':p.returncode,'timed_out':False,'start_error':None,'stdout':pin(stdout),'stderr':pin(stderr),'binary':pin(executable.read_bytes())}
 save(d/'PROCESS.json',row);need(p.returncode==0 and b'strace -- version' in stdout,'actual strace version');return row
def main():
 a=argparse.ArgumentParser();a.add_argument('--source',type=Path,required=True);a.add_argument('--graph',type=Path,required=True);a.add_argument('--output',type=Path,required=True);a.add_argument('--strace',type=Path,required=True);args=a.parse_args()
 source=args.source.absolute();graph=args.graph.absolute();out=args.output.absolute();out.mkdir(parents=True,exist_ok=False);os.umask(0o077)
 save(out/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text(),'cmdline':sys.argv,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text()})
 installation=module(source/'installation.py','_batch_public_installation');inputs=module(source/'public_cases.py','_batch_public_inputs');carrier=module(source/'capture_fixture.py','_batch_public_capture');common=carrier.common
 sources={str(p):pin(p.read_bytes()) for p in source.iterdir() if p.is_file()};save(out/'SOURCE-PINS.json',sources)
 graphraw=(graph/'GRAPH.json').read_bytes();binding=json.loads(graphraw)
 need(set(binding)=={'schema','runtime_root','source_files','public_manifest','private_manifest'},'complete normal graph binding')
 need(binding['schema']=='hepta.runtime.batch-public-main-graph.v1','normal graph binding schema')
 runtime=Path(binding['runtime_root']);need(runtime.is_absolute() and runtime.resolve()==runtime,'actual normal runtime source root')
 graphpins=binding['source_files']
 for n,v in graphpins.items():
  relative=Path(n);need(not relative.is_absolute() and '..'not in relative.parts,'relative graph source')
  need(pin((runtime/relative).read_bytes())==v,'frozen graph source '+n)
 sys.path.insert(0,str(runtime/'scripts'));dual=module(runtime/'scripts/hia_native_filesystem_public_build.py','_batch_public_dual')
 public=Path(binding['public_manifest']['path']);private=Path(binding['private_manifest']['path'])
 for path,name in ((public,'public_manifest'),(private,'private_manifest')):
  need(path.is_absolute() and path.resolve()==path,'actual selected graph manifest')
  need({'path':str(path),**pin(path.read_bytes())}==binding[name],'normal selected manifest bytes')
 build=dual.dual_build_evidence(runtime,public,private);save(out/'BUILD-EVIDENCE.json',build)
 save(out/'GRAPH-BINDING.json',{'path':str(graph/'GRAPH.json'),**pin(graphraw)})
 binary=private.parent/json.loads(private.read_bytes())['elf'];fixture=common.OwnedFixture(out/'files',create=True)
 data=inputs.materialized(fixture.root);save(out/'INPUTS.json',data)
 installed={k:installation.installed_policy(v) for k,v in data['policies'].items()};save(out/'INSTALLED-POLICIES.json',installed)
 scenarios=sorted((s for g in data['groups'] for s in g['scenarios']),key=lambda x:x['scenario_id'])
 need(len(scenarios)==15 and sum(len(s['steps']) for s in scenarios)==133,'unique exact public input domain')
 selected_tool=common.capture_tool(args.strace.absolute(),out,'strace');save(out/'SELECTED-STRACE.json',selected_tool)
 version=tool_version(args.strace.absolute(),out);parent=proc_record(os.getpid(),out,'parent');save(out/'PARENT-IDENTITY.json',parent)
 rows=[];processes=[];completed=[];started=time.monotonic_ns()
 for scenario in scenarios:
  d=out/('scenario-%03d'%scenario['scenario_id']);d.mkdir();p=None;row={'input':scenario,'steps':[]}
  try:
   row['common_setup']=actions(fixture,data['common_setup']);row['setup']=actions(fixture,scenario['setup'])
   policy=installed[scenario['policy_id']];config=None
   if policy is not None:config=d/'runtime-config.json';save(config,policy)
   row['configuration']=None if config is None else {'path':str(config),**pin(config.read_bytes())}
   row['fence_environment']=data['fence_environments'][scenario['fence_id']]
   row['started_monotonic_ns']=time.monotonic_ns()
   p=carrier.RecordedFixtureProcess(d/'process',binary,fixture.root,strace=args.strace.absolute(),config=config,fence=row['fence_environment'],trace=True)
   sessions={s['id']:i for i,s in enumerate(scenario['sessions'])};need(len(sessions) in (1,2),'fixed actual Session arenas')
   initial=[]
   for session in scenario['sessions']:
    slot=sessions[session['id']];raw=bytes.fromhex(session['root_hex'])
    rec,body=p.call(slot,36,b'HBCNEW02'+struct.pack('<Q',len(raw))+raw)
    need(body==b'HRSWR002'+bytes(24),'actual raw-root Session initialization')
    ir={'session':session['id'],'root_hex':raw.hex(),'exchange':rec,'body':blob(out,body),'public':[]}
    for message in session['initial_messages']:
     wire=canonical(message);rr,bb=p.public(slot,wire);ir['public'].append({'wire':blob(out,wire),'exchange':rr,'body':blob(out,bb)})
    initial.append(ir)
   row['initialization']=initial;row['process_identity']=identities(p,out);row['initial_state']=observe(p,sessions,out,carrier)
   save(d/'PARTIAL.json',row)
   for entry in scenario['steps']:
    e={'input':entry,'started_monotonic_ns':time.monotonic_ns(),'before_state':observe(p,sessions,out,carrier),'before_files':fixture.snapshot(scenario['observed_roots'])}
    action=entry['action'];slot=sessions[entry['session']]
    if action['kind']=='public':
     wire=common.wire(action);rec,body=p.public(slot,wire)
     e['observed']={'domain':'actual-native-frontend-and-publisher-in-private-two-session-carrier','wire':blob(out,wire),'exchange':rec,'body':blob(out,body)}
    elif action['kind']=='cache_seed':
     rec,body=p.seed(slot,action['entries']);e['observed']={'domain':'actual-native-scope-cache-seed','exchange':rec,'body':blob(out,body)}
    elif action['kind']=='filesystem':e['observed']={'domain':'external-fixture-actions','actions':actions(fixture,action['actions'])}
    else:raise ValueError('undeclared unique input action')
    e['after_files']=fixture.snapshot(scenario['observed_roots']);e['after_state']=observe(p,sessions,out,carrier);e['finished_monotonic_ns']=time.monotonic_ns()
    row['steps'].append(e);append(d/'steps.jsonl',e);completed.append(entry['case_id']);save(d/'PARTIAL.json',row)
   row['final_state']=observe(p,sessions,out,carrier);row['final_files']=fixture.snapshot(scenario['observed_roots'])
   row['process_identity_before_eof']=identities(p,out);receipt=p.close();p=None;row['process']=receipt;processes.append(receipt)
   row['finished_monotonic_ns']=time.monotonic_ns();row['status']='NATIVE_CAPTURE_COMPLETE'
   save(d/'RESULT.json',row);rows.append({'scenario_id':scenario['scenario_id'],'path':str(d/'RESULT.json'),**pin((d/'RESULT.json').read_bytes())})
   save(out/'PROCESSES.json',processes);save(out/'PROGRESS.json',{'completed_ids':completed,'scenarios':rows})
   print(json.dumps({'stage':'native-scenario','id':scenario['scenario_id'],'steps':len(row['steps']),'status':'NATIVE_CAPTURE_COMPLETE'}),flush=True)
  except BaseException:
   row['failure']=traceback.format_exc()
   if p is not None:
    try:row['process']=p.close(failed=True)
    except BaseException:row['cleanup_failure']=traceback.format_exc()
   save(d/'FAILURE.json',row);save(out/'FAILURE.json',{'scenario':scenario['scenario_id'],'completed_ids':completed,'failure':row['failure']});raise
 need(completed==list(range(90000,90133)),'all unique133 steps actual capture in order')
 final_started=time.monotonic_ns();final_trees=fixture.snapshot([os.fsencode(fixture.root).hex()]);final_finished=time.monotonic_ns()
 final_fixtures=save(out/'FINAL-FIXTURES.json',{'schema':'hepta.runtime.batch-public-final-fixture-observation.v1','stage':'native','producer_pid':os.getpid(),'started_monotonic_ns':final_started,'finished_monotonic_ns':final_finished,'trees':final_trees})
 for n,v in graphpins.items():need(pin((runtime/n).read_bytes())==v,'frozen graph source after '+n)
 for p,v in sources.items():need(pin(Path(p).read_bytes())==v,'producer sources unchanged')
 common.check_tool(selected_tool)
 need((graph/'GRAPH.json').read_bytes()==graphraw,'complete normal graph binding unchanged')
 finalbuild=dual.dual_build_evidence(runtime,public,private);need(finalbuild==build,'complete source/image/build proof unchanged')
 result={'schema':'hepta.runtime.batch-public-native-capture.v1','status':'NATIVE_CAPTURE_COMPLETE','scenario_count':len(rows),'steps':len(completed),'public_attempts':sum(e['action']['kind']=='public' for s in scenarios for e in s['steps']),'private_fixture_steps':sum(e['action']['kind']!='public' for s in scenarios for e in s['steps']),'actual_native_processes':len(processes),'actual_tracer_version_processes':1,'scenario_results':rows,'source_sha256':sources,'graph_source_sha256':graphpins,'public_manifest':{'path':str(public),**pin(public.read_bytes())},'private_manifest':{'path':str(private),**pin(private.read_bytes())},'complete_dual_build_evidence':{'path':str(out/'BUILD-EVIDENCE.json'),**pin((out/'BUILD-EVIDENCE.json').read_bytes())},'native_elf':{'path':str(binary),**pin(binary.read_bytes())},'inputs':{'path':str(out/'INPUTS.json'),**pin((out/'INPUTS.json').read_bytes())},'processes':{'path':str(out/'PROCESSES.json'),**pin((out/'PROCESSES.json').read_bytes())},'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns(),'fresh_original_comparison':False,'original_processes':0,'original_full_router_executed':False,'production_handler_complete':False,'whole_runtime_replaced':False,'trace_string_limit':4096,'complete_transport_streams':True,'native_effect_records':'complete actual stderr; kernel trace independently retains syscall order and selected data; trace strings beyond4096 are explicitly abbreviated','transient_fixture_directories':[str(fixture.root)]}
 result['final_fixtures']={'path':str(out/'FINAL-FIXTURES.json'),**final_fixtures}
 result_pin=save(out/'RESULT.json',result);summary={k:v for k,v in result.items() if k in ('status','steps','scenario_count','public_attempts','private_fixture_steps','actual_native_processes','fresh_original_comparison')};summary['result']=result_pin
 print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=='__main__':main()
