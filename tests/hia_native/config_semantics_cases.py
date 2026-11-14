"""Original validation ordering and redacted projections, including nested profiles."""
from pathlib import Path
import copy,json,random,struct,sys,collections
ROOT=Path(__file__).resolve().parents[2]
PIN='a'*64
CATALOG='6ec74dddbffeef5270c5eebb0638c87a8f7a540f8f38b8703ef8e471af582393'
RUNTIME_FILES={k:PIN for k in ['release','lib/modules','lib/server/libjvm.so','lib/libjava.so','lib/libzip.so','lib/libnio.so','lib/libjli.so']}
def base():return {'state_dir':'/state','controller_workspace_roots':['/work'], 'hosts':{'h':{'ssh_target':'admin-target','remote_state_dir':'/remote','allow_execute':True,'allow_write':True,'allowed_read_path_prefixes':['/'],'allowed_write_path_prefixes':['/']}}}
def weight():return {'host':'h','python_executable':'/bin/python','worker_path':'/worker','worker_sha256':PIN,'session_root':'/sessions','input_roots':['/inputs'],'allowed_providers':['model']}
def rea():return {'host':'h','runtime_executable':'/runtime','runtime_sha256':PIN,'provider':'gnu_readelf','backend_executable':'/readelf','backend_sha256':PIN,'backend_version':'GNU readelf fixture','working_directory':'/work','input_roots':['/input'],'allowed_operations':['headers']}
def jadx():
 p=rea();p.update(provider='jadx',backend_executable='/jre/bin/java',backend_version='openjdk 21.fixture',allowed_operations=['classes','sources'],max_artifact_bytes=32<<20,memory_max_bytes=1<<30)
 p['java_engine']={'java_home':'/jre','jar_path':'/jadx.jar','jar_sha256':PIN,'engine_version':'1.5.6','release_archive_sha256':PIN,'runtime_files':copy.deepcopy(RUNTIME_FILES)};return p
def ghidra():
 p=rea();p.update(provider='ghidra',backend_executable='/jre/bin/java',backend_version='openjdk 25.fixture',allowed_operations=['inventory'],max_artifact_bytes=8<<20,max_output_bytes=4096,memory_max_bytes=1<<30)
 p['ghidra_engine']={'java_home':'/jre','installation_root':'/ghidra','manifest_path':'/manifest','manifest_sha256':PIN,'engine_version':'12.2','release_archive_sha256':'2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67','runtime_files':copy.deepcopy(RUNTIME_FILES)};return p
def hia():return {'host':'h','python_executable':'/python','working_directory':'/hepta','state_root':'/hia-state','artifact_roots':['/artifact'],'worker_sha256':PIN,'backend_sha256':PIN,'catalog_sha256':CATALOG}
def variants():
 result={'plain':base()}
 for name,fn in [('weight',weight),('readelf',rea),('jadx',jadx),('ghidra',ghidra),('hia',hia)]:
  value=base()
  if name=='weight':value['weight_workers']={'w':fn()}
  elif name=='hia':value['hia_worker']=fn()
  else:value['rea_static_profiles']={'r':fn()}
  result[name]=value
 all_profiles=base();all_profiles['weight_workers']={'w':weight()};all_profiles['rea_static_profiles']={'gnu':rea(),'jadx':jadx(),'ghidra':ghidra()};all_profiles['hia_worker']=hia();result['all']=all_profiles
 return result
def at(value,path):
 for key in path:value=value[key]
 return value
def cases():
 rows=[]
 def add(category,value,operation=1):
  raw=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode();d=b'/default-state'
  rows.append((category,b'HRCFGJ01'+struct.pack('<4Q',operation,100,len(d),len(raw))+d+raw))
 def change(category,value,path,replacements):
  for replacement in replacements:
   v=copy.deepcopy(value);at(v,path[:-1])[path[-1]]=replacement;add(category,v)
 good=variants()
 for name,value in good.items():
  for op in [1,2,3,4]:add('baseline_'+name,value,op)
 for name in ['', 'good','@','a@b','../','bad name','中','x'*128,'x'*129,'-','__','.', '\0']:
  value=base();value['hosts']={name:value['hosts']['h']};add('host_names',value)
 for n in range(128):
  value=base();host=value['hosts']['h'];host.update(execution_mode=['isolated','operator'][n&1],platform=['linux','macos'][(n>>1)&1],allow_execute=bool(n&4),allow_pty=bool(n&8),allow_write=bool(n&16),allow_job_network=bool(n&32),allow_detached_fallback=bool(n&64));add('host_flags',value)
 for scalar in ['', ' ', '\t\r\n','\u0085','\u00a0','\u1680','\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a','\u2028\u2029','\u202f','\u205f','\u3000','\u200b','\ufeff','a',' a ','-','--x','a\0b','a\nb','a\rb','x'*10000]:
  change('ssh_target',base(),['hosts','h','ssh_target'],[scalar])
 paths=['','relative','.', '..','/','//','///a//b','/./a','/a/.','/a/../b','/..','/a/..','/a\0b','/a\nb','/a\rb','/中/😀','/'+'x'*4095,'/'+'x'*4096]
 change('state_path',base(),['state_dir'],paths)
 change('workspace_paths',base(),['controller_workspace_roots'],[[x] for x in paths]+[[],['/valid','bad']])
 for field in ['remote_state_dir','allowed_cwd_prefixes','allowed_read_path_prefixes','allowed_write_path_prefixes','protected_path_prefixes']:
  change('host_paths',base(),['hosts','h',field],[x if field=='remote_state_dir' else [x] for x in paths])
 for field in ['allowed_cwd_prefixes','protected_path_prefixes','protected_argument_substrings','denied_executables','allowed_dangerous_executables']:
  value=base();value['hosts']['h'].update(execution_mode='operator',allow_job_network=True)
  change('operator_sandbox',value,['hosts','h',field],[[],[''],['/'],['private']])
 for mode in ['isolated','operator']:
  for platform in ['linux','macos']:
   for execute in [False,True]:
    value=base();value['hosts']['h'].update(execution_mode=mode,platform=platform,allow_execute=execute,allow_job_network=True,allow_detached_fallback=True)
    for path,digest in [(None,None),('/criu',None),(None,PIN),('/criu',PIN),('relative',PIN),('/a/../criu',PIN),('/./criu',PIN),('/criu','A'*64),('/criu','a'*63),('/criu','g'*64)]:
     v=copy.deepcopy(value);v['hosts']['h'].update(checkpoint_binary=path,checkpoint_binary_sha256=digest);add('checkpoint_order',v)
 action={'executable':'/echo'}
 for key in ['ok','@','bad name','x'*129]:
  value=base();value['hosts']['h']['privileged_actions']={key:copy.deepcopy(action)};add('action_name',value)
 value=base();value['hosts']['h']['privileged_actions']={'act':action}
 change('action_path',value,['hosts','h','privileged_actions','act','executable'],paths)
 change('action_timeout',value,['hosts','h','privileged_actions','act','timeout_seconds'],[0,1,30,299,300,301,2**64-1])
 for allow,patterns in [(False,[]),(True,[]),(False,['x']),(True,['x']),(True,['(']),(True,['x']*32),(True,['x']*33),(True,['(?u)\\p{Greek}+'])]:
  v=copy.deepcopy(value);v['hosts']['h']['privileged_actions']['act'].update(allow_extra_args=allow,extra_arg_patterns=patterns);add('regex_boundary',v)
 # All nested fields: omitted/null/wrong-type observations remain typed serde failures.
 for name,path in [('weight',['weight_workers','w']),('readelf',['rea_static_profiles','r']),('jadx',['rea_static_profiles','r','java_engine']),('ghidra',['rea_static_profiles','r','ghidra_engine']),('hia',['hia_worker'])]:
  value=good[name];original=at(value,path)
  for field,old in original.items():
   samples=[None,True,0,'',[],{}]
   if isinstance(old,str):samples+=['bad','relative','/x','/'+'x'*4096,'A'*64,'a'*63,'b'*64]
   if type(old) is int:samples += [1,2**64-1]
   for replacement in samples:change('nested_field_'+name,value,path+[field],[replacement])
 for field,values in {'max_memory_bytes':[0,(256<<20)-1,256<<20,64<<30,(64<<30)+1], 'max_cpu_threads':[0,1,8,9,255,256], 'max_lifetime_seconds':[29,30,7200,7201], 'max_request_ms':[999,1000,600000,600001], 'max_active_sessions':[0,2**64-1], 'max_requests_per_session':[0,1,512,513]}.items():
  change('weight_budget',good['weight'],['weight_workers','w',field],values)
 change('weight_provider',good['weight'],['weight_workers','w','allowed_providers'],[[],[''],['good@model'],['bad model']])
 change('weight_client',good['weight'],['weight_workers','w','native_client'],[None,{'executable':'/native','sha256':PIN},{'executable':'relative','sha256':PIN},{'executable':'/native','sha256':'x'}])
 for field in ['python_executable','worker_path','session_root']:
  change('weight_path',good['weight'],['weight_workers','w',field],paths)
 change('weight_socket',good['weight'],['weight_workers','w','session_root'],['/'+'x'*61,'/'+'x'*62,'/'+'x'*63])
 for field,values in {'max_artifact_bytes':[0,1,512<<20,(512<<20)+1], 'max_output_bytes':[1023,1024,65536,65537], 'timeout_seconds':[0,1,120,121], 'memory_max_bytes':[(256<<20)-1,256<<20,2<<30,(2<<30)+1]}.items():
  change('rea_budget',good['readelf'],['rea_static_profiles','r',field],values)
 ops=['headers','sections','symbols','notes','relocations','classes','sources','inventory','functions','function','decompile','xrefs']
 for name in ['readelf','jadx','ghidra']:
  change('rea_operations',good[name],['rea_static_profiles','r','allowed_operations'],[[],ops,ops+ops]+[[o] for o in ops]+[[o,o] for o in ops])
 for name,engine_key in [('jadx','java_engine'),('ghidra','ghidra_engine')]:
  for field in RUNTIME_FILES:
   value=copy.deepcopy(good[name]);del value['rea_static_profiles']['r'][engine_key]['runtime_files'][field];add('missing_runtime_file',value)
  for relative in ['', '/absolute','../up','a/../b','a/./b','a//b','a:b','a\nb','a\0b','中', 'x'*4100]:
   value=copy.deepcopy(good[name]);value['rea_static_profiles']['r'][engine_key]['runtime_files'][relative]=PIN;add('runtime_relative',value)
 for revision in [None,0,1,2,3,4,5,2**32-1,2**32]:
  value=copy.deepcopy(good['ghidra']);value['rea_static_profiles']['r']['ghidra_engine']['bridge_revision']=revision;add('ghidra_revision',value)
  value['rea_static_profiles']['r']['ghidra_engine'].update(engine_version='12.1.4',release_archive_sha256='ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db');add('ghidra_revision_release',value)
 for field,values in {'timeout_seconds':[0,1,3600,3601], 'memory_max_bytes':[(64<<20)-1,64<<20,16<<30,(16<<30)+1], 'artifact_roots':[[],['/a']*32,['/a']*33]}.items():
  change('hia_budget',good['hia'],['hia_worker',field],values)
 for manifest,digest in [(None,None),('/native.json',None),(None,PIN),('/native.json',PIN),('/hia-state/helpers',PIN),('relative',PIN),('/native.json','A'*64)]:
  value=copy.deepcopy(good['hia']);value['hia_worker'].update(native_helpers_manifest=manifest,native_helpers_sha256=digest);add('hia_helpers',value)
 # Cross-profile policy roots use Rust Path component semantics, including embedded dots.
 for name in ['weight','readelf','jadx','ghidra','hia']:
  for field in ['allowed_cwd_prefixes','allowed_read_path_prefixes','allowed_write_path_prefixes','protected_path_prefixes']:
   change('cross_policy_'+name,good[name],['hosts','h',field],[[],['/'],['///'],['/./'],['/not'],['/jre'],['/jre/lib'],['/jre/lib/'],['/jre/lib/.'],['/hepta'],['/hia-state'],['/sessions']])
 for count in [0,1,16,17]:
  for field,profile in [('weight_workers',weight()),('rea_static_profiles',rea())]:
   value=base();value[field]={f'p{i}':copy.deepcopy(profile) for i in range(count)};add('profile_count',value)
 for count in [0,1,128,240,255,256,257]:
  for width in [2,128]:
   value=base();host=value['hosts']['h'];value['hosts']={('0123456789abcdefghijklmnopqrstuvwxyz'[i//36]+'0123456789abcdefghijklmnopqrstuvwxyz'[i%36] if width==2 else (str(i)+'x'*width)[:width]):copy.deepcopy(host) for i in range(count)}
   for op in [1,2,3,4]:add('summary_limits',value,op)
 rng=random.Random(872412)
 for i in range(600):
  value=copy.deepcopy(good['all']);host=value['hosts']['h']
  host[rng.choice(['allow_execute','allow_write','allow_pty','allow_job_network','allow_detached_fallback'])]=rng.choice([True,False])
  host[rng.choice(['allowed_cwd_prefixes','allowed_read_path_prefixes','allowed_write_path_prefixes','protected_path_prefixes'])]=rng.choice([[],['/'],['relative'],['/sessions'],['/hepta']])
  value['weight_workers']['w'][rng.choice(['session_root','worker_path','host'])]=rng.choice(['/sessions','h','unknown','relative','/not'])
  value['rea_static_profiles']['jadx']['max_artifact_bytes']=rng.choice([0,1,32<<20,33<<20])
  value['hia_worker']['timeout_seconds']=rng.choice([0,1,3600,3601]);add('first_error_order',value)
 return rows
def main():
 target=Path(sys.argv[1]);target.mkdir(parents=True,exist_ok=True);rows=cases()
 (target/'requests.hex').write_text(''.join(w.hex()+'\n' for _,w in rows));(target/'categories.json').write_text(json.dumps([c for c,_ in rows])+'\n')
 print(json.dumps({'cases':len(rows),'categories':dict(collections.Counter(c for c,_ in rows))}))
if __name__=='__main__':main()
