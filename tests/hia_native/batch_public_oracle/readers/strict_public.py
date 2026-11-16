"""Pure full-byte qualification of the frozen local Batch public graph and SDK.

All path arguments name execution origins. Explicit read roots select retained
bytes; no reader restores or inspects a live fixture. Native execution and the
fresh unchanged SDK replay remain separate admitted stages.
"""
from pathlib import Path
import collections,gzip,importlib.util,json,os,stat,struct,sys
from capture_format import Files,actual_process,blob,canonical,fields,need,parse_records,pin,same,sha,strict_json,uint
import trace_evidence as trace
ORIGINAL_SOURCES={"native_predecessor.py":{"bytes":19089,"sha256":"29d893ddcf70cda5c9b66e4a68a6f047c6feff1099e897364d810aa5d7fa85d8"},"oracle/Cargo.lock":{"bytes":19709,"sha256":"0df4a30a64d6715cd19eae658549dfa39238d6f007ad48762488926879ba080c"},"oracle/Cargo.toml":{"bytes":562,"sha256":"574543031ac035a8854d6938fcdea635baf0719ec1c682a0d4245ec819aa4db4"},"oracle/original/Cargo.lock":{"bytes":90148,"sha256":"7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43"},"oracle/original/Cargo.toml":{"bytes":4157,"sha256":"377e7dca547f0ff0d832fb28cf01862a6d84b4b6ed42c8b36dae9075cbbbb78f"},"oracle/original/config.rs":{"bytes":25272,"sha256":"228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35"},"oracle/original/core.rs":{"bytes":26443,"sha256":"51c9a864c6b18ac43957cf3e6c74b07d8ee8952e0589b68e1051e976c1dd09ec"},"oracle/original/delta.rs":{"bytes":9765,"sha256":"a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1"},"oracle/original/effect_owner_fence.rs":{"bytes":23890,"sha256":"1e2f2cd32289cd93915076981436b79c04a2756dfc184fa219f043a88f907207"},"oracle/original/line_hash.rs":{"bytes":9153,"sha256":"904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57"},"oracle/original/mcp_mod.rs":{"bytes":3316,"sha256":"9e9b7933372418ef361f85d64a1d36567618b13ae77c45d16df16799231b690c"},"oracle/original/remote.rs":{"bytes":48174,"sha256":"d87cae1d18cfaf3479cc94e0df8c8c6eefe5d2eec34f62b7ba0f0c4693704d8c"},"oracle/original/remote_unavailable.rs":{"bytes":1431,"sha256":"727d612dfccd5a7ecd83258f14507f0c97a3d7640c6f7706d5e33a38c4566ad5"},"oracle/original/request_ctx.rs":{"bytes":2860,"sha256":"81ebf6e68bcf8c119c83274a090b5e4796d00b3ca6d889c92e9922be0612e943"},"oracle/original/server.rs":{"bytes":178908,"sha256":"ea43d13d2e870188abc33afca771eb3f5ecacdf982a56467c7b7c2fa0fa81d0d"},"oracle/original/text_editing.rs":{"bytes":63372,"sha256":"e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590"},"oracle/original/truncation.rs":{"bytes":4492,"sha256":"3967bee0b0a897d470737c64dd735ee8f206c00d87f3778dee212f326334283e"},"oracle/src/context_observer.rs":{"bytes":310,"sha256":"0e7b8eb6f4e279e1087346bce35eb7589bf732cc920965b60b6aa800e7c1c76c"},"oracle/src/delta_observer.rs":{"bytes":424,"sha256":"edc615a03fc6dace620173bf0ed030e4c6208dc15008c735568939e3eeb12cde"},"oracle/src/driver.rs":{"bytes":22465,"sha256":"99d151068765368db7a38bca2bb193449b05cc570e003a0afebaf82d3e05767c"},"oracle/src/editing_observer.rs":{"bytes":750,"sha256":"8cf8a85ca17e4fc8e5abfbac6e86a3029efdaed17db8f71a9806df966b3d03d8"},"oracle/src/observe.rs":{"bytes":12399,"sha256":"08e16f67890d37c078c6388e67f1352b8980b0cd88991fd9fa221c9cd104f54e"},"oracle/src/observed_tokio.rs":{"bytes":4052,"sha256":"1d525c6d309cb82bb0b6e21d09f24703388153a6defc119a62ffb145dbbba052"},"oracle/src/public_driver.rs":{"bytes":10452,"sha256":"466e6908b5994714549b5f6864b0c7f087b75f75a27ee18374c93d41f6e22b2b"},"oracle/verify_sources.py":{"bytes":10561,"sha256":"60bb28e4ae4ccf328cf53030c7efb53a5b71d835bb19bf730053572e422179da"},"public_cases.py":{"bytes":10335,"sha256":"dff26bd6a93b5dc2e0e5743f4f94831acd2fe9786a56d8528c77426240b64912"},"run_original.py":{"bytes":9987,"sha256":"e33488f10b0edfed93269f45ae138091fb692016628772f52b4ac5fea493919c"}}
def raw_pin(raw):return {'bytes':len(raw),'sha256':sha(raw)}
def load(files,path,name):
 p=files.file(str(path));spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def bound(files,path,expected=None):
 raw=files.raw(str(path))
 if expected is not None:same(raw_pin(raw),expected,'complete artifact identity '+str(path))
 return raw
def js(files,path,expected=None):return strict_json(bound(files,path,expected))
def saved_blob(files,row):
 fields(row,('path','bytes','sha256','compressed'),'complete native blob descriptor')
 raw=gzip.decompress(bound(files,Path(row['path']),row['compressed']))
 same(raw_pin(raw),{k:row[k]for k in('bytes','sha256')},'complete raw native blob')
 return raw
def saved_stream(files,row):
 fields(row,('path','compressed','uncompressed'),'complete process stream descriptor')
 raw=gzip.decompress(bound(files,Path(row['path']),row['compressed']));same(raw_pin(raw),row['uncompressed'],'complete process stream')
 return raw
def process_streams(files,root,row,command,cwd):
 actual_process(row,command,cwd)
 status=bound(files,root/'proc-status-at-start.txt')
 parsed=dict(x.split(b':',1)for x in status.split(b'\n')if b':'in x)
 same(int(parsed[b'Pid'].strip()),row['pid'],'actual original proc PID')
 same(parsed[b'Umask'].strip(),b'0077','actual original proc umask')
 same(row['umask'],63,'requested actual child umask')
 return bound(files,root/'stdout.bin',row['stdout']),bound(files,root/'stderr.bin',row['stderr'])
def original_provenance(files,source,output,receipt,native_request,native):
 result=js(files,output/'RESULT.json');table=js(files,output/'SOURCE-FILES.json')
 same(table,ORIGINAL_SOURCES,'entire fixed original source closure');same(result['source_files'],table,'reported original source closure')
 for name,expected in table.items():bound(files,source/name,expected)
 verifier=load(files,source/'oracle/verify_sources.py','_batch_public_bound_original_materializer')
 materialized,proof=verifier.assemble(files.path(str(source/'oracle/verify_sources.py')).parent)
 same(js(files,output/'SOURCE.json'),proof,'actual unchanged whole modules/spans and locked dependencies')
 same(len(proof['unchanged_spans']),25,'complete original function span closure')
 same(len(proof['unchanged_whole_modules']),8,'complete original whole-module closure')
 same(proof['registry_dependencies'],82,'all actual locked registry dependencies')
 for name,raw in materialized.items():same(bound(files,output/'crate'/name),raw,'full independently materialized unchanged crate '+name)
 saved_native=js(files,output/'NATIVE-EVIDENCE.json');same(saved_native,native,'fresh replay complete native causal predecessor')
 predecessor=js(files,output/'NATIVE-ADMISSION.json')
 fields(predecessor,('complete_native','native_artifact_sha256','admitted_monotonic_ns','original_started'),'complete native admission')
 same(predecessor['complete_native'],raw_pin(bound(files,output/'NATIVE-EVIDENCE.json')),'native admission full bytes')
 same(predecessor['native_artifact_sha256'],native['artifact_sha256'],'native admission full artifact set')
 need(predecessor['original_started']is False,'original started before causal admission')
 requested=js(files,output/'NATIVE-REQUEST.json')
 same({k:v for k,v in requested.items()if k!='origins'},{k:str(v)for k,v in native_request.items()if k!='origins'},'actual native predecessor parameters')
 tools=js(files,output/'TOOLS.json');fields(tools,('cargo','rustc','strace'),'actual selected tools')
 for name,v in tools.items():
  fields(v,('invocation','resolved','retained','bytes','sha256'),'complete retained tool')
  need(Path(v['invocation']).is_absolute()and Path(v['resolved']).is_absolute(),'actual selected tool path')
  same(v['retained'],str(output/('tool-'+name)),'retained tool location')
  bound(files,output/('tool-'+name),{k:v[k]for k in('bytes','sha256')})
 cargo,rustc,tracer=[tools[n]['invocation']for n in('cargo','rustc','strace')]
 need(Path(cargo).parent==Path(rustc).parent,'one explicit Rust toolchain')
 outer=js(files,receipt);cmd=[outer['command'][0],'-I','-B',str(source/'run_original.py')]
 for key,value in [('source',source),('native-source',native_request['source']),('native-output',native_request['output']),('native-receipt',native_request['receipt']),('graph',native_request['graph']),('output',output),('cargo',cargo),('rustc',rustc),('strace',tracer)]:cmd+=['--'+key,str(value)]
 actual_process(outer,cmd,source)
 stdout=bound(files,receipt.parent/'stdout.bin',outer['stdout']);same(bound(files,receipt.parent/'stderr.bin',outer['stderr']),b'','actual outer stderr')
 remote=js(files,output/'remote-process.json');same(remote['pid'],outer['pid'],'actual original group PID');same(remote['argv'],cmd[3:],'actual original argv')
 need(type(remote['cgroup'])is str and type(remote['boot_id'])is str,'complete actual cgroup/boot observations')
 admitted=uint(predecessor['admitted_monotonic_ns'],'actual admission clock')
 need(outer['started_monotonic_ns']<=admitted<outer['finished_monotonic_ns'],'native admission belongs to actual original process interval')
 rows=js(files,output/'PROCESSES.json');names=['rustc-version','cargo-version','strace-version','build']+['sdk-%03d'%i for i in range(15)]
 same([r['name']for r in rows],names,'complete19 actual process order');need(len({r['pid']for r in rows})==19,'distinct original child processes')
 previous=admitted;tool_outputs={}
 env=rows[0]['environment'];fields(env,('HOME','PATH','RUSTC','CARGO_BUILD_JOBS','CARGO_TARGET_DIR','LC_ALL'),'actual isolated build environment')
 need(Path(env['HOME']).is_absolute(),'actual HOME')
 same({k:v for k,v in env.items()if k!='HOME'},{'PATH':str(Path(rustc).parent)+':/usr/bin:/bin','RUSTC':rustc,'CARGO_BUILD_JOBS':'2','CARGO_TARGET_DIR':str(output/'target'),'LC_ALL':'C'},'fixed actual compiler environment')
 for i,row in enumerate(rows):
  d=output/'processes'/row['name'];same(js(files,d/'PROCESS.json'),row,'actual independent child receipt')
  need(previous<=uint(row['started_monotonic_ns'],'child actual start')<row['finished_monotonic_ns']<=outer['finished_monotonic_ns'],'child process within actual native-first original interval');previous=row['finished_monotonic_ns']
  if i<4:
   commands=[[rustc,'--version','--verbose'],[cargo,'--version','--verbose'],[tracer,'-V'],[cargo,'build','--locked','--release','--manifest-path',str(output/'crate/Cargo.toml')]]
   same(row['environment'],env,'actual fixed build/version environment')
   so,se=process_streams(files,d,row,commands[i],source);tool_outputs[row['name']]=(so,se)
 for name in names[:3]:same(tool_outputs[name][1],b'','actual version stderr')
 rv=tool_outputs['rustc-version'][0];cv=tool_outputs['cargo-version'][0]
 need(b'\nrelease: 1.95.0\n'in rv and b'\nhost: x86_64-unknown-linux-gnu\n'in rv and rv.startswith(b'rustc 1.95.0 '),'actual fixed rustc1.95')
 need(cv.startswith(b'cargo 1.95.0 ')and b'x86_64-unknown-linux-gnu'in cv,'actual fixed Cargo1.95')
 need(tool_outputs['strace-version'][0].startswith(b'strace -- version '),'actual tracer version')
 so,se=tool_outputs['build'];same(so,b'','actual Cargo stdout')
 need(b'Compiling hepta-batch-call-original v0.1.0'in se and b'Finished'in se and b'release'in se,'actual fresh locked release compilation')
 info=js(files,output/'target.rustc_info.json');need(type(info['outputs'])is dict,'actual Cargo compiler cache')
 need(any(v['stdout'].encode()==rv and v['success']is True and v['code']==0 and v['stderr']==''for v in info['outputs'].values()),'actual compiler used by Cargo equals full selected version')
 binary=bound(files,output/'reference.elf');need(binary[:4]==b'\x7fELF'and binary[4:7]==b'\2\1\1','actual x86-64 original executable')
 build=js(files,output/'BUILD.json');same(build,{'binary':raw_pin(binary),'fresh_locked':True,'native_predecessor':raw_pin(bound(files,output/'NATIVE-EVIDENCE.json')),'source':proof},'actual original build identity')
 for key,value in [('schema','hepta.runtime.batch-public-original-capture.v1'),('status','CAPTURED'),('scenarios',15),('steps',133),('actual_processes',19),('fresh_locked_builds',1),('sdk_replay_processes',15),('actual_original_batch_method',True),('actual_original_sdk',True),('actual_original_full_router',False),('actual_original_config_loader',False),('whole_runtime_replaced',False),('native_original_comparison_complete',False)]:
  same(result[key],value,'actual original capture boundary '+key)
 same(result['native_evidence'],raw_pin(bound(files,output/'NATIVE-EVIDENCE.json')),'reported native predecessor')
 final_path=output/'FINAL-FIXTURES.json';descriptor=result['final_fixtures']
 fields(descriptor,('path','bytes','sha256'),'complete original final fixture descriptor');same(descriptor['path'],str(final_path),'actual original final fixture location')
 final=js(files,final_path,{k:descriptor[k]for k in('bytes','sha256')})
 fields(final,('schema','stage','producer_pid','started_monotonic_ns','finished_monotonic_ns','trees'),'complete original final fixture observation')
 same([final['schema'],final['stage'],final['producer_pid']],['hepta.runtime.batch-public-final-fixture-observation.v1','original',outer['pid']],'actual original final fixture producer')
 same([tree['root_hex']for tree in final['trees']],[os.fsencode(Path(native_request['output'])/'files').hex()],'complete owned original fixture root')
 need(rows[-1]['finished_monotonic_ns']<=uint(final['started_monotonic_ns'],'original final snapshot start')<uint(final['finished_monotonic_ns'],'original final snapshot end')<=outer['finished_monotonic_ns'],'actual original final capture after all SDK processes')
 logs=[strict_json(x)for x in stdout.split(b'\n')if x]
 need(len(logs)==16,'all15 replay plus terminal real stdout records')
 same(logs[-1],{'status':'CAPTURED','scenarios':15,'steps':133,'actual_processes':19,'result':raw_pin(bound(files,output/'RESULT.json'))},'actual group terminal stdout')
 return result,rows,tools,proof,logs

import state_comparison as states
def native_graph(files,native_request,original_source,qualification_source):
 # The same portable reader admits the native stage before fresh Rust execution
 # and later consumes the retained bytes. No execution receipt is rewritten.
 path=original_source/'native_predecessor.py'
 bound(files,path,ORIGINAL_SOURCES['native_predecessor.py'])
 reader=load(files,path,'_batch_public_actual_causal_reader')
 prior=reader.native_evidence(**native_request)
 for path,expected in prior['artifact_sha256'].items():
  raw=bound(files,Path(path),expected)
  if path.endswith('.json'):strict_json(raw)
 return prior
def native_capture(files,output,result,index):
 d=output/('scenario-%03d'%index);record=result['scenario_results'][index]
 row=js(files,d/'RESULT.json',{k:record[k]for k in('bytes','sha256')});p=row['process']
 streams={k:saved_stream(files,v)for k,v in p['streams'].items()}
 raw=bound(files,Path(p['trace']['path']),{k:p['trace'][k]for k in('bytes','sha256')})
 parsed=trace.parse_trace(raw,markers=False)
 wire=trace.stream_evidence(parsed,stdin=streams['stdin'],stdout=streams['stdout'],stderr=streams['stderr'])
 fd=trace.descriptor_lifetimes(parsed,os.fsencode(output/'files'))
 receipts=trace.native_receipts(streams['stderr'])
 for phase in('initial_state','final_state'):
  for state in row[phase].values():states.terminal_native_state(state,lambda b:saved_blob(files,b))
 for step in row['steps']:
  for phase in('before_state','after_state'):
   for state in step[phase].values():states.terminal_native_state(state,lambda b:saved_blob(files,b))
 return row,parsed,wire,fd,receipts
def compare_state(files,native,meta,get,scenario,trees_native,trees_original):
 names={i:s['id']for i,s in enumerate(scenario['sessions'])};called=meta['session']
 for phase in('before','after'):
  ns=native[phase+'_state'];actual=ns[called]['view']['projection'];expected=states.session(meta['state_'+phase],get)
  same({k:actual[k]for k in expected},expected,'actual raw Session '+phase)
  observed=meta[phase];need(type(observed['caches'])is list,'complete original cache collection')
  same([v['session']for v in observed['caches']],list(names),'all real Sessions in original cache snapshot')
  for cache in observed['caches']:
   need(type(cache['poisoned'])is bool,'actual original cache poison flag')
   view=ns[names[cache['session']]]['view'];raw=saved_blob(files,view['sections']['cache']);poison=states.word(raw,32)
   need(poison in(0,1),'native cache poison flag')
   values={}
   for e in cache['entries']:
    fields(e,('key_blob','value_blob'),'complete original cache entry')
    key=get(e['key_blob']).hex();need(key not in values,'duplicate original cache key');values[key]=get(e['value_blob']).hex()
   same({'poisoned':bool(poison),'entries':{k.encode().hex():v.encode().hex()for k,v in view['projection']['cache_entries'].items()}},{'poisoned':cache['poisoned'],'entries':values},'complete per-Session cache byte equality')
  history,locks=states.terminal_native_state(ns[called],lambda b:saved_blob(files,b))
  same(history,states.original_history(observed['history'],get),'complete shared History values/order/bytes')
  trace.lock_state(observed['file_locks'],released=True)
  # Lazy Rust map allocation and eagerly-created private native arena differ.
  # Both full representations are retained; compare the actual retained map.
  same({k:locks[k]for k in('poisoned','entries')},{k:observed['file_locks'][k]for k in('poisoned','entries')},'complete released lock map')
  trees_native.append(native[phase+'_files']);trees_original.append(states.original_trees(meta['files_'+phase],get))
def actual_response(meta,native,get):
 result=meta['result'];fields(result,('request_blob','request_bytes_written','response_blob','transport')if result['transport']!='write-error'else('request_blob','request_bytes_written','response_blob','transport','error'),'complete actual SDK exchange')
 request=get(result['request_blob']);same(request,native['request'],'complete actual raw request')
 n=uint(result['request_bytes_written'],'actual SDK accepted request bytes');need(n<=len(request),'SDK wrote beyond request')
 body=b''if result['response_blob']is None else get(result['response_blob'])
 same(body,native['body'],'complete actual raw JSON response, without path or text replacement')
 transport=result['transport'];need(transport in('response','notification','eof','write-error'),'actual SDK transport')
 if transport=='response':
  need(n==len(request)and body.endswith(b'\n'),'complete successful SDK line')
  response=strict_json(body);need(type(response)is dict and response.get('jsonrpc')=='2.0','actual SDK JSON-RPC response')
  same(response['id'],meta['case_id'],'actual response request ID')
  exits=[e for e in meta['events']if e['kind']=='handler_exit']
  if exits:
   value=exits[0]['data'];need(type(value['ok'])is bool,'actual handler result boolean')
   bodytext=get(value['body_blob']).decode()
   actual=response['result'];same(actual['content'],[{'type':'text','text':bodytext}],'actual SDK serialized complete handler String')
   same(actual.get('isError',False),not value['ok'],'actual SDK String Result tag')
 elif transport=='notification':need(result['response_blob']is None and n==len(request),'actual no-reply notification')
 elif transport=='eof':need(body==b''and n==len(request),'actual transport EOF')
 else:
  need(body==b''and n<len(request),'actual partial/failed write')
  fields(result['error'],('ok','short_blob','kind','errno'),'complete actual transport error')
  need(result['error']['ok']is False and type(result['error']['kind'])is str,'actual transport error')
  short=get(result['error']['short_blob']);short.decode();need(bool(short),'complete actual transport diagnostic')
  need(result['error']['errno']is None or type(result['error']['errno'])is int and 0<result['error']['errno']<4096,'actual transport errno')
 return {'transport':transport,'request':raw_pin(request),'response':raw_pin(body),'native_mode':native['mode']}
def evidence(*,qualification_source,native_source,native_output,native_receipt,graph,original_source,original_output,original_receipt,origins):
 roots={k:Path(v)for k,v in locals().copy().items()if k not in('origins',)}
 files=Files(origins)
 for k,p in roots.items():need(p.is_absolute()and'..'not in p.parts,'absolute evidence origin '+k)
 Q=roots['qualification_source'];S=roots['original_source'];O=roots['original_output'];N=roots['native_output']
 reader_sources={}
 for name in('capture_format.py','trace_evidence.py','state_comparison.py','strict_public.py'):
  raw=bound(files,Q/name);reader_sources[name]=raw_pin(raw)
  current=Path(__file__).parent/name;same(current.read_bytes(),raw,'actual executed strict reader source '+name)
 request={'source':str(roots['native_source']),'output':str(N),'graph':str(roots['graph']),'receipt':str(roots['native_receipt']),'origins':origins}
 prior=native_graph(files,request,S,Q)
 original,processes,tools,source,logs=original_provenance(files,S,O,roots['original_receipt'],request,prior)
 result=js(files,N/'RESULT.json');data=js(files,N/'INPUTS.json');policies=js(files,N/'INSTALLED-POLICIES.json')
 scenarios=sorted((s for g in data['groups']for s in g['scenarios']),key=lambda s:s['scenario_id'])
 same(logs[:-1],[{'stage':'unchanged-sdk','scenario_id':s['scenario_id'],'steps':len(s['steps']),'status':'CAPTURED'}for s in scenarios],'all actual scenario progress stdout')
 cases=[];captures=[];all_ids=[];marker_count=0;events=collections.Counter();public=0;actual_bytes=0;inner_handlers=0;outer_calls=0
 for index,scenario in enumerate(scenarios):
  native,nt,nw,nfd,receipt_rows=native_capture(files,N,result,index)
  same(native['input'],scenario,'same original/native input scenario')
  d=O/('scenario-%03d'%index);capture=js(files,d/'RESULT.json')
  same(capture,original['captures'][index],'complete original scenario manifest')
  same(capture['scenario_id'],index,'actual original scenario identity')
  input_raw=bound(files,d/'input.jsonl',{k:capture['input'][k]for k in('bytes','sha256')})
  same(input_raw,canonical(scenario),'same complete original input bytes')
  policy_raw=bound(files,d/'policy.json',{k:capture['policy'][k]for k in('bytes','sha256')})
  same(strict_json(policy_raw),policies[scenario['policy_id']],'same complete installed policy')
  setup=js(files,d/'COMMON-SETUP.json');same([x['action']for x in setup],data['common_setup'],'all actual original common setup')
  p=processes[4+index];same(capture['process'],p,'actual original replay process')
  process_root=O/'processes'/('sdk-%03d'%index);same(capture['process_root'],str(process_root),'actual captured process location')
  same(p['environment'],{'PATH':'/usr/bin:/bin','LC_ALL':'C',**data['fence_environments'][scenario['fence_id']]},'actual original fence environment')
  common=load(files,roots['native_source']/'capture_common.py','_batch_public_full_common_'+str(index))
  cmd=[tools['strace']['invocation'],*common.TRACE_ARGS,'-o',str(d/'original.strace'),'--',str(O/'reference.elf'),'--sdk',str(N/'files'),str(d/'policy.json')]
  raw,stderr=process_streams(files,process_root,p,cmd,N/'files');same(stderr,b'','actual SDK stderr')
  traces=bound(files,d/'original.strace',{k:capture['trace'][k]for k in('bytes','sha256')})
  ot=trace.parse_trace(traces,markers=True);ow=trace.stream_evidence(ot,stdin=input_raw,stdout=raw,stderr=stderr)
  ofd=trace.descriptor_lifetimes(ot,os.fsencode(N/'files'));records=parse_records(raw,b'HBCSO002',counted=False)
  same([r['metadata']['kind']for r in records],['scenario_start']+['case']*len(scenario['steps'])+['scenario_end'],'complete full original record sequence')
  flattened=[e['marker']for r in records for e in r['metadata']['events']]
  same(flattened,list(ot['markers']),'all actual original event markers accounted once')
  marker_count+=len(flattened);start,end=records[0],records[-1]
  same(start['metadata']['scenario_id'],index,'actual original scenario entry')
  same(start['metadata']['name'],scenario['name'],'actual original scenario name')
  need(start['metadata']['actual_original_full_router']is False and start['metadata']['actual_original_get_info']is False,'SDK carrier coverage boundary')
  need(start['metadata']['events'][0]['kind']=='scenario_setup_begin','actual setup marker')
  same(start['metadata']['events'][0]['data'],{'scenario_id':index},'actual setup identity')
  same([e['data']['action']for e in start['metadata']['events']if e['kind']=='public_fixture_action_enter'],scenario['setup'],'all actual original setup mutations')
  ntree=[];otree=[];per_session={s['id']:{'outer':0,'handler':0}for s in scenario['sessions']};scenario_cases=[]

  for init,declared in zip(start['metadata']['sessions'],scenario['sessions']):
   same(init['session'],declared['id'],'actual original initial Session')
   need(init['initialization_fixture']is True,'SDK initialization fixture boundary')
   same(len(init['exchanges']),len(declared['initial_messages']),'complete original initialization calls')
   get=lambda i:blob(raw,start,i)
   for observed,message in zip(init['exchanges'],declared['initial_messages']):
    same(get(observed['request_blob']),canonical(message),'actual complete initialization request')
    same(observed['request_bytes_written'],len(canonical(message)),'actual initialization write')
    if observed['response_blob']is not None:get(observed['response_blob'])
   expected=states.session(init['state'],get);actual=native['initial_state'][declared['id']]['view']['projection']
   same({k:actual[k]for k in expected},expected,'initial raw Session equality')
  for n,r,step in zip(native['steps'],records[1:-1],scenario['steps']):
   m=r['metadata'];get=lambda i:blob(raw,r,i)
   fields(m,('kind','scenario_id','case_id','name','domain','session','state_before','state_after','before','after','files_before','files_after','result','outer_call_tool_entries','handler_entries','request_context_present_after','original_full_router_executed','events','hook_used'),'complete original case metadata')
   for k in('case_id','name','domain','session'):same(m[k],step[k],'actual complete original case '+k)
   same(m['scenario_id'],index,'original case scenario');same(m['hook_used'],[],'public corpus has no hidden mutation hooks')
   all_ids.append(step['case_id']);events.update(e['kind']for e in m['events'])
   logical=trace.public_lifecycle(m,step,get,ot)
   per_session[m['session']]['outer']+=m['outer_call_tool_entries'];per_session[m['session']]['handler']+=m['handler_entries']
   inner_handlers+=m['handler_entries'];outer_calls+=m['outer_call_tool_entries']
   compared_response=None;transfer=[]
   if step['action']['kind']=='public':
    public+=1
    compared_response=actual_response(m,{'request':saved_blob(files,n['observed']['wire']),'body':saved_blob(files,n['observed']['body']),'mode':n['observed']['exchange']['header']['mode']},get)
    actual_bytes+=compared_response['response']['bytes']
    nr=trace.exchange_interval(nt,nw,n['observed']['exchange']);orr=trace.interval(ot,m['events'][0],m['events'][-1])
    transfer=trace.actual_file_transfers(nr,os.fsencode(N/'files'))
    same(transfer,trace.actual_file_transfers(orr,os.fsencode(N/'files')),'complete real file read/write/rename/mode sequence')
   elif step['action']['kind']=='cache_seed':same(m['result'],{'actual_private_cache_seed':True},'actual original cache seed control')
   else:
    same(m['result'],{'actual_private_fixture_actions':True},'actual original external fixture action')
    same([e['data']['action']for e in m['events']if e['kind']=='public_fixture_action_enter'],step['action']['actions'],'full original external mutations')
   compare_state(files,n,m,get,scenario,ntree,otree)
   case={'case_id':step['case_id'],'scenario_id':index,'name':step['name'],'domain':step['domain'],'session':step['session'],'request_action':raw_pin(canonical(step['action'])),'actual_response':compared_response,'original_complete_record':r['record'],'native_original_file_data_operations':transfer,'original_completed_operation_checks':logical,'original_event_count':len(m['events']),'original_handler_entries':m['handler_entries'],'original_outer_entries':m['outer_call_tool_entries'],'complete_state_equality':True}
   cases.append(case);scenario_cases.append(case)
  projected_n,nreused=states.incarnation_snapshots(ntree);projected_o,oreused=states.incarnation_snapshots(otree)
  same(projected_n,projected_o,'all complete file bytes/modes/links/within-run object incarnations')
  last=records[-2];same(capture['final_files'],states.original_trees(last['metadata']['files_after'],lambda i:blob(raw,last,i)),'actual original final tree vs complete last observation')
  em=end['metadata'];same(em['scenario_id'],index,'actual final scenario identity')
  same(list(em['sessions']),sorted(per_session),'all original Sessions retired')
  terminal_errors=[]
  for name,v in em['sessions'].items():
   same(v['outer_calls'],per_session[name]['outer'],'actual terminal outer-call count');same(v['handler_calls'],per_session[name]['handler'],'actual terminal typed handler count')
   expected=states.session(v['state'],lambda i:blob(raw,end,i));actual=native['final_state'][name]['view']['projection']
   same({k:actual[k]for k in expected},expected,'actual terminal Session equality')
   service=v['service'];need(type(service['initialized'])is bool,'actual SDK terminal initialization state')
   if service['initialized']:
    fields(service,('initialized','terminal'),'complete actual SDK terminal result')
    same(service['terminal'],'Ok(Closed)','actual SDK EOF drain result')
   else:
    fields(service,('initialized','error_blob'),'complete actual SDK initialization failure')
    # This frozen carrier stores the task's blob index when serve() returns,
    # before finish() later copies that index into scenario_end.  Require an
    # unambiguous actual record owner; do not treat it as an end-record index.
    error_index=uint(service['error_blob'],'actual deferred initialization error index')
    candidates=[r for r in records if error_index<len(r['blobs'])]
    same(len(candidates),1,'unambiguous complete record for deferred SDK error')
    failed=candidates[0];fm=failed['metadata']
    same(fm.get('session'),name,'deferred error belongs to the failing Session')
    same((fm['outer_call_tool_entries'],fm['handler_entries']),(0,0),'initialization failed before original handler')
    response=strict_json(blob(raw,failed,fm['result']['response_blob']))
    same(response['error']['code'],-32602,'actual rejected initialization response')
    later=[r['metadata']for r in records[records.index(failed)+1:-1]if r['metadata']['session']==name]
    need(later and all(x['result']['transport']=='write-error' and x['result']['error']['kind']=='BrokenPipe' and x['outer_call_tool_entries']==x['handler_entries']==0 for x in later),'actual subsequent broken SDK transport')
    error=blob(raw,failed,error_index,text=True);need(error!=b'','actual complete initialization failure diagnostic')
    terminal_errors.append({'session':name,'record':failed['record'],'case_id':fm['case_id'],'blob_index':error_index,'cross_record_observation':True,'complete_error':raw_pin(error)})
  same([e['kind']for e in em['events']],['scenario_end'],'actual EOF marker')
  same(em['events'][0]['data'],{'scenario_id':index},'actual EOF scenario')
  trace.lock_state(em['after']['file_locks'],released=True)
  captures.append({'scenario_id':index,'native_pid':native['process_identity']['native']['pid'],'native_tracer_pid':native['process']['pid'],'original_tracer_pid':p['pid'],'steps':len(scenario_cases),'complete_native_pipe_bytes':nw['bytes'],'complete_original_pipe_bytes':ow['bytes'],'native_trace':{'bytes':nt['bytes'],'sha256':nt['sha256'],'lines':nt['line_count'],'syscalls':len(nt['records']),'fd_lifetimes':nfd},'original_trace':{'bytes':ot['bytes'],'sha256':ot['sha256'],'lines':ot['line_count'],'syscalls':len(ot['records']),'markers':len(ot['markers']),'fd_lifetimes':ofd},'native_outer_receipts':receipt_rows['counts'],'complete_state_projection_sha256':sha(canonical(projected_n)),'terminal_initialization_errors':terminal_errors,'inode_reuse_observations':{'native':nreused,'original':oreused}})
 same(all_ids,list(range(90000,90133)),'all133 exact input IDs in order')
 for file,key,retained in [('NATIVE-FIXTURE-RENAME.json','retained',N/'files.native-retained-for-original-v1'),('ORIGINAL-FIXTURE-RETIREMENT.json','retired',O/'original-files-retired')]:
  v=js(files,O/file);fields(v,('original',key,'identity_before','identity_after','origin_absent'),'complete owned fixture retirement')
  same(v['original'],str(N/'files'),'exact replay fixture origin');same(v[key],str(retained),'exact retained fixture destination')
  same(v['identity_before'],v['identity_after'],'same actual inode retained')
  for k in('device','inode','uid','gid','mode'):uint(v['identity_before'][k],'actual retained inode identity')
  need(v['origin_absent']is True,'original fixture origin retirement not observed')
 return {'schema':'hepta.runtime.batch-public-original-qualification.v1','status':'PASS','native_predecessor':prior,'reader_sources':reader_sources,'original_source':source,'actual_original_processes':19,'actual_fresh_locked_original_builds':1,'actual_original_sdk_processes':15,'actual_native_processes':15,'actual_public_attempts':public,'actual_fixture_controls':133-public,'actual_steps':133,'actual_response_bytes':actual_bytes,'actual_original_markers':marker_count,'actual_original_handler_entries':inner_handlers,'actual_original_outer_call_tool_entries':outer_calls,'original_event_counts':dict(sorted(events.items())),'cases':cases,'captures':captures,'complete_original_comparison':True,'native_inner_child_completion_receipts_available':False,'native_inner_observation':['complete kernel trace','actual full caller/history/lock workspaces','actual request-context/scope/lease prefixes','fixed source control flow'],'configured_fence_authority_success_covered':False,'public_async_dispatch_covered':False,'ordinary_public_stdio_transport_covered':False,'actual_original_full_router':False,'actual_original_get_info':False,'actual_original_config_loader':False,'production_handler_complete':False,'whole_runtime_replaced':False,'new_native_calls':0,'new_rust_processes':0,'artifact_sha256':dict(sorted(files.artifacts.items())),'transient_fixture_directories':[]}


def native_evidence(*,qualification_source,native_source,native_output,native_receipt,graph,causal_source,origins):
 """Full actual native streams/build/state, without any original capture read."""
 files=Files(origins);Q=Path(qualification_source);S=Path(causal_source);N=Path(native_output)
 reader_sources={}
 for name in('capture_format.py','trace_evidence.py','state_comparison.py','strict_public.py'):
  raw=bound(files,Q/name);reader_sources[name]=raw_pin(raw)
  same((Path(__file__).parent/name).read_bytes(),raw,'actual native reader source '+name)
 request={'source':str(native_source),'output':str(N),'graph':str(graph),'receipt':str(native_receipt),'origins':origins}
 prior=native_graph(files,request,S,Q);result=js(files,N/'RESULT.json');captures=[];ids=[];public=0
 for i in range(15):
  row,parsed,wire,fds,receipts=native_capture(files,N,result,i)
  ids.extend(s['input']['case_id']for s in row['steps'])
  public+=sum(s['action']['kind']=='public'for s in row['input']['steps'])
  captures.append({'scenario_id':i,'complete_pipe_bytes':wire['bytes'],'actual_trace':{'bytes':parsed['bytes'],'sha256':parsed['sha256'],'lines':parsed['line_count'],'syscalls':len(parsed['records'])},'actual_fd_lifetimes':fds,'actual_outer_receipts':receipts['counts']})
 same(ids,list(range(90000,90133)),'all133 actual native step IDs')
 return {'schema':'hepta.runtime.batch-public-native-qualification.v1','status':'PASS','native_predecessor':prior,'reader_sources':reader_sources,'actual_native_processes':15,'actual_steps':133,'actual_public_attempts':public,'actual_fixture_controls':133-public,'captures':captures,'fresh_original_comparison':False,'native_inner_child_completion_receipts_available':False,'production_handler_complete':False,'whole_runtime_replaced':False,'new_native_calls':0,'new_rust_processes':0,'artifact_sha256':dict(sorted(files.artifacts.items()))}
