"""Fresh original SDK recipe and full retained comparison; no live fixtures."""
from pathlib import Path,PurePosixPath
import hashlib,io,json,math,os,stat,sys,tarfile,tomllib
import hia_native_request_registry_pipeline as p
import hia_native_request_registry_qualification as q
CHECK='request-registry-original'
CONTROL_CHECK='request-registry-original-evidence'
RUNNER='tests/hia_native/request_registry_sdk/run_original.py'
CONTROL_RUNNER='tests/hia_native/test_request_registry_original_evidence.py'
PREFIX='request-registry/original/'

def _main(root,output,report,name,argv,expected,completed):
 rows=[r for r in report.get('checks',[])if r.get('name')==name];q.require(len(rows)==1,'one actual original main invocation');row=rows[0]
 q.equal(row['command'],argv,'original main invocation bound to recorded origin')
 q.require(row['exit_code']==0 and type(row['exit_code'])is int and row['timed_out']is False and not row.get('start_error'),'original main invocation passed')
 q.require(type(row['timeout_seconds'])is int and row['timeout_seconds']==180,'original main deadline')
 elapsed=row['elapsed_seconds'];q.require(type(elapsed)in(int,float)and math.isfinite(elapsed)and 0<elapsed<=180,'original main interval')
 q.require(type(row.get('pid'))is int and row['pid']>0 and row['cwd']==str(Path(argv[3]).parents[3] if name==CHECK else Path(argv[3]).parents[2]),'original main PID/cwd')
 artifacts={};folder=report.get('check_artifact_directories',{}).get(name,'.')
 q.require(not Path(folder).is_absolute()and '..'not in Path(folder).parts,'original log directory')
 for kind in ('stdout','stderr'):
  relative=(Path(folder)/(name+'.'+kind)).as_posix();path=output/relative;actual=p.pin(path)
  q.equal(actual,{'bytes':row[kind+'_bytes'],'sha256':row[kind+'_sha256']},'full original main stream')
  artifacts[relative]=actual['sha256']
  if kind=='stdout':q.equal(p.read(path),expected,'whole original main summary')
  else:q.require(path.read_bytes()==b'','original main stderr empty')
 q.equal(row['summary'],expected,'original reported summary')
 if completed is not None:q.equal(list(completed(output,report,name)),[row,expected],'original completion callback')
 return row,artifacts

def read_original(root,output,report,native,completed=None):
 source,files=q.Files(root),q.Files(output)
 for name,sha in native['source_sha256'].items():q.require(source.pin(name)['sha256']==sha,'unchanged admitted source')
 binding=files.json(PREFIX+'execution.json');result=files.json(PREFIX+'RESULT.json')
 q.equal(binding['source_files'],p.source_table(root),'complete original source closure')
 old_root,old_output=Path(binding['source_root']),Path(binding['output_root'])
 q.require(old_root.is_absolute()and old_output.is_absolute()and '..'not in old_root.parts+old_output.parts,'normalized original invocation origins')
 argv=[binding['python'],'-I','-B',str(old_root/RUNNER),'--output',str(old_output),'--cargo',binding['cargo'],'--rustc',binding['rustc']]
 expected={'status':'PASS','error':None,'processes':5,'cases':68,'steps':7879,'new_native_calls':0,'whole_runtime_replaced':False}
 main,extra=_main(root,output,report,CHECK,argv,expected,completed)
 q.require(result['status']=='PASS'and result['error']is None and result['whole_runtime_replaced']is False and result['strict_comparison_pending']is True,'original producer success/scope')
 q.require(main['pid']==result['driver_pid'],'original actual driver PID')
 q.equal(files.json(PREFIX+'native-predecessor.json'),native,'complete native-first predecessor')
 q.equal(result['native_first'],{'evidence':files.pins[PREFIX+'native-predecessor.json'],'cases':files.pin('request-registry/sdk/sdk-cases.jsonl')},'exact native-first input')
 provenance=files.json(PREFIX+'SDK-PROVENANCE.json');crate=files.read(PREFIX+'rmcp-3.4.1.crate')
 q.require(q.digest(crate)==q.SDK_CRATE,'unchanged SDK crate checksum differs');q.equal(provenance['crate'],files.pins[PREFIX+'rmcp-3.4.1.crate'],'original crate pin')
 rows={}
 with tarfile.open(fileobj=io.BytesIO(crate),mode='r:*')as archive:
  for member in archive:
   q.require(member.isdir()or member.isfile(),'ordinary crate members')
   if not member.isfile():continue
   name=PurePosixPath(member.name).relative_to('rmcp-3.4.1').as_posix();q.relative(name);q.require(name not in rows,'unique SDK member')
   body=archive.extractfile(member).read();rows[name]={'bytes':len(body),'sha256':q.digest(body)}
   retained='tests/hia_native/request_registry_sdk/original/'+name
   if retained in source.pins:q.equal(source.read(retained),body,'unchanged original SDK source')
 q.equal(provenance['source_files'],rows,'complete original SDK source capture');q.require(len(rows)==result['sdk_source_files']==175,'SDK source count')
 oracle='tests/hia_native/request_registry_sdk/oracle/'
 runtime=source.read('tests/hia_native/request_registry_sdk/original/runtime-Cargo.lock');lock=source.read(oracle+'Cargo.lock')
 q.equal(provenance['runtime_lock'],source.pins['tests/hia_native/request_registry_sdk/original/runtime-Cargo.lock'],'original runtime lock')
 q.equal(provenance['oracle_lock'],source.pins[oracle+'Cargo.lock'],'original fixture lock')
 fixed={(r['name'],r['version']):r['checksum']for r in tomllib.loads(runtime.decode())['package']if r.get('source','').startswith('registry+')}
 packages=[r for r in tomllib.loads(lock.decode())['package']if r.get('source','').startswith('registry+')]
 for package in packages:q.equal(fixed[(package['name'],package['version'])],package['checksum'],'unchanged locked dependency')
 q.equal(provenance['registry_dependencies'],packages,'full original dependency capture');q.require(len(packages)==result['dependencies']==82,'locked dependency count')
 rustc,cargo=Path(binding['rustc']),Path(binding['cargo']);env=binding['environment']
 q.require(rustc.is_absolute()and cargo.is_absolute()and rustc.parent==cargo.parent,'exact sibling toolchain paths')
 q.equal(set(env),{'PATH','CARGO_HOME','RUSTUP_HOME','RUSTC','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','LANG'},'controlled original environment keys')
 q.equal({k:env[k]for k in ('PATH','RUSTC','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','LANG')},{'PATH':str(rustc.parent)+':/usr/bin:/bin','RUSTC':str(rustc),'CARGO_TARGET_DIR':str(old_output/'request-registry/original-target'),'CARGO_BUILD_JOBS':'2','LANG':'C.UTF-8'},'actual toolchain environment')
 for key in ('CARGO_HOME','RUSTUP_HOME'):q.require(Path(env[key]).is_absolute()and '..'not in Path(env[key]).parts,'normalized tool cache root')
 sdk=Path(provenance['source']);q.require(sdk.is_relative_to(Path(env['CARGO_HOME'])/'registry/src'),'actual selected registry SDK origin')
 expected_argv={'rustc':[str(rustc),'-Vv'],'cargo':[str(cargo),'--version'],
  'metadata':[str(cargo),'metadata','--locked','--format-version','1'],
  'build':[str(cargo),'build','--release','--locked'],'original':[str(old_output/'request-registry/original/original-sdk.elf')]}
 process_names=['rustc','cargo','metadata','build','original']
 q.equal([r['record']['name']for r in result['processes']],process_names,'five actual original processes')
 previous=result['started_monotonic_ns'];pids=set();cargo_identity=None
 for wrapped in result['processes']:
  q.equal(set(wrapped),{'record','environment','stdin'},'complete original receipt wrapper')
  row=wrapped['record'];name=row['name'];q.equal(row,files.json(PREFIX+name+'.process.json'),'retained original process')
  q.equal(set(row),{'name','argv','cwd','pid','started_monotonic_ns','finished_monotonic_ns','timeout_seconds','timed_out','start_error','exit_code','stdout','stderr','executable','executable_identity'},'complete actual original process receipt')
  q.equal(row['argv'],expected_argv[name],'fixed original process argv differs');q.equal(wrapped['environment'],env,'same controlled tool environment')
  q.require(row['cwd']==str(old_root/oracle)and row['exit_code']==0 and type(row['exit_code'])is int and row['timed_out']is False and row['start_error']is None,'original process passed')
  timeout={'rustc':30,'cargo':30,'metadata':60,'build':180,'original':180}[name]
  q.require(type(row['timeout_seconds'])is int and row['timeout_seconds']==timeout,'original exact child deadline')
  q.require(type(row['pid'])is int and row['pid']>0 and row['pid']not in pids,'original distinct process PID');pids.add(row['pid'])
  begin,end=row['started_monotonic_ns'],row['finished_monotonic_ns']
  q.require(type(begin)is int and type(end)is int and previous<=begin<=end<=result['finished_monotonic_ns']and end-begin<=timeout*10**9,'original complete process chronology');previous=end
  for kind in ('stdout','stderr'):files.assert_pin(PREFIX+name+'.'+kind,row[kind])
  identity=row['executable_identity'];q.require(type(identity)is dict and set(identity)=={'dev','ino','mode','uid'}and all(type(v)is int for v in identity.values())and identity['dev']>0 and identity['ino']>0 and stat.S_ISREG(identity['mode'])and identity['mode']&0o111,'original full executable identity')
  tool_pin=row['executable'];q.require(type(tool_pin)is dict and set(tool_pin)=={'bytes','sha256'}and type(tool_pin['bytes'])is int and tool_pin['bytes']>0 and type(tool_pin['sha256'])is str and q.SHA.fullmatch(tool_pin['sha256']),'complete original executable pin differs')
  if name!='original':
   tool='rustc'if name=='rustc'else'cargo';q.equal(tool_pin,q.RUST_TOOL_PINS[tool],'fixed original tool executable bytes differ')
   if tool=='cargo':
    if cargo_identity is None:cargo_identity=identity
    else:q.equal(identity,cargo_identity,'original cargo executable identity changed between processes')
   q.require(wrapped['stdin']is None,'non-replay stdin absent')
  else:
   q.equal(wrapped['stdin'],files.pins['request-registry/sdk/sdk-cases.jsonl'],'actual complete original input')
   files.assert_pin(PREFIX+'original-sdk.elf',tool_pin)
 q.require('release: 1.95.0\n'in files.read(PREFIX+'rustc.stdout').decode(),'actual fixed Rust version')
 q.require(files.read(PREFIX+'cargo.stdout').decode().startswith('cargo 1.95.0 '),'actual fixed Cargo version')
 for name in ('rustc','cargo','original'):q.require(files.read(PREFIX+name+'.stderr')==b'','original stable stderr')
 # Cargo metadata may perform an actual locked download on a fresh CI runner;
 # retain that entire stream and bind the exact resulting registry graph.
 files.read(PREFIX+'metadata.stderr');stderr=files.read(PREFIX+'build.stderr')
 q.require(b'Compiling rmcp v3.4.1'in stderr and b'Finished'in stderr and b'release'in stderr,'fresh original build stream')
 metadata=files.json(PREFIX+'metadata.stdout');chosen=[r for r in metadata['packages']if r['name']=='rmcp'and r['version']=='3.4.1']
 q.require(len(chosen)==1 and chosen[0]['manifest_path']==str(sdk/'Cargo.toml'),'actual SDK compiler selection')
 actual={(r['name'],r['version'])for r in metadata['packages']if (r.get('source')or'').startswith('registry+')}
 q.equal(actual,{(r['name'],r['version'])for r in packages},'full metadata dependency set')
 expected_names=[PREFIX+n+'.'+ext for n in process_names for ext in ('stdout','stderr','process.json')]
 expected_names += [PREFIX+n for n in ('RESULT.json','execution.json','native-predecessor.json','SDK-PROVENANCE.json','rmcp-3.4.1.crate','original-sdk.elf')]
 q.equal(files.regular_names(PREFIX.rstrip('/')),sorted(expected_names),'complete original artifacts')
 comparison=q.sdk_comparison(Path(output))
 artifacts=dict(native['artifact_sha256']);artifacts.update({n:pin['sha256']for n,pin in files.pins.items()});artifacts.update(extra)
 return {'schema':'hepta.runtime.request-registry-original-evidence.v1','status':'PASS','native_predecessor_sha256':q.digest(q.canonical(native)),
  'source_sha256':native['source_sha256'],'artifact_sha256':dict(sorted(artifacts.items())),
  'processes':result['processes'],'main_process':main,'comparison':comparison,'fresh_original_processes':5,
  'sdk_version':'3.4.1','sdk_crate_sha256':q.SDK_CRATE,'sdk_sources':175,'locked_dependencies':82,
  'new_native_calls':0,'new_original_processes':0,'whole_runtime_replaced':False,'production_activated':False,'old_stack_removal_qualified':False}

def retained_original(root,output,report,completed=None,*,with_controls=True):
 root,output=Path(root).absolute(),Path(output).absolute();native=p.native_evidence(root,output,report,completed)
 q.equal(native,report['request_registry_evidence'],'same fully admitted native predecessor')
 result=read_original(root,output,report,native,completed)
 if with_controls:
  summary=p.read(output/'request-registry/original-controls/summary.json')
  execution=p.read(output/PREFIX/'execution.json')
  argv=[execution['python'],'-I','-B',str(Path(execution['source_root'])/CONTROL_RUNNER)]
  control_check,artifacts=_main(root,output,report,CONTROL_CHECK,argv,summary,completed)
  controls=q.controls_evidence(root,output,result,domain='original')
  q.equal(controls['driver_pid'],control_check['pid'],'actual original refusal driver PID');result['controls']=controls
  result['artifact_sha256'].update(controls['artifact_sha256']);result['artifact_sha256'].update(artifacts)
 result['artifact_sha256']=dict(sorted(result['artifact_sha256'].items()));return result

def execute_original(root,output,report,rustc,*,record_check,completed,qualification_env):
 root,output=Path(root),Path(output);native=p.native_evidence(root,output,report,completed)
 q.equal(native,report['request_registry_evidence'],'normal original native-first admission')
 env=qualification_env(output,report);env.update(p.environment(root,output,report))
 rustc=Path(rustc).resolve(strict=True);cargo=rustc.with_name('cargo')
 command=[sys.executable,'-I','-B',str(root/RUNNER),'--output',str(output),'--cargo',str(cargo),'--rustc',str(rustc)]
 record_check(output,report,name=CHECK,command=command,timeout=180,env=env,record_identity=True)
 # Read every original byte before the refusal process is admitted.
 retained_original(root,output,report,completed,with_controls=False)
 command=[sys.executable,'-I','-B',str(root/CONTROL_RUNNER)]
 record_check(output,report,name=CONTROL_CHECK,command=command,timeout=180,env=env,record_identity=True)
 result=retained_original(root,output,report,completed)
 return result
