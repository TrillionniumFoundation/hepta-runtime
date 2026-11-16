"""Parameterised native-first request-registry qualification and retained admission.

The HIA owner is a generic NativeBuild module. These processes observe complete
borrowed buffers; they never provide production registry semantics or a public
scheduler. Recorded execution origins are bound to actual main invocations.
"""
from pathlib import Path
import argparse,hashlib,json,math,os,signal,stat,subprocess,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1]
KEY='request_registry'
FOLDER='request-registry'
MANIFEST='build/modules/request-registry/manifest.json'
MANIFEST_SHA256='768c43ab712e081f4eb85c6780ff27b4777078e4fc9b908109d72b158a2663d3'
CONTRACT='native/request_registry_sources.json'
PRIVATE_TEST='test_request_registry.py'
SDK_TEST='test_request_registry_sdk.py'
EVIDENCE_TEST='test_request_registry_evidence.py'
TESTS=(PRIVATE_TEST,SDK_TEST,EVIDENCE_TEST)
DRIVER='tests/hia_native/request_registry_sdk/native.py'

def require(value,message):
 if not value:raise ValueError(message)
def unique(pairs):
 result={}
 for key,value in pairs:
  require(key not in result,'duplicate JSON key: '+key);result[key]=value
 return result
def decode(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda v:(_ for _ in()).throw(ValueError(v)))
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def same(a,b,message):require(encoded(a)==encoded(b),message)
def regular(path):
 path=Path(path).absolute();require(path.resolve(strict=True)==path and stat.S_ISREG(path.lstat().st_mode),'evidence must be an unsymlinked regular file: '+str(path));return path
def pin(path):
 path=regular(path);before=path.stat()
 with path.open('rb')as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
 after=path.stat();identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
 require(identity(before)==identity(after),'file changed while hashing');return {'bytes':before.st_size,'sha256':sha}
def read(path):return decode(regular(path).read_bytes())
def write_new(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb')as stream:stream.write(encoded(value))
def source_table(root):
 root=Path(root).absolute();contract=read(root/CONTRACT)
 require(contract['schema']=='hepta.runtime.request-registry-sources.v1','source contract schema')
 names=contract['runtime_sources'];require(type(names)is list and names==sorted(set(names)),'exact sorted source set')
 require(CONTRACT not in names and set(contract['frozen_sources'])<=set(names),'source contract closure')
 result={name:pin(root/name)for name in [CONTRACT,*names]}
 for name,wanted in contract['frozen_sources'].items():same(result[name],wanted,'unchanged qualified source: '+name)
 same((root/'tests/hia_native/request_registry_sdk/original/runtime-Cargo.lock').read_bytes().hex(),
      (root/'Cargo.lock').read_bytes().hex(),'unchanged original runtime lock')
 result['Cargo.lock']=pin(root/'Cargo.lock')
 return dict(sorted(result.items()))
def executable_identity(path):
 path=Path(path);info=path.stat()
 require(stat.S_ISREG(info.st_mode)and info.st_mode&0o111,'actual executable must be regular executable')
 return {'dev':info.st_dev,'ino':info.st_ino,'mode':info.st_mode,'uid':info.st_uid}
def record(folder,name,argv,*,cwd,timeout=180,env=None,stdin=None):
 folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
 start=time.monotonic_ns();timed_out=False;start_error=None;child=None;code=None
 tool=pin(Path(argv[0]).resolve(strict=True));identity=executable_identity(argv[0])
 with (folder/(name+'.stdout')).open('xb')as out,(folder/(name+'.stderr')).open('xb')as err:
  try:
   child=subprocess.Popen(argv,cwd=cwd,env=env,stdin=stdin,stdout=out,stderr=err,start_new_session=True)
   try:code=child.wait(timeout=timeout)
   except subprocess.TimeoutExpired:
    timed_out=True
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    code=child.wait()
  except OSError as error:start_error={'type':type(error).__name__,'message':str(error)}
 row={'name':name,'argv':argv,'cwd':str(cwd),'pid':child.pid if child else None,
  'started_monotonic_ns':start,'finished_monotonic_ns':time.monotonic_ns(),
  'timeout_seconds':timeout,'timed_out':timed_out,'start_error':start_error,'exit_code':code,
  'stdout':pin(folder/(name+'.stdout')),'stderr':pin(folder/(name+'.stderr')),
  'executable':tool,'executable_identity':identity}
 same(pin(Path(argv[0]).resolve(strict=True)),tool,'executed binary unchanged')
 same(executable_identity(argv[0]),identity,'executed binary identity unchanged')
 write_new(folder/(name+'.process.json'),row)
 require(not start_error and not timed_out and code==0,'actual process failed: '+name)
 return row

def environment(root,output,report):
 return {'HIA_REQUEST_REGISTRY_OUTPUT':str(Path(output).absolute()),
         'HIA_REQUEST_REGISTRY_MANIFEST':str(Path(output).absolute()/MANIFEST)}
def test_commands(root,output,report):
 return {name:[sys.executable,'-I','-B',str(Path(root)/'tests/hia_native'/name)]for name in TESTS}
def _execution(root,output):
 root,output=Path(root).absolute(),Path(output).absolute();path=output/FOLDER/'execution.json'
 table=source_table(root)
 wanted={'schema':'hepta.runtime.request-registry-execution.v1','source_root':str(root),'output_root':str(output),
         'manifest':str(output/MANIFEST),'python':sys.executable,
         'python_executable':pin(Path(sys.executable).resolve(strict=True)),
         'python_identity':executable_identity(sys.executable),'source_files':table}
 if path.exists():same(read(path),wanted,'one unchanged request-registry execution')
 else:write_new(path,wanted)
 return wanted

def run_native(root,output,domain):
 root,output=Path(root).absolute(),Path(output).absolute()
 require(domain in ('private','sdk'),'fixed native domain')
 binding=_execution(root,output);base=output/FOLDER
 require(pin(output/MANIFEST)['sha256']==MANIFEST_SHA256,'fixed real module identity')
 argv=[sys.executable,'-I','-B',str(root/DRIVER),'--domain',domain,'--manifest',str(output/MANIFEST),
       '--output',str(base/domain),'--execution',str(base/'execution.json')]
 receipt=record(base,domain,argv,cwd=root)
 result=read(base/domain/'RESULT.json')
 require(result['status']=='PASS'and result['error']is None,'native domain completed')
 same(source_table(root),binding['source_files'],'complete sources after native execution')
 counts=(11514,45)if domain=='private'else(8044,68)
 same([result['native_calls'],result['sessions']],list(counts),'complete original native corpus')
 summary={'status':'PASS','test_groups':1,'skipped':0,'errors':0,'failures':0,'domain':domain,
          'native_calls':counts[0],'sessions':counts[1],'source_files':len(binding['source_files']),
          'child_pid':receipt['pid'],'original_sdk_executed':False,'whole_runtime_replaced':False}
 write_new(base/(domain+'.summary.json'),summary);print(json.dumps(summary,sort_keys=True),flush=True)

def _module(output,report):
 item=report['modules'][KEY]
 same(item['manifest'],MANIFEST,'registered request-registry manifest')
 same(item['source'],'native/request_registry.hepta','registered HIA owner')
 same(item.get('builder'),'borrowed_bytes','generic request-registry NativeBuild')
 same(pin(Path(output)/MANIFEST)['sha256'],item['sha256'],'registered module identity')

def _check(root,output,report,name,completed,binding,expected):
 rows=[r for r in report.get('checks',[])if r.get('name')==name]
 require(len(rows)==1,'one actual request-registry main suite: '+name);row=rows[0]
 command=[binding['python'],'-I','-B',str(Path(binding['source_root'])/'tests/hia_native'/name)]
 same(row['command'],command,'recorded origin bound to actual main invocation')
 require(type(row['exit_code'])is int and row['exit_code']==0 and row['timed_out']is False and not row.get('start_error'),'main suite completed')
 require(type(row['timeout_seconds'])is int and row['timeout_seconds']==180,'main suite exact deadline')
 elapsed=row['elapsed_seconds'];require(type(elapsed)in(int,float)and math.isfinite(elapsed)and 0<elapsed<=180,'main suite actual interval')
 require(type(row.get('pid'))is int and row['pid']>0 and row['cwd']==binding['source_root'],'main process identity')
 artifacts={}
 folder=report.get('check_artifact_directories',{}).get(name,'.')
 require(not Path(folder).is_absolute()and '..'not in Path(folder).parts,'relative main stream directory')
 for kind in ('stdout','stderr'):
  relative=(Path(folder)/(name+'.'+kind)).as_posix();path=Path(output)/relative
  actual=pin(path);same(actual,{'bytes':row[kind+'_bytes'],'sha256':row[kind+'_sha256']},'complete main stream')
  artifacts[relative]=actual['sha256']
  if kind=='stdout':same(read(path),expected,'complete main result')
  else:require(path.read_bytes()==b'','main suite stderr empty')
 same(row.get('summary'),expected,'main summary')
 if completed is not None:same(list(completed(output,report,name)),[row,expected],'actual main completion callback')
 return row,artifacts

def native_evidence(root,output,report,completed=None,*,with_controls=True):
 import hia_native_request_registry_qualification as reader
 root,output=Path(root).absolute(),Path(output).absolute();_module(output,report)
 binding=read(output/FOLDER/'execution.json')
 table=source_table(root);same(table,binding['source_files'],'complete source-owned captured closure')
 same({n:report['source_sha256'].get(n)for n in table},{n:p['sha256']for n,p in table.items()},'main source inventory')
 for key in ('source_root','output_root'):
  path=Path(binding[key]);require(path.is_absolute()and '..'not in path.parts,'normalized actual origin')
 same(binding['manifest'],str(Path(binding['output_root'])/MANIFEST),'actual manifest origin')
 checks={};extra={}
 for name,domain in [(PRIVATE_TEST,'private'),(SDK_TEST,'sdk')]:
  checks[domain],artifacts=_check(root,output,report,name,completed,binding,read(output/FOLDER/(domain+'.summary.json')))
  extra.update(artifacts)
 raw=reader.native_evidence(root,output,binding)
 raw['artifact_sha256'].update(extra)
 for name in extra:raw['artifact_bytes'][name]=pin(output/name)['bytes']
 raw.update(main_checks=checks,execution_source_root=binding['source_root'],execution_output_root=binding['output_root'])
 raw['artifact_sha256']=dict(sorted(raw['artifact_sha256'].items()));raw['artifact_bytes']=dict(sorted(raw['artifact_bytes'].items()))
 if with_controls:
  summary=read(output/FOLDER/'native-controls/summary.json')
  control_check,artifacts=_check(root,output,report,EVIDENCE_TEST,completed,binding,summary);extra.update(artifacts)
  controls=reader.controls_evidence(root,output,raw,domain='native')
  same(controls['driver_pid'],control_check['pid'],'actual native refusal driver PID')
  raw['controls']=controls
  raw['artifact_sha256'].update(controls['artifact_sha256']);raw['artifact_bytes'].update(controls['artifact_bytes'])
 raw['artifact_sha256'].update(extra)
 for name in extra:raw['artifact_bytes'][name]=pin(output/name)['bytes']
 raw.update(main_checks=checks,execution_source_root=binding['source_root'],execution_output_root=binding['output_root'])
 raw['artifact_sha256']=dict(sorted(raw['artifact_sha256'].items()));raw['artifact_bytes']=dict(sorted(raw['artifact_bytes'].items()))
 return raw

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
 parser.add_argument('--report',type=Path,required=True);parser.add_argument('--result',type=Path,required=True)
 parser.add_argument('--without-controls',action='store_true');args=parser.parse_args()
 value=native_evidence(args.root,args.output,read(args.report),with_controls=not args.without_controls)
 write_new(args.result,value);print(json.dumps({'status':'PASS','artifacts':len(value['artifact_sha256']),'new_native_calls':0,'new_original_processes':0},sort_keys=True))
if __name__=='__main__':main()
