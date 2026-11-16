"""Read complete request-registry native/SDK evidence without executing HIA or Rust."""
from pathlib import Path,PurePosixPath
import argparse,ast,collections,gzip,hashlib,io,itertools,json,math,os,random,re,stat,struct,tarfile,tomllib,types
COMPILER='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
COMMIT='d3e2c90173cf733e42b299d0c4274df4b593a12f'
TREE='8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'
HIA='ecb9f3db921f0aec1ca5ab0870faeb0fdf1cf9e7a82ec112c8280e6077a567cf'
IMAGE='ecba291fa5e5a6afa3a7b758aa9b50347c8de2938e69756a8e215800de1a3fe5'
MANIFEST='768c43ab712e081f4eb85c6780ff27b4777078e4fc9b908109d72b158a2663d3'
SDK_CRATE='5b6317cd8c13e3ec9033cf2aa5aa92cd743f0f4f8a93cddc42ea0ae6ce3b8898'
FOLDER='request-registry'
PRIVATE='request-registry/private'
SDK='request-registry/sdk'
ORIGINAL='request-registry/original'
RUST_TOOL_PINS={'rustc':{'bytes':644784,'sha256':'bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6'},'cargo':{'bytes':42185192,'sha256':'841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66'}}
SHA=re.compile(r'[0-9a-f]{64}\Z')
def require(ok,message):
 if not ok:raise ValueError(message)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def unique(pairs):
 value={}
 for key,item in pairs:
  require(key not in value,'duplicate JSON key: '+key);value[key]=item
 return value
def parse(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda value:(_ for _ in()).throw(ValueError(value)))
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def equal(left,right,message):
 if isinstance(left,(bytes,set))or isinstance(right,(bytes,set)):require(type(left)is type(right)and left==right,message)
 else:require(canonical(left)==canonical(right),message)
def relative(name):
 require(type(name)is str and name and '\\'not in name and '\0'not in name,'invalid relative name')
 path=PurePosixPath(name)
 require(not path.is_absolute()and all(p not in {'','.','..'}for p in name.split('/')),'relative path escapes evidence')
 return Path(*path.parts)
class Files:
 def __init__(self,root):
  self.root=Path(root).absolute();require(self.root.resolve(strict=True)==self.root and not self.root.is_symlink(),'evidence root crosses symlink')
  self.pins={}
 def path(self,name):
  path=self.root/relative(name)
  require(path.resolve(strict=True)==path.absolute(),'evidence path crosses symlink')
  info=path.stat();require(stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid(),'evidence path is not owned regular file')
  return path
 def read(self,name):
  path=self.path(name);before=path.stat();raw=path.read_bytes();after=path.stat()
  identity=lambda row:(row.st_dev,row.st_ino,row.st_mode,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
  require(identity(before)==identity(after)and len(raw)==before.st_size,'evidence changed while reading')
  pin={'bytes':len(raw),'sha256':digest(raw)}
  if name in self.pins:equal(self.pins[name],pin,'evidence changed between reads')
  self.pins[name]=pin;return raw
 def pin(self,name):
  path=self.path(name);before=path.stat()
  with path.open('rb')as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
  after=path.stat();require((before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'stream changed while hashing')
  pin={'bytes':before.st_size,'sha256':sha}
  if name in self.pins:equal(self.pins[name],pin,'evidence changed between hash/read')
  self.pins[name]=pin;return pin
 def json(self,name):return parse(self.read(name))
 def jsonl(self,name):
  self.pin(name);path=self.path(name)
  with (gzip.open(path,'rb')if name.endswith('.gz')else path.open('rb'))as stream:
   for raw in stream:
    require(raw.endswith(b'\n'),'incomplete JSONL record');yield parse(raw)
 def assert_pin(self,name,pin):equal(self.pin(name),pin,'full byte pin differs: '+name)
 def regular_names(self,folder):
  base=self.root/relative(folder);require(base.resolve(strict=True)==base.absolute()and base.is_dir(),'artifact directory differs')
  names=[]
  for parent,dirs,files in os.walk(base,followlinks=False):
   for name in dirs:
    path=Path(parent)/name;info=path.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==os.getuid(),'artifact subtree crosses link or owner')
   for name in files:
    path=Path(parent)/name;relative_name=path.relative_to(self.root).as_posix();self.path(relative_name);names.append(relative_name)
  return sorted(names)

def build_evidence(source,files):
 prefix='build/modules/request-registry/'
 manifest=files.json(prefix+'manifest.json');require(files.pins[prefix+'manifest.json']['sha256']==MANIFEST,'frozen native manifest differs')
 require(manifest['source_sha256']==HIA and manifest['image_sha256']==IMAGE and manifest['compiler_sha256']==COMPILER,'native module identity differs')
 require(manifest['compiler_commit']==COMMIT and manifest['standalone']is None and manifest['buffer_profile']=='history.v1','native module scope differs')
 raw=source.read('native/request_registry.hepta');require(digest(raw)==HIA,'frozen HIA differs')
 equal(files.read(prefix+'request-registry.hepta'),raw,'compiled source differs')
 equal(files.read(prefix+'module.input.bin'),raw,'compiler full input differs')
 image=files.read(prefix+'module.image.bin');require(digest(image)==IMAGE and len(image)==89776,'native executable image differs')
 build=files.json(prefix+'build.json');bootstrap=files.json('build/bootstrap/bootstrap.json')
 require(build['whole_runtime_replaced']is False,'development build overclaims runtime replacement')
 dependency=build['compiler_dependency'];require(dependency['commit']==COMMIT and dependency['tree']==TREE and dependency['files'],'fixed compiler dependency differs')
 equal(bootstrap['dependency'],dependency,'compiler source identities differ')
 require(bootstrap['schema']=='hepta.runtime.native-bootstrap.v1'and bootstrap['generation_sha256']==COMPILER and bootstrap['qualification']=='development_fixed_point','bootstrap scope differs')
 for label in ['B1','B2','B3']:require(files.pin('build/bootstrap/'+label+'.image.bin')['sha256']==COMPILER,'compiler generation differs')
 receipt=files.json(prefix+'module.receipt.json');equal(build['compile_receipt'],receipt,'compile receipts differ')
 require(receipt['status']=='returned'and receipt['abi_status']==0 and receipt['core_u32']==89776 and receipt['result_u64']==89776,'native compiler did not return exact image')
 require(receipt['source_unchanged']is True and receipt['forbidden_compiler_modules_loaded']==[]and receipt['artifact_sha256']==COMPILER,'native compiler input custody differs')
 require(receipt['source_sha256']==receipt['input_sha256']==HIA and receipt['input_bytes']==len(raw),'compiler source input differs')
 require(receipt['produced_bytes']==len(image)and receipt['produced_sha256']==IMAGE,'produced native image differs')
 output=files.read(prefix+'module.output.bin');require(len(output)==1048576 and digest(output)==receipt['output_sha256']and output[:len(image)]==image,'complete compiler output differs')
 request=files.json(prefix+'module.request.json');require(request['image_sha256']==COMPILER and request['source_sha256']==HIA and request['capacity']==1048576 and request['workspace_size']==1048576 and request['workspace_fill']==0,'compiler request differs')
 stdout=files.json(prefix+'module.stdout.log')
 stdout_fields={'abi_status','core_u32','forbidden_compiler_modules_loaded','image_sha256','limits','loader_operations','native_elapsed_ns','output_sha256','output_unchanged','result_u64','return_encoding','source_sha256','source_unchanged','status','workspace_header'}
 equal(set(stdout),stdout_fields,'complete compiler stdout fields differ')
 equal(stdout,{key:receipt[key]for key in stdout_fields},'complete compiler stdout differs from receipt')
 require(receipt['image_sha256']==COMPILER and receipt['return_encoding']=='zero-extended-u32'and receipt['output_unchanged']is False,'compiler return encoding/image/output scope differs')
 equal(receipt['limits'],{'address_bytes':268435456,'core_dumpable':False,'cpu_seconds':10,'output_capacity':1048576,'stack_bytes':8388608,'workspace_bytes':1048576},'compiler execution limits differ')
 require(type(receipt['native_elapsed_ns'])is int and type(receipt['wall_elapsed_ns'])is int and 0<receipt['native_elapsed_ns']<=receipt['wall_elapsed_ns']<=10*10**9,'compiler actual execution interval differs')
 require(receipt['runner_sha256']==dependency['files']['tools/hia_selfhost_child.py']=='1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29','compiler loader source differs')
 require(files.read(prefix+'module.stderr.log')==b'','native compiler stderr is not empty')
 expected=[prefix+n for n in ['build.json','manifest.json','module.image.bin','module.input.bin','module.output.bin','module.receipt.json','module.request.json','module.stderr.log','module.stdout.log','request-registry.hepta']]
 expected+=['build/bootstrap/'+name for name in ['B1.image.bin','B2.image.bin','B3.image.bin','bootstrap.json']]
 equal(files.regular_names('build/modules/request-registry'),sorted(n for n in expected if n.startswith(prefix)),'complete native module inventory differs')
 return {'manifest_sha256':MANIFEST,'source_sha256':HIA,'image_sha256':IMAGE,'compiler_sha256':COMPILER,'compiler_commit':COMMIT,'compiler_tree':TREE,'compiler_source_files':len(dependency['files']),'fresh_full_cold_claimed':False}

def request_bytes(op,generation=0,kind=0,key=b'',reason=0):
 return struct.pack('<8s7Q',b'HRQREG01',op,generation,kind,len(key),reason,0,0)+key
def result_bytes(op,generation=0,related=0,decision=0,count=0,mapped=0,status=0):
 return struct.pack('<8s7Q',b'HRQRR001',op,status,generation,related,decision,count,mapped)
def typed_id(ident):
 if type(ident)is int:return 1,struct.pack('<q',ident)
 require(type(ident)is str,'request ID must preserve its integer/string type');return 2,ident.encode()
class Registry:
 def __init__(self):
  self.next=1;self.records={};self.ids={};self.parent=False;self.drain=0;self.used=64
 def flags(self,g):
  record=self.records[g]
  return int(record['cancelled'])+2*int(record['completed'])+4*int(self.ids.get(record['id'])==g)
 def step(self,op,g=0,kind=0,key=b'',reason=0):
  generation=related=decision=0
  if op==1:
   require(not self.drain,'register after drain')
   generation=self.next;self.next+=1;ident=(kind,key);related=self.ids.get(ident,0)
   self.records[generation]={'id':ident,'cancelled':self.parent,'completed':False};self.ids[ident]=generation
   decision=4+int(self.parent)
  elif op==2:
   require(not self.drain,'cancel notification after drain')
   related=self.ids.pop((kind,key),0)
   if related:self.records[related]['cancelled']=True
   decision=int(bool(related))
  elif op==3:
   require(g in self.records and not self.records[g]['completed'],'invalid completion')
   generation=g;related=self.ids.pop(self.records[g]['id'],0)
   if related:self.records[related]['cancelled']=True
   self.records[g]['completed']=True;decision=int(bool(related))
  elif op==4:
   require(g in self.records and self.records[g]['completed'],'unfinished handler cannot retire')
   generation=g;del self.records[g]
  elif op==5:
   require(g in self.records,'inspect missing record')
   generation=g;decision=self.flags(g)+8*int(self.parent)+16*int(bool(self.drain))
  elif op==6:
   decision=int(not self.parent);self.parent=True
   for record in self.records.values():record['cancelled']=True
  elif op==7:
   require(not self.drain and(reason==1 or(reason==2 and self.parent)),'invalid drain transition')
   self.drain=reason;decision=5000 if reason==1 else 2000
  else:require(op==0,'unknown operation')
  self.used=64+sum((48+len(record['id'][1])+7)&~7 for record in self.records.values())
  return result_bytes(op,generation,related,decision,len(self.records),len(self.ids))
 def arena(self,capacity):
  value=bytearray(struct.pack('<8s7Q',b'HRQRS001',self.next,self.used,len(self.records),len(self.ids),int(self.parent),self.drain,0))
  for g,r in self.records.items():
   kind,key=r['id'];extent=(48+len(key)+7)&~7
   value.extend(struct.pack('<6Q',extent,g,kind,len(key),self.flags(g),0));value.extend(key);value.extend(bytes(extent-48-len(key)))
  require(len(value)==self.used<=capacity,'reconstructed state exceeds owned arena')
  value.extend(bytes(capacity-len(value)));return bytes(value)
 def snapshot(self):
  return [{'generation':g,'cancelled':r['cancelled'],'completed':r['completed']}for g,r in self.records.items()]
 def id_value(self,g):
  kind,key=self.records[g]['id'];return struct.unpack('<q',key)[0]if kind==1 else key.decode('utf-8')

class Journal:
 def __init__(self,files,native,receipt):
  self.files=files;self.native=native;self.receipt=receipt;self.rows=iter(files.jsonl('request-registry/sdk/native/calls.jsonl.gz'))
  self.cache={};self.count=0;self.growth=0;self.last=receipt['started_monotonic_ns'];self.session=0
 def content(self,reference):
  require(type(reference)is dict and set(reference)=={'bytes','sha256','chunks'},'invalid complete buffer reference')
  require(type(reference['bytes'])is int and reference['bytes']>=0 and SHA.fullmatch(reference['sha256']),'invalid buffer identity')
  chunks=[]
  for index,sha in enumerate(reference['chunks']):
   require(type(sha)is str and SHA.fullmatch(sha),'invalid chunk SHA')
   if sha not in self.cache:
    raw=self.files.read('request-registry/sdk/native/blobs/'+sha)
    require(digest(raw)==sha and 0<len(raw)<=4096,'physical chunk differs')
    self.cache[sha]=raw
   raw=self.cache[sha]
   if index+1<len(reference['chunks']):require(len(raw)==4096,'short intermediate chunk')
   chunks.append(raw)
  raw=b''.join(chunks);require(len(raw)==reference['bytes']and digest(raw)==reference['sha256'],'whole native buffer differs')
  require(len(reference['chunks'])==(len(raw)+4095)//4096,'chunk extent differs');return raw
 def start(self,domain):
  self.session+=1;self.domain='sdk-schedule/'+domain;self.model=Registry();self.output=bytes([0xa7])*96;self.work=bytes(64)
  return self.call(0)
 def call(self,op,g=0,kind=0,key=b'',reason=0):
  request=request_bytes(op,g,kind,key,reason)
  while True:
   row=next(self.rows);self.count+=1
   equal(set(row),{'ordinal','session','domain','pid','started_monotonic_ns','finished_monotonic_ns','actual_code','expected_code','request','expected','output_before','output_after','workspace_before','workspace_after'},'native journal fields differ')
   require(row['ordinal']==self.count and row['session']==self.session and row['pid']==self.native['pid']==self.receipt['pid'],'native process/order binding differs')
   begin=row['started_monotonic_ns'];end=row['finished_monotonic_ns']
   require(type(begin)is int and type(end)is int and self.last<=begin<=end<=self.receipt['finished_monotonic_ns'],'native call clocks differ');self.last=end
   require(row['actual_code']==row['expected_code']==64,'unexpected native return in SDK schedule')
   equal(self.content(row['request']),request,'source-bound native request differs')
   equal(self.content(row['output_before']),self.output,'complete output continuity differs')
   equal(self.content(row['workspace_before']),self.work,'complete arena continuity differs')
   needed=self.model.used+((48+len(key)+7)&~7)if op==1 else 64
   grows=op in(0,1)and needed>len(self.work)
   if grows:
    expected=result_bytes(op,related=needed,count=len(self.model.records),mapped=len(self.model.ids),status=2)
    after_work=self.work;self.growth+=1
   else:
    expected=self.model.step(op,g,kind,key,reason);after_work=self.model.arena(len(self.work))
   equal(row['domain'],self.domain+('/growth'if grows else''),'native call domain differs')
   equal(self.content(row['expected']),expected,'retained expected response differs from independently reconstructed transition')
   self.output=expected+self.output[64:]
   equal(self.content(row['output_after']),self.output,'complete native response/tail differs')
   equal(self.content(row['workspace_after']),after_work,'complete native arena differs')
   self.work=after_work
   if not grows:return struct.unpack('<8s7Q',expected)
   self.work+=bytes(max(needed,len(self.work)*2)-len(self.work));self.output=bytes([0xa7])*96
 def finish(self):
  require(next(self.rows,None)is None,'extra native journal records')
  require(self.count==self.native['native_calls']==8044 and self.growth==self.native['growth']==167 and self.session==68,'complete native call counts differ')
  require(len(self.cache)==self.native['blob_count']==45818,'complete native chunk count differs')
  expected=sorted('request-registry/sdk/native/blobs/'+sha for sha in self.cache)
  equal(self.files.regular_names('request-registry/sdk/native/blobs'),expected,'unreferenced or missing native chunks')

def sdk_native_evidence(source,files,binding):
 native,receipt=domain_evidence(source,files,binding,'sdk')
 case_scope={};exec(compile(source.read('tests/hia_native/request_registry_sdk/cases.py'),'<frozen request registry schedules>','exec'),case_scope)
 cases=case_scope['schedules']()
 raw=b''.join(canonical(case)+b'\n'for case in cases)
 equal(files.read('request-registry/sdk/sdk-cases.jsonl'),raw,'full native input corpus differs from frozen source')
 equal(files.pins['request-registry/sdk/sdk-cases.jsonl'],native['cases'],'native corpus identity differs')
 observed=iter(files.jsonl('request-registry/sdk/native-observations.jsonl.gz'));journal=Journal(files,native,receipt)
 steps=0;domains=[]
 for case in cases:
  journal.start(case['name']);started=[];emitted=[];notifications=[];reason=None
  for ordinal,step in enumerate(case['steps']):
   op=step['op']
   if op=='init':require(ordinal==0,'invalid schedule initialization')
   elif op=='register':
    kind,key=typed_id(step['id']);response=journal.call(1,kind=kind,key=key);require(response[3]==step['generation'],'native generation differs')
    started.append({'generation':response[3],'id':journal.model.id_value(response[3])})
   elif op=='cancel':
    if step['id']is not None:
     kind,key=typed_id(step['id']);journal.call(2,kind=kind,key=key)
    params={'reason':'notification-'+str(ordinal)}
    if step['id']is not None:params['requestId']=step['id']
    notifications.append(params)
   elif op=='complete':
    g=step['generation'];ident=journal.model.id_value(g);response=journal.call(3,g)
    if response[5]&1:emitted.append({'generation':g,'id':ident,'error':g%3==0})
   elif op=='retire':journal.call(4,step['generation'])
   elif op=='inspect':journal.call(5,step['generation'])
   elif op=='parent':journal.call(6)
   elif op=='drain':journal.call(7,reason=step['reason']);reason=step['reason']
   else:raise ValueError('unknown frozen schedule operation')
   equal(next(observed),{'event':'step','case':case['case'],'ordinal':ordinal,'op':op,'records':journal.model.snapshot()},'full HIA snapshot differs from raw native journal')
   steps+=1
  require(not journal.model.records and not journal.model.ids,'native records or ID mappings leaked')
  end={'event':'end','case':case['case'],'started':started,'notifications':notifications,'emissions':emitted,'terminal':'Cancelled'if reason==2 else'Closed'}
  equal(next(observed),end,'native terminal projection differs from full raw journal')
  domains.append({'case':case['case'],'name':case['name'],'steps':len(case['steps']),'handlers':len(started),'notifications':len(notifications),'emitted':len(emitted),'terminal_projection_sha256':digest(canonical(end))})
 require(next(observed,None)is None,'extra native projected observations');journal.finish()
 require(steps==native['steps']==7879 and native['sessions']==68,'native schedule accounting differs')
 expected_names=['request-registry/sdk/RESULT.json','request-registry/sdk/sdk-cases.jsonl','request-registry/sdk/native-observations.jsonl.gz','request-registry/sdk/native/calls.jsonl.gz']
 expected_names+=['request-registry/sdk/native/blobs/'+sha for sha in journal.cache]
 equal(files.regular_names('request-registry/sdk'),sorted(expected_names),'native artifact closure differs')
 return native,receipt,cases,domains

def process_evidence(files,name,argv,cwd,binding,timeout=180):
 row=files.json(FOLDER+'/'+name+'.process.json')
 equal(set(row),{'name','argv','cwd','pid','started_monotonic_ns','finished_monotonic_ns','timeout_seconds','timed_out','start_error','exit_code','stdout','stderr','executable','executable_identity'},'complete actual process receipt')
 equal(row['argv'],argv,'source-owned native process argv')
 require(row['name']==name and row['cwd']==cwd,'source-owned native process origin')
 require(type(row['pid'])is int and row['pid']>0,'native child PID')
 require(type(row['exit_code'])is int and row['exit_code']==0 and row['timed_out']is False and row['start_error']is None,'native invocation did not complete')
 require(type(row['timeout_seconds'])is int and row['timeout_seconds']==timeout,'native exact deadline')
 begin,end=row['started_monotonic_ns'],row['finished_monotonic_ns']
 require(type(begin)is int and type(end)is int and 0<begin<=end and end-begin<=timeout*10**9,'native actual process interval')
 equal(row['executable'],binding['python_executable'],'actual Python executable full bytes')
 equal(row['executable_identity'],binding['python_identity'],'actual Python executable identity')
 require(set(row['executable'])=={'bytes','sha256'}and type(row['executable']['bytes'])is int and row['executable']['bytes']>0 and SHA.fullmatch(row['executable']['sha256']),'complete Python executable pin')
 identity=row['executable_identity'];require(set(identity)=={'dev','ino','mode','uid'}and all(type(v)is int for v in identity.values())and identity['dev']>0 and identity['ino']>0 and stat.S_ISREG(identity['mode'])and identity['mode']&0o111,'complete Python executable identity')
 for kind in ('stdout','stderr'):files.assert_pin(FOLDER+'/'+name+'.'+kind,row[kind])
 require(files.read(FOLDER+'/'+name+'.stderr')==b'','native stderr is not empty')
 return row

def domain_evidence(source,files,binding,domain):
 prefix=FOLDER+'/'+domain
 result=files.json(prefix+'/RESULT.json')
 require(result['status']=='PASS'and result['error']is None and result['domain']==domain and result['original_sdk_executed']is False and result['whole_runtime_replaced']is False,'native-first domain status/scope')
 equal(result['source_files'],binding['source_files'],'native complete source closure')
 equal(result['manifest'],files.pins['build/modules/request-registry/manifest.json'],'native module pin')
 equal(result['execution'],files.pins[FOLDER+'/execution.json'],'native execution binding')
 root=Path(binding['source_root']);output=Path(binding['output_root'])
 argv=[binding['python'],'-I','-B',str(root/'tests/hia_native/request_registry_sdk/native.py'),'--domain',domain,
       '--manifest',str(output/'build/modules/request-registry/manifest.json'),'--output',str(output/prefix),
       '--execution',str(output/FOLDER/'execution.json')]
 receipt=process_evidence(files,domain,argv,str(root),binding)
 require(receipt['pid']==result['pid'],'native actual child identity')
 require(receipt['started_monotonic_ns']<=result['started_monotonic_ns']<=result['finished_monotonic_ns']<=receipt['finished_monotonic_ns'],'native domain interval')
 equal(files.json(FOLDER+'/'+domain+'.stdout'),{k:v for k,v in result.items()if k!='source_files'},'native complete stdout differs')
 summary=files.json(FOLDER+'/'+domain+'.summary.json')
 expected={'status':'PASS','test_groups':1,'skipped':0,'errors':0,'failures':0,'domain':domain,
           'native_calls':11514 if domain=='private'else 8044,'sessions':45 if domain=='private'else 68,
           'source_files':len(binding['source_files']),'child_pid':receipt['pid'],'original_sdk_executed':False,'whole_runtime_replaced':False}
 equal(summary,expected,'source-owned native suite summary')
 return result,receipt

class Pointer:
 def __init__(self,buffer,offset=0):self.buffer,self.offset=buffer,offset
 def __add__(self,offset):return Pointer(self.buffer,self.offset+offset)
class ByteArrays:
 """Only Python byte arrays; no ctypes, native code, mmap or external execution."""
 @staticmethod
 def span(value,n):
  buffer,at=(value.buffer,value.offset)if isinstance(value,Pointer)else(value,0)
  require(type(n)is int and 0<=at<=len(buffer)and 0<=n<=len(buffer)-at,'pure replay borrowed span');return buffer,at
 @staticmethod
 def addressof(value):return Pointer(value)
 @classmethod
 def string_at(cls,value,n):buffer,at=cls.span(value,n);return bytes(buffer[at:at+n])
 @classmethod
 def memset(cls,value,byte,n):buffer,at=cls.span(value,n);buffer[at:at+n]=bytes([byte])*n
 @classmethod
 def memmove(cls,target,value,n):
  buffer,at=cls.span(target,n);raw=cls.string_at(value,n);buffer[at:at+n]=raw

class PrivateReplay:
 def __init__(self,files,result,receipt):
  self.files,self.result,self.receipt=files,result,receipt
  self.rows=iter(files.jsonl(PRIVATE+'/calls.jsonl.gz'));self.current=None;self.calls=0;self.sessions=0
  self.domains=collections.Counter();self.errors=collections.Counter();self.growth=0;self.cache={};self.last=receipt['started_monotonic_ns'];self.clock_phase=0
 def next(self):
  if self.current is None:
   self.current=next(self.rows);row=self.current
   equal(set(row),{'ordinal','session','domain','pid','started_monotonic_ns','finished_monotonic_ns','actual_code','expected_code','request','expected','output_before','output_after','workspace_before','workspace_after'},'complete private call fields')
   require(row['ordinal']==self.calls+1 and row['pid']==self.receipt['pid']==self.result['pid'],'private raw call process/order')
   begin,end=row['started_monotonic_ns'],row['finished_monotonic_ns']
   require(type(begin)is int and type(end)is int and self.last<=begin<=end<=self.result['finished_monotonic_ns'],'private raw call clocks');self.last=end
  return self.current
 def content(self,ref):
  require(type(ref)is dict and set(ref)=={'bytes','sha256','chunks'}and type(ref['bytes'])is int and ref['bytes']>=0 and type(ref['chunks'])is list and type(ref['sha256'])is str and SHA.fullmatch(ref['sha256']),'complete private buffer reference')
  chunks=[]
  for index,sha in enumerate(ref['chunks']):
   require(type(sha)is str and SHA.fullmatch(sha),'private chunk name')
   if sha not in self.cache:
    raw=self.files.read(PRIVATE+'/blobs/'+sha);require(digest(raw)==sha and 0<len(raw)<=4096,'private physical full chunk');self.cache[sha]=raw
   raw=self.cache[sha]
   require(index+1==len(ref['chunks'])or len(raw)==4096,'private intermediate chunk size');chunks.append(raw)
  raw=b''.join(chunks)
  require(len(raw)==ref['bytes']and digest(raw)==ref['sha256']and len(chunks)==(len(raw)+4095)//4096,'complete private buffer bytes');return raw
 def monotonic_ns(self):
  row=self.next();value=row['started_monotonic_ns']if self.clock_phase==0 else row['finished_monotonic_ns'];self.clock_phase^=1;return value
 def session(self,*,output_capacity,workspace_capacity):
  owner=self
  class VirtualSession:
   def __init__(self):
    self.output_capacity=output_capacity;self.workspace_capacity=workspace_capacity
    self._output=bytearray(output_capacity);self._workspace=bytearray(workspace_capacity);self.closed=False
   def invoke_raw(self,raw):
    require(not self.closed,'pure replay session was closed');row=owner.next()
    equal(owner.content(row['request']),raw,'source-derived complete private input')
    equal(owner.content(row['output_before']),bytes(self._output),'private output continuity')
    equal(owner.content(row['workspace_before']),bytes(self._workspace),'private state/explicit fault continuity')
    output=owner.content(row['output_after']);work=owner.content(row['workspace_after'])
    require(len(output)==self.output_capacity and len(work)==self.workspace_capacity,'private full returned borrowed extents')
    self._output[:]=output;self._workspace[:]=work;return row['actual_code'],output,work
   def close(self):self.closed=True
  return VirtualSession()
 def row(self,session,domain,raw,expected_code,expected,out_before,work_before,actual,out_after,work_after,start,end):
  row=self.next()
  equal([row['session'],row['domain'],row['expected_code'],row['actual_code'],row['started_monotonic_ns'],row['finished_monotonic_ns']],
        [session,domain,expected_code,actual,start,end],'source-derived complete private call identity')
  for name,value in [('request',raw),('expected',expected),('output_before',out_before),('workspace_before',work_before),('output_after',out_after),('workspace_after',work_after)]:
   equal(self.content(row[name]),value,'complete private buffer '+name)
  self.calls+=1;self.domains[domain]+=1
  if actual>=0xffff0000:self.errors[str(actual)]+=1
  self.current=None;require(self.clock_phase==0,'private call clock pair')
 def finish(self):
  require(self.current is None and next(self.rows,None)is None,'complete private journal consumed')
  equal([self.calls,self.sessions,self.growth,len(self.cache)],[self.result['native_calls'],self.result['sessions'],self.result['growth'],self.result['retained_blob_count']],'complete private counters')
  require(self.calls==11514 and self.sessions==45 and len(self.cache)==55563,'unchanged complete private corpus')
  equal(dict(self.domains),self.result['domains'],'private domains');equal(dict(self.errors),self.result['refusals'],'private refusals')
  expected=[PRIVATE+'/'+n for n in ['RESULT.json','calls.jsonl.gz']]+[PRIVATE+'/blobs/'+name for name in self.cache]
  equal(self.files.regular_names(PRIVATE),sorted(expected),'complete private artifacts')
  return {'calls':self.calls,'sessions':self.sessions,'growth':self.growth,'chunks':len(self.cache),'domains':dict(self.domains),'refusals':dict(self.errors),'process':self.receipt,'pure_source_plan_replays':1,'new_native_calls':0}

def private_evidence(source,files,binding):
 result,receipt=domain_evidence(source,files,binding,'private');replay=PrivateReplay(files,result,receipt)
 raw=source.read('tests/hia_native/request_registry_sdk/private_cases.py');tree=ast.parse(raw)
 # Only fixed corpus declarations are loaded. Capture, imports and file/process
 # entry points are excluded; the two corpus functions receive bytearray replay.
 declarations=[]
 for node in tree.body:
  if isinstance(node,(ast.FunctionDef,ast.ClassDef))and node.name!='Capture':declarations.append(node)
  elif isinstance(node,ast.Assign):
   names=[n.id for n in ast.walk(node)if isinstance(n,ast.Name)and isinstance(n.ctx,ast.Store)]
   if set(names)<= {'INVALID','CAPACITY','STATE','RESOURCE','MAX'}:declarations.append(node)
 scope={'__builtins__':__builtins__,'collections':collections,'hashlib':hashlib,'itertools':itertools,'json':json,'os':types.SimpleNamespace(getpid=lambda:receipt['pid']),
        'random':random,'struct':struct,'time':replay,'ctypes':ByteArrays}
 exec(compile(ast.Module(body=declarations,type_ignores=[]),'<source-owned private buffer replay>','exec'),scope)
 scope['semantic'](replay,replay);scope['private'](replay,replay)
 return replay.finish()

def native_evidence(source_root,output_root,binding):
 require(__debug__,'optimized evidence reads are forbidden')
 source,files=Files(source_root),Files(output_root)
 equal(files.json(FOLDER+'/execution.json'),binding,'actual invocation origin binding')
 for name,pin in binding['source_files'].items():source.assert_pin(name,pin)
 build=build_evidence(source,files)
 native,receipt,cases,domains=sdk_native_evidence(source,files,binding)
 private=private_evidence(source,files,binding)
 private_receipt=private['process']
 require(private_receipt['finished_monotonic_ns']<=receipt['started_monotonic_ns'],'private qualification precedes SDK schedules')
 for name in sorted(source.pins):source.pin(name)
 for name in sorted(files.pins):files.pin(name)
 return {'schema':'hepta.runtime.request-registry-native-evidence.v1','status':'PASS',
  'source_sha256':{n:p['sha256']for n,p in sorted(source.pins.items())},
  'artifact_sha256':{n:p['sha256']for n,p in sorted(files.pins.items())},'artifact_bytes':{n:p['bytes']for n,p in sorted(files.pins.items())},
  'build':build,'private':private,'sdk':{'calls':native['native_calls'],'sessions':native['sessions'],'steps':native['steps'],'growth':native['growth'],'chunks':native['blob_count'],'process':receipt,'domains':domains},
  'complete_buffers_checked':True,'original_sdk_executed':False,'new_native_calls':0,'new_original_processes':0,
  'scope':{'controlled_request_handlers':True,'public_stdio_scheduler':False,'handler_deadline_expiry':False,'runtime_destruction':False},
  'whole_runtime_replaced':False,'production_activated':False,'old_stack_removal_qualified':False}

def compare_unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise ValueError('duplicate JSON key '+k)
  d[k]=v
 return d
def compare_parse(raw):return json.loads(raw,object_pairs_hook=compare_unique,parse_constant=lambda value:(_ for _ in()).throw(ValueError(value)))
def canon(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def same(left,right,where):
 if canon(left)!=canon(right):raise ValueError('full comparison differs: '+str(where))
def lines(path):
 opener=gzip.open if str(path).endswith('.gz')else open
 with opener(path,'rb')as stream:
  for raw in stream:
   assert raw.endswith(b'\n');yield compare_parse(raw)
def sha(path):
 with Path(path).open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def sdk_comparison(root):
 original=root/'request-registry/original'
 receipt=compare_parse((original/'original.process.json').read_bytes());assert receipt['exit_code']==0 and receipt['timed_out']is False
 assert (original/'original.stderr').read_bytes()==b''
 assert sha(original/'original.stdout')==receipt['stdout']['sha256']
 assert sha(original/'original-sdk.elf')==receipt['executable']['sha256']
 native_result=compare_parse((root/'request-registry/sdk/RESULT.json').read_bytes());assert native_result['status']=='PASS'
 assert receipt['started_monotonic_ns']>0
 expected=iter(lines(root/'request-registry/sdk/native-observations.jsonl.gz'));actual=iter(lines(original/'original.stdout'))
 cases=list(lines(root/'request-registry/sdk/sdk-cases.jsonl'))
 counts={'cases':0,'steps':0,'started':0,'emitted':0,'suppressed':0,'notifications':0,'successes':0,'errors':0}
 for case in cases:
  header=next(actual);same({k:v for k,v in header.items()if k!='pid'},{'event':'case','case':case['case'],'name':case['name'],'initial_parent':case['initial_parent']},('case',case['case']))
  assert header['pid']==receipt['pid']
  for ordinal,step in enumerate(case['steps']):
   left=next(expected);right=next(actual)
   assert left['event']=='step'and left['case']==case['case']and left['ordinal']==ordinal
   same(left,right,(case['case'],ordinal,step['op']));counts['steps']+=1
  end=next(actual);wanted=next(expected)
  assert end['event']==wanted['event']=='end'and end['case']==wanted['case']==case['case']
  for field in ['started','notifications','terminal']:same(wanted[field],end[field],(case['case'],field))
  assert end['retained_contexts']==0 and type(end['elapsed_ns'])is int and end['elapsed_ns']>0
  incoming=[]
  def request(step,modern=False):
   params={'name':'registry_probe','arguments':{'generation':step['generation']}}
   if modern:params['_meta']={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}
   return {'jsonrpc':'2.0','id':step['id'],'method':'tools/call','params':params}
  if case['initial_parent']:incoming.append(request(next(s for s in case['steps']if s['op']=='register'),True))
  else:
   incoming.extend([{'jsonrpc':'2.0','id':'fixture-initialize','method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'request-registry-original','version':'1'}}},
                    {'jsonrpc':'2.0','method':'notifications/initialized'}])
  first=True
  for ordinal,step in enumerate(case['steps']):
   if step['op']=='register':
    if not(case['initial_parent']and first):incoming.append(request(step))
    first=False
   elif step['op']=='cancel':
    params={'reason':'notification-'+str(ordinal)}
    if step['id']is not None:params['requestId']=step['id']
    incoming.append({'jsonrpc':'2.0','method':'notifications/cancelled','params':params})
  assert all(raw.endswith('\n')for raw in end['incoming'])
  same(incoming,[compare_parse(raw)for raw in end['incoming']],(case['case'],'all complete original input frames'))
  responses=[compare_parse(raw)for raw in end['responses']];assert all(raw.endswith('\n')for raw in end['responses'])
  if not case['initial_parent']:
   initialize=responses.pop(0)
   assert set(initialize)=={'jsonrpc','id','result'}and initialize['jsonrpc']=='2.0'and initialize['id']=='fixture-initialize'
   assert initialize['result']['protocolVersion']=='2024-11-05'
  emitted=[]
  for value in responses:
   assert value.get('jsonrpc')=='2.0'
   if 'error'in value:
    assert set(value)=={'jsonrpc','id','error'}and set(value['error'])=={'code','message'}and value['error']['code']==-32602
    marker=value['error']['message'];is_error=True
   else:
    assert set(value)=={'jsonrpc','id','result'}
    result=value['result']
    assert set(result)==({'content','isError','resultType'}if case['initial_parent']else{'content','isError'}),(case['case'],'result keys',list(result))
    if case['initial_parent']:assert result['resultType']=='complete'
    assert result['isError']is False and len(result['content'])==1
    assert set(result['content'][0])=={'type','text'}and result['content'][0]['type']=='text'
    marker=result['content'][0]['text'];is_error=False
   match=re.fullmatch(r'registry-completion-([1-9][0-9]*)-end',marker);assert match
   generation=int(match.group(1));assert is_error==(generation%3==0)
   emitted.append({'generation':generation,'id':value['id'],'error':is_error})
   counts['errors'if is_error else'successes']+=1
  same(wanted['emissions'],emitted,(case['case'],'complete ordered response IDs and handler results'))
  completes=sum(s['op']=='complete'for s in case['steps']);suppressed=completes-len(emitted)
  drops=sum('dropping response for cancelled request'in s for s in end['traces'])
  eof=sum('input stream terminated'in s for s in end['traces'])
  parent=sum('task cancelled'in s for s in end['traces'])
  assert drops==suppressed and eof==int(end['terminal']=='Closed')and parent==int(end['terminal']=='Cancelled')
  assert len(end['traces'])==drops+eof+parent
  counts['cases']+=1;counts['started']+=len(end['started']);counts['emitted']+=len(emitted);counts['suppressed']+=suppressed;counts['notifications']+=len(end['notifications'])
 assert next(expected,None)is None and next(actual,None)is None
 assert counts['cases']==68 and counts['steps']==7879
 result={'status':'PASS','counts':counts,'native_calls':native_result['native_calls'],'full_original_stdout':receipt['stdout'],'complete_typed_ids_compared':True,'complete_context_snapshots_compared':True,'complete_wire_inputs_compared':True,'complete_wire_outputs_retained':True,
         'new_native_calls':0,'new_original_processes':0,'whole_runtime_replaced':False,'original_public_runtime_replaced':False}
 
 return result

def controls_evidence(source_root,output_root,baseline,*,domain):
 source,files=Files(source_root),Files(output_root);prefix=FOLDER+'/'+domain+'-controls/'
 result=files.json(prefix+'RESULT.json');summary=files.json(prefix+'summary.json')
 raw=source.read('tests/hia_native/request_registry_sdk/controls.py');tree=ast.parse(raw)
 plans={}
 for node in tree.body:
  if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in ('NATIVE_NAMES','ORIGINAL_NAMES','GUARDS'):
   plans[node.targets[0].id]=ast.literal_eval(node.value)
 names=plans['NATIVE_NAMES'if domain=='native'else'ORIGINAL_NAMES']
 require(result['schema']=='hepta.runtime.request-registry-controls.v1'and result['status']=='PASS'and result['kind']==domain,'physical controls status/schema')
 equal([row['name']for row in result['rows']],list(names),'exact source-owned refusal set')
 require(result['controls']==len(names)and result['test_groups']==2 and result['new_native_calls']==result['new_original_processes']==0,'refusal scope/count')
 require(type(result['pid'])is int and result['pid']>0 and type(result['started_monotonic_ns'])is int and type(result['finished_monotonic_ns'])is int and 0<result['started_monotonic_ns']<=result['finished_monotonic_ns'],'actual refusal driver identity')
 if domain=='native':execution=files.json(FOLDER+'/execution.json')
 else:execution=files.json(ORIGINAL+'/execution.json')
 for key in ('source_root','output_root','python'):equal(result[key],execution[key],'actual refusal driver '+key)
 equal(result['python_executable'],execution['python_executable'],'actual refusal driver Python bytes')
 equal(result['python_identity'],execution['python_identity'],'actual refusal driver Python identity')
 for name,pin in result['source_files'].items():source.assert_pin(name,pin)
 equal({n:p['sha256']for n,p in result['source_files'].items()},baseline['source_sha256'],'complete refusal source closure')
 equal(files.json(prefix+'baseline.json'),baseline,'complete refusal predecessor')
 equal(files.pins[prefix+'baseline.json'],result['baseline'],'refusal predecessor full bytes')
 if domain=='original':
  predecessor=files.json(prefix+'native-baseline.json')
  equal(digest(canonical(predecessor)),baseline['native_predecessor_sha256'],'original refusal native predecessor')
 expected_summary={'status':'PASS','test_groups':2,'skipped':0,'errors':0,'failures':0,'controls':len(names),'native_cases_added_by_replay':0,'new_original_processes':0,'whole_runtime_replaced':False}
 equal(summary,expected_summary,'actual refusal suite summary')
 working=Path(result['working_root']);origin=Path(result['source_root']);out_origin=Path(result['output_root'])
 require(working.is_absolute()and origin.is_absolute()and out_origin.is_absolute()and '..'not in working.parts+origin.parts+out_origin.parts and working.parent==out_origin.parent and working.name.startswith('request-registry-controls-'),'own physical refusal working namespace')
 # Main process commands separately bind these origins. No old live path is
 # opened here; complete mutation bytes are retained inside the output tree.
 previous=result['started_monotonic_ns'];pids=set();expected_files=[prefix+n for n in ('RESULT.json','summary.json','baseline.json')]
 if domain=='original':expected_files.append(prefix+'native-baseline.json')
 for row in result['rows']:
  name=row['name'];folder=prefix+'controls/'+name+'/'
  require(row['status']=='REJECTED'and type(row['guard'])is str and row['guard'],'actual refusal result')
  equal(row['guard'],plans['GUARDS'][name],'exact source-owned refusal guard')
  receipt=files.json(folder+'read.process.json');equal(receipt,row['process'],'full refusal child receipt')
  argv=[result['python'],'-I','-B',str(origin/'tests/hia_native/request_registry_sdk/read_evidence.py'),
        '--source',str(working/'source'),'--output',str(working/'output'),'--kind',domain,'--result',str(out_origin/folder/'unexpected.json')]
  if domain=='original':argv+=['--native-baseline',str(out_origin/prefix/'native-baseline.json')]
  equal(receipt['argv'],argv,'source-owned refusal child command')
  require(receipt['name']=='read'and receipt['cwd']==str(origin)and type(receipt['pid'])is int and receipt['pid']>0 and receipt['pid']not in pids,'actual distinct refusal process identity');pids.add(receipt['pid'])
  require(type(receipt['exit_code'])is int and receipt['exit_code']!=0 and receipt['timed_out']is False and receipt['start_error']is None and type(receipt['timeout_seconds'])is int and receipt['timeout_seconds']==180,'completed refusal rather than timeout')
  begin,end=receipt['started_monotonic_ns'],receipt['finished_monotonic_ns']
  require(type(begin)is int and type(end)is int and previous<=begin<=end<=result['finished_monotonic_ns']and end-begin<=180*10**9,'refusal process interval');previous=end
  equal(receipt['executable'],result['python_executable'],'refusal child Python bytes');equal(receipt['executable_identity'],result['python_identity'],'refusal child Python identity')
  for kind in ('stdout','stderr'):
   files.assert_pin(folder+'read.'+kind,receipt[kind]);expected_files.append(folder+'read.'+kind)
  require(files.read(folder+'read.stdout')==b'','refusal did not produce a successful result')
  require(row['guard']in files.read(folder+'read.stderr').decode(),'retained refusal guard in complete stderr')
  expected_files.append(folder+'read.process.json')
  changed=set();require(row['mutations'],'physical mutation evidence')
  for i,mutation in enumerate(row['mutations']):
   relative_name=mutation['relative'];relative(relative_name);require(relative_name not in changed,'unique mutated file');changed.add(relative_name)
   namespace,relative_path=relative_name.split('/',1);require(namespace in ('source','output'),'owned mutation namespace')
   expected=baseline['source_sha256']if namespace=='source'else baseline['artifact_sha256']
   if mutation['before']is None:require(relative_path not in expected,'new mutation path absent from baseline')
   else:require(mutation['before']['sha256']==expected.get(relative_path),'physical mutation predecessor')
   kind=mutation['kind']
   if kind=='file':
    retained=folder+str(i)+'.bytes.gz';equal(mutation['retained'],retained,'exact retained mutation path');files.assert_pin(retained,mutation['retained_pin'])
    h=hashlib.sha256();length=0
    with gzip.open(files.path(retained),'rb')as stream:
     while block:=stream.read(1<<20):h.update(block);length+=len(block)
    equal({'bytes':length,'sha256':h.hexdigest()},mutation['after'],'complete re-signed physical mutation bytes');expected_files.append(retained)
    require(mutation['before']!=mutation['after'],'actual changed bytes')
   elif kind=='missing':require(mutation['before']is not None,'actual removal')
   elif kind=='symlink':
    require(name=='same-bytes-source-symlink'and relative_name=='source/native/request_registry.hepta','source-owned symlink mutation')
    equal(mutation['target'],str(origin/'native/request_registry.hepta'),'outside same-byte source target')
   else:raise ValueError('unknown physical mutation')
 equal(files.regular_names(prefix.rstrip('/')),sorted(expected_files),'complete refusal artifact closure')
 if domain=='original':
  require(result['python_executable']==result['rows'][0]['process']['executable'],'original refusal Python pin')
 return {'status':'PASS','domain':domain,'test_groups':2,'controls':len(names),'names':list(names),'driver_pid':result['pid'],
  'artifact_sha256':{n:p['sha256']for n,p in sorted(files.pins.items())},'artifact_bytes':{n:p['bytes']for n,p in sorted(files.pins.items())},
  'new_native_calls':0,'new_original_processes':0}
