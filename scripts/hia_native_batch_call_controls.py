"""Pure complete-byte admission for private Batch and packer controls.

The caller supplies its explicit origin-to-read-root Files reader. This module
never opens a live fixture, starts a process, or calls a native image.
"""
from pathlib import Path
import gzip,hashlib,io,json,struct

INVALID=0xffffffff
CAPACITY=0xfffffffe
STATE=0xfffffff8
RESOURCE=0xfffffffc

def _need(value,message):
    if not value:raise ValueError(message)

def _equal(a,b):
    if type(a) is not type(b):return False
    if type(a) is dict:return a.keys()==b.keys() and all(_equal(a[k],b[k]) for k in a)
    if type(a) in (list,tuple):return len(a)==len(b) and all(_equal(x,y) for x,y in zip(a,b))
    return a==b

def _same(actual,expected,message):_need(_equal(actual,expected),message)
def _sha(raw):return hashlib.sha256(raw).hexdigest()

def _json(raw):
    def pairs(values):
        result={}
        for key,value in values:
            _need(key not in result,'duplicate private evidence JSON member');result[key]=value
        return result
    def invalid(value):raise ValueError('non-finite private evidence JSON: '+value)
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid)

def _q(raw,at):
    _need(type(at) is int and at>=0 and at+8<=len(raw),'private u64 extent')
    return struct.unpack_from('<Q',raw,at)[0]

def _patch(raw,changes):
    result=bytearray(raw)
    for at,value in changes:struct.pack_into('<Q',result,at,value)
    return bytes(result)

def _frame(op,g=0,seq=0,a=0,b=0,payload=b''):
    return b'HBCALQ02'+struct.pack('<7Q',op,g,seq,a,b,0,0)+payload

def _header(status,g=0,seq=0,target=0,body=0,aux=0):
    return b'HBCAR002'+struct.pack('<7Q',status,g,seq,target,body,aux,0)

class _Read:
    def __init__(self,files):self.files=files;self.artifacts={}
    def raw(self,path):
        name=str(path);value=self.files.raw(name);self.artifacts[name]=_sha(value);return value
    def json(self,path):return _json(self.raw(path))

def _records(reader,folder,*,start,packing=False,input_limit=4096,output_limit=65536):
    raw=reader.raw(folder/'index.jsonl')
    _need(raw.endswith(b'\n'),'incomplete private control index')
    index=[_json(line) for line in raw.split(b'\n')[:-1]]
    _same(len(index),14 if packing else 52,'source-owned private record count')
    stream=gzip.GzipFile(fileobj=io.BytesIO(reader.raw(folder/'complete.bin.gz')),mode='rb')
    offset=0
    for ordinal,row in enumerate(index,start):
        expected={'label','return_code','offset','bytes','sha256'}
        if packing:expected.add('expected_return')
        _same(set(row),expected,'complete private control index fields')
        _need(type(row['label']) is str,'private control label')
        for key in ('return_code','offset','bytes')+ (('expected_return',) if packing else ()):
            _need(type(row[key]) is int and row[key]>=0,'private control integer '+key)
        header=stream.read(64);_same(len(header),64,'complete private record header')
        number,code,ilen,ocap,wcap,a,b,c=struct.unpack('<8Q',header)
        _same((number,a,b,c),(ordinal,0,0,0),'private record identity and reserved fields')
        _need(code<1<<32 and ilen<=input_limit and ocap<=output_limit and wcap<=65536,
              'source-owned private control admitted extent')
        _same(row['bytes'],64+ilen+2*ocap+2*wcap,'private record declared physical extent')
        parts=[]
        for length in (ilen,ocap,wcap,ocap,wcap):
            value=stream.read(length);_same(len(value),length,'complete private buffer');parts.append(value)
        digest=hashlib.sha256(header)
        for value in parts:digest.update(value)
        size=64+sum(map(len,parts))
        _same((row['offset'],row['bytes'],row['sha256'],row['return_code']),
              (offset,size,digest.hexdigest(),code),'private record full physical bytes')
        offset+=size
        yield row,code,*parts,offset
    _same(stream.read(),b'','unindexed private stream tail')
    stream.close()

def state_evidence(files,native_run,native_source):
    """Validate all 52 source-owned private calls, including refusal immutability."""
    read=_Read(files);folder=Path(native_run)/'state-controls'
    read.raw(Path(native_source)/'tests/hia_native/test_batch_call_state.py')
    records=list(_records(read,folder,start=1));_same(len(records),52,'all private controller calls')
    observed={}
    for row,code,wire,before_o,before_w,after_o,after_w,offset in records:
        label=row['label'];_need(label not in observed,'duplicate private control label')
        _same(before_o,b'\xa5'*len(before_o),'source-owned private output sentinel')
        observed[label]=(code,wire,before_o,before_w,after_o,after_w)
    expected_order=[]
    def case(label,wire,before,capacity,code,after=None,output=None):
        expected_order.append(label);_need(label in observed,'missing private control '+label)
        got,request,bo,bw,ao,aw=observed[label]
        _same((got,request,bo,bw),(code,wire,b'\xa5'*capacity,before),'private control complete input '+label)
        if code>=0xffff0000:
            _same((ao,aw),(bo,bw),'refused private call changed borrowed buffers: '+label)
        else:
            _same(aw,after,'complete private state transition '+label)
            _same(ao,output+b'\xa5'*(capacity-len(output)),'complete private response and tail '+label)
        return aw
    initial=b'HBCINI02'+struct.pack('<7Q',0,0,0,10,7,0,0)
    for n in (0,1,63):case('output-short-'+str(n),initial,bytes(4096),n,CAPACITY)
    for n in (0,1,4095):case('workspace-short-'+str(n),initial,bytes(n),64,CAPACITY)
    for at in (0,1,7,8,15,63,64,511,512,1023,1024,2047,2048,4087,4088,4095):
        dirty=bytearray(4096);dirty[at]=0x80
        case('dirty-install-'+str(at),initial,bytes(dirty),64,STATE)
    for at,value in ((8,2),(16,1),(24,1),(32,9),(40,8),(48,1),(56,1)):
        case('bad-install-'+str(at),_patch(initial,[(at,value)]),bytes(4096),64,INVALID)
    installed=_patch(bytes(65536),[(0,int.from_bytes(b'HBCWS002','little')),(48,4096),(512,4096),(64,10),(72,7)])
    case('install',initial,bytes(65536),64,64,installed,_header(7))
    _need('start' in observed,'missing actual private START')
    params=observed['start'][1][64:]
    _need(len(params)>=64 and params[:8]==b'HBPRR002','actual typed private input')
    status,path_size,json_size,count,a,b,c=struct.unpack_from('<7Q',params,8)
    _same((status,count,a,b,c),(0,0,0,0,0),'empty operations typed frame')
    _same(len(params),64+path_size+json_size,'complete private typed extent')
    _same(params[64:64+path_size],b'file','private typed path')
    _same(_json(params[64+path_size:]),{'operations':[],'path':'file'},'private typed parameters')
    request=_frame(1,a=len(params),payload=params)
    case('growth-work',request,installed[:4096],64,64,installed[:4096],
         _header(5,target=1,aux=4096+len(params)))
    case('growth-output',request,installed,64,64,installed,_header(5,target=2,aux=192+len(params)))
    pending=_patch(installed,[(8,2),(16,1),(24,1),(32,12),(48,4096+len(params)),
        (512,4096+len(params)),(192,4096),(200,len(params)),(176,4096+len(params))])
    pending=pending[:4096]+params+pending[4096+len(params):]
    child=b'HBPIQ002'+struct.pack('<7Q',0,len(params),0,0,0,0,0)+params
    case('start',request,installed,65536,64,pending,_header(1,1,1,12,len(child))+child)
    for label,wire in [('wrong-gen',_frame(2,2,1)),('wrong-seq',_frame(2,1,2)),
            ('drop-live',_frame(6)),('cancel-nonawait',_frame(3,1,1)),
            ('wake-nonwait',_frame(5,1,1)),('late-without-borrow',_frame(4,1,1))]:
        case(label,wire,pending,65536,STATE)
    for label,wire in [('unknown-op',_frame(9,1,1)),('return-upper',_frame(2,1,1,1<<32)),
            ('extent',_frame(2,1,1,64,64)),('reserved',_patch(_frame(2,1,1),[(48,1)])),
            ('error-payload',_frame(2,1,1,RESOURCE,1,b'x'))]:
        case(label,wire,pending,65536,INVALID)
    case('invalid-child-magic',_frame(2,1,1,64,64,bytes(64)),pending,65536,STATE)
    case('generation-overflow',request,_patch(installed,[(16,(1<<64)-1)]),65536,RESOURCE)
    case('corrupt-owned-used',_frame(2,1,1),_patch(pending,[(48,65537)]),65536,STATE)
    case('corrupt-highwater',_frame(2,1,1),_patch(pending,[(512,4095)]),65536,STATE)
    before=_patch(pending,[(8,51),(32,6),(96,7),(104,9),(464,1),(472,4096),(480,63)])
    response=b'HRSCR001'+struct.pack('<7Q',7,9,1,0,0,0,0)
    case('corrupt-saved-delivery',_frame(2,1,1,64,64,response),before,65536,STATE)
    before=_patch(pending,[(8,50),(32,6),(96,7),(104,8),(456,99),(464,0)])
    response=b'HRSCR001'+struct.pack('<7Q',7,9,2,0,0,0,0)
    case('corrupt-deferred-phase',_frame(2,1,1,64,64,response),before,65536,STATE)
    cleaned=_patch(pending,[(8,0),(32,0),(128,6),(400,RESOURCE)])
    case('native-resource-cleanup',_frame(2,1,1,RESOURCE),pending,65536,64,
         cleaned,_header(6,1,1,aux=RESOURCE))
    case('drop-after-native-failure',_frame(6),cleaned,65536,64,bytes(65536),_header(7))
    _same([row[0]['label'] for row in records],expected_order,'fixed private control execution order')
    result=read.json(folder/'RESULT.json')
    _same(result,{'status':'PASS','private_controls':52,'complete_uncompressed_bytes':records[-1][-1],
          'failures':[],'original_rust_executions':0,'synthetic_success_completions':0},
          'actual private control complete result')
    return {'schema':'hepta.runtime.batch-call-state-evidence.v1','status':'PASS','private_controls':52,
            'complete_uncompressed_bytes':records[-1][-1],'batch_semantic_cases_added':0,
            'new_native_calls':0,'new_original_rust_processes':0,
            'artifact_sha256':dict(sorted(read.artifacts.items()))}

def packer_evidence(files,native_source,manifest,controls_run,*,python_executable,test_source):
    """Admit 14 actual HIA packer calls and six physical source refusals."""
    read=_Read(files);source=Path(native_source);manifest=Path(manifest);run=Path(controls_run)
    folder=run/'capture';meta=read.json(manifest)
    identity=read.json(folder/'IDENTITY.json')
    _same(identity['source'],str(source),'packer control source origin')
    _same(identity['manifest'],str(manifest),'packer control build origin')
    _same(identity['test_source'],str(test_source),'source-owned packing test origin')
    def pin(path):
        raw=read.raw(path);return {'bytes':len(raw),'sha256':_sha(raw)}
    _same(identity['manifest_pin'],pin(manifest),'packer manifest complete pin')
    _same(identity['test_pin'],pin(Path(identity['test_source'])),'actual packing control source')
    _same(identity['builder_pin'],pin(source/'scripts/hia_native_batch_call_build.py'),'actual builder source')
    _same(identity['loader_pin'],pin(source/'scripts/hia_native_loader.py'),'actual native loader source')
    _same(identity['packer_manifest_pin'],pin(manifest.parent/meta['packer_manifest']),'actual packer manifest')
    proof_path='native/batch_call_packer_composition.json'
    _same(identity['composition_pin'],pin(source/proof_path),'actual packer contract')
    frame=read.raw(manifest.parent/'packer.input.bin');elf=read.raw(manifest.parent/'packer.output.bin')
    _same(_sha(frame),meta['input_frame_sha256'],'complete packer input')
    _same(_sha(elf),meta['elf_sha256'],'complete packer output')
    n=len(elf);wire_cases=[('exact',frame,n,160,n),('spare-borrow-tails',frame,n+31,191,n),
        ('short-header',frame[:191],n,160,INVALID),('wrong-magic',b'BADFRAME'+frame[8:],n,160,INVALID)]
    for label,at,value in [('prefix-extent',8,meta['prefix_bytes']+1),('image-count',16,19),
                           ('table',24,meta['table_offset']+8),('zero-image',32,0),
                           ('oversized-image',32,(1<<64)-1)]:
        wire_cases.append((label,_patch(frame,[(at,value)]),n,160,INVALID))
    changed=bytearray(frame);changed[192+100]^=1
    wire_cases.extend([('changed-prefix',bytes(changed),n,160,INVALID),
        ('trailing-frame-byte',frame+b'\0',n,160,INVALID),('short-output',frame,n-1,160,CAPACITY),
        ('zero-output',frame,0,160,CAPACITY),('short-workspace',frame,n,159,CAPACITY)])
    positions=struct.pack('<20Q',*meta['image_offsets'])
    early={'short-header','wrong-magic','prefix-extent','image-count','table','zero-image',
           'oversized-image','short-workspace'}
    count=0;total=0
    for record in _records(read,folder,start=0,packing=True,input_limit=len(frame)+1,output_limit=n+31):
        row,code,wire,bo,bw,ao,aw,total=record
        _need(count<len(wire_cases),'extra actual packing control')
        label,expected_wire,ocap,wcap,expected_code=wire_cases[count];count+=1
        _same((row['label'],code,row['expected_return'],wire,bo,bw),
              (label,expected_code,expected_code,expected_wire,b'\xa5'*ocap,b'\x6d'*wcap),
              'exact actual packer input '+label)
        if expected_code==n:
            _same(ao,elf+b'\xa5'*(ocap-n),'whole actual packed ELF and borrowed tail')
            _same(aw,bytes(160)+b'\x6d'*(wcap-160),'packer success private scratch/tail')
        else:
            _same(ao,bo,'refused packer modified output')
            _same(aw,bw if label in early else positions,'complete refused packer workspace')
    _same(count,14,'all actual packing calls')
    result=read.json(folder/'RESULT.json')
    _same(result,{'status':'PASS','test_groups':2,'native_packer_calls':14,'source_contract_refusals':6,
         'complete_uncompressed_bytes':total,'failures':[],'original_rust_executions':0,
         'batch_semantic_cases_added':0},'complete actual packing control result')
    proof=read.json(source/proof_path)
    sources=list(proof['boundary']['sources'])+[proof_path,'native/batch_call_packer.hepta',
        *[item['source'] for item in proof['imports']]]
    _same(len(sources),19,'closed source contract dependency count')
    originals={name:read.raw(source/name) for name in sources}
    contracts=read.json(folder/'contracts.json')
    actual_pins={name:{'bytes':len(raw),'sha256':_sha(raw)} for name,raw in originals.items()}
    _same(contracts['baseline_pins'],actual_pins,'source contract baseline full pins')
    for name,raw in originals.items():
        _same(read.raw(folder/'contracts/baseline'/name),raw,'source contract complete baseline bytes')
    mutation_specs=[('assembly-source','scripts/batch_call_fixture.S',None,
        'assembled native boundary differs from the frozen HIA packer contract'),
        ('packer-source','native/batch_call_packer.hepta',None,'frozen HIA packer source changed'),
        ('imported-source',proof['imports'][0]['source'],None,'HIA packer imported source changed'),
        ('prefix-pin',proof_path,('prefix_sha256','0'*64),
         'assembled native boundary differs from the frozen HIA packer contract'),
        ('table-offset',proof_path,('table_offset',meta['table_offset']+8),
         'assembled native boundary differs from the frozen HIA packer contract'),
        ('slot-routing',proof_path,('slots',list(reversed(meta['slots']))),
         'assembled native boundary differs from the frozen HIA packer contract')]
    _same(len(contracts['controls']),6,'all physical source contract refusals')
    for row,(label,changed_name,change,error) in zip(contracts['controls'],mutation_specs):
        expected=dict(originals)
        if change is None:expected[changed_name]+=b'\n'
        else:
            data=_json(expected[changed_name]);data['boundary'][change[0]]=change[1]
            expected[changed_name]=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode()
        pins={name:{'bytes':len(raw),'sha256':_sha(raw)} for name,raw in expected.items()}
        _same(row,{'label':label,'rejected':True,'error':error,'source_pins':pins},
              'actual source contract refusal '+label)
        for name,raw in expected.items():
            _same(read.raw(folder/'contracts'/label/name),raw,'physical source contract mutation '+label)
    process=read.json(run/'PROCESS.json')
    expected_command=[str(python_executable),'-I','-B',str(test_source),'--source',str(source),
        '--manifest',str(manifest),'--output',str(folder)]
    _same(process['command'],expected_command,'actual packing process argv')
    _need(Path(python_executable).is_absolute(),'actual selected Python path')
    _same(process['cwd'],str(source),'actual packing process cwd')
    _same((process['exit_code'],process['timed_out'],process['start_error'],process['timeout_seconds']),
          (0,False,None,180),'actual packing process terminal state')
    for key in ('pid','started_monotonic_ns','finished_monotonic_ns'):
        _need(type(process[key]) is int and process[key]>0,'actual packing process identity '+key)
    elapsed=(process['finished_monotonic_ns']-process['started_monotonic_ns'])/1e9
    _need(0<=elapsed<=180,'actual packing process deadline')
    _same(process['elapsed_seconds'],elapsed,'actual packing process complete clocks')
    for kind in ('stdout','stderr'):
        raw=read.raw(run/kind)
        _same(process[kind],{'bytes':len(raw),'sha256':_sha(raw)},'actual packing process '+kind)
        if kind=='stdout':_same(_json(raw),result,'actual packing process complete result')
        else:_same(raw,b'','actual packing process stderr')
    terminal=read.json(run/'RESULT.json')
    _same(terminal,{'status':'PASS','process':process,'source_unchanged':True,
          'new_batch_semantic_cases':0,'new_original_rust_processes':0},'actual packing suite terminal report')
    return {'schema':'hepta.runtime.batch-call-packer-evidence.v1','status':'PASS','test_groups':2,
            'native_packer_calls':14,'source_contract_refusals':6,'complete_uncompressed_bytes':total,
            'batch_semantic_cases_added':0,'new_native_calls':0,'new_original_rust_processes':0,
            'artifact_sha256':dict(sorted(read.artifacts.items()))}
