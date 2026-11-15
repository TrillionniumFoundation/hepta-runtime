"""Private controller corruption controls; no mocked successful effects."""
from pathlib import Path
import argparse,ctypes,gzip,hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
sha=lambda raw:hashlib.sha256(raw).hexdigest();meta=json.loads(args.manifest.read_bytes())
def module(name):
    path=args.manifest.parent/next(m['manifest'] for m in meta['members'] if m['name']==name)
    return NativeModule(path,manifest_sha256=sha(path.read_bytes()))
caller=module('batch_call');typed=module('batch_edit_params')
def frame(op,g=0,seq=0,a=0,b=0,payload=b''):
    return b'HBCALQ02'+struct.pack('<7Q',op,g,seq,a,b,0,0)+payload
def patch(raw,at,value):
    out=bytearray(raw);struct.pack_into('<Q',out,at,value);return bytes(out)
initial=b'HBCINI02'+struct.pack('<7Q',0,0,0,10,7,0,0)
records=[];offset=0;failures=[]
stream=gzip.GzipFile(filename=str(args.output/'complete.bin.gz'),mode='wb',compresslevel=1,mtime=0)
index=(args.output/'index.jsonl').open('wb',buffering=0)
def call(label,wire,before,capacity=65536,expected=None,unchanged=False):
    global offset
    with caller.session(workspace_capacity=len(before),output_capacity=capacity) as s:
        ctypes.memmove(s._workspace,before,len(before));ctypes.memset(s._output,0xa5,capacity)
        code,out,after=s.invoke_raw(wire)
    header=struct.pack('<8Q',len(records)+1,code,len(wire),capacity,len(before),0,0,0)
    digest=hashlib.sha256();n=0
    for part in (header,wire,b'\xa5'*capacity,before,out,after):stream.write(part);digest.update(part);n+=len(part)
    row={'label':label,'return_code':code,'offset':offset,'bytes':n,'sha256':digest.hexdigest()};offset+=n
    records.append(row);index.write(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n');stream.flush()
    if expected is not None and code!=expected:failures.append({'label':label,'reason':'return','actual':code,'expected':expected})
    if unchanged and (after!=before or out!=b'\xa5'*capacity):
        failures.append({'label':label,'reason':'refusal mutated borrowed buffers',
            'workspace_differences':[i for i,(a,b) in enumerate(zip(after,before)) if a!=b],
            'output_differences':[i for i,(a,b) in enumerate(zip(out,b'\xa5'*capacity)) if a!=b]})
    return code,out,after
INVALID=0xffffffff;CAPACITY=0xfffffffe;STATE=0xfffffff8;RESOURCE=0xfffffffc
for n in (0,1,63):call('output-short-'+str(n),initial,bytes(4096),n,CAPACITY,True)
for n in (0,1,4095):call('workspace-short-'+str(n),initial,bytes(n),64,CAPACITY,True)
for at in [0,1,7,8,15,63,64,511,512,1023,1024,2047,2048,4087,4088,4095]:
    dirty=bytearray(4096);dirty[at]=0x80;call('dirty-install-'+str(at),initial,bytes(dirty),64,STATE,True)
for at,value in [(8,2),(16,1),(24,1),(32,9),(40,8),(48,1),(56,1)]:
    call('bad-install-'+str(at),patch(initial,at,value),bytes(4096),64,INVALID,True)
_,_,installed=call('install',initial,bytes(65536),64,64)
raw=b'{"operations":[],"path":"file"}';wire=b'HBPRQ002'+struct.pack('<2Q',len(raw),0)+raw
with typed.session(workspace_capacity=65536,output_capacity=65536) as s:
    code,out,_=s.invoke_raw(wire);assert code==64 and struct.unpack_from('<Q',out,8)[0]==0
    n=64+struct.unpack_from('<Q',out,16)[0]+struct.unpack_from('<Q',out,24)[0];params=out[:n]
request=frame(1,a=len(params),payload=params)
_,out,short=call('growth-work',request,installed[:4096],64,64)
assert short==installed[:4096] and struct.unpack_from('<Q',out,8)[0]==5
_,out,short=call('growth-output',request,installed,64,64)
assert short==installed and struct.unpack_from('<Q',out,8)[0]==5
_,_,pending=call('start',request,installed,65536,64)
for label,wire in [('wrong-gen',frame(2,2,1)),('wrong-seq',frame(2,1,2)),('drop-live',frame(6)),
                   ('cancel-nonawait',frame(3,1,1)),('wake-nonwait',frame(5,1,1)),('late-without-borrow',frame(4,1,1))]:
    call(label,wire,pending,65536,STATE,True)
for label,wire in [('unknown-op',frame(9,1,1)),('return-upper',frame(2,1,1,1<<32)),('extent',frame(2,1,1,64,64)),
                   ('reserved',patch(frame(2,1,1),48,1)),('error-payload',frame(2,1,1,RESOURCE,1,b'x'))]:
    call(label,wire,pending,65536,INVALID,True)
call('invalid-child-magic',frame(2,1,1,64,64,bytes(64)),pending,65536,STATE,True)
call('generation-overflow',request,patch(installed,16,(1<<64)-1),65536,RESOURCE,True)
call('corrupt-owned-used',frame(2,1,1),patch(pending,48,65537),65536,STATE,True)
call('corrupt-highwater',frame(2,1,1),patch(pending,512,4095),65536,STATE,True)
# A corrupted saved delivery must not consume the suspended binding.
# This deliberately invalid private state is not a successful scope oracle.
corrupt=pending
for at,value in [(8,51),(32,6),(96,7),(104,9),(464,1),(472,4096),(480,63)]:corrupt=patch(corrupt,at,value)
response=b'HRSCR001'+struct.pack('<7Q',7,9,1,0,0,0,0)
call('corrupt-saved-delivery',frame(2,1,1,64,64,response),corrupt,65536,STATE,True)
corrupt=pending
for at,value in [(8,50),(32,6),(96,7),(104,8),(456,99),(464,0)]:corrupt=patch(corrupt,at,value)
response=b'HRSCR001'+struct.pack('<7Q',7,9,2,0,0,0,0)
call('corrupt-deferred-phase',frame(2,1,1,64,64,response),corrupt,65536,STATE,True)
_,out,cleaned=call('native-resource-cleanup',frame(2,1,1,RESOURCE),pending,65536,64)
assert struct.unpack_from('<Q',out,8)[0]==6
_,_,dropped=call('drop-after-native-failure',frame(6),cleaned,65536,64);assert not any(dropped)
stream.close();index.close();caller.close();typed.close()
result={'status':'FAIL' if failures else 'PASS','private_controls':len(records),'complete_uncompressed_bytes':offset,
        'failures':failures,'original_rust_executions':0,'synthetic_success_completions':0}
(args.output/'RESULT.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result),flush=True)
if failures:raise SystemExit(1)
