"""Execute the native shadow-record owner, full retained corpus and static ELF controls."""
from pathlib import Path
import argparse,copy,gzip,hashlib,json,os,random,struct,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/hia_native'));sys.path.insert(0,str(ROOT/'scripts'))
from execution_shadow_cases import fixture,packet,expected,FIELDS,CLASSES,diagnostic
from hia_native_loader import NativeModule

def cases():
 base=fixture();yield 'golden',base
 identities=['run_id','turn_id','cell_id','organ_id','operation_id','principal','host','idempotency_key','rollback_reference']
 for field in identities:
  for scalar in range(256):
   c=copy.deepcopy(base)
   if field=='organ_id':c['cell_id']=None
   c[field]=chr(scalar);yield 'identity_scalar',c
  for size in range(259):
   c=copy.deepcopy(base)
   if field=='organ_id':c['cell_id']=None
   c[field]='x'*size;yield 'identity_length',c
  for scalar in (0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff):
   c=copy.deepcopy(base)
   if field=='organ_id':c['cell_id']=None
   c[field]=chr(scalar);yield 'identity_unicode',c
 for field in ('objective_digest','policy_digest','candidate_digest','payload_digest'):
  for position in range(64):
   for scalar in range(256):
    c=copy.deepcopy(base);c[field]='0'*position+chr(scalar)+'0'*(63-position)
    yield 'digest_scalar_position',c
  for size in range(67):
   c=copy.deepcopy(base);c[field]='a'*size;yield 'digest_length',c
 for options in range(16):
  for current in range(3):
   for kind in range(7):
    c=copy.deepcopy(base);c['currentness']=current;c['class']=kind
    for name,flag,text in [('cell_id',1,'cell'),('organ_id',2,'organ'),('predecessor',4,''),('rollback_reference',8,'rollback')]:c[name]=text if options&flag else None
    yield 'option_class_currentness',c
 values=[0,1,2,255,256,2**32-1,2**32,2**63-1,2**63,2**64-1]
 for generation in values:
  for schema in [0,1,2,255,256,2**31-1,2**31,2**32-1]:
   c=copy.deepcopy(base);c['generation']=generation;c['schema_version']=schema;yield 'integer_boundaries',c
 for kind in range(7):
  for target in ('cell_id','organ_id'):
   for char in ('x','"','\\','/','~','!'):
    for generation in (1,2**32,2**64-1):
     c=copy.deepcopy(base);c['class']=kind;c['generation']=generation
     for name in identities:c[name]=char*256
     c['cell_id']=None if target=='organ_id' else char*256;c['organ_id']=None if target=='cell_id' else char*256
     yield 'maximum_valid_serialization',c
 for mask in range(128):
  c=copy.deepcopy(base)
  if mask&1:c['schema_version']=0
  if mask&2:c['predecessor']=''
  if mask&4:c['run_id']=''
  if mask&8:c['cell_id']=None
  if mask&16:c['objective_digest']='0'*64
  if mask&32:c['rollback_reference']=''
  if mask&64:c['class']=4
  yield 'validation_order',c
 rng=random.Random(0x48585352)
 for _ in range(2048):
  c=copy.deepcopy(base);c['generation']=rng.randrange(1,2**64);c['class']=rng.randrange(7)
  for name in identities:
   c[name]=''.join(chr(rng.randrange(33,127)) for _ in range(rng.randrange(1,257)))
  if rng.randrange(2):c['cell_id']=None
  else:c['organ_id']=None
  for name in ('objective_digest','policy_digest','candidate_digest','payload_digest'):c[name]=''.join(rng.choice('0123456789abcdef') for _ in range(64))
  yield 'deterministic_full_records',c
 c=copy.deepcopy(base);c['run_id']='x'*((8<<20)-(len(packet(base))-len(base['run_id'])));assert len(packet(c))==8<<20
 yield 'exact_standard_input_capacity',c
 c=copy.deepcopy(base);c['run_id']='\U0010ffff'*(1<<20);yield 'large_valid_utf8_invalid_identity',c

def wire_row(raw):return f'{len(raw):08x}:'.encode()+raw.hex().encode()+b'\n'

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 out=args.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 manifest=args.manifest.resolve();meta=json.loads(manifest.read_bytes());source=(ROOT/'native/execution_shadow.hepta').read_bytes()
 assert meta['source_sha256']==hashlib.sha256(source).hexdigest()
 start=time.monotonic();counts={};total=0;success=0;error_counts={};max_canonical=0;stream=hashlib.sha256()
 with NativeModule(manifest,manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest()) as module:
  with module.session(output_capacity=16384,workspace_capacity=65536) as session, gzip.open(out/'requests.hex.gz','wb') as requests, gzip.open(out/'native-output.hex.gz','wb') as outputs, gzip.open(out/'cases.jsonl.gz','wb') as domains:
   for label,case in cases():
    data=packet(case);observed=session.invoke(data);wanted=expected(case)
    assert observed==wanted,(label,total,case if len(data)<5000 else 'large',observed[:180],wanted[:180])
    fields=struct.unpack('<8s7Q',observed[:64]);assert fields[0]==b'HXSRSL01'
    if fields[1]==0:success+=1;max_canonical=max(max_canonical,fields[2]);assert json.loads(observed[64+fields[2]+64:])['executable'] is False
    else:
     error=observed[64:].decode();error_counts[error]=error_counts.get(error,0)+1
    row=wire_row(observed);stream.update(row);requests.write(data.hex().encode()+b'\n');outputs.write(row)
    domains.write((json.dumps({'label':label,'case':case},ensure_ascii=True,separators=(',',':'))+'\n').encode())
    counts[label]=counts.get(label,0)+1;total+=1
  # Invalid typed-ABI frames and byte capacities never mutate the output.
  good=packet(fixture());bad=[]
  for end in (0,1,7,8,15,16,23,24,31,32,39,40,47,48,55,56,63,len(good)-1):bad.append(good[:end])
  for offset,value in ((0,0),(8,0),(8,2),(16,2**32),(32,7),(40,3),(48,16),(56,1),(64,2**64-1)):
   data=bytearray(good);struct.pack_into('<Q',data,offset,value);bad.append(bytes(data))
  bad+=[good+b'x',good+b'\0']
  for value in (b'\x80',b'\xc0\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xf5\x80\x80\x80',b'\xe2\x82'):
   data=bytearray(good);old=struct.unpack_from('<Q',data,64)[0];data[72:72+old]=value;struct.pack_into('<Q',data,64,len(value));bad.append(bytes(data))
  for data in bad:
   code,output,_=module.invoke_raw(data,output_capacity=16384,workspace_capacity=65536,output_fill=0xa6,workspace_fill=0x5a)
   assert code==0xffffffff and output==b'\xa6'*16384,(code,len(data))
  valid=expected(fixture());capacity_controls=0
  for size in (0,1,63,64,len(valid)-1):
   code,output,_=module.invoke_raw(good,output_capacity=size,workspace_capacity=65536,output_fill=0xa6,workspace_fill=0x5a)
   assert code==0xfffffffe and output==b'\xa6'*size;capacity_controls+=1
  for size in (0,1,4096,65535):
   code,output,_=module.invoke_raw(good,output_capacity=16384,workspace_capacity=size,output_fill=0xa6,workspace_fill=0x5a)
   assert code==0xfffffffe and output==b'\xa6'*16384;capacity_controls+=1
  assert module.invoke(good,output_capacity=len(valid),workspace_capacity=65536)==valid
  elf=manifest.parent/meta['standalone']['path'];assert hashlib.sha256(elf.read_bytes()).hexdigest()==meta['standalone']['sha256']
  assert meta['standalone']['inspection']['dynamic_loader'] is False and meta['standalone']['inspection']['libc'] is False
  actual_elf=[]
  for kind in range(7):
   c=fixture();c['class']=kind
   if kind>=2:c['rollback_reference']='rollback'
   wire=packet(c);run=subprocess.run([str(elf)],input=wire,capture_output=True,timeout=5,env={'PATH':''})
   assert run.returncode==0 and not run.stderr and run.stdout==expected(c)
   actual_elf.append({'class':kind,'exit_code':run.returncode,'input_sha256':hashlib.sha256(wire).hexdigest(),'stdout_sha256':hashlib.sha256(run.stdout).hexdigest()})
  refused=subprocess.run([str(elf)],input=bad[-1],capture_output=True,timeout=5,env={'PATH':''})
  assert refused.returncode!=0 and refused.stdout==b''
 report={'schema':'hepta.runtime.execution-shadow-native-test.v1','status':'PASS','cases':total,'counts':counts,'successful_records':success,'semantic_error_counts':error_counts,'maximum_canonical_bytes':max_canonical,'framing_refusals':len(bad),'capacity_refusals':capacity_controls,'exact_capacity_success':1,'actual_elf_requests':8,'actual_elf_success':actual_elf,'actual_elf_refusal_exit':refused.returncode,'complete_output_sha256':stream.hexdigest(),'source_sha256':meta['source_sha256'],'image_sha256':meta['image_sha256'],'executable_sha256':meta['standalone']['sha256'],'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'elapsed_seconds':time.monotonic()-start,'production_activated':False,'json_admission_qualified':False,'installed_host_lookup_qualified':False}
 report['files']={p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir()}
 (out/'native-corpus.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
