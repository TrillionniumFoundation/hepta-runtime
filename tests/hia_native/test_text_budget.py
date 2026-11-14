"""Native parity for the original release-mode text budget and line renderers."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,math,os,random,struct,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
MAGIC=int.from_bytes(b'HRTEXT01','little')
U64=(1<<64)-1
COUNTS={}

def packet(op,a=0,b=0,c=0,d=0,lines=()):
 raw=struct.pack('<8Q',MAGIC,op,a&U64,b&U64,c&U64,d&U64,len(lines),0)
 for line in lines:
  data=line.encode('utf-8') if isinstance(line,str) else line
  raw+=struct.pack('<Q',len(data))+data
 return raw

def hashed(line):
 value=2166136261
 for byte in line.encode('utf-8'):value=((value^byte)*16777619)&0xffffffff
 folded=(value>>16)^(value&0xffff)
 return format((folded>>8)^(folded&0xff),'02x')

def render(lines,first,range_value=None):
 line=lambda i:f'{(first+i)&U64}:{hashed(lines[i])}|{lines[i]}'
 if range_value is None:return '\n'.join(line(i) for i in range(len(lines))).encode()
 start,end=range_value
 start_idx=0 if start==0 else start-1
 end_idx=len(lines) if end==-1 else min(end&U64,len(lines))
 if start_idx>=len(lines):return f'Start line {start} exceeds content length ({len(lines)} lines)'.encode()
 if start_idx>end_idx:return f'Start line {start} must be less than or equal to end line {end}'.encode()
 result=[line(i) for i in range(start_idx,end_idx)]
 remaining=len(lines)-end_idx
 if start_idx>0 or remaining>0:
  result.append(f'[end of file, {len(lines)} lines total]' if remaining==0 else f'[... {remaining} more lines, {len(lines)} total]')
 return '\n'.join(result).encode()

def smart(lines,first,limit=None):
 actual=50 if limit is None else limit
 if len(lines)<=actual:return render(lines,first)
 head=((actual*2)&U64)//3
 tail=(actual-head-1)&U64
 line=lambda i:f'{(first+i)&U64}:{hashed(lines[i])}|{lines[i]}'
 result=[line(i) for i in range(head)]
 result.append(f'[...{(len(lines)-head-tail)&U64} lines more]')
 result.extend(line(i) for i in range((len(lines)-tail)&U64,len(lines)))
 return '\n'.join(result).encode()

def cases():
 rng=random.Random(0x545854)
 numbers=set(range(1025))
 for bit in range(65):
  for delta in range(-12,13):
   n=(1<<bit)+delta
   if 0<=n<=U64:numbers.add(n)
 numbers.update((7<<50)+i for i in range(-256,257))
 numbers.update(U64-i for i in range(4097))
 numbers.update(262144+i*524288 for i in range(128))
 numbers.update(rng.getrandbits(64) for _ in range(4000))
 for n in sorted(numbers):
  yield 'estimate',packet(1,n),struct.pack('<Q',math.ceil(float(n)/3.5))
  yield 'megabytes',packet(2,n),(format(float(n)/(1024*1024),'.1f')+' MB').encode()
 texts=['','a','hello','é😀漢','a\x00b','x\ry','a\nb','"\\','\t','\U0010ffff']
 for count in range(10):
  lines=[texts[i%len(texts)] for i in range(count)]
  for first in [0,1,13,U64-3,U64]:
   yield 'full_lines',packet(3,first,lines=lines),render(lines,first)
   for start in [0,1,2,count,count+1,count+2,U64]:
    for end in [-2,-1,-(1<<63),0,1,count//2,count,count+1]:
     yield 'ranged_lines',packet(3,first,1,start,end,lines),render(lines,first,(start,end))
 for count in [0,1,2,3,4,5,10,29,30,31,49,50,51,70,100]:
  lines=[texts[i%len(texts)] for i in range(count)]
  for first in [0,1,25,U64]:
   yield 'smart_default',packet(4,first,lines=lines),smart(lines,first)
   for limit in [0,1,2,3,4,5,10,29,30,31,49,50,51,count,count+1,U64]:
    yield 'smart_explicit',packet(4,first,1,limit,lines=lines),smart(lines,first,limit)
 for _ in range(800):
  lines=[''.join(rng.choice('abé漢😀\x00\r\n"\\') for _ in range(rng.randrange(12))) for _ in range(rng.randrange(25))]
  first=rng.choice([rng.randrange(10000),U64-rng.randrange(30)])
  if rng.randrange(2):
   start=rng.randrange(len(lines)+3);end=rng.randrange(-3,len(lines)+3)
   yield 'random_ranged',packet(3,first,1,start,end,lines),render(lines,first,(start,end))
  else:
   limit=rng.randrange(35)
   yield 'random_smart',packet(4,first,1,limit,lines=lines),smart(lines,first,limit)
 yield 'constants',packet(5),struct.pack('<Qd',8<<20,3.5)


def function_source(text,name):
 marker='fn '+name+'('
 start=text.index(marker)
 start=text.rfind('\n',0,start)+1
 brace=text.index('{',start)
 at=brace+1;depth=1
 while depth:
  if text[at]=='{':depth+=1
  if text[at]=='}':depth-=1
  at+=1
 return text[start:at]


def oracle_source(repo):
 original=(repo/'src/utils/truncation.rs').read_text()
 line_hash=(repo/'src/utils/line_hash.rs').read_text()
 snippets='\n'.join(function_source(line_hash,name) for name in ['fnv1a_8','line_hash','line_id'])
 return (original[:original.index('// Shared truncation')]+'// Test oracle: exact original owners, compiled with release overflow semantics.\n'
  'mod utils { pub mod line_hash {\n'+snippets+'\n}\npub mod truncation {\n'+original+'\n}}\n'+r'''
use std::io::{self, BufRead, Write};
fn hex(raw: &[u8]) -> String { raw.iter().map(|v| format!("{v:02x}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn word(s: &[u8], at: usize) -> u64 { u64::from_le_bytes(s[at..at+8].try_into().unwrap()) }
fn apply(raw: &[u8]) -> Vec<u8> {
 let op=word(raw,8);let a=word(raw,16) as usize;let b=word(raw,24);
 let c=word(raw,32) as usize;let d=word(raw,40) as i64;let count=word(raw,48) as usize;
 let mut at=64;let mut lines=Vec::new();
 for _ in 0..count { let n=word(raw,at) as usize; at+=8; lines.push(std::str::from_utf8(&raw[at..at+n]).unwrap());at+=n; }
 match op {
  1 => (utils::truncation::estimate_tokens(a) as u64).to_le_bytes().to_vec(),
  2 => utils::truncation::format_megabytes(a).into_bytes(),
  3 => utils::truncation::format_content_with_line_numbers(&lines,a,if b==0 {None} else {Some((c,d))}).into_bytes(),
  4 => utils::truncation::format_extracted_content_smart(&lines,a,if b==0 {None} else {Some(c)}).into_bytes(),
  5 => { let mut v=(utils::truncation::MAX_RESULT_BYTES as u64).to_le_bytes().to_vec();v.extend(utils::truncation::CHARS_PER_TOKEN.to_bits().to_le_bytes());v },
  _ => panic!("unknown test operation"),
 }
}
fn main() {
 std::panic::set_hook(Box::new(|_|{}));
 let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
 for line in stdin.lock().lines() {
  let raw=unhex(&line.unwrap());
  match std::panic::catch_unwind(||apply(&raw)) {
   Ok(bytes) => writeln!(&mut out,"OK {}",hex(&bytes)).unwrap(),
   Err(_) => writeln!(&mut out,"PANIC").unwrap(),
  }
 }
}
''')


def invalid_frames():
 good=packet(3,1,lines=['abc'])
 for length in range(64):yield good[:length]
 yield b'BADTEXT1'+good[8:]
 yield packet(0)
 yield packet(6)
 yield packet(1,1,1)
 yield packet(2,1,c=1)
 yield packet(5,1)
 yield packet(3,1,2,lines=['a'])
 yield packet(3,1,0,1,lines=['a'])
 yield packet(4,1,1,3,4,lines=['a'])
 yield packet(3,1,lines=['a'])+b'x'
 yield packet(3,1,lines=['a'])[:-1]
 yield good[:56]+struct.pack('<Q',1)+good[64:]
 yield good[:48]+struct.pack('<Q',U64)+good[56:]
 yield packet(3,1,lines=[b'\xff'])
 yield packet(3,1,lines=[b'\xc0\xaf'])
 yield packet(3,1,lines=[b'\xed\xa0\x80'])
 yield packet(3,1,lines=[b'\xf4\x90\x80\x80'])
 yield packet(3,1,lines=[b'\xf0\x9f\x98'])
 yield packet(3,1,lines=[b'\xc2a'])
 yield good[:64]+struct.pack('<Q',U64)+good[72:]


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_TEXT_MANIFEST'))
 parser.add_argument('--source',type=Path,default=ROOT/'native/text_budget.hepta')
 parser.add_argument('--loader',type=Path,default=ROOT/'scripts/hia_native_loader.py')
 parser.add_argument('--repo',type=Path,default=ROOT)
 parser.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'))
 parser.add_argument('--vm-only',action='store_true')
 parser.add_argument('--emit-oracle-dir',type=Path)
 parser.add_argument('--rust-oracle',type=Path)
 parser.add_argument('--corpus-dir',type=Path,default=os.environ.get('HIA_TEXT_CORPUS_DIR'))
 args=parser.parse_args()
 started=time.monotonic()
 if args.emit_oracle_dir:
  folder=args.emit_oracle_dir;folder.mkdir(parents=True,exist_ok=False)
  request_file=folder/'requests.hex';expected_file=folder/'expected.txt'
  counts={}
  with request_file.open('w') as request,expected_file.open('w') as expected:
   for kind,raw,out in cases():
    request.write(raw.hex()+'\n');expected.write('OK '+out.hex()+'\n');counts[kind]=counts.get(kind,0)+1
  (folder/'oracle.rs').write_text(oracle_source(args.repo))
  metadata={'schema':'hepta.runtime.text-original-oracle.v1','overflow_checks':False,'cases':sum(counts.values()),'counts':counts,'source_sha256':hashlib.sha256(args.source.read_bytes()).hexdigest(),'original_truncation_sha256':hashlib.sha256((args.repo/'src/utils/truncation.rs').read_bytes()).hexdigest(),'original_line_hash_sha256':hashlib.sha256((args.repo/'src/utils/line_hash.rs').read_bytes()).hexdigest(),'requests_sha256':hashlib.sha256(request_file.read_bytes()).hexdigest(),'expected_sha256':hashlib.sha256(expected_file.read_bytes()).hexdigest(),'oracle_sha256':hashlib.sha256((folder/'oracle.rs').read_bytes()).hexdigest()}
  (folder/'manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
  print(json.dumps({'status':'oracle_prepared',**metadata}));return
 if args.vm_only:
  assert args.hepta,'--hepta or HIA_HEPTA_DIR required for VM'
  sys.path.insert(0,str(args.hepta))
  from hepta.hia_agent_assembly import assemble_program
  from hepta.hia_program_runtime import _Machine,_Owner,_View
  module=assemble_program(args.source.read_bytes())
  samples=[(packet(1,U64),struct.pack('<Q',math.ceil(float(U64)/3.5))),(packet(2,U64),b'17592186044416.0 MB'),(packet(3,1,lines=['é😀','']),render(['é😀',''],1)),(packet(4,5,1,0,lines=['a','b']),smart(['a','b'],5,0)),(packet(3,1,1,8,9,['a']),render(['a'],1,(8,9)))]
  for raw,expected in samples:
   owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(4096)),_Owner(-3,bytearray(4096))]
   machine=_Machine(module,5_000_000,1<<20,None,128)
   code=machine.invoke(module.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
   assert code==len(expected) and bytes(owners[1].data[:code])==expected,(code,expected)
  print(json.dumps({'status':'passed','vm_cases':len(samples),'source_sha256':hashlib.sha256(args.source.read_bytes()).hexdigest()}));return
 assert args.manifest,'--manifest or HIA_TEXT_MANIFEST required'
 spec=importlib.util.spec_from_file_location('hia_native_loader',args.loader);loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
 metadata=json.loads(args.manifest.read_bytes())
 assert metadata['source_sha256']==hashlib.sha256(args.source.read_bytes()).hexdigest()
 corpus_requests=None;corpus_output=None
 if args.corpus_dir:
  args.corpus_dir.mkdir(parents=True,exist_ok=True)
  corpus_requests=(args.corpus_dir/'requests.hex').open('x')
  corpus_output=(args.corpus_dir/'native-output.txt').open('x')
 with loader.NativeModule(args.manifest,manifest_sha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest()) as native:
  with native.session(output_capacity=65536,workspace_capacity=65536) as session:
   for kind,raw,expected in cases():
    actual=session.invoke(raw)
    if corpus_requests:
     corpus_requests.write(raw.hex()+'\n');corpus_output.write('OK '+actual.hex()+'\n')
    assert actual==expected,(kind,raw.hex(),actual,expected)
    COUNTS[kind]=COUNTS.get(kind,0)+1
  for raw in invalid_frames():
   code,out,work=native.invoke_raw(raw,output_capacity=4096,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0x5a)
   assert code==0xffffffff and out==b'\xa5'*4096,(raw.hex(),hex(code))
   COUNTS['invalid']=COUNTS.get('invalid',0)+1
  sample=packet(3,1,lines=['a','é😀',''])
  expected=render(['a','é😀',''],1)
  for output,workspace in [(len(expected)-1,176),(0,176),(len(expected),175),(7,128)]:
   raw=packet(1,123) if workspace==128 else sample
   code,out,work=native.invoke_raw(raw,output_capacity=output,workspace_capacity=workspace,output_fill=0xa5,workspace_fill=0x5a)
   assert code==0xfffffffe and out==b'\xa5'*output,(code,output,workspace)
   COUNTS['capacity']=COUNTS.get('capacity',0)+1
  code,out,work=native.invoke_raw(sample,output_capacity=len(expected),workspace_capacity=176,output_fill=0xa5,workspace_fill=0x5a)
  assert code==len(expected) and out==expected
  COUNTS['exact_capacity']=1
  elf=metadata.get('standalone')
  assert elf and elf['transport']=='filter','the text owner must also build a standalone native filter'
  executable=args.manifest.parent/elf['path']
  for raw,expected in [(packet(1,U64),struct.pack('<Q',math.ceil(float(U64)/3.5))),(sample,render(['a','é😀',''],1)),(packet(2,262144),b'0.2 MB')]:
   proc=subprocess.run([str(executable)],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/does-not-exist','LANG':'C'},timeout=10)
   assert proc.returncode==0 and proc.stderr==b'' and proc.stdout==expected,(proc.returncode,proc.stdout,expected)
   COUNTS['standalone_elf']=COUNTS.get('standalone_elf',0)+1
 if corpus_requests:
  corpus_requests.close();corpus_output.close()
  request_file=args.corpus_dir/'requests.hex';output_file=args.corpus_dir/'native-output.txt'
  oracle=Path(__file__).with_name('oracle_text_budget.rs')
  original_oracle=oracle_source(args.repo)
  assert oracle.read_text()==original_oracle,'checked-in Rust oracle differs from the original source owners'
  count=sum(v for k,v in COUNTS.items() if k in {'estimate','megabytes','full_lines','ranged_lines','smart_default','smart_explicit','random_ranged','random_smart','constants'})
  corpus={'schema':'hepta.runtime.native-corpus.v1','component':'text_budget','cases':count,
          'requests_file':'requests.hex','requests_sha256':hashlib.sha256(request_file.read_bytes()).hexdigest(),'requests_bytes':request_file.stat().st_size,
          'native_output_file':'native-output.txt','native_output_sha256':hashlib.sha256(output_file.read_bytes()).hexdigest(),'native_output_bytes':output_file.stat().st_size,
          'source_sha256':metadata['source_sha256'],'image_sha256':metadata['image_sha256'],
          'oracle':'tests/hia_native/oracle_text_budget.rs','oracle_sha256':hashlib.sha256(oracle.read_bytes()).hexdigest(),
          'original_truncation_sha256':hashlib.sha256((args.repo/'src/utils/truncation.rs').read_bytes()).hexdigest(),
          'original_line_hash_sha256':hashlib.sha256((args.repo/'src/utils/line_hash.rs').read_bytes()).hexdigest(),
          'rust_compile_flags':['--edition=2021','-O','-C','overflow-checks=off'],'counts':COUNTS}
  (args.corpus_dir/'native-corpus.json').write_text(json.dumps(corpus,indent=2,sort_keys=True)+'\n')
 if args.rust_oracle:
  data=list(cases())
  raw=''.join(wire.hex()+'\n' for _,wire,_ in data).encode()
  actual=subprocess.run([str(args.rust_oracle)],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=60).stdout.decode().splitlines()
  expected=['OK '+out.hex() for _,_,out in data]
  assert len(actual)==len(expected) and actual==expected,next(((i,a,e) for i,(a,e) in enumerate(zip(actual,expected)) if a!=e),('length',len(actual),len(expected)))
  COUNTS['original_rust_cases']=len(data)
 print(json.dumps({'status':'passed','counts':COUNTS,'elapsed_seconds':time.monotonic()-started,'source_sha256':metadata['source_sha256']},sort_keys=True))

if __name__=='__main__':main()
