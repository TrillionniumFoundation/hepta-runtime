#!/usr/bin/env python3
"""Native exact parity for the original bounded line-diff and rendering owner."""
from pathlib import Path
import argparse,hashlib,importlib.util,itertools,json,os,random,struct,subprocess,sys,time

ROOT=Path(__file__).resolve().parents[2]
U64=(1<<64)-1
COUNTS={}
PIN='a0dcdda1991ec536d5e2d252c006a778993fa566'

def packet(op,a=0,b=0,old=(),new=()):
 strings=list(old)+list(new)
 raw=struct.pack('<8s7Q',b'HRTDLT01',op,a,b,len(old),len(new),0,0)
 for line in strings:
  encoded=line.encode() if isinstance(line,str) else line
  raw+=struct.pack('<Q',len(encoded))+encoded
 return raw

def line_hash(text):
 h=2166136261
 for byte in text.encode():h=((h^byte)*16777619)&0xffffffff
 h=(h>>16)^(h&65535)
 return f'{((h>>8)^(h&255)):02x}'

def line_id(lines,index):return f'{index+1}:{line_hash(lines[index])}'

def removed(old,first,last):
 return '-'+line_id(old,first)+(f' (1 line)' if first==last else '..'+line_id(old,last)+f' ({last-first+1} lines)')

def diff(old,new,maximum):
 n,m=len(old),len(new);maximum=min(maximum,n+m);offset=maximum+1
 v=[0]*(2*maximum+3);trace=[]
 for d in range(maximum+1):
  trace.append(v.copy())
  for k in range(-d,d+1,2):
   down=k==-d or (k!=d and v[k-1+offset]<v[k+1+offset])
   x=v[k+1+offset] if down else v[k-1+offset]+1;y=x-k
   while x<n and y<m and old[x]==new[y]:x+=1;y+=1
   v[k+offset]=x
   if x>=n and y>=m:
    ops=[];x,y=n,m
    for d in range(len(trace)-1,-1,-1):
     v=trace[d];k=x-y
     previous=k+1 if k==-d or (k!=d and v[k-1+offset]<v[k+1+offset]) else k-1
     px=v[previous+offset];py=px-previous
     while x>px and y>py:x-=1;y-=1;ops.append((0,x,y))
     if d:
      ops.append((2,U64,y-1) if x==px else (1,x-1,U64));x,y=px,py
    return list(reversed(ops))
 return None

def encode_ops(ops):
 if ops is None:return struct.pack('<Q',0)
 return struct.pack('<QQ',1,len(ops))+b''.join(struct.pack('<3Q',*op) for op in ops)

def render(old,new):
 ops=diff(old,new,500)
 if ops is None:return struct.pack('<Q',0)
 hunks=[]
 for i,op in enumerate(ops):
  if op[0]==0:continue
  start=max(i-2,0);end=min(i+2,len(ops)-1)
  if hunks and start<=hunks[-1][1]+1:hunks[-1]=(hunks[-1][0],max(hunks[-1][1],end))
  else:hunks.append((start,end))
 out=[f'[changed since your last view: {len(hunks)} hunk(s), {len(new)} lines now]']
 for start,end in hunks:
  if start>0:out.append('...')
  i=start
  while i<=end:
   kind,a,b=ops[i]
   if kind==0:out.append(line_id(new,b)+'|'+new[b])
   elif kind==2:out.append('+'+line_id(new,b)+'|'+new[b])
   else:
    first=last=a
    while i<end and ops[i+1][0]==1:i+=1;last=ops[i][1]
    out.append(removed(old,first,last))
   i+=1
 if hunks and hunks[-1][1]+1<len(ops):out.append('...')
 return struct.pack('<Q',1)+'\n'.join(out).encode()

def rust_lines(text):
 if not text:return []
 parts=text.split('\n')
 result=[line[:-1] if line.endswith('\r') else line for line in parts[:-1]]
 if parts[-1]:result.append(parts[-1])
 return result

def encode_lines(lines):
 encoded=[line.encode() for line in lines]
 return struct.pack('<Q',len(encoded))+b''.join(struct.pack('<Q',len(line))+line for line in encoded)

def replay(old,new,ops):
 i=j=edits=0;rebuilt=[]
 for kind,a,b in ops:
  if kind==0:
   assert (a,b)==(i,j) and old[a]==new[b]
   rebuilt.append(new[b]);i+=1;j+=1
  elif kind==1:assert a==i and b==U64;i+=1;edits+=1
  else:assert a==U64 and b==j;rebuilt.append(new[b]);j+=1;edits+=1
 assert (i,j)==(len(old),len(new)) and rebuilt==list(new)
 return edits

def minimum_edits(old,new):
 # Independent dynamic-programming length, with no Myers frontier/tie logic.
 row=[0]*(len(new)+1)
 for a in old:
  previous=0
  for j,b in enumerate(new,1):
   saved=row[j];row[j]=previous+1 if a==b else max(row[j],row[j-1]);previous=saved
 return len(old)+len(new)-2*row[-1]

def cases():
 sets=[(),('a',),('a','b'),('x','y','z'),('A','B','C','A','B','B','A'),('C','B','A','B','A','C'),('é','漢','😀','\x00','\r','\n',''),('same',)*8]
 for old in sets:
  for new in sets:
   for maximum in sorted(set([0,1,2,len(old)+len(new),U64])):
    yield 'edges_diff',packet(1,maximum,old=old,new=new),encode_ops(diff(old,new,maximum))
   yield 'edges_render',packet(2,old=old,new=new),render(old,new)
 seq=[v for n in range(5) for v in itertools.product(('a','b'),repeat=n)]
 for old in seq:
  for new in seq:
   minimum=minimum_edits(old,new)
   for maximum in sorted(set([0,max(0,minimum-1),minimum,8,U64])):
    ops=diff(old,new,maximum)
    assert (ops is None)==(minimum>maximum)
    if ops is not None:assert replay(old,new,ops)==minimum
    yield 'exhaustive_diff',packet(1,maximum,old=old,new=new),encode_ops(ops)
   yield 'exhaustive_render',packet(2,old=old,new=new),render(old,new)
 rng=random.Random(0xD317A)
 pool=['','a','b','é','漢','😀','x\r','\x00','line\ninside','\r\n','👩\u200d🔧','e\u0301']
 for _ in range(500):
  old=[rng.choice(pool) for _ in range(rng.randrange(32))]
  new=list(old)
  for _ in range(rng.randrange(16)):
   at=rng.randrange(len(new)+1)
   if at<len(new) and rng.randrange(2):new.pop(at)
   else:new.insert(at,rng.choice(pool))
  minimum=minimum_edits(old,new)
  for maximum in sorted(set([max(0,minimum-1),minimum,rng.randrange(70)])):
   ops=diff(old,new,maximum)
   assert (ops is None)==(minimum>maximum)
   if ops is not None:assert replay(old,new,ops)==minimum
   yield 'random_diff',packet(1,maximum,old=old,new=new),encode_ops(ops)
  yield 'random_render',packet(2,old=old,new=new),render(old,new)
 original=[f'l{i}' for i in range(1,21)];updated=original.copy();updated[4]='L5';del updated[11:14]
 yield 'original_hunks',packet(2,old=original,new=updated),render(original,updated)
 for gap in range(0,11):
  old=['left']+['same']*gap+['right'];new=['LEFT']+['same']*gap+['RIGHT']
  yield 'context_merging',packet(2,old=old,new=new),render(old,new)
 for old in [pool,original,['']*20]:
  for first in range(len(old)):
   for last in sorted(set([first,min(first+1,len(old)-1),len(old)-1])):
    yield 'removed_marker',packet(3,first,last,old=old),removed(old,first,last).encode()
 texts=['','\n','\r','\r\n','\n\n','a\r\nb\rc\n','a\r\r\n','a\n\r','\u0085\u2028\u2029','\x00\r\n😀','é\r\n漢\r','\r\n\r\n']
 for _ in range(500):texts.append(''.join(rng.choice(['a','é','😀','\r','\n','\r\n','\x00','\u2028','']) for _ in range(rng.randrange(70))))
 for text in texts:
  yield 'normalize',packet(4,old=[text]),text.replace('\r\n','\n').encode()
  yield 'split_lines',packet(5,old=[text]),encode_lines(rust_lines(text))
 for size in [499,500,501]:
  for old,new in [([],['x']*size),(['x']*size,[])]:
   yield 'distance_boundary',packet(2,old=old,new=new),render(old,new)
   yield 'distance_boundary',packet(1,size,old=old,new=new),encode_ops(diff(old,new,size))
 old=['a']*251;new=['b']*250
 yield 'distance_boundary',packet(2,old=old,new=new),render(old,new)
 yield 'distance_boundary',packet(1,U64,old=old,new=new),encode_ops(diff(old,new,U64))

def invalid_frames():
 good=packet(2,old=['a'],new=['b'])
 for size in range(64):yield good[:size]
 yield b'BADDLT01'+good[8:]
 yield packet(0)
 yield packet(6)
 yield packet(1,b=1)
 yield packet(2,a=1)
 yield packet(3,0,0)
 yield packet(3,0,1,old=['a'])
 yield packet(3,1,0,old=['a','b'])
 yield packet(3,0,0,old=['a'],new=['b'])
 yield packet(4,old=[])
 yield packet(4,old=['a','b'])
 yield packet(4,a=1,old=['a'])
 yield packet(5,old=['a'],new=['b'])
 yield good+b'x'
 yield good[:-1]
 for at in [32,40,48,56]:yield good[:at]+struct.pack('<Q',U64)+good[at+8:]
 for text in [b'\xff',b'\xc0\xaf',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xf0\x9f\x98',b'\xc2a']:
  yield packet(2,old=[text])
 yield good[:64]+struct.pack('<Q',U64)+good[72:]

def function_source(text,name):
 start=text.index('fn '+name+'(');start=text.rfind('\n',0,start)+1
 brace=text.index('{',start);at=brace+1;depth=1
 while depth:
  if text[at]=='{':depth+=1
  if text[at]=='}':depth-=1
  at+=1
 return text[start:at]

def oracle_source(repo):
 delta=(repo/'src/mcp/fs/delta.rs').read_text();hashes=(repo/'src/utils/line_hash.rs').read_text()
 header=delta[:delta.index('//! Delta views')]
 snippets='\n\n'.join(function_source(delta,n) for n in ['normalize','render_delta','removed_marker','diff_lines','backtrack'])
 enum=delta[delta.index('#[derive(Debug, Clone, Copy, PartialEq, Eq)]'):delta.index('/// Myers line diff')]
 line_helpers='\n\n'.join(function_source(hashes,n) for n in ['fnv1a_8','line_hash','line_id','line_id_at'])
 return header+'// Exact original source owners; only framing below is test code.\n'+line_helpers+'\nconst CONTEXT: usize = 2;\nconst MAX_EDIT_DISTANCE: usize = 500;\n'+enum+snippets+r'''

use std::io::{self, BufRead, Write};
fn hex(raw: &[u8]) -> String { raw.iter().map(|v| format!("{v:02x}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn word(s: &[u8], at: usize) -> u64 { u64::from_le_bytes(s[at..at+8].try_into().unwrap()) }
fn put(out: &mut Vec<u8>, n: u64) { out.extend_from_slice(&n.to_le_bytes()); }
fn apply(raw: &[u8]) -> Vec<u8> {
 let op=word(raw,8);let a=word(raw,16) as usize;let b=word(raw,24) as usize;
 let n=word(raw,32) as usize;let m=word(raw,40) as usize;
 let mut at=64;let mut lines=Vec::new();
 for _ in 0..n+m { let len=word(raw,at) as usize;at+=8;lines.push(std::str::from_utf8(&raw[at..at+len]).unwrap());at+=len; }
 let (old,new)=lines.split_at(n);let mut out=Vec::new();
 match op {
  1 => match diff_lines(old,new,a) {
   None => put(&mut out,0),
   Some(ops) => { put(&mut out,1);put(&mut out,ops.len() as u64);
    for op in ops { match op {
     DiffOp::Equal(i,j) => {put(&mut out,0);put(&mut out,i as u64);put(&mut out,j as u64);},
     DiffOp::Delete(i) => {put(&mut out,1);put(&mut out,i as u64);put(&mut out,u64::MAX);},
     DiffOp::Insert(j) => {put(&mut out,2);put(&mut out,u64::MAX);put(&mut out,j as u64);},
    }}
   }
  },
  2 => match render_delta(old,new) {None => put(&mut out,0),Some(text) => {put(&mut out,1);out.extend_from_slice(text.as_bytes());}},
  3 => out=removed_marker(old,a,b).into_bytes(),
  4 => out=normalize(old[0]).into_bytes(),
  5 => {let parts:Vec<&str>=old[0].lines().collect();put(&mut out,parts.len() as u64);for part in parts {put(&mut out,part.len() as u64);out.extend_from_slice(part.as_bytes());}},
  _ => panic!("unknown test operation"),
 }
 out
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
'''

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_DELTA_MANIFEST'))
 parser.add_argument('--source',type=Path,default=ROOT/'native/delta.hepta')
 parser.add_argument('--loader',type=Path,default=ROOT/'scripts/hia_native_loader.py')
 parser.add_argument('--repo',type=Path,default=ROOT)
 parser.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'))
 parser.add_argument('--vm-only',action='store_true')
 parser.add_argument('--emit-oracle-dir',type=Path)
 parser.add_argument('--rust-oracle',type=Path)
 parser.add_argument('--corpus-dir',type=Path,default=os.environ.get('HIA_DELTA_CORPUS_DIR'))
 args=parser.parse_args();started=time.monotonic()
 if args.emit_oracle_dir:
  args.emit_oracle_dir.mkdir(parents=True,exist_ok=False)
  (args.emit_oracle_dir/'oracle.rs').write_text(oracle_source(args.repo))
  with (args.emit_oracle_dir/'requests.hex').open('x') as requests,(args.emit_oracle_dir/'expected.txt').open('x') as expected:
   for kind,wire,out in cases():requests.write(wire.hex()+'\n');expected.write('OK '+out.hex()+'\n');COUNTS[kind]=COUNTS.get(kind,0)+1
  print(json.dumps({'status':'oracle_prepared','cases':sum(COUNTS.values()),'counts':COUNTS}));return
 if args.vm_only:
  assert args.hepta,'--hepta or HIA_HEPTA_DIR required for VM'
  sys.path.insert(0,str(args.hepta))
  from hepta.hia_agent_assembly import assemble_program
  from hepta.hia_program_runtime import _Machine,_Owner,_View
  program=assemble_program(args.source.read_bytes())
  samples=[(packet(1,3,old=['a','b'],new=['b','a']),encode_ops(diff(['a','b'],['b','a'],3))),
           (packet(2,old=['é','😀'],new=['漢','😀']),render(['é','😀'],['漢','😀'])),
           (packet(3,0,1,old=['a','b']),removed(['a','b'],0,1).encode()),
           (packet(4,old=['a\r\n\r']),b'a\n\r'),
           (packet(5,old=['a\r\n\r']),encode_lines(['a','\r']))]
  for raw,expected in samples:
   owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(4096)),_Owner(-3,bytearray(16384))]
   machine=_Machine(program,10_000_000,1<<20,None,128)
   code=machine.invoke(program.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
   assert code==len(expected) and bytes(owners[1].data[:code])==expected,(code,bytes(owners[1].data[:code]),expected)
  print(json.dumps({'status':'passed','vm_cases':len(samples),'source_sha256':hashlib.sha256(args.source.read_bytes()).hexdigest()}));return
 assert args.manifest,'HIA_DELTA_MANIFEST or --manifest required'
 spec=importlib.util.spec_from_file_location('hia_native_loader',args.loader);loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
 metadata=json.loads(args.manifest.read_bytes());assert metadata['source_sha256']==hashlib.sha256(args.source.read_bytes()).hexdigest()
 requests=outputs=None;valid=0
 if args.corpus_dir:
  args.corpus_dir.mkdir(parents=True,exist_ok=True)
  requests=(args.corpus_dir/'requests.hex').open('x');outputs=(args.corpus_dir/'native-output.txt').open('x')
 with loader.NativeModule(args.manifest,manifest_sha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest()) as native:
  with native.session(output_capacity=65536,workspace_capacity=262144) as session,native.session(output_capacity=65536,workspace_capacity=8<<20) as large:
   for kind,wire,expected in cases():
    actual=(large if kind=='distance_boundary' else session).invoke(wire)
    if requests:requests.write(wire.hex()+'\n');outputs.write('OK '+actual.hex()+'\n')
    assert actual==expected,(kind,wire.hex(),actual,expected)
    COUNTS[kind]=COUNTS.get(kind,0)+1;valid+=1
  for wire in invalid_frames():
   code,out,work=native.invoke_raw(wire,output_capacity=4096,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0x5a)
   assert code==0xffffffff and out==b'\xa5'*4096,(wire.hex(),hex(code))
   COUNTS['invalid']=COUNTS.get('invalid',0)+1
  sample=packet(1,2,old=['a'],new=['b']);expected=encode_ops(diff(['a'],['b'],2))
  for out_size,work_size in [(len(expected)-1,560),(0,560),(len(expected),559),(len(expected),287)]:
   code,out,work=native.invoke_raw(sample,output_capacity=out_size,workspace_capacity=work_size,output_fill=0xa5,workspace_fill=0x5a)
   assert code==0xfffffffe and out==b'\xa5'*out_size,(code,out_size,work_size)
   COUNTS['capacity']=COUNTS.get('capacity',0)+1
  code,out,work=native.invoke_raw(sample,output_capacity=len(expected),workspace_capacity=560,output_fill=0xa5,workspace_fill=0x5a)
  assert code==len(expected) and out==expected;COUNTS['exact_capacity']=1
  no_match=packet(1,0,old=['a'],new=['b'])
  code,out,work=native.invoke_raw(no_match,output_capacity=8,workspace_capacity=384,output_fill=0xa5,workspace_fill=0x5a)
  assert code==8 and out==b'\x00'*8;COUNTS['none_not_capacity']=1
  standalone=metadata.get('standalone');assert standalone and standalone['transport']=='filter'
  executable=args.manifest.parent/standalone['path']
  for wire,expected in [(sample,expected),(packet(2,old=['a','b'],new=['b','😀']),render(['a','b'],['b','😀'])),(packet(4,old=['a\r\n漢\r']),b'a\n'+ '漢\r'.encode())]:
   proc=subprocess.run([str(executable)],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/does-not-exist','LANG':'C'},timeout=10)
   assert proc.returncode==0 and proc.stderr==b'' and proc.stdout==expected,(proc.returncode,proc.stdout,expected)
   COUNTS['standalone_elf']=COUNTS.get('standalone_elf',0)+1
 if requests:
  requests.close();outputs.close()
  request_file=args.corpus_dir/'requests.hex';output_file=args.corpus_dir/'native-output.txt';oracle=Path(__file__).with_name('oracle_delta.rs')
  assert oracle.read_text()==oracle_source(args.repo),'checked-in Rust oracle differs from the original owners'
  corpus={'schema':'hepta.runtime.native-corpus.v1','component':'delta','cases':valid,'counts':COUNTS,
          'requests_file':request_file.name,'requests_sha256':hashlib.sha256(request_file.read_bytes()).hexdigest(),'requests_bytes':request_file.stat().st_size,
          'native_output_file':output_file.name,'native_output_sha256':hashlib.sha256(output_file.read_bytes()).hexdigest(),'native_output_bytes':output_file.stat().st_size,
          'source_sha256':metadata['source_sha256'],'image_sha256':metadata['image_sha256'],
          'oracle':'tests/hia_native/oracle_delta.rs','oracle_sha256':hashlib.sha256(oracle.read_bytes()).hexdigest(),
          'original_commit':PIN,'original_delta_sha256':hashlib.sha256((args.repo/'src/mcp/fs/delta.rs').read_bytes()).hexdigest(),
          'original_line_hash_sha256':hashlib.sha256((args.repo/'src/utils/line_hash.rs').read_bytes()).hexdigest(),
          'rust_compile_flags':['--edition=2021','-O','-C','overflow-checks=off']}
  (args.corpus_dir/'native-corpus.json').write_text(json.dumps(corpus,indent=2,sort_keys=True)+'\n')
 if args.rust_oracle:
  data=list(cases());wire=''.join(raw.hex()+'\n' for _,raw,_ in data).encode()
  result=subprocess.run([str(args.rust_oracle)],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=60)
  actual=result.stdout.decode().splitlines();expected=['OK '+raw.hex() for _,_,raw in data]
  assert not result.stderr and actual==expected,next(((i,a,b) for i,(a,b) in enumerate(zip(actual,expected)) if a!=b),('length',len(actual),len(expected)))
  COUNTS['original_rust_cases']=len(data)
 print(json.dumps({'status':'passed','counts':COUNTS,'valid_cases':valid,'elapsed_seconds':time.monotonic()-started,'source_sha256':metadata['source_sha256']},sort_keys=True))

if __name__=='__main__':main()
