#!/usr/bin/env python3
"""Native parity for administrator-owned typed capability policy decisions."""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,itertools,json,os,random,re,struct,subprocess,sys,time

ROOT=Path(__file__).resolve().parents[2]
U64=(1<<64)-1
PIN='a0dcdda1991ec536d5e2d252c006a778993fa566'
CONFIG_SHA='228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35'
DANGEROUS='sudo su doas sh bash dash zsh fish ksh ssh scp sftp nohup setsid tmux screen systemd-run crontab at nsenter unshare kill pkill killall systemctl service loginctl reboot shutdown poweroff halt init mount umount modprobe insmod rmmod apt apt-get dpkg rpm dnf yum snap docker podman virsh nft iptables ip6tables'.split()
ENVIRONMENT='LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH PYTHONPATH PYTHONHOME NODE_OPTIONS BASH_ENV ENV PERL5OPT RUBYOPT GIT_SSH GIT_SSH_COMMAND SSH_ASKPASS SUDO_ASKPASS'.split()
WHITE={*range(9,14),32,133,160,5760,*range(8192,8203),8232,8233,8239,8287,12288}
LISTS=('cwd_roots','read_roots','write_roots','protected_paths','protected_args','denied','permitted')
COUNTS={}

def case(op,**kwargs):
 value={'op':op,'state':2,'mode':0,'allow':0,'request':0,'name':'node','alias':'node','value':'','cwd':'','root':'','args':[],'env':[]}
 value.update({key:[] for key in LISTS});value.update(kwargs);return value

def raw(value):return value.encode() if isinstance(value,str) else value

def packet(c):
 env=c['env'];counts=[len(c['args']),len(env)]+[len(c[k]) for k in LISTS]
 data=struct.pack('<8s15Q',b'HRTPLC01',c['op'],c['state'],c['mode'],c['allow'],c['request'],*counts,0)
 records=[c[k] for k in ('name','alias','value','cwd','root')]+list(c['args'])
 records.extend(x for pair in env for x in pair)
 for key in LISTS:records.extend(c[key])
 for item in records:
  value=raw(item);data+=struct.pack('<Q',len(value))+value
 return data

def result(tag,value=0,body=b''):
 body=raw(body);return struct.pack('<8s3Q',b'HRTPLR01',tag,value,len(body))+body

def ok():return result(0)
def err(message):return result(1,body=message)
def boolean(value):return result(2,int(value))

def protected(c,value):
 return next((p for p in c['protected_paths']+c['protected_args'] if p and p in value),None)

def allowed(value,prefixes):
 return any(value==prefix or value.startswith(prefix.rstrip('/')+'/') for prefix in prefixes)

def parent(value):return '..' in value.split('/')

def components(path):
 path=raw(path);parts=path.split(b'/');out=[]
 if path.startswith(b'/'):out.append(b'/')
 for i,part in enumerate(parts):
  if not part:continue
  if part==b'.' and i!=0:continue
  out.append(part)
 return out

def expected(c):
 op=c['op'];name=c['name'];value=c['value'];flags=c['allow'];request=c['request'];state=c['state']
 if op in [1,2,4]:
  if state==0:return err('runtime tools are disabled; start with --runtime-config <file>')
  if state==1:return err(f'unknown host `{name}`; call host_list for configured names')
 if op==1:
  if request&1 and not flags&2:return err(f'PTY execution is disabled for host `{name}`')
  if not request&1 and not flags&1:return err(f'process execution is disabled for host `{name}`')
  if all(ord(cp) in WHITE for cp in value) or '\x00' in value:return err('executable must be a non-empty absolute path')
  if not value.startswith('/') or parent(value):return err(f'executable `{value}` must be an absolute path without parent traversal')
  found=protected(c,value)
  if found is not None:return err(f'executable intersects protected value `{found}` on host `{name}`')
  base=value.rsplit('/',1)[-1]
  denied=base in c['denied'] or value in c['denied'];permitted=base in c['permitted'] or value in c['permitted']
  if denied or (c['mode']==0 and base in DANGEROUS and not permitted):return err(f'executable `{base}` is denied on host `{name}`; use a named privileged_action when configured')
  if request&2:
   cwd=c['cwd']
   if '\x00' in cwd or not cwd.startswith('/') or parent(cwd):return err('cwd must be an absolute path')
   if c['cwd_roots'] and not allowed(cwd,c['cwd_roots']):return err(f'cwd `{cwd}` is outside configured execution roots on host `{name}`')
   found=protected(c,cwd)
   if found is not None:return err(f'cwd intersects protected value `{found}` on host `{name}`')
  for arg in c['args']:
   if '\x00' in arg:return err('arguments may not contain NUL bytes')
   found=protected(c,arg)
   if found is not None:return err(f'argument intersects protected value `{found}` on host `{name}`')
  return ok()
 if op==2:
  for key,value in c['env']:
   if '\x00' in value:return err('environment values may not contain NUL bytes')
   if c['mode']==0 and key in ENVIRONMENT:return err(f'environment variable `{key}` is denied on host `{name}`')
   found=protected(c,value)
   if found is not None:return err(f'environment value intersects protected value `{found}` on host `{name}`')
  return ok()
 if op==3:
  found=protected(c,value);return result(4) if found is None else result(3,body=found)
 if op==4:
  found=protected(c,value)
  return ok() if found is None else err(f'value intersects protected value `{found}` on host `{name}`')
 if op==5:return boolean(allowed(value,c['read_roots']))
 if op==6:
  if state==0:return ok()
  if state==1:return err(f'remote file access to unregistered SSH host `{c["alias"]}` is disabled')
  if request&12:return err('remote file access must use the registered SSH alias without user or port overrides')
  if not value.startswith('/') or value=='/~' or value.startswith('/~/'):return err('remote file access requires an absolute target path')
  if parent(value):return err('remote path traversal is not allowed')
  found=next((p for p in c['protected_paths'] if allowed(value,[p])),None)
  if found is not None:return err(f'path `{value}` is protected by prefix `{found}` on host `{name}`')
  if request&16:
   if not flags&4:return err(f'remote writes are disabled for host `{name}`')
   if not allowed(value,c['write_roots']):return err(f'path `{value}` is outside configured write roots on host `{name}`')
  elif not allowed(value,c['read_roots']):return err(f'path `{value}` is outside configured read roots on host `{name}`')
  return ok()
 if op==7:
  value=raw(value);display=value.decode('utf-8','replace')
  if not value.startswith(b'/'):return err(f'path `{display}` must be absolute')
  normalized=[]
  for part in value.split(b'/'):
   if part in [b'',b'.']:continue
   if part==b'..':
    if not normalized:return err(f'path `{display}` escapes the filesystem root')
    normalized.pop()
   else:normalized.append(part)
  return result(5,body=b'/'+b'/'.join(normalized))
 if op==8:
  candidate=components(value);root=components(c['root']);return boolean(candidate[:len(root)]==root)
 raise AssertionError(op)

def cases():
 for state in range(3):
  for op in [1,2,4,6]:
   yield 'lookup_order',case(op,state=state,value='bad\x00',env=[('BASH_ENV','bad\x00')],request=31,protected_args=['bad'])
 for allow in range(8):
  for pty in range(2):
   for value in ['', ' ', '\u2000', 'relative','/a/../b','/bin/tool','/bin/bash','/bad\x00']:
    yield 'permission_order',case(1,allow=allow,request=pty,value=value)
 for name in DANGEROUS:
  path='/usr/bin/'+name
  for mode in range(2):
   for permitted in [[],[name],[path],['different']]:
    for denied in [[],[name],[path]]:
     yield 'default_executable_policy',case(1,allow=3,value=path,mode=mode,permitted=permitted,denied=denied)
  for value in [path+'/',path+'-safe','/'+name.upper(),'/a/./'+name]:
   yield 'basename_boundaries',case(1,allow=1,value=value)
 for cp in sorted(WHITE|{0x1c,0x1d,0x1e,0x1f,0x180e,0x200b,0xfeff}):
  for text in [chr(cp),chr(cp)*2,chr(cp)+'/bin/tool'+chr(cp)]:
   yield 'unicode_trim',case(1,allow=1,value=text)
 pools=[[],[''],['SECRET'],['/root','SECRET'],['SECRET','SEC'],['SEC','SECRET'],['漢','é'],['x\x00','z']]
 for paths in pools:
  for args in pools:
   for value in ['','prefixSECRET suffix','/root/a','/rooted','漢é','x\x00']:
    for op in [3,4]:yield 'protected_order',case(op,value=value,protected_paths=paths,protected_args=args)
 for name in ENVIRONMENT:
  for mode in range(2):
   for value in ['normal','SECRET','\x00SECRET']:
    for key in [name,name.lower()]:
     yield 'environment_policy',case(2,mode=mode,env=[(key,value)],protected_args=['SECRET'])
 envs=[[('A','SECRET'),('BASH_ENV','ok')],[('A','\x00'),('BASH_ENV','SECRET')],[('BASH_ENV','SECRET'),('Z','\x00')],[('','ok'),('漢','SECRET')],[('BAD=KEY','ok')],[('\x00','ok')]]
 for env in envs:
  for mode in range(2):yield 'environment_first_error',case(2,env=env,mode=mode,protected_args=['SECRET'])
 values=['','/','//','/a','/a/','/a//','/ab','/a/b','/a/./b','/a/../b','/..','/a/...','/~','/~/a','/~x','relative','./a','/漢/é','/a\x00b','/a\\b']
 prefixes=['','/','//','/a','/a/','/a//','/ab','/a/b','/漢','a','/a/..']
 for value in values:
  for prefix in prefixes:
   yield 'remote_prefix',case(5,value=value,read_roots=[prefix])
   for request,allow in [(0,0),(16,0),(16,4)]:
    yield 'remote_path_policy',case(6,value=value,read_roots=[prefix],write_roots=[prefix],request=request,allow=allow)
 for request in range(32):
  for state in range(3):
   yield 'remote_first_error',case(6,value='/secret/../a',state=state,request=request,protected_paths=['/secret'],read_roots=['/'],write_roots=['/'],allow=4)
 for cwd in values:
  for roots in [[],['/'],['/a'],['/a/'],['/a','/漢']]:
   for args in [[],['ok'],['SECRET'],['SECRET','bad\x00'],['bad\x00','SECRET']]:
    yield 'execution_first_error',case(1,allow=1,value='/bin/tool',request=2,cwd=cwd,cwd_roots=roots,protected_args=['SECRET'],args=args)
 for value in ['/bin/SECRET','/bin/bash']:
  yield 'execution_protection_before_denial',case(1,allow=1,value=value,protected_paths=[value],denied=[value],args=['\x00'],cwd='bad',request=2)
 segments=[b'',b'a',b'.',b'..',b'\xc3\xa9',b'\x00',b'\xff']
 paths=[]
 for length in range(4):
  for parts in itertools.product(segments,repeat=length):
   value=b'/'.join(parts)
   for path in [value,b'/'+value]:
    yield 'normalize_components',case(7,value=path)
   if length<3:paths.append(value)
 for a in paths:
  for b in paths:
   yield 'path_under_components',case(8,value=a,root=b)
 for value in range(256):
  for text in [bytes([value]),b'/../'+bytes([value])]:
   yield 'raw_path_display',case(7,value=text)
 for tail in [b'\xe0\x80\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xe2\x82',b'\xf0\x9f\x92',b'\xe2\x82A',b'\xf0\x9fA',b'\xc2A']:
  yield 'raw_path_display',case(7,value=tail)
  yield 'raw_path_display',case(7,value=b'/../'+tail)
 rng=random.Random(0xC0F16)
 byte_pool=[b'a',b'/',b'.',b'..',b'',b'\xff',b'\x00',b'\xc2',b'\x80',b'\xf0\x9f\x98\x80']
 for _ in range(1000):
  value=b'/'.join(rng.choice(byte_pool) for _ in range(rng.randrange(8)))
  if rng.randrange(2):value=b'/'+value
  yield 'random_normalize',case(7,value=value)
  root=b'/'.join(rng.choice(byte_pool) for _ in range(rng.randrange(5)))
  if rng.randrange(2):root=b'/'+root
  yield 'random_path_under',case(8,value=value,root=root)
 for _ in range(1000):
  op=rng.choice([1,2,3,4,5,6]);value=rng.choice(values+['/bin/bash','/bin/tool','SECRET','漢é','\x00'])
  state=2 if op==3 else rng.randrange(3)
  env=sorted({rng.choice(ENVIRONMENT+['A','Z','é']):rng.choice(['ok','SECRET','\x00']) for _ in range(rng.randrange(4))}.items())
  yield 'random_typed_policy',case(op,value=value,state=state,mode=rng.randrange(2),allow=rng.randrange(8),request=rng.randrange(32),
   cwd=rng.choice(values),args=[rng.choice(['ok','SECRET','\x00','漢']) for _ in range(rng.randrange(4))],env=env,
   cwd_roots=rng.sample(prefixes,rng.randrange(4)),read_roots=rng.sample(prefixes,rng.randrange(4)),write_roots=rng.sample(prefixes,rng.randrange(4)),
   protected_paths=rng.choice(pools),protected_args=rng.choice(pools),denied=rng.sample(['bash','/bin/tool','tool'],rng.randrange(4)),permitted=rng.sample(['bash','/bin/bash','tool'],rng.randrange(4)))
 for op in [3,4]:
  for ending in ['a','b']:
   yield 'long_overlapping_prefix',case(op,value='a'*131072+ending,protected_args=['a'*65536+'b'])

def invalid_frames():
 good=packet(case(1,allow=1,value='/bin/tool'))
 for size in range(128):yield good[:size]
 yield b'BADPLC01'+good[8:]
 for at,value in [(8,0),(8,9),(16,3),(24,2),(32,8),(40,32),(120,1),(48,U64),(56,U64),(112,U64)]:
  yield good[:at]+struct.pack('<Q',value)+good[at+8:]
 yield packet(case(3,state=0))
 yield packet(case(3,state=1))
 yield good+b'x'
 yield good[:-1]
 yield good[:128]+struct.pack('<Q',U64)+good[136:]
 yield packet(case(2,env=[('z','first'),('a','last')]))
 yield packet(case(2,env=[('a','first'),('a','last')]))
 for value in [b'\xff',b'\xc0\xaf',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xf0\x9f\x98',b'\xc2a']:
  for op in [1,2,3,4,5,6]:yield packet(case(op,value=value))
  yield packet(case(7,value=b'/ok',name=value))

def function_source(text,name):
 start=text.index('fn '+name+'(');start=text.rfind('\n',0,start)+1
 brace=text.index('{',start);at=brace+1;depth=1
 while depth:
  if text[at]=='{':depth+=1
  if text[at]=='}':depth-=1
  at+=1
 return text[start:at]

def oracle_source(repo):
 original=(repo/'src/mcp/runtime/config.rs').read_bytes();assert hashlib.sha256(original).hexdigest()==CONFIG_SHA
 original=original.decode();header=original[:original.index('//! Fail-closed')]
 functions='\n\n'.join(function_source(original,name) for name in ['executable_basename','protected_value','check_environment','check_protected_input','check_execution','validate_execution','normalize_absolute','path_under','remote_path_allowed','check_remote_path'])
 constants='\n\n'.join(re.search(r'const '+name+r':.*?= &\[.*?\];',original,re.S).group(0) for name in ['DEFAULT_DANGEROUS','DANGEROUS_ENV'])
 methods='\n\n'.join(function_source(original,name) for name in ['host','host_by_alias'])
 return header+r'''
// Test-only typed configuration fixture. Policy function bodies below are unchanged.
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::io::{self, BufRead, Write};
type Result<T> = std::result::Result<T, String>;
macro_rules! anyhow { ($($arg:tt)*) => { format!($($arg)*) }; }
macro_rules! bail { ($($arg:tt)*) => {{ return Err(format!($($arg)*)); }}; }
#[derive(Clone,Copy,PartialEq,Eq)]
enum ExecutionMode { Isolated, Operator }
#[derive(Clone)]
struct HostConfig {
 execution_mode:ExecutionMode,ssh_target:String,allow_execute:bool,allow_pty:bool,allow_write:bool,
 allowed_cwd_prefixes:Vec<String>,allowed_read_path_prefixes:Vec<String>,allowed_write_path_prefixes:Vec<String>,
 protected_path_prefixes:Vec<String>,protected_argument_substrings:Vec<String>,denied_executables:Vec<String>,allowed_dangerous_executables:Vec<String>,
}
struct RuntimeConfig { hosts:BTreeMap<String,HostConfig> }
thread_local! { static FIXTURE:Cell<Option<&'static RuntimeConfig>> = const { Cell::new(None) }; }
fn runtime_config() -> Result<&'static RuntimeConfig> {
 FIXTURE.with(|slot|slot.get().ok_or_else(||"runtime tools are disabled; start with --runtime-config <file>".to_owned()))
}
fn maybe_runtime_config() -> Option<&'static RuntimeConfig> { FIXTURE.with(Cell::get) }
impl RuntimeConfig {
'''+methods+'\n}\n'+constants+'\n'+functions+r'''

fn hex(raw: &[u8]) -> String { raw.iter().map(|v| format!("{v:02x}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn word(s: &[u8], at: usize) -> u64 { u64::from_le_bytes(s[at..at+8].try_into().unwrap()) }
fn output(tag:u64,value:u64,body:&[u8]) -> Vec<u8> {
 let mut out=b"HRTPLR01".to_vec();out.extend_from_slice(&tag.to_le_bytes());out.extend_from_slice(&value.to_le_bytes());out.extend_from_slice(&(body.len() as u64).to_le_bytes());out.extend_from_slice(body);out
}
fn unit(value:Result<()>) -> Vec<u8> {match value {Ok(())=>output(0,0,&[]),Err(err)=>output(1,0,err.as_bytes())}}
fn apply(raw:&[u8]) -> Vec<u8> {
 let op=word(raw,8);let state=word(raw,16);let mode=word(raw,24);let flags=word(raw,32);let request=word(raw,40);
 let counts:Vec<usize>=(48..=112).step_by(8).map(|i|word(raw,i) as usize).collect();
 let count=5+counts.iter().sum::<usize>()+counts[1];let mut at=128;let mut records=Vec::new();
 for _ in 0..count {let n=word(raw,at) as usize;at+=8;records.push(&raw[at..at+n]);at+=n;}
 let text=|i:usize|std::str::from_utf8(records[i]).unwrap();
 let name=text(0);let alias=text(1);let mut index=5;
 let args:Vec<String>=(index..index+counts[0]).map(|i|text(i).to_owned()).collect();index+=counts[0];
 let mut env=BTreeMap::new();for _ in 0..counts[1] {env.insert(text(index).to_owned(),text(index+1).to_owned());index+=2;}
 let mut lists=Vec::new();for count in &counts[2..] {lists.push((index..index+count).map(|i|text(i).to_owned()).collect::<Vec<_>>());index+=count;}
 let host=HostConfig {execution_mode:if mode==0 {ExecutionMode::Isolated} else {ExecutionMode::Operator},ssh_target:alias.to_owned(),
  allow_execute:flags&1!=0,allow_pty:flags&2!=0,allow_write:flags&4!=0,
  allowed_cwd_prefixes:lists[0].clone(),allowed_read_path_prefixes:lists[1].clone(),allowed_write_path_prefixes:lists[2].clone(),
  protected_path_prefixes:lists[3].clone(),protected_argument_substrings:lists[4].clone(),denied_executables:lists[5].clone(),allowed_dangerous_executables:lists[6].clone()};
 if state==0 {FIXTURE.with(|slot|slot.set(None));} else {
  let mut hosts=BTreeMap::new();if state==2 {hosts.insert(name.to_owned(),host.clone());}
  FIXTURE.with(|slot|slot.set(Some(Box::leak(Box::new(RuntimeConfig{hosts})))));
 }
 match op {
  1=>unit(check_execution(name,text(2),&args,if request&2!=0 {Some(text(3))} else {None},request&1!=0).map(|_|())),
  2=>unit(check_environment(name,&env)),
  3=>match protected_value(&host,text(2)) {Some(s)=>output(3,0,s.as_bytes()),None=>output(4,0,&[])},
  4=>unit(check_protected_input(name,text(2))),
  5=>output(2,remote_path_allowed(text(2),&host.allowed_read_path_prefixes) as u64,&[]),
  6=>unit(check_remote_path(alias,text(2),request&4!=0,request&8!=0,request&16!=0)),
  7=>match normalize_absolute(Path::new(OsStr::from_bytes(records[2]))) {Ok(p)=>output(5,0,p.as_os_str().as_bytes()),Err(err)=>output(1,0,err.as_bytes())},
  8=>output(2,path_under(Path::new(OsStr::from_bytes(records[2])),Path::new(OsStr::from_bytes(records[4]))) as u64,&[]),
  _=>panic!("unknown operation"),
 }
}
fn main() {
 std::panic::set_hook(Box::new(|_|{}));let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
 for line in stdin.lock().lines() {let raw=unhex(&line.unwrap());match std::panic::catch_unwind(||apply(&raw)) {
  Ok(bytes)=>writeln!(&mut out,"OK {}",hex(&bytes)).unwrap(),Err(_)=>writeln!(&mut out,"PANIC").unwrap(),
 }}
}
'''

def check_composition(source,repo,hepta):
 assert hepta,'HIA_HEPTA_DIR or --hepta required for imported HIA source verification'
 sys.path.insert(0,str(hepta))
 from hepta.hia_agent_assembly import assemble_program
 proof=json.loads(source.with_name('policy_provenance.json').read_bytes())
 assert proof['source_sha256']==hashlib.sha256(source.read_bytes()).hexdigest()
 assert proof['original_config_sha256']==CONFIG_SHA
 dest=assemble_program(source.read_bytes()).as_dict()
 for row in proof['imports'].values():
  raw=(repo/row['source']).read_bytes();assert hashlib.sha256(raw).hexdigest()==row['source_sha256']
  original=assemble_program(raw).as_dict();a=next(f for f in original['functions'] if f['name']==row['function'])
  assert hashlib.sha256(json.dumps(a,sort_keys=True,separators=(',',':')).encode()).hexdigest()==row['function_sha256']
  b=copy.deepcopy(next(f for f in dest['functions'] if f['name']==row['destination_function']));b['name']=row['function'];assert a==b

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_POLICY_MANIFEST'))
 parser.add_argument('--source',type=Path,default=ROOT/'native/policy.hepta')
 parser.add_argument('--loader',type=Path,default=ROOT/'scripts/hia_native_loader.py')
 parser.add_argument('--repo',type=Path,default=ROOT)
 parser.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'))
 parser.add_argument('--vm-only',action='store_true')
 parser.add_argument('--emit-oracle-dir',type=Path)
 parser.add_argument('--rust-oracle',type=Path)
 parser.add_argument('--corpus-dir',type=Path,default=os.environ.get('HIA_POLICY_CORPUS_DIR'))
 args=parser.parse_args();started=time.monotonic()
 if args.emit_oracle_dir:
  args.emit_oracle_dir.mkdir(parents=True,exist_ok=False)
  (args.emit_oracle_dir/'oracle.rs').write_text(oracle_source(args.repo))
  with (args.emit_oracle_dir/'requests.hex').open('x') as requests,(args.emit_oracle_dir/'expected.txt').open('x') as out:
   for kind,c in cases():requests.write(packet(c).hex()+'\n');out.write('OK '+expected(c).hex()+'\n');COUNTS[kind]=COUNTS.get(kind,0)+1
  print(json.dumps({'status':'oracle_prepared','cases':sum(COUNTS.values()),'counts':COUNTS}));return
 check_composition(args.source,args.repo,args.hepta)
 samples=[case(1,allow=1,value='/bin/bash'),case(2,env=[('BASH_ENV','ok')]),case(3,value='SECRET',protected_args=['SEC','SECRET']),case(5,value='/ab',read_roots=['/a']),case(6,value='/secret/x',protected_paths=['/secret'],read_roots=['/']),case(7,value=b'/a/../b/./'),case(7,value=b'\xe2\x82'),case(8,value=b'./a/b',root=b'./a')]
 if args.vm_only:
  from hepta.hia_agent_assembly import assemble_program
  from hepta.hia_program_runtime import _Machine,_Owner,_View
  program=assemble_program(args.source.read_bytes())
  for c in samples:
   wire=packet(c);want=expected(c);owners=[_Owner(-1,bytearray(wire)),_Owner(-2,bytearray(4096)),_Owner(-3,bytearray(4096))]
   machine=_Machine(program,10_000_000,1<<20,None,128)
   code=machine.invoke(program.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
   assert code==len(want) and bytes(owners[1].data[:code])==want,(c,code,bytes(owners[1].data[:code]),want)
  print(json.dumps({'status':'passed','vm_cases':len(samples)}));return
 assert args.manifest,'HIA_POLICY_MANIFEST or --manifest required'
 spec=importlib.util.spec_from_file_location('hia_native_loader',args.loader);loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
 metadata=json.loads(args.manifest.read_bytes());assert metadata['source_sha256']==hashlib.sha256(args.source.read_bytes()).hexdigest()
 requests=outputs=None;valid=0
 if args.corpus_dir:
  args.corpus_dir.mkdir(parents=True,exist_ok=True);requests=(args.corpus_dir/'requests.hex').open('x');outputs=(args.corpus_dir/'native-output.txt').open('x')
 with loader.NativeModule(args.manifest,manifest_sha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest()) as native:
  with native.session(output_capacity=16384,workspace_capacity=65536) as session,native.session(output_capacity=1<<20,workspace_capacity=4<<20) as large:
   for kind,c in cases():
    wire=packet(c);want=expected(c);actual=(large if kind=='long_overlapping_prefix' else session).invoke(wire)
    if requests:requests.write(wire.hex()+'\n');outputs.write('OK '+actual.hex()+'\n')
    assert actual==want,(kind,c,actual,want)
    COUNTS[kind]=COUNTS.get(kind,0)+1;valid+=1
  for wire in invalid_frames():
   code,out,work=native.invoke_raw(wire,output_capacity=4096,workspace_capacity=4096,output_fill=0xa5,workspace_fill=0x5a)
   assert code==0xffffffff and out==b'\xa5'*4096,(wire.hex(),hex(code));COUNTS['invalid']=COUNTS.get('invalid',0)+1
  sample=case(1,allow=1,value='/bin/bash');wire=packet(sample);want=expected(sample)
  for out_size,work_size in [(len(want)-1,336),(0,336),(len(want),335)]:
   code,out,work=native.invoke_raw(wire,output_capacity=out_size,workspace_capacity=work_size,output_fill=0xa5,workspace_fill=0x5a)
   assert code==0xfffffffe and out==b'\xa5'*out_size,(code,out_size,work_size);COUNTS['capacity']=COUNTS.get('capacity',0)+1
  code,out,work=native.invoke_raw(wire,output_capacity=len(want),workspace_capacity=336,output_fill=0xa5,workspace_fill=0x5a)
  assert code==len(want) and out==want;COUNTS['exact_capacity']=1
  normalized=case(7,value=b'/a/../b');wire=packet(normalized);want=expected(normalized);needed=336+len(normalized['value'])
  for work_size,success in [(needed-1,False),(needed,True)]:
   code,out,work=native.invoke_raw(wire,output_capacity=len(want),workspace_capacity=work_size,output_fill=0xa5,workspace_fill=0x5a)
   assert (code==len(want) and out==want) if success else (code==0xfffffffe and out==b'\xa5'*len(want))
   COUNTS['normalize_capacity']=COUNTS.get('normalize_capacity',0)+1
  lossy=case(7,value=b'\xff'*2048);wire=packet(lossy);want=expected(lossy)
  code,out,work=native.invoke_raw(wire,output_capacity=4096,workspace_capacity=336,output_fill=0xa5,workspace_fill=0x5a)
  assert code==0xfffffffe and out==b'\xa5'*4096;COUNTS['lossy_growth_capacity']=1
  search=case(3,value='a'*400,protected_args=['a'*100+'b']);wire=packet(search);want=expected(search);needed=352+4*101
  for work_size,success in [(needed-1,False),(needed,True)]:
   code,out,work=native.invoke_raw(wire,output_capacity=len(want),workspace_capacity=work_size,output_fill=0xa5,workspace_fill=0x5a)
   assert (code==len(want) and out==want) if success else (code==0xfffffffe and out==b'\xa5'*len(want))
   COUNTS['substring_capacity']=COUNTS.get('substring_capacity',0)+1
  denied=case(1,allow=0,value='/a',protected_args=['a'*100+'b']);wire=packet(denied);want=expected(denied)
  code,out,work=native.invoke_raw(wire,output_capacity=len(want),workspace_capacity=352,output_fill=0xa5,workspace_fill=0x5a)
  assert code==len(want) and out==want;COUNTS['early_denial_without_search_workspace']=1
  standalone=metadata.get('standalone');assert standalone and standalone['transport']=='filter'
  executable=args.manifest.parent/standalone['path']
  for c in [samples[0],samples[5],samples[6]]:
   proc=subprocess.run([str(executable)],input=packet(c),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/does-not-exist','LANG':'C'},timeout=10)
   assert proc.returncode==0 and proc.stderr==b'' and proc.stdout==expected(c),(c,proc.returncode,proc.stdout)
   COUNTS['standalone_elf']=COUNTS.get('standalone_elf',0)+1
 if requests:
  requests.close();outputs.close();request_file=args.corpus_dir/'requests.hex';output_file=args.corpus_dir/'native-output.txt';oracle=Path(__file__).with_name('oracle_policy.rs')
  assert oracle.read_text()==oracle_source(args.repo),'checked-in oracle differs from unchanged pinned policy bodies'
  corpus={'schema':'hepta.runtime.native-corpus.v1','component':'policy','cases':valid,'counts':COUNTS,
          'requests_file':request_file.name,'requests_sha256':hashlib.sha256(request_file.read_bytes()).hexdigest(),'requests_bytes':request_file.stat().st_size,
          'native_output_file':output_file.name,'native_output_sha256':hashlib.sha256(output_file.read_bytes()).hexdigest(),'native_output_bytes':output_file.stat().st_size,
          'source_sha256':metadata['source_sha256'],'image_sha256':metadata['image_sha256'],'oracle':'tests/hia_native/oracle_policy.rs','oracle_sha256':hashlib.sha256(oracle.read_bytes()).hexdigest(),
          'original_commit':PIN,'original_config_sha256':CONFIG_SHA,'composition_sha256':hashlib.sha256(args.source.with_name('policy_provenance.json').read_bytes()).hexdigest(),
          'rust_compile_flags':['--edition=2021','-O','-C','overflow-checks=off']}
  (args.corpus_dir/'native-corpus.json').write_text(json.dumps(corpus,indent=2,sort_keys=True)+'\n')
 if args.rust_oracle:
  data=list(cases());wire=''.join(packet(c).hex()+'\n' for _,c in data).encode()
  result_value=subprocess.run([str(args.rust_oracle)],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=60)
  actual=result_value.stdout.decode().splitlines();want=['OK '+expected(c).hex() for _,c in data]
  assert not result_value.stderr and actual==want,next(((i,a,b) for i,(a,b) in enumerate(zip(actual,want)) if a!=b),('length',len(actual),len(want)))
  COUNTS['original_rust_cases']=len(data)
 print(json.dumps({'status':'passed','valid_cases':valid,'counts':COUNTS,'elapsed_seconds':time.monotonic()-started,'source_sha256':metadata['source_sha256']},sort_keys=True))

if __name__=='__main__':main()
