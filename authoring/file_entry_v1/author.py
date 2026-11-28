"""Author a closed pure-HIA self-pinned remote file entry; no runtime Python."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,stat,struct,subprocess
ROOT=Path(__file__).resolve().parents[2]
SHA=lambda b:hashlib.sha256(b).hexdigest()
WORD=lambda s:int.from_bytes(s.encode(),'little')
def literal(name,text,match=False):
 b=text.encode();kind='readbuf' if match else 'mutbuf'
 lines=[f'def {name}(s: {kind}, at: u64) -> '+('bool:' if match else 'u64:')]
 for i,v in enumerate(b):
  if match: lines += [f'    if byte(s, at + {i}) != {v}:','        return False']
  else:lines.append(f'    store(s, at + {i}, {v})')
 lines.append('    return True' if match else f'    return at + {len(b)}')
 return '\n'.join(lines)+'\n'
def elf_text(raw):
 if raw[:6]!=b'\x7fELF\x02\x01':raise ValueError('author object is not little-endian ELF64')
 off=struct.unpack_from('<Q',raw,40)[0]
 ent,num,names=struct.unpack_from('<HHH',raw,58)
 if ent!=64:raise ValueError('unexpected section layout')
 sections=[struct.unpack_from('<IIQQQQIIQQ',raw,off+i*ent) for i in range(num)]
 ns=sections[names];strings=raw[ns[4]:ns[4]+ns[5]]
 name=lambda at:strings[at:strings.index(0,at)].decode()
 indexed={name(s[0]):(i,s) for i,s in enumerate(sections)}
 ti,t=indexed['.text'];body=bytearray(raw[t[4]:t[4]+t[5]])
 si,sym=indexed['.symtab'];string=sections[sym[6]];symstrings=raw[string[4]:string[4]+string[5]]
 symbols=[]
 for pos in range(sym[4],sym[4]+sym[5],sym[9]):
  nm,info,other,shndx,value,size=struct.unpack_from('<IBBHQQ',raw,pos)
  text=symstrings[nm:symstrings.index(0,nm)].decode()
  symbols.append((text,shndx,value,size))
 rels=[]
 for section in sections:
  if section[1]!=4 or section[7]!=ti:continue
  if section[6]!=si or section[9]!=24:raise ValueError('relocation ownership differs')
  for pos in range(section[4],section[4]+section[5],24):
   target,info,addend=struct.unpack_from('<QQq',raw,pos);index=info>>32;kind=info&0xffffffff
   nm,shndx,value,size=symbols[index]
   if kind!=2 or shndx!=ti or target+4>len(body):raise ValueError('non-local PC-relative author relocation')
   result=value+addend-target
   struct.pack_into('<i',body,target,result)
   rels.append({'offset':target,'symbol':nm,'addend':addend,'value':result,'kind':'R_X86_64_PC32'})
 holes={name:value for name,shndx,value,size in symbols if name in ('entry_policy_call_hole','entry_image_size_hole') and shndx==ti}
 if set(holes)!=set(('entry_policy_call_hole','entry_image_size_hole')):raise ValueError('entry adapter holes differ')
 for name,width in [('entry_policy_call_hole',4),('entry_image_size_hole',8)]:
  at=holes[name]
  if body[at:at+width]!=bytes(width):raise ValueError('adapter hole is not empty')
 return bytes(body),holes,rels
def header():
 return (b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x400000+176,64,0,0,64,56,2,0,0,0)
  +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
  +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
def table(raw):
 values=[int.from_bytes(raw[i:i+8].ljust(8,b'\0'),'little') for i in range(0,len(raw),8)]
 parts=[];groups=(len(values)+31)//32
 for group in range(groups):
  lines=[f'def template_{group}(index: u64) -> u64:']
  for i in range(group*32,min((group+1)*32,len(values))):
   lines.extend([f'    if index == {i}:',f'        return {values[i]}'])
  lines.append('    return 0');parts.append('\n'.join(lines))
 lines=['def template_word(index: u64) -> u64:']
 for group in range(groups):lines.extend([f'    if index < {(group+1)*32}:',f'        return template_{group}(index)'])
 lines.append('    return 0');parts.append('\n'.join(lines))
 return '\n\n'.join(parts)+'\n'
def main():
 p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 names=['authoring/file_entry_v1/author.py','authoring/file_entry_v1/guard.pseudo','authoring/file_entry_v1/packer.pseudo','scripts/file_entry_guard.S','authoring/public_publication_v1/source_support.py','native/binary_codec.hepta','native/binary_codec_composition.json','scripts/hia_native_composition_build.py','native/composition_packer.hepta','native/local_read_composition.json']
 def read(name):
  path=ROOT/name
  if path.resolve(strict=True)!=path or not stat.S_ISREG(path.lstat().st_mode):raise ValueError('nonphysical input: '+name)
  return path.read_bytes()
 captures={n:read(n) for n in names}
 meta=json.loads(captures['native/binary_codec_composition.json'])
 if meta['composed_source_sha256']!=SHA(captures['native/binary_codec.hepta']):raise ValueError('codec source binding differs')
 a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
 cmd=['/usr/bin/clang','-target','x86_64-unknown-linux-gnu','-c',str(ROOT/'scripts/file_entry_guard.S'),'-o',str(a.output/'adapter.o')]
 done=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 (a.output/'clang.stdout').write_bytes(done.stdout);(a.output/'clang.stderr').write_bytes(done.stderr)
 (a.output/'clang.json').write_text(json.dumps({'argv':cmd,'returncode':done.returncode},indent=2)+'\n')
 done.check_returncode()
 adapter,holes,rels=elf_text((a.output/'adapter.o').read_bytes())
 (a.output/'adapter.bin').write_bytes(adapter)
 template=header()+adapter
 (a.output/'template.bin').write_bytes(template)
 spec=importlib.util.spec_from_file_location('_file_entry_pinned_source_support',ROOT/'authoring/public_publication_v1/source_support.py')
 support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support);api=support.tools(a.hepta)
 common={'load':'f13','get':'f21','put':'f22'}
 pseudo=captures['authoring/file_entry_v1/guard.pseudo'].decode()+'\n'
 pseudo+=literal('pin_option','--pin',True)+'\n'+literal('root_option','--local-read-profile',True)+'\n'
 pseudo+=literal('child_name','native-local-read.elf\0')+'\n'+literal('child_flag','--local-read-profile\0')+'\n'
 aliases=dict(common,sha_constants='f17',sha_initial='f18',sha_update='f9',sha_finish='f10')
 guard,ga,gp=support.compile_new(api,captures['native/binary_codec.hepta'],aliases,pseudo,{'FOOTER':WORD('HFBENF01')},'runtime_file_entry_guard')
 pp=captures['authoring/file_entry_v1/packer.pseudo'].decode()+'\n'+table(template)
 constants={'MAGIC':WORD('HFBEPK01'),'FOOTER':WORD('HFBENF01'),'TEMPLATE_BYTES':len(template),'CALL_HOLE':176+holes['entry_policy_call_hole'],'SIZE_HOLE':176+holes['entry_image_size_hole']}
 packer,pa,mp=support.compile_new(api,captures['native/binary_codec.hepta'],common,pp,constants,'runtime_file_entry_packer')
 proof={'schema':'hepta.runtime.file-entry-author.v1','compiler_author_commit':'d3e2c90173cf733e42b299d0c4274df4b593a12f','inputs':{n:{'bytes':len(b),'sha256':SHA(b)} for n,b in captures.items()},'adapter':{'bytes':len(adapter),'sha256':SHA(adapter),'object_sha256':SHA((a.output/'adapter.o').read_bytes()),'holes':holes,'local_relocations':rels},'template':{'bytes':len(template),'sha256':SHA(template)},'guard':dict(gp,aliases=ga),'packer':dict(mp,aliases=pa,constants=constants),'native_built':False,'remote_qualified':False,'public_qualified':False}
 for n,b in captures.items():
  if read(n)!=b:raise ValueError('author input changed: '+n)
 for stem,raw,metadata in [('file_entry_guard',guard,proof['guard']),('file_entry_packer',packer,proof['packer'])]:
  path=ROOT/'native'/(stem+'.hepta');mpath=path.with_name(stem+'_composition.json')
  if path.exists() or mpath.exists():raise FileExistsError(path)
  path.write_bytes(raw);mpath.write_text(json.dumps({'schema':'hepta.runtime.'+stem+'.v1','source_bytes':len(raw),'source_sha256':SHA(raw),'inputs':proof['inputs'],**metadata},sort_keys=True,indent=2)+'\n')
 (a.output/'source-author.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
 for n,b in captures.items():
  if read(n)!=b:raise ValueError('author terminal input changed: '+n)
 print(json.dumps({'adapter_bytes':len(adapter),'guard':gp['source'],'guard_functions':gp['functions'],'guard_operations':gp['operations'],'packer':mp['source'],'packer_functions':mp['functions'],'packer_operations':mp['operations']}))
if __name__=='__main__':main()
