"""Generate the pure full ProcessStart request binding and native SHA256."""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,json,re,stat
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def module(name,path,captured):
 import types as _types
 out=_types.ModuleType(name);out.__file__=str(path)
 exec(compile(captured,str(path),"exec"),out.__dict__);return out
def main():
 p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 s=a.source.resolve(strict=True);q=a.output.absolute()
 if q.exists():raise FileExistsError(q)
 names=['authoring/process_owner_v1/identity_author.py','authoring/process_owner_v1/identity.pseudo','authoring/process_owner_v1/validation_author.py','authoring/public_publication_v1/source_support.py','native/process_validation.hepta','native/process_validation_composition.json','native/binary_codec.hepta','native/binary_codec_composition.json','src/mcp/runtime/jobs.rs']
 def take(n):
  path=s/n;st=path.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or path.resolve()!=path:raise ValueError(n)
  raw=path.read_bytes()
  after=path.lstat()
  fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  if any(getattr(after,k)!=getattr(st,k) for k in fields):raise ValueError('changed '+n)
  return raw
 before={n:take(n) for n in names}
 support=module('_process_identity_support',s/names[3],before[names[3]]);tables=module('_process_identity_tables',s/names[2],before[names[2]]).tables
 api=support.tools(a.hepta);assemble,render=api[3:]
 vmeta=json.loads(before[names[5]]);vraw=before[names[4]]
 assert SHA(vraw)==vmeta['source_sha256'] and len(vraw)==vmeta['source_bytes']
 assert SHA(before[names[6]])==json.loads(before[names[7]])['composed_source_sha256']
 vnames=['checked_typed','load','get','put','field','field_size','field_value','present','decode','string_info','vbyte']
 inputs=[(names[4],vraw,{n:vmeta['aliases'][n] for n in vnames}),
         (names[6],before[names[6]],{'sha_init':'f17','sha_block':'f19'})]
 combined=[];roots={};relations=[]
 for path,raw,imports in inputs:
  doc=assemble(raw).as_dict();old={f['name']:f for f in doc['functions']};closed=set();queue=list(imports.values())
  while queue:
   name=queue.pop()
   if name in closed:continue
   closed.add(name);queue += [op['attrs']['function'] for b in old[name]['blocks'] for op in b['ops'] if op['op']=='call']
  ordered=sorted(closed,key=lambda n:int(n[1:]));mapping={n:'f'+str(len(combined)+i) for i,n in enumerate(ordered)}
  proof={}
  for name in ordered:
   fn=copy.deepcopy(old[name]);fn['name']=mapping[name]
   for block in fn['blocks']:
    for op in block['ops']:
     if op['op']=='call':op['attrs']['function']=mapping[op['attrs']['function']]
   combined.append(fn);proof[name]={'to':mapping[name],'ast_sha256':SHA(support.CANON(old[name]))}
  roots.update({alias:mapping[name] for alias,name in imports.items()})
  relations.append({'path':path,'bytes':len(raw),'sha256':SHA(raw),'whole_function_renames':proof})
 union=render({'schema':doc['schema'],'module':'runtime_process_identity_imports','functions':combined}).encode()
 struct=before['src/mcp/runtime/jobs.rs'].decode().split("struct RequestBinding<'a> {",1)[1].split('\n}',1)[0]
 keys=re.findall(r'^\s*([a-z_]+):',struct,re.M)
 assert keys==['args','cpu_quota_percent','cwd','env','executable','host','memory_max_bytes','nice','stdin','timeout_seconds']
 values={i+1:('{' if i==0 else ',')+json.dumps(k)+':' for i,k in enumerate(keys)};values[11]='null'
 pseudo=before[names[1]].decode()+'\n'+tables(values)
 W=lambda x:int.from_bytes(x.encode(),'little')
 constants={'REQUEST':W('HPRIDQ01'),'RESPONSE':W('HPRIDR01'),'INVALID':0xffffffff,'CAPACITY':0xfffffffe,'MAXIMUM':2**64-1}
 raw,aliases,proof=support.compile_new(api,union,roots,pseudo,constants,'runtime_process_identity')
 assert all(take(n)==b for n,b in before.items())
 q.mkdir()
 result={'schema':'hepta.runtime.process-identity.v1',**proof,'aliases':aliases,'constants':constants,'source_bytes':len(raw),'source_sha256':SHA(raw),'original_binding_fields':keys,'input_files':{n:{'bytes':len(b),'sha256':SHA(b)} for n,b in before.items()},'imports':relations,'typed_record_must_come_from_captured_params':True,'canonical_map_sorted_unique':True,'native_compiled':False,'public_handler_qualified':False}
 (q/'process_identity.hepta').write_bytes(raw);(q/'process_identity_composition.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
 (q/'process_identity.pseudo').write_text(pseudo);(q/'imports.hepta').write_bytes(union)
 assert all(take(n)==b for n,b in before.items())
 print(json.dumps({k:result[k] for k in ['source_bytes','source_sha256','functions','blocks','operations']}))
if __name__=='__main__':main()
