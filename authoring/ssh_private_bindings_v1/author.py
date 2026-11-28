"""Emit the two fixed private SSH mechanics from HIA, with full source/code pins."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,stat,struct
ROOT=Path(__file__).resolve().parents[2]
SHA=lambda b:hashlib.sha256(b).hexdigest()
SELF=Path(__file__).read_bytes()
SPECS=[
 dict(role='ssh_registry_engine_packer',source='scripts/ssh_direct_registry_engine.S',source_sha256='c80144e7959c9a2097d580f7c17dc64d2bdd1aca6bf179a9cb3a56e2b1d7ecaf',bytes=1480,sha256='16583f15fcbc628da27874d1ffda88ec3604202c24b13e2f724ffd9bd8a720f4',request='HSSGEQ01',result='HSSGEP01',exports={'create':0,'invoke':5,'destroy':10},tail=[0]),
 dict(role='ssh_file_binding_packer',source='scripts/ssh_file_binding_engine.S',source_sha256='502abee75b76213cc22e5f36a90a2169b21814748d0dd3899ba60b45b263f35a',bytes=2734,sha256='cd379b3c83718963c2f55ff5eeb443f5cae02ad7e4077752157519fd960d402c',request='HSSBEQ01',result='HSSBEP01',exports={'create':0,'step':5,'notify':10,'rebind':15,'finish':20,'destroy':25},tail=[])]
def main():
 p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);a=p.parse_args()
 names=['authoring/ssh_private_bindings_v1/author.py','authoring/ssh_private_bindings_v1/code.json','authoring/public_publication_v1/source_support.py','native/binary_codec.hepta','native/binary_codec_composition.json']+[x['source']for x in SPECS]
 def take(n):
  p=ROOT/n;st=p.lstat();assert p.resolve(strict=True)==p and stat.S_ISREG(st.st_mode)and st.st_nlink==1,n
  return p.read_bytes(),stat.S_IMODE(st.st_mode)
 captures={n:take(n)for n in names};assert captures[names[0]][0]==SELF
 records=json.loads(captures[names[1]][0]);assert set(records)=={x['role']for x in SPECS}
 meta=json.loads(captures[names[4]][0]);assert SHA(captures[names[3]][0])==meta['composed_source_sha256']
 spec=importlib.util.spec_from_file_location('_ssh_private_emitter_support',ROOT/names[2]);support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support);api=support.tools(a.hepta)
 results=[]
 for row in SPECS:
  data=records[row['role']];code=bytes.fromhex(data['flat_hex'])
  assert SHA(captures[row['source']][0])==row['source_sha256']
  assert len(code)==row['bytes']==data['flat_bytes'] and SHA(code)==row['sha256']==data['flat_sha256']
  assert data['source_path']==row['source']and data['source_sha256']==row['source_sha256'] and data['exports']==row['exports']
  assert all(type(v)is int and code[v]==0xe9 for v in data['exports'].values())
  fields=[1,len(code),len(row['exports']),*row['exports'].values(),*row['tail']]
  expected=row['result'].encode()+struct.pack('<'+'Q'*len(fields),*fields)+code
  parts=[]
  for start in range(0,len(expected),512):
   end=min(start+512,len(expected));at=start;lines=['def part_'+str(len(parts))+'(o: mutbuf) -> u64:']
   while at+8<=end:lines.append('    put(o, '+str(at)+', '+str(int.from_bytes(expected[at:at+8],'little'))+')');at+=8
   while at<end:lines.append('    store(o, '+str(at)+', '+str(expected[at])+')');at+=1
   lines.append('    return 0');parts.append('\n'.join(lines))
  pseudo='def entry(s: readbuf, o: mutbuf, w: mutbuf) -> u32:\n    if length(s) != 24:\n        return 4294967295\n'
  pseudo+='    if load(s, 0) != '+str(int.from_bytes(row['request'].encode(),'little'))+' or load(s, 8) != 1 or load(s, 16) != 0:\n        return 4294967295\n'
  pseudo+='    if length(o) < '+str(len(expected))+':\n        return 4294967294\n'
  for i in range(len(parts)):pseudo+='    part_'+str(i)+'(o)\n'
  pseudo+='    return '+str(len(expected))+'\n\n'+'\n\n'.join(parts)+'\n'
  raw,mapping,proof=support.compile_new(api,captures[names[3]][0],dict(load='f13',put='f22'),pseudo,{},'runtime_'+row['role'])
  for n,v in captures.items():assert take(n)==v,n
  proof.update(schema='hepta.runtime.private-ssh-emitter.v1',source_bytes=len(raw),source_sha256=SHA(raw),aliases=mapping,exports=row['exports'],engine_source_path=row['source'],engine_source_sha256=row['source_sha256'],expected_flat_bytes=len(code),expected_flat_sha256=SHA(code),expected_output_bytes=len(expected),expected_output_sha256=SHA(expected),request_hex=(row['request'].encode()+struct.pack('<QQ',1,0)).hex(),input_files={n:dict(bytes=len(b),sha256=SHA(b),mode=mode)for n,(b,mode)in captures.items()},installed_assembler_required=False,private_only=True,public_qualified=False)
  paths=[ROOT/'native'/(row['role']+'.hepta'),ROOT/'native'/(row['role']+'_composition.json'),ROOT/'authoring/ssh_private_bindings_v1'/(row['role']+'.pseudo')]
  assert all(not p.exists()for p in paths)
  paths[0].write_bytes(raw);paths[1].write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n');paths[2].write_text(pseudo)
  results.append({k:proof[k]for k in('source_bytes','source_sha256','functions','blocks','operations','expected_flat_sha256','expected_output_sha256')})
 for n,v in captures.items():assert take(n)==v,n
 print(json.dumps(results,sort_keys=True),flush=True)
if __name__=='__main__':main()
