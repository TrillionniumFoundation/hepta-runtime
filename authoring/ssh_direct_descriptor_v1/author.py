"""Emit the fixed direct-SSH syscall boundary from HIA; assembler is QA only."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,stat,struct
ROOT=Path(__file__).resolve().parents[2]
SHA=lambda b:hashlib.sha256(b).hexdigest()
SELF=Path(__file__).read_bytes()
ENGINE='518f76f357319333adf1c00b12f2b7f82e84d96d28d0db21f5f09950cc2a9ab9'
FLAT='5501ceeed786e8bc8b4fd581b6a8a1d378e1d879b102d3c69e86a27d278298e5'
def main():
 p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);a=p.parse_args()
 names=['authoring/ssh_direct_descriptor_v1/author.py','authoring/ssh_direct_descriptor_v1/code.json','scripts/ssh_direct_descriptor_engine.S','authoring/public_publication_v1/source_support.py','native/binary_codec.hepta','native/binary_codec_composition.json']
 def take(n):
  p=ROOT/n;st=p.lstat();assert p.resolve(strict=True)==p and stat.S_ISREG(st.st_mode) and st.st_nlink==1,n
  return p.read_bytes(),stat.S_IMODE(st.st_mode)
 captures={n:take(n) for n in names}
 assert captures[names[0]][0]==SELF and SHA(captures[names[2]][0])==ENGINE
 record=json.loads(captures[names[1]][0]);code=bytes.fromhex(record['flat_hex'])
 entries={'create':0,'step':5,'child_ack':10,'notify':15,'rebind':20,'destroy':25}
 assert type(record['flat_bytes']) is int and len(code)==record['flat_bytes']==5151 and SHA(code)==record['flat_sha256']==FLAT
 assert record['source_path']=='scripts/ssh_direct_descriptor_engine.S' and record['source_sha256']==ENGINE
 assert record['exports']==entries and all(type(v)is int for v in record['exports'].values())
 assert all(code[offset]==0xe9 for offset in entries.values())
 output=b'HSSHEP01'+struct.pack('<9Q',1,len(code),len(entries),*entries.values())+code
 assert len(output)==5231
 parts=[]
 for start in range(0,len(output),512):
  end=min(start+512,len(output));at=start;lines=['def part_'+str(len(parts))+'(o: mutbuf) -> u64:']
  while at+8<=end:
   lines.append('    put(o, '+str(at)+', '+str(int.from_bytes(output[at:at+8],'little'))+')');at+=8
  while at<end:
   lines.append('    store(o, '+str(at)+', '+str(output[at])+')');at+=1
  lines.append('    return 0');parts.append('\n'.join(lines))
 entry='def entry(s: readbuf, o: mutbuf, w: mutbuf) -> u32:\n    if length(s) != 24:\n        return 4294967295\n'
 entry+='    if load(s, 0) != '+str(int.from_bytes(b'HSSHEQ01','little'))+' or load(s, 8) != 1 or load(s, 16) != 0:\n        return 4294967295\n'
 entry+='    if length(o) < 5231:\n        return 4294967294\n'
 for i in range(len(parts)):entry+='    part_'+str(i)+'(o)\n'
 entry+='    return 5231\n'
 pseudo=entry+'\n\n'+'\n\n'.join(parts)+'\n'
 spec=importlib.util.spec_from_file_location('_ssh_descriptor_source_support',ROOT/names[3]);support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
 api=support.tools(a.hepta)
 meta=json.loads(captures[names[5]][0]);assert SHA(captures[names[4]][0])==meta['composed_source_sha256']
 raw,mapping,proof=support.compile_new(api,captures[names[4]][0],{'load':'f13','put':'f22'},pseudo,{},'runtime_direct_ssh_descriptor_packer')
 for n,row in captures.items():assert take(n)==row,n
 proof.update(schema='hepta.runtime.direct-ssh-descriptor-packer.v1',source_bytes=len(raw),source_sha256=SHA(raw),aliases=mapping,exports=entries,engine_source_sha256=ENGINE,expected_flat_sha256=FLAT,expected_flat_bytes=len(code),expected_output_sha256=SHA(output),expected_output_bytes=len(output),request_hex=(b'HSSHEQ01'+struct.pack('<QQ',1,0)).hex(),input_files={n:{'bytes':len(b),'sha256':SHA(b),'mode':mode}for n,(b,mode)in captures.items()},installed_assembler_required=False,private_only=True,native_executed=False,public_qualified=False)
 out=ROOT/'native/ssh_direct_descriptor_packer.hepta';mp=out.with_name('ssh_direct_descriptor_packer_composition.json');ps=ROOT/'authoring/ssh_direct_descriptor_v1/generated.pseudo'
 assert not out.exists() and not mp.exists() and not ps.exists()
 out.write_bytes(raw);mp.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n');ps.write_text(pseudo)
 for n,row in captures.items():assert take(n)==row,n
 print(json.dumps({k:proof[k]for k in ('source_bytes','source_sha256','functions','blocks','operations','expected_output_sha256')}),flush=True)
if __name__=='__main__':main()
