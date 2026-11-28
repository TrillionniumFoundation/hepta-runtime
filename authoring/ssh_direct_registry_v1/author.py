"""Author process-owned direct-SSH admission; private typed state, no runtime Python."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,stat
ROOT=Path(__file__).resolve().parents[2]
SHA=lambda b:hashlib.sha256(b).hexdigest()
SELF=Path(__file__).read_bytes()
def main():
 p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);a=p.parse_args()
 names=['authoring/ssh_direct_registry_v1/author.py','authoring/ssh_direct_registry_v1/registry.pseudo','authoring/public_publication_v1/source_support.py','native/binary_codec.hepta','native/binary_codec_composition.json','src/mcp/runtime/ssh_direct.rs','src/mcp/runtime/ssh_direct_tests.rs','src/mcp/runtime/ssh_direct_entry_tests.rs']
 def take(n):
  p=ROOT/n;st=p.lstat();assert p.resolve(strict=True)==p and stat.S_ISREG(st.st_mode) and st.st_nlink==1,n
  return p.read_bytes(),stat.S_IMODE(st.st_mode)
 captures={n:take(n)for n in names};assert captures[names[0]][0]==SELF
 spec=importlib.util.spec_from_file_location('_ssh_registry_support',ROOT/names[2]);support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
 api=support.tools(a.hepta)
 meta=json.loads(captures[names[4]][0]);assert SHA(captures[names[3]][0])==meta['composed_source_sha256']
 constants={k:int.from_bytes(v.encode(),'little')for k,v in dict(REQUEST='HSSGRQ01',RESULT='HSSGRR01',STATE='HSSGST01',GROW_TAG='HGRWS002').items()}
 constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,GROW=0xffffffd0,MAXIMUM=(1<<64)-1)
 raw,mapping,proof=support.compile_new(api,captures[names[3]][0],dict(load='f13',get='f21',put='f22'),captures[names[1]][0].decode(),constants,'runtime_direct_ssh_registry')
 for n,row in captures.items():assert take(n)==row,n
 proof.update(schema='hepta.runtime.direct-ssh-registry.v1',source_bytes=len(raw),source_sha256=SHA(raw),aliases=mapping,constants=constants,input_files={n:dict(bytes=len(b),sha256=SHA(b),mode=mode)for n,(b,mode)in captures.items()},process_global=True,queue_cap=None,per_target_cap=None,private_only=True,native_executed=False,original_nineteen_methods_passed=False,public_qualified=False)
 out=ROOT/'native/ssh_direct_registry.hepta';mp=out.with_name('ssh_direct_registry_composition.json')
 assert not out.exists()and not mp.exists();out.write_bytes(raw);mp.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
 for n,row in captures.items():assert take(n)==row,n
 print(json.dumps({k:proof[k]for k in ('source_bytes','source_sha256','functions','blocks','operations')}),flush=True)
if __name__=='__main__':main()
