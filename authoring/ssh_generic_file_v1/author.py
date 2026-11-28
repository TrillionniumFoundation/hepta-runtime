"""Pure HIA file-plan framing for the qualified process-owned generic SSH graph."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,stat,ast
ROOT=Path(__file__).resolve().parents[2]
SHA=lambda b:hashlib.sha256(b).hexdigest()
WORD=lambda b:int.from_bytes(b.encode(),'little')
def main():
 p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);a=p.parse_args()
 names=['authoring/ssh_generic_file_v1/author.py','authoring/ssh_generic_file_v1/adapter.pseudo','authoring/public_publication_v1/source_support.py','authoring/ssh_direct_owner_v1/author.py','authoring/ssh_direct_owner_v1/owner.pseudo','native/binary_codec.hepta','native/binary_codec_composition.json','native/file_transport_policy_v3.hepta','native/file_transport_policy_v3_composition.json','native/ssh_generic_owner_abi.md']
 def read(n):
  p=ROOT/n;st=p.lstat();assert p.resolve(strict=True)==p and stat.S_ISREG(st.st_mode) and st.st_nlink==1
  return p.read_bytes()
 captured={n:read(n) for n in names}
 spec=importlib.util.spec_from_file_location('_ssh_generic_source_support',ROOT/'authoring/public_publication_v1/source_support.py')
 support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support);api=support.tools(a.hepta)
 meta=json.loads(captured['native/binary_codec_composition.json']);assert SHA(captured['native/binary_codec.hepta'])==meta['composed_source_sha256']
 aliases={'load':'f13','put':'f22'}
 constants={k:WORD(v) for k,v in {'COMMAND_REQUEST':'HSGCMD01','COMMAND_RESULT':'HSGCMR01','COMMAND':'HSDCMD01','RESULT_REQUEST':'HSGRSP01','RESULT':'HSSHRR01','PLAN':'HFBSHP03','GROW_TAG':'HGRWS002'}.items()}
 constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,GROW=0xffffffd0,LIMIT=0xfffeffff,MAXIMUM=(1<<64)-1)
 fixed=json.loads(captured['native/file_transport_policy_v3_composition.json'])['fixed_argv']
 assert fixed==['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no']
 pseudo=captured['authoring/ssh_generic_file_v1/adapter.pseudo'].decode()+'\ndef fixed_argument(s: readbuf, at: u64, size: u64, index: u64) -> bool:\n'
 for i,arg in enumerate(fixed):
  b=arg.encode();pseudo+=f'    if index == {i}:\n        if size != {len(b)}:\n            return False\n'
  for j,v in enumerate(b):pseudo+=f'        if byte(s, at + {j}) != {v}:\n            return False\n'
  pseudo+='        return True\n'
 pseudo+='    return False\n'
 raw,mapping,proof=support.compile_new(api,captured['native/binary_codec.hepta'],aliases,pseudo,constants,'runtime_generic_ssh_file_framing')
 for n,b in captured.items():assert read(n)==b,n
 proof.update(schema='hepta.runtime.generic-ssh-file-framing.v1',source_bytes=len(raw),source_sha256=SHA(raw),aliases=mapping,constants=constants,input_files={n:{'bytes':len(b),'sha256':SHA(b)}for n,b in captured.items()},fixed_argv=fixed,private_sealed_program=True,environment_captured_from_actual_kernel_envp=True,native_executed=False,public_qualified=False)
 out=ROOT/'native/ssh_generic_file_adapter.hepta';mp=out.with_name('ssh_generic_file_adapter_composition.json')
 assert not out.exists() and not mp.exists();out.write_bytes(raw);mp.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
 for n,b in captured.items():assert read(n)==b,n
 print(json.dumps({k:proof[k]for k in ('source_bytes','source_sha256','functions','blocks','operations')}),flush=True)
if __name__=='__main__':main()
