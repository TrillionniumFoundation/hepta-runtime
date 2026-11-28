"""Generate the private exact-envelope native file SSH response decoder."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,stat
ROOT=Path(__file__).resolve().parents[2]
SHA=lambda b:hashlib.sha256(b).hexdigest()
WORD=lambda b:int.from_bytes(b.encode(),'little')
def matcher(name,value):
 lines=[f'def {name}(s: readbuf, at: u64, end: u64) -> u64:',f'    if at > end or {len(value)} > end - at:','        return 0']
 words=len(value)//8
 for i in range(words):
  word=int.from_bytes(value[i*8:i*8+8],'little')
  lines.extend([f'    if load(s, at + {i*8}) != {word}:','        return 0'])
 for i in range(words*8,len(value)):
  lines.extend([f'    if byte(s, at + {i}) != {value[i]}:','        return 0'])
 lines.append(f'    return at + {len(value)}')
 return '\n'.join(lines)+'\n'
def main():
 a=argparse.ArgumentParser();a.add_argument('--hepta',type=Path,required=True);a=a.parse_args()
 names=['authoring/file_transport_result_v1/author.py','authoring/file_transport_result_v1/result.pseudo','authoring/public_publication_v1/source_support.py','native/binary_read_params.hepta','native/binary_read_params_composition.json','native/local_service.hepta','native/local_service_composition.json','src/mcp/runtime/ssh.rs','src/mcp/runtime/binary.rs']
 def read(n):
  p=ROOT/n;assert p.resolve(strict=True)==p and stat.S_ISREG(p.lstat().st_mode);return p.read_bytes()
 captured={n:read(n) for n in names}
 spec=importlib.util.spec_from_file_location('_file_response_source_support',ROOT/'authoring/public_publication_v1/source_support.py')
 support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support);api=support.tools(a.hepta)
 meta=json.loads(captured['native/binary_read_params_composition.json']);assert SHA(captured['native/binary_read_params.hepta'])==meta['source_sha256']
 pseudo=captured['authoring/file_transport_result_v1/result.pseudo'].decode()+'\n'
 literals={
 'initialized':b'{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"hepta-runtime-hia-local-read","version":"0.1.0"}}}\n',
 'result_prefix':b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":',
 'success_suffix':b'}],"isError":false}}\n',
 'error_suffix':b'}],"isError":true}}\n'}
 for name,value in literals.items():pseudo+=matcher(name,value)+'\n'
 constants={k:WORD(v) for k,v in {'REQUEST':'HFBRSQ01','RESULT':'HFBRRS01','GROW_TAG':'HGRWS002'}.items()}
 constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,GROW=0xffffffd0,MAXIMUM=(1<<64)-1,LIMIT=0xffff0000)
 aliases={n:meta['aliases'][n] for n in ('load','get','put','string_info','copy_string')}
 raw,mapping,proof=support.compile_new(api,captured['native/binary_read_params.hepta'],aliases,pseudo,constants,'runtime_native_file_transport_result')
 for n,b in captured.items():assert read(n)==b,n
 proof.update(schema='hepta.runtime.native-file-transport-result.v1',source_bytes=len(raw),source_sha256=SHA(raw),aliases=mapping,constants=constants,input_files={n:{'bytes':len(b),'sha256':SHA(b)} for n,b in captured.items()},private_only=True,result_schema='HFBRRS01',original_ssh_error_formatting=False,native_compiled=False,native_executed=False,public_qualified=False)
 out=ROOT/'native/file_transport_result.hepta';mp=out.with_name('file_transport_result_composition.json')
 assert not out.exists() and not mp.exists();out.write_bytes(raw);mp.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
 for n,b in captured.items():assert read(n)==b,n
 print(json.dumps({k:proof[k] for k in ('source_bytes','source_sha256','functions','blocks','operations')}),flush=True)
if __name__=='__main__':main()
