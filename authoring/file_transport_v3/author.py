"""Generate the fixed native file SSH plan. Python is authoring only."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,stat
ROOT=Path(__file__).resolve().parents[2]
SHA=lambda b:hashlib.sha256(b).hexdigest()
WORD=lambda s:int.from_bytes(s.encode(),'little')
def literal(name,text):
 b=text.encode()
 lines=[f'def {name}(o: mutbuf, at: u64) -> u64:']
 for i,v in enumerate(b):lines.append(f'    store(o, at + {i}, {v})')
 lines.append(f'    return at + {len(b)}')
 return '\n'.join(lines)+'\n'
def main():
 a=argparse.ArgumentParser();a.add_argument('--hepta',type=Path,required=True);a=a.parse_args()
 names=['authoring/file_transport_v3/author.py','authoring/file_transport_v3/policy.pseudo','authoring/public_publication_v1/source_support.py','native/binary_call_plan.hepta','native/binary_call_plan_composition.json','native/config_transport_files_owner_span.hepta','native/config_transport_files_owner_span_composition.json','src/mcp/runtime/ssh.rs','src/mcp/runtime/binary.rs']
 def read(n):
  p=ROOT/n
  assert p.resolve(strict=True)==p and stat.S_ISREG(p.lstat().st_mode),n
  return p.read_bytes()
 captured={n:read(n) for n in names}
 spec=importlib.util.spec_from_file_location('_native_file_transport_source_support',ROOT/'authoring/public_publication_v1/source_support.py')
 support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support);api=support.tools(a.hepta)
 meta=json.loads(captured['native/binary_call_plan_composition.json'])
 assert SHA(captured['native/binary_call_plan.hepta'])==meta['source_sha256']
 argv=['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no']
 pseudo=captured['authoring/file_transport_v3/policy.pseudo'].decode()+'\n'
 for i,v in enumerate(argv):pseudo+=literal('arg_'+str(i),v)+'\n'
 prefix='native file transport is not configured for host '+chr(96)
 error='observation_pool_payload_unsupported: queued command and stdin exceed64KiB; no fallback'
 for name,text in [('pin_flag',' --pin '),('root_flag',' --local-read-profile '),('missing_prefix',prefix),('pool_error_text',error)]:pseudo+=literal(name,text)+'\n'
 pseudo+='def missing_prefix_size() -> u64:\n    return '+str(len(prefix))+'\n\n'
 pseudo+='def pool_error_size() -> u64:\n    return '+str(len(error))+'\n\n'
 pseudo+='def fixed_extent() -> u64:\n    return '+str(sum(8+len(x) for x in argv))+'\n\n'
 pseudo+='def fixed_argv(o: mutbuf, at: u64) -> u64:\n'
 for i,v in enumerate(argv):pseudo+=f'    put(o, at, {len(v)})\n    at = arg_{i}(o, at + 8)\n'
 pseudo+='    return at\n\n'
 pseudo+='def basename(s: readbuf, at: u64) -> bool:\n'
 for i,b in enumerate(b'hia-file-entry'):pseudo+=f'    if byte(s, at + {i}) != {b}:\n        return False\n'
 pseudo+='    return True\n'
 literals={
 'mcp_initialize':'{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"hia-runtime-native-file","version":"1"}}}\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
 'mcp_info':'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"file_info","arguments":{"host":"native-local","path":',
 'mcp_read':'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"binary_read","arguments":{"host":"native-local","path":',
 'mcp_offset':',"offset":','mcp_limit':',"limit":','mcp_expected':',"expected_version":','mcp_null':'null','mcp_end':'}}}\n'}
 for name,text in literals.items():
  bs=text.encode();lines=[f'def {name}(o: mutbuf, at: u64, write: bool) -> u64:','    if write:']
  for i,v in enumerate(bs):lines.append(f'        store(o, at + {i}, {v})')
  lines.append(f'    return at + {len(bs)}')
  pseudo+='\n'.join(lines)+'\n\n'
 constants={k:WORD(v) for k,v in {'REQUEST':'HFBTRQ03','RESULT':'HFBSHP03','CONFIG':'HRCFGM01','HOST':'HRCFTR01','FILES':'HRCFFL01','PLAN':'HBPLR001','GROW_TAG':'HGRWS002'}.items()}
 constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,GROW=0xffffffd0,LIMIT=0xffff0000)
 aliases={n:meta['aliases'][n] for n in ('load','get','put','utf8','valid_typed')}
 raw,mapping,proof=support.compile_new(api,captured['native/binary_call_plan.hepta'],aliases,pseudo,constants,'runtime_native_file_transport_policy')
 for n,b in captured.items():assert read(n)==b,n
 proof.update(schema='hepta.runtime.native-file-ssh-policy.v3',source_bytes=len(raw),source_sha256=SHA(raw),aliases=mapping,constants=constants,input_files={n:{'bytes':len(b),'sha256':SHA(b)} for n,b in captured.items()},fixed_argv=argv,capture_limit=8388608,timeout_ms=30000,native_compiled=False,native_executed=False,ssh_executed=False,public_qualified=False)
 out=ROOT/'native/file_transport_policy_v3.hepta';mp=out.with_name('file_transport_policy_v3_composition.json')
 assert not out.exists() and not mp.exists()
 out.write_bytes(raw);mp.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
 for n,b in captured.items():assert read(n)==b,n
 print(json.dumps({k:proof[k] for k in ('source_bytes','source_sha256','functions','blocks','operations')}),flush=True)
if __name__=='__main__':main()
