"""Reproduce the public118 mixed-opener and actual catalog-presence successor."""
from pathlib import Path
import hashlib,importlib.util,json,re,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
SHA=lambda b:hashlib.sha256(b).hexdigest()
PIN=lambda b:{'bytes':len(b),'sha256':SHA(b)}
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def module(name):
    spec=importlib.util.spec_from_file_location('public_mixed_'+name,ROOT/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def apply(source,hepta,locked_sdk_source=None):
    source,hepta=Path(source).resolve(strict=True),Path(hepta).resolve(strict=True)
    inputs=json.loads((ROOT/'INPUTS.json').read_bytes())
    binding_path=source/'native/runtime_mcp_sources.json';binding_before=binding_path.read_bytes()
    assert SHA(binding_before)==inputs['baseline_binding']
    original_rows={p.relative_to(source).as_posix():PIN(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
    assert len(original_rows)==inputs['baseline_files']==436
    assert json.loads(binding_before)['sources']=={n:r for n,r in original_rows.items() if n!='native/runtime_mcp_sources.json'}
    sdk=Path(locked_sdk_source if locked_sdk_source is not None else ROOT/'locked_sdk_server.rs').read_bytes()
    assert PIN(sdk)==inputs['locked_sdk_source']
    assert b'continue;' in sdk and b'expect_next_message(&mut transport, "initialize request")' in sdk
    assert b'// Enter the main service loop immediately after sending InitializeResult.' in sdk
    for name in original_rows:
        if name.startswith('scripts/') and name.endswith('.S'):
            text=(source/name).read_text()
            assert not re.search(r'\br15\s*\+\s*(?:920|0x398)\b',text),(name,'parent config exit field already used')
    sys.path.insert(0,str(source/'authoring/public_extract'))
    import source_support as support
    assert SHA(Path(support.__file__).read_bytes())==inputs['support_sha256']
    api=support.tools(hepta);changes={}
    def save(name,data):
        path=source/name;before=path.read_bytes() if path.exists() else None
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        changes[name]={'before':PIN(before) if before is not None else None,'after':PIN(data)}
    connection=module('connection_author').generate(source,api,support,inputs,save)
    catalog=module('catalog_author').generate(source,api,support,inputs,save)
    for name in ('author.py','connection_author.py','catalog_author.py','connection_eof.pseudo',
                 'connection_eof_boundary.S','connection_eof_engine.S','catalog_frontend.pseudo','INPUTS.json'):
        save('authoring/public_mixed_opener/'+name,(ROOT/name).read_bytes())
    abi=b"""# Actual connection EOF capability

The fixed transport invokes global descriptor 55 with HRCNQ001, operation 3,
body length 0 and exactly 24 input bytes. Public JSON cannot choose this private
operation. Operations 1 and 2 retain their old input/output ABI.

Operation 3 requires the existing valid G2 workspace (at least 65536 bytes).
It returns HRCEOF01 followed by three u64 words: exit status, stderr offset,
stderr length. A settled connection returns 32 bytes, status 0 and empty span.
An unselected lifecycle returns status 1 and the exact SDK initialization error
at offset 32. The required complete output capacity is checked before writes.

The mode is read from the actual persistent G2 state. Missing metadata and an
unsupported inline version during the opener reply and retain that opener.
Ping and bootstrap discover do not select a lifecycle. A valid initialize
selects the legacy lifecycle immediately after its response.

The host first drains the existing task registry and closes stdout, then invokes
this capability. It checks the complete descriptor and writes only its returned
stderr span, including short writes/EINTR/EAGAIN. It stores the admitted status
at the newly reserved parent configuration context word 920, completes all
existing HIA config cleanup, and exits with that status. The host does not parse
JSON or determine SDK policy.
"""
    save('native/sdk_connection_eof_abi.md',abi)
    text=binding_before.decode();needle='\n  "sources": ';assert text.count(needle)==1
    start=text.index(needle)+len(needle);old,end=json.JSONDecoder().raw_decode(text[start:])
    assert old=={n:r for n,r in original_rows.items() if n!='native/runtime_mcp_sources.json'}
    rows={p.relative_to(source).as_posix():PIN(p.read_bytes()) for p in source.rglob('*') if p.is_file() and p!=binding_path}
    payload=json.dumps(rows,sort_keys=True,indent=2).replace('\n','\n  ')
    text=text[:start]+payload+text[start+end:]
    extension={'g2_source':connection['source'],'connection_eof':PIN((source/'native/sdk_connection_eof_composition.json').read_bytes()),
      'catalog_presence':PIN((source/'native/runtime_mcp_catalog_presence_composition.json').read_bytes()),
      'actual_catalog_pipeline_run':43813791993,'baseline_source':inputs['baseline_source'],
      'complete_public_domain_qualified':False,'public_wait_qualified':False}
    payload=json.dumps(extension,sort_keys=True,indent=2).replace('\n','\n  ')
    text=text.replace(needle,'\n  "mixed_opener_catalog_extension": '+payload+','+needle)
    save('native/runtime_mcp_sources.json',text.encode())
    final={p.relative_to(source).as_posix():PIN(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
    assert all(final[n]==r for n,r in original_rows.items() if n not in changes)
    assert final['native/sdk_message_target.hepta']==original_rows['native/sdk_message_target.hepta']
    assert final['native/serde_json_span.hepta']==original_rows['native/serde_json_span.hepta']
    assert final['native/caller_authority.hepta']==original_rows['native/caller_authority.hepta']
    assert final['native/sdk_public_protocol.hepta']==original_rows['native/sdk_public_protocol.hepta']
    assert json.loads((source/'native/runtime_mcp_sources.json').read_bytes())['sources']=={n:r for n,r in final.items() if n!='native/runtime_mcp_sources.json'}
    return {'schema':'hepta.runtime.public118-mixed-opener-source-author.v1','baseline_source':inputs['baseline_source'],
      'source_files':final,'changed_files':changes,'source_binding_sha256':SHA(binding_path.read_bytes()),
      'connection':connection,'catalog':catalog,'runtime_hia_images':118,'physical_images':111,'descriptor_slots':64,
      'installed_handlers':10,'visible_without_runtime_config':7,'native_or_rust_executions':0,
      'full_sdk_qualified':False,'public_wait_qualified':False,'whole_runtime_replaced':False}
