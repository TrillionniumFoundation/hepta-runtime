"""Project current typed ListTools/context into a private owned frontend frame.

Only current G1 variant 15 after actual G2 kind 2 can reach this producer.  It
does not reinterpret raw public metadata or use the connection lifecycle bit
as a feature predicate.  All input bytes come from those owned child replies.
"""
from __future__ import annotations
import argparse,ast,copy,hashlib,importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
SHA=lambda b:hashlib.sha256(b).hexdigest()
CANON=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()
PINS={
 'baseline-sdk_public_protocol.hepta':'27f486900a1486e3a79fa32d41af45f01847f0d01e79ac3a23ea5baf0f274f5a',
 'baseline-sdk_public_protocol_composition.json':'f5b816a477ca1110e932be0ca1c37ca60c8a01a2a79f198615e554132caea51e',
 'baseline-runtime_mcp.hepta':'6e0862f7dde67a3eca7db6f0c79ee36c942d4fc552449dad939016b16fb6d9aa',
 'baseline-runtime_mcp_composition.json':'13e4043006981ee98d4cc895f06ca02869e2ef712ce23a530c8886c42dfa35fe',
 'qualified-context_protocol_policy.hepta':'8a8e922b2d4e9bec6b1bf7f0184f9ea2cd42c8ab44c6b94d80f94f87fd3e0751',
 'retained_author_connection.py':'98d2850cb1e52d96d754643d76ebf0c56f459f85afeb897b6c9eaa24e3e211f0',
 'retained_connection_protocol.txt':'2c472907771274d0982f071a433c85630682b6e39f859ca0c26f58c2eb10eb4b',
}
PROJECTION='''
def list_projection(o:mutbuf, w:mutbuf) -> u32:
    extent = get(w, 48)
    if connection_pair(w, MESSAGE, extent, 80) == False:
        return INVALID
    if connection_pair(w, MESSAGE, extent, 96) == False:
        return INVALID
    if connection_pair(w, BRIDGE, get(w, 64), 144) == False:
        return INVALID
    id_at = get(w, MESSAGE + 80)
    id_size = get(w, MESSAGE + 88)
    meta_present = get(w, MESSAGE + 32)
    meta_at = get(w, MESSAGE + 96)
    meta_size = get(w, MESSAGE + 104)
    version_at = get(w, BRIDGE + 144)
    version_size = get(w, BRIDGE + 152)
    if id_at == 0 or id_size == 0 or meta_present > 1:
        return INVALID
    if meta_at == 0 or meta_size < 2:
        return INVALID
    if id_size > TEMP_CAP - 192:
        return RESOURCE
    if meta_size > TEMP_CAP - 192 - id_size:
        return RESOURCE
    if version_size > TEMP_CAP - 192 - id_size - meta_size:
        return RESOURCE
    version_present = 0
    if version_at != 0:
        version_present = 1
    modern = resolved_cache_hints(w, BRIDGE + version_at, version_size, version_present)
    fill_range(w, TEMP, 192, 0)
    put(w, TEMP, PROTOCOL_OUTPUT)
    put(w, TEMP + 16, 3)
    put(w, TEMP + 32, get(w, 32))
    put(w, TEMP + 40, 3)
    put(w, TEMP + 48, id_size)
    put(w, TEMP + 56, meta_size)
    put(w, TEMP + 64, version_size)
    put(w, TEMP + 72, version_present)
    put(w, TEMP + 80, meta_present)
    put(w, TEMP + 88, modern)
    put(w, TEMP + 104, 192 + id_size)
    put(w, TEMP + 112, meta_size)
    if version_present == 1:
        put(w, TEMP + 120, 192 + id_size + meta_size)
    put(w, TEMP + 128, version_size)
    put(w, TEMP + 144, LIST_TAG)
    copy_within(w, TEMP + 192, MESSAGE + id_at, id_size)
    copy_within(w, TEMP + 192 + id_size, MESSAGE + meta_at, meta_size)
    if version_size != 0:
        copy_within(w, TEMP + 192 + id_size + meta_size, BRIDGE + version_at, version_size)
    total = 192 + id_size + meta_size + version_size
    put(w, 88, total)
    put(w, 8, 6)
    return finish(o, w, 192, total)

def resolved_cache_hints(w:mutbuf, start:u64, size:u64, present:u64) -> u64:
    if present == 0:
        return 0
    index = 0
    while index < 10:
        if index >= size:
            return 0
        actual = byte(w, start + index)
        expected = context_threshold(index)
        if actual > expected:
            return 1
        if actual < expected:
            return 0
        index = index + 1
    return 1
'''
FRONTEND='''
def after_protocol(s:readbuf, o:mutbuf, w:mutbuf, code:u64, size:u64) -> u32:
    frame = region(w, 1)
    if code == 192 and size >= 192:
        if get(w, frame) == PROTOCOL_OUTPUT and get(w, frame + 144) == LIST_TAG:
            return accept_current_list(s, o, w, size)
    return retained_list_protocol(s, o, w, code, size)

def accept_current_list(s:readbuf, o:mutbuf, w:mutbuf, size:u64) -> u32:
    frame = region(w, 1)
    if get(w, frame + 8) != 0 or get(w, frame + 16) != 3 or get(w, frame + 24) != 0:
        return INVALID
    if get(w, frame + 32) > 2 or get(w, frame + 40) != 3:
        return INVALID
    identifier = get(w, frame + 48)
    metadata = get(w, frame + 56)
    version = get(w, frame + 64)
    available = size - 192
    if identifier == 0 or identifier > available:
        return INVALID
    if metadata < 2 or metadata > available - identifier:
        return INVALID
    if version != available - identifier - metadata:
        return INVALID
    present = get(w, frame + 72)
    meta_present = get(w, frame + 80)
    modern = get(w, frame + 88)
    if present > 1 or meta_present > 1 or modern > 1:
        return INVALID
    if present == 0:
        if version != 0 or modern != 0 or get(w, frame + 120) != 0:
            return INVALID
    else:
        if get(w, frame + 120) != 192 + identifier + metadata:
            return INVALID
    if get(w, frame + 104) != 192 + identifier or get(w, frame + 112) != metadata:
        return INVALID
    if get(w, frame + 128) != version or get(w, frame + 96) != 0 or get(w, frame + 136) != 0:
        return INVALID
    offset = 152
    while offset < 192:
        if get(w, frame + offset) != 0:
            return INVALID
        offset = offset + 8
    if reserve(w, 2, size) == 0:
        return pending_grow(o, w)
    frame = region(w, 1)
    copy_within(w, region(w, 2), frame, size)
    wire_mode = 1
    if modern == 1:
        wire_mode = 2
    put(w, 64, wire_mode)
    put(w, 72, 3)
    put(w, 80, 0)
    put(w, 88, modern)
    put(w, 96, 0)
    put(w, 104, 0)
    return catalog(s, o, w, 1, modern, 0)
'''

def load_support():
    spec=importlib.util.spec_from_file_location('retained_connection_author',ROOT/'retained_author_connection.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--hepta',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    for name,want in PINS.items():assert SHA((ROOT/name).read_bytes())==want,name
    support=load_support();sys.path.insert(0,str(a.hepta))
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    old=(ROOT/'baseline-sdk_public_protocol.hepta').read_bytes();program=assemble_program(old).as_dict();before={f['name']:f for f in program['functions']};assert len(before)==19
    comp=json.loads((ROOT/'baseline-sdk_public_protocol_composition.json').read_bytes());constants=dict(comp['constants']);constants['LIST_TAG']=int.from_bytes(b'HRCLST01','little')
    parsed=ast.parse((ROOT/'retained_connection_protocol.txt').read_text())
    after=next(n for n in parsed.body if n.name=='after_connection');exact=ast.unparse(after)+'\n'
    rebuilt,_,_=support.compile_delta(a.hepta,old,comp['aliases'],support.substitute(exact,constants),{'after_connection':'f11'},{})
    assert next(f for f in assemble_program(rebuilt).as_dict()['functions'] if f['name']=='f11')==before['f11']
    expected='        if variant == 1:\n            return empty_result(o, w)\n        return child(w, 4, 3, ORIGINAL, get(w, 24), TEMP, TEMP_CAP)'
    assert exact.count(expected)==1
    changed=exact.replace(expected,'        if variant == 1:\n            return empty_result(o, w)\n        if variant == 15:\n            return list_projection(o, w)\n        return child(w, 4, 3, ORIGINAL, get(w, 24), TEMP, TEMP_CAP)')
    qualified=assemble_program((ROOT/'qualified-context_protocol_policy.hepta').read_bytes()).as_dict();threshold=copy.deepcopy(next(f for f in qualified['functions'] if f['name']=='f3'));threshold['name']='f21'
    program['functions'].append(threshold);with_threshold=render_assembly(program).encode()
    pseudo=changed+'\n'+PROJECTION
    aliases={**comp['aliases'],'context_threshold':'f21'}
    raw,functions,retained=support.compile_delta(a.hepta,with_threshold,aliases,support.substitute(pseudo,constants),{'after_connection':'f11'},{'list_projection':'f19','resolved_cache_hints':'f20'})
    assert functions['f21']==threshold
    assert all(functions[n]==f for n,f in before.items() if n!='f11')
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'sdk_public_protocol.hepta').write_bytes(raw)
    (a.output/'list_projection.pseudo').write_text(pseudo)
    protocol_note={
       'schema':'hepta.current-typed-list-projection.v2','source_sha256':SHA(raw),'source_bytes':len(raw),'functions':len(functions),
       'baseline_sha256':SHA(old),'retained_exact_functions':{n:SHA(CANON(f)) for n,f in before.items() if n!='f11'},
       'changed_functions':['f11'],'added_functions':{'list_projection':'f19','resolved_cache_hints':'f20','qualified_context_threshold':'f21'},
       'g1_source_sha256':'e1ef0dd6bb5993f6ad07499ee68e5a63b1fbd4a97ebf0e17b89aec1234af6a6b',
       'g2_source_sha256':'a3e6353b4d8e98682e6605e711bc19c533d8d524c2eb1b55c788709974a234f2',
       'g1_variant':15,'g2_admitted_kind':2,'g1_canonical_id_pair':80,'g1_actual_metadata_pair':96,'g1_metadata_presence_word':32,
       'g2_resolved_version_pair':144,'g2_version_is_complete_raw_utf8':True,'g2_lifecycle_word24_used_for_features':False,
       'g2_feature_word32_used_for_features':False,'qualified_protocol_policy_sha256':PINS['qualified-context_protocol_policy.hepta'],
       'qualified_threshold_function':{'from':'f3','to':'f21','relocated_ast_sha256':SHA(CANON(threshold))},
       'resolved_comparison':'None=false; for each index 0..9, exhausted=false, byte>threshold=true, byte<threshold=false; all ten equal=true. Exact original Rust str lexicographic predicate.',
       'projection_magic':'HRCLST01','header_bytes':192,'metadata_and_version_are_owned_payloads':True,
       'cursor_after_actual_typed_acceptance':'Current target list_tools ignores the typed cursor. No public JSON is accepted by this private producer.',
       'historical_raw_offsets_used_for_list':False,'public_all_configuration_qualified':False,'whole_runtime_replaced':False}
    (a.output/'list_projection_composition.json').write_text(json.dumps(protocol_note,sort_keys=True,indent=2)+'\n')
    front=(ROOT/'baseline-runtime_mcp.hepta').read_bytes();fc=json.loads((ROOT/'baseline-runtime_mcp_composition.json').read_bytes());names=fc['functions']
    raw,functions,retained=support.compile_delta(a.hepta,front,{**names,'retained_list_protocol':'f77'},support.substitute(FRONTEND,constants),{'after_protocol':'f1'},{'accept_current_list':'f78'},(('f1','f77'),))
    (a.output/'runtime_mcp.hepta').write_bytes(raw);(a.output/'list_frontend.pseudo').write_text(FRONTEND)
    fnote={'schema':'hepta.current-typed-list-frontend.v2','source_sha256':SHA(raw),'source_bytes':len(raw),'functions':len(functions),
        'baseline_sha256':SHA(front),'retained_exact_functions':retained,'changed_functions':['f1'],'relocated_exact_functions':{'f1':'f77'},
        'added_functions':{'accept_current_list':'f78'},'private_projection_magic':'HRCLST01','full_id_metadata_resolved_version_preserved':True,
        'no_raw_metadata_span_reinterpretation':True,'actual_current_g1_g2_precede_private_list':True,'original_target_list_uses_only_resolved_version_and_config':True,
        'catalog_actual_config_query_retained':True,'installed_mask':1,'public_all_configuration_qualified':False,'whole_runtime_replaced':False}
    fc['functions']={**names,'retained_list_protocol':'f77','accept_current_list':'f78'};fc['function_sha256']={n:SHA(CANON(f)) for n,f in functions.items()};fc['source_sha256']=SHA(raw);fc['source_bytes']=len(raw);fc['current_typed_list_extension']=fnote
    (a.output/'runtime_mcp_composition.json').write_text(json.dumps(fc,sort_keys=True,indent=2)+'\n')
    (a.output/'list_frontend_composition.json').write_text(json.dumps(fnote,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'protocol':protocol_note,'frontend':fnote},sort_keys=True))

if __name__=='__main__':main()
