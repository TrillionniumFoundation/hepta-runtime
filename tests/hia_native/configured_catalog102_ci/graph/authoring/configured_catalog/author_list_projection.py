"""Project a current G1/G2-admitted ListTools request for the retained frontend.

The target list handler ignores pagination. The current typed G1 admission is
the only source of acceptance; no public cursor is reinterpreted. Canonical ID
and the original typed metadata are retained. All non-list paths stay exact.
"""
from pathlib import Path
import argparse,ast,copy,hashlib,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from retained_author_connection import compile_delta,substitute
sha=lambda b:hashlib.sha256(b).hexdigest()
enc=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()

LIST='''def list_projection(o:mutbuf, w:mutbuf) -> u32:
    extent = get(w, 48)
    if connection_pair(w, MESSAGE, extent, 80) == False:
        return INVALID
    if connection_pair(w, MESSAGE, extent, 96) == False:
        return INVALID
    id_at = get(w, MESSAGE + 80)
    id_size = get(w, MESSAGE + 88)
    meta_present = get(w, MESSAGE + 32)
    meta_at = get(w, MESSAGE + 96)
    meta_size = get(w, MESSAGE + 104)
    if id_at == 0 or id_size == 0 or meta_present > 1:
        return INVALID
    if meta_present == 1:
        if meta_at == 0 or meta_size < 2:
            return INVALID
    else:
        meta_size = 0
    if id_size > ORIGINAL_CAP - 128:
        return RESOURCE
    if meta_size > ORIGINAL_CAP - 128 - id_size:
        return RESOURCE
    at = response_prefix(w, ORIGINAL + 32)
    copy_within(w, at, MESSAGE + id_at, id_size)
    at = list_request_suffix(w, at + id_size)
    if meta_present == 1:
        at = metadata_key(w, at)
        copy_within(w, at, MESSAGE + meta_at, meta_size)
        at = at + meta_size
    store(w, at, 125)
    store(w, at + 1, 125)
    size = at + 2 - ORIGINAL - 32
    put(w, ORIGINAL, PROTOCOL_INPUT)
    put(w, ORIGINAL + 8, get(w, 32))
    put(w, ORIGINAL + 16, size)
    put(w, ORIGINAL + 24, 0)
    return child(w, 4, 3, ORIGINAL, size + 32, TEMP, TEMP_CAP)
'''

def literal(name,raw):
    text='\ndef '+name+'(w:mutbuf, at:u64) -> u64:\n'
    for index in range(0,len(raw)//8*8,8):text+='    put(w,at+'+str(index)+','+str(int.from_bytes(raw[index:index+8],'little'))+')\n'
    for index in range(len(raw)//8*8,len(raw)):text+='    store(w,at+'+str(index)+','+str(raw[index])+')\n'
    return text+'    return at+'+str(len(raw))+'\n'

def generate(hepta,source,output):
    raw=(source/'baseline-sdk_public_protocol.hepta').read_bytes()
    assert sha(raw)=='27f486900a1486e3a79fa32d41af45f01847f0d01e79ac3a23ea5baf0f274f5a'
    comp=json.loads((source/'baseline-sdk_public_protocol_composition.json').read_bytes())
    text=(source/'retained_connection_protocol.txt').read_text()
    a=text.index('def after_connection(');b=text.index('\ndef ',a+1);old=text[a:b]+'\n'
    unchanged,ast_old,_=compile_delta(hepta,raw,comp['aliases'],substitute(old,comp['constants']),{'after_connection':'f11'}, {})
    sys.path.insert(0,str(hepta));from hepta.hia_agent_assembly import assemble_program
    before=assemble_program(raw).as_dict()
    assert ast_old['f11']==before['functions'][11],'exact retained G2 admission reconstructed'
    marker='        if variant == 1:\n            return empty_result(o, w)\n'
    assert old.count(marker)==1
    changed=old.replace(marker,marker+'        if variant == 15:\n            return list_projection(o, w)\n')
    pseudo=changed+'\n'+LIST+literal('list_request_suffix',b',"method":"tools/list","params":{')+literal('metadata_key',b'"_meta":')
    result,after,retained=compile_delta(hepta,raw,comp['aliases'],substitute(pseudo,comp['constants']),
        {'after_connection':'f11'},{'list_projection':'f19','list_request_suffix':'f20','metadata_key':'f21'})
    assert len(after)==22 and len(retained)==18
    proof={'schema':'hepta.runtime.current-sdk-list-projection-source.v1',
        'source_sha256':sha(result),'source_bytes':len(result),'baseline_sha256':sha(raw),
        'source_functions':22,'unchanged_functions':retained,'changed_functions':['f11'],
        'added_functions':{'list_projection':'f19','list_request_suffix':'f20','metadata_key':'f21'},
        'retained_after_connection_reproduced_exactly':True,'author_sha256':sha(Path(__file__).read_bytes()),
        'retained_author_sha256':sha((source/'retained_author_connection.py').read_bytes()),
        'target_message_source_sha256':'e1ef0dd6bb5993f6ad07499ee68e5a63b1fbd4a97ebf0e17b89aec1234af6a6b','target_connection_source_sha256':comp['connection_source_sha256'],
        'g1_request_disposition':1,'g1_typed_variant':15,'g2_admitted_kind':2,
        'g1_canonical_id_pair':80,'g1_actual_metadata_pair':96,'g1_metadata_presence_word':32,
        'metadata_is_not_synthesized_from_peer_capabilities':True,
        'target_handler_ignores_cursor':True,'current_typed_message_admission_required':True,
        'remaining_projection':'The retained historical protocol and actual metadata admission still execute on the typed ID and actual request metadata; current connection admission has already succeeded.',
        'public_handler_qualified':False,'whole_runtime_replaced':False}
    output.mkdir(parents=True,exist_ok=False)
    (output/'sdk_public_protocol.hepta').write_bytes(result)
    (output/'list_projection.pseudo').write_text(pseudo)
    (output/'list_projection_composition.json').write_bytes(enc(proof))
    return proof

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);p.add_argument('--source',type=Path,default=ROOT);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(generate(a.hepta.resolve(strict=True),a.source.resolve(strict=True),a.output.absolute()),sort_keys=True))
