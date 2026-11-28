"""Reproduce only the caller-authority zero helper; preserve fallback trap writes."""
from pathlib import Path
import hashlib,re
BEFORE='c8762a6c08a7270e473b6868798de059cbee2443ad47c1cd49962fe5d27b4775'
AFTER='bbffb3be87e042e38d1b947be29f1f8f9a59cdb5b919e12d9482d50c214dc373'
def generate(source,fast):
    assert hashlib.sha256(source).hexdigest()==BEFORE
    matches=list(re.finditer(rb'fn f20\([\s\S]*?\nend\n',source));assert len(matches)==1 and b'fn f33(' not in source
    old=matches[0].group();a,b=matches[0].span();result=source[:a]+fast+source[b:]+old.replace(b'fn f20(',b'fn f33(',1)
    assert hashlib.sha256(result).hexdigest()==AFTER
    return result
def verify(before,after,fast):
    assert generate(before,fast)==after
    from hepta.hia_agent_assembly import assemble_program
    left=assemble_program(before).as_dict();right=assemble_program(after).as_dict()
    assert len(left['functions'])==33 and len(right['functions'])==34
    for i in range(33):
        if i!=20:assert left['functions'][i]==right['functions'][i],('unchanged function',i)
    fallback=dict(right['functions'][33]);fallback['name']='f20'
    assert fallback==left['functions'][20]
    return {'before_sha256':BEFORE,'after_sha256':AFTER,'unchanged_original_functions':32,'original_zero_loop_exact_as_f33':True,'whole_range_bulk_only_if_fully_valid':True,'zero_length_does_not_validate_offset':True,'invalid_or_wrapping_range_uses_exact_original_loop':True,'native_or_rust_executions':0}

import json,sys
ROOT=Path(__file__).resolve().parent
ENC=lambda value:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
PIN=lambda raw:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def apply(source,hepta):
    source,hepta=Path(source).resolve(strict=True),Path(hepta).resolve(strict=True)
    sys.path.insert(0,str(hepta))
    inputs=json.loads((ROOT/'INPUTS.json').read_bytes());binding_path=source/'native/runtime_mcp_sources.json'
    original_binding=binding_path.read_bytes();assert PIN(original_binding)['sha256']==inputs['baseline_binding']
    original_rows={p.relative_to(source).as_posix():PIN(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
    assert len(original_rows)==inputs['baseline_files']==428
    before=(source/'native/caller_authority.hepta').read_bytes();fast=(ROOT/'zero_helper.txt').read_bytes();after=generate(before,fast)
    proof=verify(before,after,fast);assert PIN(after)==inputs['source_after']
    profile_path=source/'native/caller_owner_export_profile.json';old_profile=profile_path.read_bytes();profile=old_profile
    for left,right in ((b'"image_bytes": 128422',b'"image_bytes": 129692'),(b'795da0a7234853e9e1afbf8f993321a2f12aa86f16c06a6374a1913473693417',inputs['image_after']['sha256'].encode()),(BEFORE.encode(),AFTER.encode())):
        assert profile.count(left)==1;profile=profile.replace(left,right)
    assert PIN(before)=={'bytes':101917,'sha256':BEFORE}
    changes={}
    def save(name,raw):
        target=source/name;previous=target.read_bytes() if target.exists() else None
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        changes[name]={'before':PIN(previous) if previous is not None else None,'after':PIN(raw)}
    save('native/caller_authority.hepta',after);save('native/caller_owner_export_profile.json',profile)
    for name in ('author.py','INPUTS.json','zero_helper.txt'):save('authoring/public_owner_clear/'+name,(ROOT/name).read_bytes())
    composition={'schema':'hepta.runtime.caller-clear-overlay.v1','source_proof':proof,'inputs':inputs,'author':PIN(Path(__file__).read_bytes()),'helper':PIN(fast),
        'previous_owner_export_proof':original_rows['native/caller_owner_export_source_proof.json'],
        'old_profile':PIN(old_profile),'new_profile':PIN(profile),'runtime_hia_images':118,'installed_tools':10,'front_and_host_unchanged':True,'whole_public_domain_qualified':False}
    save('native/caller_owner_clear_composition.json',ENC(composition))
    text=original_binding.decode();old='\n  "sources": '
    assert text.count(old)==1
    start=text.index(old)+len(old);decoder=json.JSONDecoder();old_rows,end=decoder.raw_decode(text[start:])
    assert old_rows=={n:r for n,r in original_rows.items() if n!='native/runtime_mcp_sources.json'}
    new_rows={p.relative_to(source).as_posix():PIN(p.read_bytes()) for p in source.rglob('*') if p.is_file() and p!=binding_path}
    encoded=json.dumps(new_rows,sort_keys=True,indent=2).replace('\n','\n  ')
    text=text[:start]+encoded+text[start+end:]
    needle='"owner_source_sha256": "'+BEFORE+'"'
    assert text.count(needle)==1;text=text.replace(needle,'"owner_source_sha256": "'+AFTER+'"')
    save('native/runtime_mcp_sources.json',text.encode())
    all_rows={p.relative_to(source).as_posix():PIN(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
    assert len(all_rows)==432 and set(changes)=={'native/caller_authority.hepta','native/caller_owner_export_profile.json','native/runtime_mcp_sources.json','native/caller_owner_clear_composition.json',*('authoring/public_owner_clear/'+n for n in ('author.py','INPUTS.json','zero_helper.txt'))}
    return {'schema':'hepta.runtime.extract-public-owner-clear-source.v1','baseline_source':inputs['baseline_source'],'baseline_binding':inputs['baseline_binding'],
        'source_binding_sha256':PIN(binding_path.read_bytes())['sha256'],'source_files':all_rows,'changed_files':changes,'source_proof':proof,
        'runtime_hia_images':118,'direct_hia_members':110,'physical_images':111,'installed_catalog_tools':10,'extract_slots':[59,60,61,62,63],
        'native_or_rust_executed':False,'public_handler_qualified':False,'full_async_cancellation_qualified':False,'whole_runtime_replaced':False}
