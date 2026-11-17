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
