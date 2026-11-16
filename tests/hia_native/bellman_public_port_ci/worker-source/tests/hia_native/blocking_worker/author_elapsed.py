"""Actual-clock duration to binary64, reusing the exact finite arithmetic owner."""
from __future__ import annotations
import argparse, ast, copy, hashlib, json, sys
from pathlib import Path

SOURCE = r'''
def elapsed(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 32 or old_1(s, 0) != MAGIC or old_1(s, 24) != 0:
        return 4294967295
    if length(o) < 24:
        return 4294967293
    first = old_1(s, 8)
    last = old_1(s, 16)
    if last < first:
        return 4294967295
    ns = last - first
    secs = 0
    nanos = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        nanos = (nanos << 1) | ((ns >> bit) & 1)
        if nanos >= 1000000000:
            nanos = nanos - 1000000000
            secs = secs | (1 << bit)
    whole = integer_bits(secs)
    partial = old_14(integer_bits(nanos), 4741671816366391296)
    result = old_8(whole, partial)
    old_3(o, 0, RESULT_MAGIC)
    old_3(o, 8, result)
    old_3(o, 16, ns)
    return 24

def integer_bits(value:u64) -> u64:
    if value == 0:
        return 0
    exponent = 0
    shifted = value
    while shifted > 1:
        shifted = shifted >> 1
        exponent = exponent + 1
    if exponent <= 52:
        significand = value << (52 - exponent)
    else:
        count = exponent - 52
        significand = value >> count
        remainder = value & ((1 << count) - 1)
        half = 1 << (count - 1)
        if remainder > half or (remainder == half and (significand & 1) != 0):
            significand = significand + 1
        if significand == 9007199254740992:
            significand = significand >> 1
            exponent = exponent + 1
    return ((1023 + exponent) << 52) | (significand & 4503599627370495)
'''

def author(root,hepta):
    sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import _parse_assembly_document,render_assembly
    from hepta.hia_program import verify_program
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    raw=(root/'native/finite_binary64.hepta').read_bytes();old=_parse_assembly_document(raw)
    old_functions={fn['name']:fn for fn in old['functions']}
    source=SOURCE.replace('RESULT_MAGIC',str(int.from_bytes(b'HBELRS01','little'))).replace('MAGIC',str(int.from_bytes(b'HBELRQ01','little')))
    for fn in old['functions'][1:]:
        args=', '.join(f'p{i}:{p["type"]}' for i,p in enumerate(fn['params']))
        returned='False' if fn['returns'][0]=='bool' else '0'
        source+=f'\ndef old_{fn["name"][1:]}({args}) -> {fn["returns"][0]}:\n    return {returned}\n'
    nodes=ast.parse(source).body
    names={'elapsed':'f0','integer_bits':'f'+str(len(old['functions']))}
    names.update({'old_'+fn['name'][1:]:fn['name'] for fn in old['functions'][1:]})
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],'returns':[b.returns],
                          'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    doc=compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'bellman_elapsed','functions':functions})
    for i,fn in enumerate(doc['functions']):
        if fn['name'] in old_functions and fn['name']!='f0':doc['functions'][i]=copy.deepcopy(old_functions[fn['name']])
    doc['functions'].sort(key=lambda f:int(f['name'][1:]));verify_program(doc)
    out=render_assembly(doc).encode();assert _parse_assembly_document(out)==doc
    sha=lambda b:hashlib.sha256(b).hexdigest()
    (root/'native/bellman_elapsed.hepta').write_bytes(out)
    result={'schema':'hepta.runtime.bellman-elapsed.source-proof.v1','status':'SOURCE_ONLY_PASS','source_sha256':sha(out),
            'source_bytes':len(out),'finite_binary64_source_sha256':sha(raw),'author_sha256':sha(Path(__file__).read_bytes()),
            'unchanged_helpers':[f['name'] for f in old['functions'][1:]],'functions':len(doc['functions']),
            'blocks':sum(len(f['blocks']) for f in doc['functions']),'rust_executed':False,'native_executed':False}
    (root/'native/bellman_elapsed_source_proof.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source-root',type=Path,required=True);p.add_argument('--hepta',type=Path,required=True);a=p.parse_args()
    print(json.dumps(author(a.source_root.resolve(),a.hepta.resolve()),sort_keys=True))
