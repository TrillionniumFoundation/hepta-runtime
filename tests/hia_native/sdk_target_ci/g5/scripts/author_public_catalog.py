#!/usr/bin/env python3
"""Replace only tools/list bytes in the pinned eight-tool public catalog."""
from pathlib import Path
import argparse,copy,hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--hepta',required=True);a=p.parse_args()
sys.path.insert(0,a.hepta);sys.dont_write_bytecode=True
from compile_overlay import compile_source
from hepta.hia_agent_assembly import assemble_program,render_assembly
base=(ROOT/'frontend/runtime_mcp_catalog.hepta').read_bytes();assert sha(base)=='278ac15d5143fed12e63e678861b187f32ad93670e46fcc456fa38c5c5af9116'
doc=assemble_program(base).as_dict();before=copy.deepcopy(doc)
names=json.loads((ROOT/'frontend/runtime_mcp_catalog_composition.json').read_bytes())['functions']
names['old_entry']='f'+str(len(doc['functions']))
old=copy.deepcopy(doc['functions'][0]);old['name']=names['old_entry'];doc['functions'].append(old)
for i in range(2,14):names['retained_literal_'+str(i)]='f'+str(i+16)
normal=ROOT/'evidence/normal-v2';summary=json.loads((normal/'summary.json').read_bytes());assert summary['status']=='PASS'
assets=[(normal/('public-tools-policy'+str(n)+'.suffix.bin')).read_bytes() for n in (1,2)]
for raw in assets:
 assert raw.startswith(b',"result":') and raw.endswith(b'}')
 value=json.loads(b'{"case":0'+raw)['result'];assert len(value['tools'])==8
s='''def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 24 or load(s, 0) != REQUEST or load(s, 8) != 1:
        return old_entry(s, o, w)
    if length(o) < 32:
        return 4294967294
    if length(w) < 4096:
        return grow(o, 1, 4096)
    mode = load(s, 16)
    if length(s) != 24 or mode > 1:
        return 4294967295
    size = target_size(mode)
    if size > length(o) - 32:
        return grow(o, 2, 32 + size)
    target_literal(o, 32, mode)
    return finish(o, size)

def target_size(mode:u64) -> u64:
    if mode == 0:
        return LEGACY_SIZE
    return MODERN_SIZE

def target_literal(o:mutbuf, at:u64, mode:u64) -> u64:
'''.replace('REQUEST',str(int.from_bytes(b'HRMCD002','little'))).replace('LEGACY_SIZE',str(len(assets[0]))).replace('MODERN_SIZE',str(len(assets[1])))
common=assets[0][len(b',"result":{'):]
assert assets[1].endswith(common)
prefixes=[raw[:-len(common)] for raw in assets]
for mode,prefix in enumerate(prefixes):
 s+=f'    if mode == {mode}:\n        prefix_{mode}(o, at)\n        common_literal(o, at + {len(prefix)})\n        return 0\n'
s+='    return 0\n\ndef common_literal(o:mutbuf, at:u64) -> u64:\n'
for start in range(0,len(common),512):s+=f'    common_{start}(o, at + {start})\n'
s+='    return 0\n'
pieces=[('prefix_'+str(i),raw) for i,raw in enumerate(prefixes)]+[('common_'+str(start),common[start:start+512]) for start in range(0,len(common),512)]
for name,body in pieces:
  s+=f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
  full=len(body)//8*8
  for i in range(0,full,8):s+=f'    put(o, at + {i}, {int.from_bytes(body[i:i+8],"little")})\n'
  for i in range(full,len(body)):s+=f'    store(o, at + {i}, {body[i]})\n'
  s+='    return 0\n'
s+='''
def old_entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 32:
        return 4294967294
    if length(w) < 4096:
        return grow(o, 1, 4096)
    if length(s) < 24 or load(s, 0) != REQUEST:
        return 4294967295
    op = load(s, 8)
    arg = load(s, 16)
    if op == 4:
        if arg != length(s) - 24 or arg < 2 or byte(s, 24) != 34 or byte(s, length(s) - 1) != 34:
            return 4294967295
        prefix = old_size(10)
        suffix = old_size(11)
        if arg > 18446744073709551583 - prefix - suffix:
            return grow(o, 3, 0)
        size = prefix + arg + suffix
        if size > length(o) - 32:
            return grow(o, 2, 32 + size)
        old_literal(o, 32, 10)
        copy_range(o, s, 32 + prefix, 24, arg)
        old_literal(o, 32 + prefix + arg, 11)
        return finish(o, size)
    if length(s) != 24:
        return 4294967295
    if op == 6:
        if arg < 1 or arg > 8:
            return 4294967295
        if length(o) < 512:
            return grow(o, 2, 512)
        at = length(w) - 4096
        put(w, at, 32)
        put(w, at + 8, 0)
        protocol_suffix(o, w, arg)
        if get(w, at + 8) != 0:
            return 4294967295
        return finish(o, get(w, at) - 32)
    which = 0
    if op == 2 and arg >= 1 and arg <= 4:
        which = arg + 1
    elif op == 3 and arg >= 1 and arg <= 3:
        which = arg + 6
    elif op == 5 and arg <= 1:
        which = arg + 12
    if which == 0:
        return 4294967295
    size = old_size(which)
    if size > length(o) - 32:
        return grow(o, 2, 32 + size)
    old_literal(o, 32, which)
    return finish(o, size)

def old_literal(o:mutbuf, at:u64, which:u64) -> u64:
'''.replace('REQUEST',str(int.from_bytes(b'HRMCD002','little')))
for i in range(2,14):s+=f'    if which == {i}:\n        retained_literal_{i}(o, at)\n        return old_size({i})\n'
s+='    return 0\n'
raw,after,names=compile_source(s,doc,names,{})
old_by={f['name']:f for f in before['functions']};new_by={f['name']:f for f in after['functions']}
unchanged={n:sha(json.dumps(f,sort_keys=True,separators=(',',':')).encode()) for n,f in old_by.items() if f==new_by[n]}
assert set(old_by)-set(unchanged)=={'f0','f10'}
todo=['f0'];reachable=set()
while todo:
 n=todo.pop()
 if n in reachable:continue
 reachable.add(n)
 for block in new_by[n]['blocks']:
  for op in block['ops']:
   if op['op']=='call':todo.append(op['attrs']['function'])
ordered=sorted(reachable,key=lambda n:int(n[1:]));relocation={n:'f'+str(i) for i,n in enumerate(ordered)};functions=[]
for n in ordered:
 f=copy.deepcopy(new_by[n]);f['name']=relocation[n]
 for block in f['blocks']:
  for op in block['ops']:
   if op['op']=='call':op['attrs']['function']=relocation[op['attrs']['function']]
 functions.append(f)
after['functions']=functions;raw=render_assembly(after).encode();assemble_program(raw)
(ROOT/'native/runtime_mcp_catalog_target.hepta').write_bytes(raw)
(ROOT/'scripts/public_catalog_authoring.txt').write_text(s)
record={'schema':'hepta.g5.public-catalog-overlay.v1','source_sha256':sha(raw),'baseline_sha256':sha(base),'changed_original_functions':['f0','f10'],'retained_exact_functions_before_relocation':{n:h for n,h in unchanged.items() if n in reachable},'removed_unreachable_old_literal_functions':sorted(set(old_by)-reachable,key=lambda n:int(n[1:])),'function_relocation':relocation,'non_list_entry':relocation[names['old_entry']],'functions':len(after['functions']),'blocks':sum(len(f['blocks']) for f in after['functions']),'aliases':{n:relocation[v] for n,v in names.items() if v in relocation},'assets':[{'path':str((normal/('public-tools-policy'+str(n)+'.suffix.bin')).relative_to(ROOT)),'sha256':sha(assets[i]),'bytes':len(assets[i]),'target_policy':n} for i,n in enumerate((1,2))],'normal_qualification_sha256':sha((normal/'summary.json').read_bytes()),'asset_producer':'actual native sdk_catalog owner from captured pinned eight-tool schemas','original_sdk_expected_not_used_as_implementation':True,'request_magic':'HRMCD002','response_magic':'HRCATR02','entry_return_bytes':32,'fixed_extra_slot':0,'registered_tools':8,'full_sdk_qualified':False,'production_activated':False}
(ROOT/'native/runtime_mcp_catalog_target_composition.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:record[k] for k in ['source_sha256','functions','blocks']},sort_keys=True))
