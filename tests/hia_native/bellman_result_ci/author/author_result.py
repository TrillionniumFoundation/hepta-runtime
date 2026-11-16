"""Emit the HIA result owner and prove exact imported formatter graphs."""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys

from result_source import SOURCE

SERDE_SHA = 'ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18'
TARGET_SHA = '254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'

STATIC = {
    'schema': 'hepta.weight.bellman-plan.v1',
    'semantics_version': 'finite_dag_ordered_f64_v1',
    'method': 'finite_dag_ordered_dynamic_programming_f64',
    'action_names': ['STOP', 'WAIT', 'READ', 'REPAIR', 'SUBMIT_0', 'SUBMIT_1'],
    'recurrence': 'in supplied branch order: total += probability * ((child_value + reward) - fee); zero probabilities skipped; first legal strict maximum',
    'request_commitment_encoding': 'typed canonical serde_json; not raw JSON-RPC transport bytes',
    'self_consistency_is_numerical_error_bound': False,
    'operation_budget_units': 8000000,
    'canonical_request_byte_budget': 8388608,
    'gradient_steps': 0,
    'training_targets_used': False,
    'checkpoint_verified': False,
    'environment_law_verified': False,
    'real_arithmetic_optimality_certified': False,
    'independent_holdout_verified': False,
    'production_eligible': False,
    'scope': 'bounded planning over the caller-declared finite DAG; no file access, checkpoint mutation, circuit identification, authentication of true dynamics, or end-to-end efficacy claim',
}
COUNTS = {'state_count':72, 'legal_action_count':80, 'continuing_action_count':88,
          'branch_count':96, 'zero_probability_branch_count':104,
          'exact_tie_state_count':128, 'near_tie_state_count':136,
          'operation_charged_units':120}
FLOATS = {'native_operation_wall_seconds':32, 'maximum_probability_sum_error_f64':112,
          'maximum_self_consistency_residual_f64':160}
FIXED_FLOATS = {'probability_sum_tolerance':1e-12, 'near_tie_relative_threshold':2e-12}
DIGESTS = {'implementation_source_sha256':48, 'request_sha256':16, 'plan_id':80}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def generate(hepta, runtime, target, destination):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    serde = (runtime/'native/serde_json.hepta').read_bytes()
    original = target.read_bytes()
    assert sha(serde) == SERDE_SHA and sha(original) == TARGET_SHA
    functions = {f['name']:f for f in assemble_program(serde).as_dict()['functions']}
    closure = set()
    def visit(name):
        if name in closure:
            return
        closure.add(name)
        for block in functions[name]['blocks']:
            for op in block['ops']:
                if op['op']=='call':
                    visit(op['attrs']['function'])
    visit('f16')
    assert closure == {'f'+str(i) for i in range(7,21)}
    relocation = {old:('format_bits' if old=='f16' else 'format_'+old)
                  for old in sorted(closure,key=lambda x:int(x[1:]))}
    source=SOURCE
    for label, value in {'INPUT_MAGIC':b'HBLMRQ01','OUTPUT_MAGIC':b'HBLMRS01',
                         'CORE_MAGIC':b'HIABPLN1','COMMITMENT_MAGIC':b'HBCMTRES'}.items():
        source=source.replace(label,str(int.from_bytes(value,'little')))
    text = {'array_open':b'[','array_close':b']','object_close':b'}','comma':b',',
            'null':b'null','quote':b'"','state_open':b'{"action":',
            'q_open':b',"q":[','value':b'],"value":','plan_prefix':b'"wb1_'}
    fields=sorted(set(STATIC)|set(COUNTS)|set(FLOATS)|set(FIXED_FLOATS)|set(DIGESTS)|
                  {'states','request_bytes','minimum_relative_action_gap_f64'})
    source+='\ndef render(s:readbuf, w:mutbuf, commitment:u64) -> u64:\n'
    for index,key in enumerate(fields):
        text['key_'+key]=(('{' if index==0 else ',')+json.dumps(key)+':').encode()
        source+=f'    text_key_{key}(w)\n'
        if key in STATIC:
            text['static_'+key]=json.dumps(STATIC[key],ensure_ascii=False,separators=(',',':')).encode()
            source+=f'    text_static_{key}(w)\n'
        elif key in COUNTS:
            source+=f'    emit_integer(w, get(s, {COUNTS[key]}))\n'
        elif key in FLOATS:
            source+=f'    emit_float(w, get(s, {FLOATS[key]}))\n'
        elif key in FIXED_FLOATS:
            bits=struct.unpack('<Q',struct.pack('<d',FIXED_FLOATS[key]))[0]
            source+=f'    emit_float(w, {bits})\n'
        elif key in DIGESTS:
            source+=('    text_plan_prefix(w)\n' if key=='plan_id' else '    text_quote(w)\n')
            source+=f'    emit_digest(s, w, commitment + {DIGESTS[key]})\n    text_quote(w)\n'
        elif key=='states':
            source+='    render_states(s, w)\n'
        elif key=='request_bytes':
            source+='    emit_integer(w, get(s, commitment + 8))\n'
        else:
            source+='    if get(s, 144) == 0:\n        text_null(w)\n    else:\n        emit_float(w, get(s, 152))\n'
    source+='    return text_object_close(w)\n'
    for name,raw in text.items():
        source+=f'\ndef text_{name}(w:mutbuf) -> u64:\n    at = reserve(w, {len(raw)})\n    if at == 0:\n        return 0\n'
        source+=''.join(f'    store(w, at + {i}, {value})\n' for i,value in enumerate(raw))
        source+='    return 0\n'
    for old,new in relocation.items():
        fn=functions[old]
        args=', '.join(f'p{i}:{p["type"]}' for i,p in enumerate(fn['params']))
        source+=f'\ndef {new}({args}) -> {fn["returns"][0]}:\n    return 0\n'
    nodes=ast.parse(source).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);new=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        new.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
                    'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    doc=compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'bellman_result','functions':new})
    mapping={old:names[new] for old,new in relocation.items()};proof={}
    for old,new in mapping.items():
        function=copy.deepcopy(functions[old]);function['name']=new
        for block in function['blocks']:
            for op in block['ops']:
                if op['op']=='call':op['attrs']['function']=mapping[op['attrs']['function']]
        index=next(i for i,f in enumerate(doc['functions']) if f['name']==new)
        doc['functions'][index]=function
        proof[old]=sha(json.dumps(functions[old],sort_keys=True,separators=(',',':')).encode())
    raw=render_assembly(doc).encode();parsed=assemble_program(raw).as_dict()
    assert parsed==doc
    for f in doc['functions']:
        assert len(f['blocks'])<=256
        assert max(len(b['params']) for b in f['blocks'])<=16,f['name']
        for b in f['blocks']:
            for op in b['ops']:assert not op['op'].startswith(('float.','ffi.','foreign.'))
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_bytes(raw)
    destination.with_suffix('.names.json').write_text(json.dumps(names,indent=2)+'\n')
    destination.with_suffix('.author.txt').write_text(source)
    composition={'schema':'hepta.runtime.bellman-result-composition.v1','source_sha256':sha(raw),
        'source_bytes':len(raw),'target_source_sha256':TARGET_SHA,'serde_source_sha256':SERDE_SHA,
        'formatter_function_graphs':proof,'formatter_relocation':mapping,
        'allowed_import_changes':['function names and direct call targets'],
        'result_keys':fields,'public_handler_qualified':False,'whole_runtime_replaced':False}
    destination.with_suffix('.composition.json').write_text(json.dumps(composition,indent=2)+'\n')
    return composition

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('hepta','runtime','target','destination'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    result=generate(args.hepta.resolve(),args.runtime.resolve(),args.target.resolve(),args.destination.resolve())
    print(json.dumps(result,sort_keys=True))
