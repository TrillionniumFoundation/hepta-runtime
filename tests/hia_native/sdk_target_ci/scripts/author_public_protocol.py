#!/usr/bin/env python3
"""Author the ordinary native protocol child chain; no protocol logic in Python."""
from pathlib import Path
import argparse,copy,hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--hepta',required=True);a=p.parse_args()
sys.dont_write_bytecode=True;sys.path.insert(0,a.hepta)
from compile_overlay import compile_source
from hepta.hia_agent_assembly import assemble_program,render_assembly
source=(ROOT/'native/sdk_request.hepta').read_bytes()
assert sha(source)=='ed335f8fae0ab751d6d1282fa62d7351f72b7ce622dd4efca4e2f6a62f5c5641'
doc=assemble_program(source).as_dict();doc['module']='sdk_target_public_protocol_controller'
names=json.loads((ROOT/'native/sdk_request_composition.json').read_bytes())['aliases']
constants={'WORK_MIN':208<<20,'ORIGINAL':4096,'ORIGINAL_CAP':(20<<20)-4096,'TEMP':20<<20,'TEMP_CAP':20<<20,'MESSAGE':40<<20,'MESSAGE_CAP':64<<20,'REQUEST':104<<20,'REQUEST_CAP':64<<20,'BRIDGE':168<<20,'BRIDGE_CAP':32<<20,'JSON_MAX':(16<<20)-1,'CALL':0xfffffff0,'GROW':0xffffffd0,'INVALID':0xffffffff,'RESOURCE':0xfffffffc}
for name,magic in [('STATE_MAGIC',b'HRQPCS01'),('ACTION_MAGIC',b'HRQPCA01'),('GROW_MAGIC',b'HGRWS002'),('PROTOCOL_INPUT',b'HRJPRQ02'),('PROTOCOL_RESUME',b'HRJPRQ03'),('PROTOCOL_OUTPUT',b'HRJPRR02'),('MESSAGE_INPUT',b'HRCJQ001'),('MESSAGE_OUTPUT',b'HRCJR001'),('REQUEST_OUTPUT',b'HRQPO001'),('BRIDGE_INPUT',b'HRQFB001')]:
    assert len(magic)==8;constants[name]=int.from_bytes(magic,'little')
author=(ROOT/'scripts/public_protocol_authoring.txt').read_text()
_,built,names=compile_source(author,doc,names,constants)
by={f['name']:f for f in built['functions']};todo=[names['entry']];seen=set()
while todo:
    n=todo.pop()
    if n in seen:continue
    seen.add(n)
    for block in by[n]['blocks']:
        for op in block['ops']:
            if op['op']=='call':todo.append(op['attrs']['function'])
ordered=sorted(seen,key=lambda n:int(n[1:]));renames={n:'f'+str(i) for i,n in enumerate(ordered)};functions=[]
for n in ordered:
    f=copy.deepcopy(by[n]);f['name']=renames[n]
    for block in f['blocks']:
        for op in block['ops']:
            if op['op']=='call':op['attrs']['function']=renames[op['attrs']['function']]
    functions.append(f)
built['functions']=functions;raw=render_assembly(built).encode();assemble_program(raw)
(ROOT/'native/sdk_public_protocol.hepta').write_bytes(raw)
record={'schema':'hepta.g5.public-protocol-controller.v1','source_sha256':sha(raw),'source_bytes':len(raw),'functions':len(functions),'blocks':sum(len(f['blocks']) for f in functions),'author_sha256':sha(author.encode()),'imported_helper_source_sha256':sha(source),'aliases':{k:renames[v] for k,v in names.items() if v in renames},'constants':constants,'input_magics':['HRJPRQ02','HRJPRQ03'],'action_magic':'HRQPCA01','child_order':{'0':'target_message','1':'target_request','2':'target_frontend_bridge','3':'historical_protocol'},'entry_return_bytes':192,'output_magic':'HRJPRR02','full_extent':'192 + u64@48 + u64@56 + u64@64','ordinary_typed_calltool_native_chain':True,'non_call_and_selected_id_routes':'exact historical protocol owner after valid G1 model; Q03 forwarded unchanged','target_connection_identity_integrated':False,'target_response_owner_integrated':False,'full_sdk_qualified':False,'production_activated':False,'old_path_removed':False}
(ROOT/'native/sdk_public_protocol_composition.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:record[k] for k in ['source_sha256','source_bytes','functions','blocks']},sort_keys=True))
