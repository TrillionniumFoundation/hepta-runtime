"""Lower the Bellman continuation and preserve qualified typed child graphs."""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
PINS={
    'params_original.hepta':'e4f02f4bba338b1a77bb60319f39576471138bc5596280856c374fc3921d712e',
    'diagnostic_original.hepta':'25e3a3fd54dbf13bd03a35f3daa589e255b951c4266442bf6bba932e7171f376',
}
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANONICAL=lambda value:json.dumps(value,sort_keys=True,separators=(',',':')).encode()
WORD=lambda value:int.from_bytes(value.encode(),'little')
PRIMITIVES='''
def load(s:readbuf, p:u64) -> u64:
    return byte(s,p) | (byte(s,p+1)<<8) | (byte(s,p+2)<<16) | (byte(s,p+3)<<24) | (byte(s,p+4)<<32) | (byte(s,p+5)<<40) | (byte(s,p+6)<<48) | (byte(s,p+7)<<56)
def get(w:mutbuf, p:u64) -> u64:
    return byte(w,p) | (byte(w,p+1)<<8) | (byte(w,p+2)<<16) | (byte(w,p+3)<<24) | (byte(w,p+4)<<32) | (byte(w,p+5)<<40) | (byte(w,p+6)<<48) | (byte(w,p+7)<<56)
def put(w:mutbuf, p:u64, v:u64) -> u64:
    store(w,p,v)
    store(w,p+1,v>>8)
    store(w,p+2,v>>16)
    store(w,p+3,v>>24)
    store(w,p+4,v>>32)
    store(w,p+5,v>>40)
    store(w,p+6,v>>48)
    store(w,p+7,v>>56)
    return 0
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hepta',type=Path,required=True)
    p.add_argument('--only-adapters',action='store_true')
    a=p.parse_args();sys.dont_write_bytecode=True;sys.path.insert(0,str(a.hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    class Bulk(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='wide':
                return self.cast(self.expr(node.args[0]),'u64')
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='copy_within':
                args=[self.expr(value) for value in node.args]
                return self.op('buffer.move_within',[args[0],*[self.cast(v,'usize') for v in args[1:]]])
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='copy_range':
                dst,src,dp,sp,count=[self.expr(value) for value in node.args]
                if src[1]=='mutbuf':
                    if ast.dump(node.args[0])==ast.dump(node.args[1]):
                        return self.op('buffer.move_within',[dst,self.cast(dp,'usize'),self.cast(sp,'usize'),self.cast(count,'usize')])
                    loan=self.op('borrow.read',[src],'readbuf')
                    self.op('buffer.copy_range',[dst,loan,self.cast(dp,'usize'),self.cast(sp,'usize'),self.cast(count,'usize')])
                    self.op('loan.end',[loan]);return None
                return self.op('buffer.copy_range',[dst,src,self.cast(dp,'usize'),self.cast(sp,'usize'),self.cast(count,'usize')])
            return super().expr(node)
    common=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,RESOURCE=0xfffffffc,
        CALL=0xfffffff0,GROW=0xffffffd0,DELIVERY=0xffffffcd,FIRST_ERROR=0xffff0000,
        GROW_MAGIC=WORD('HGRWS002'),MAXIMUM=(1<<64)-1)
    def lower(name,source,constants,imports=(),aliases=None):
        class Constants(ast.NodeTransformer):
            def visit_Name(self,node):
                if isinstance(node.ctx,ast.Load) and node.id in constants:
                    return ast.copy_location(ast.Constant(constants[node.id]),node)
                return node
        nodes=[Constants().visit(node) for node in ast.parse(source).body]
        assert all(isinstance(n,ast.FunctionDef) for n in nodes)
        names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
        signatures={node.name:([p.annotation.id for p in node.args.args],node.returns.id) for node in nodes}
        imported=[];relocation={}
        if imports:
            relocation={f['name']:'f'+str(len(nodes)+i) for i,f in enumerate(imports)}
            for old in imports:
                fn=copy.deepcopy(old);fn['name']=relocation[old['name']]
                for block in fn['blocks']:
                    for op in block['ops']:
                        if op['op']=='call':op['attrs']['function']=relocation[op['attrs']['function']]
                imported.append(fn)
            originals={f['name']:f for f in imports}
            for alias,target in (aliases or {}).items():
                fn=originals[target];names[alias]=relocation[target]
                signatures[alias]=([p['type'] for p in fn['params']],fn['returns'][0])
        total=total_scalar_functions(nodes);functions=[]
        for node in nodes:
            builder=Bulk(node,names,signatures,total);builder.statements(node.body)
            functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
                returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
        document=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module=name,functions=functions+imported))
        document['functions']=document['functions'][:len(functions)]+imported
        raw=render_assembly(document).encode();assert assemble_program(raw).as_dict()==document
        stats={'functions':len(document['functions']),'blocks':sum(len(f['blocks']) for f in document['functions']),
            'operations':sum(len(b['ops']) for f in document['functions'] for b in f['blocks'])}
        assert stats['functions']<=128 and stats['blocks']<=1536 and stats['operations']<=8192,stats
        assert all(len(f['blocks'])<=256 for f in document['functions'])
        assert all(len(b['params'])<=16 for f in document['functions'] for b in f['blocks'])
        path=ROOT/'source/native';(path/(name+'.hepta')).write_bytes(raw)
        (path/(name+'.author.txt')).write_text(source)
        (path/(name+'.names.json')).write_text(json.dumps(names,indent=2,sort_keys=True)+'\n')
        proof={'schema':'hepta.bellman-call.author.v1','source_sha256':SHA(raw),'source_bytes':len(raw),**stats,
            'imported_graphs':{f['name']:SHA(CANONICAL(f)) for f in imports},'relocation':relocation,
            'import_changes':['function names and direct call targets'] if imports else [],
            'native_qualified':False,'public_handler_qualified':False,'whole_runtime_replaced':False}
        (path/(name+'.composition.json')).write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
        print(json.dumps({'module':name,**proof},sort_keys=True))
    for name,source,minimum,response in (
        ('bellman_params_callable','params_original.hepta',128,'HBLPAT01'),
        ('bellman_diagnostic_callable','diagnostic_original.hepta',64,'HBLPDR01')):
        raw=(ROOT/'source/native'/source).read_bytes();assert SHA(raw)==PINS[source]
        original=assemble_program(raw).as_dict()['functions']
        lower(name,(ROOT/'adapter.pseudo').read_text()+PRIMITIVES,{**common,'MINIMUM':minimum,'RESPONSE':WORD(response)},original,{'qualified':'f0'})
    if a.only_adapters:return
    wanted=('region','region_capacity','reserve','request_grow','pending_grow','admit_growth','delivery_again')
    region_source=(ROOT/'reference/region_owner.pseudo').read_text()
    region_nodes=[n for n in ast.parse(region_source).body if isinstance(n,ast.FunctionDef) and n.name in wanted]
    assert {n.name for n in region_nodes}==set(wanted)
    helpers='\n\n'.join(ast.unparse(n) for n in region_nodes)+'\n'
    original=ast.parse((ROOT/'reference/qualify_bellman.py').read_text())
    errors=next(ast.literal_eval(n.value) for n in original.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ERRORS' for t in n.targets))
    errors.update({0xfffffdf0:'Bellman planning exceeded its 30-second compute deadline',
                   0xfffffde1:'Bellman canonical serialization exceeded its deadline',
                   0xffffff00:'Bellman canonical request exceeds 8 MiB'})
    texts={1:'failed to deserialize parameters: ',2:'native Bellman planning capacity exhausted; no work admitted'}
    codes={code:i+3 for i,code in enumerate(sorted(errors))}
    texts.update({codes[code]:text for code,text in errors.items()})
    generated='\ndef error_literal(code:u64) -> u64:\n'
    for code,index in codes.items():generated+=f'    if code == {code}:\n        return {index}\n'
    generated+='    return 0\n\ndef literal_size(index:u64) -> u64:\n'
    for index,text in texts.items():generated+=f'    if index == {index}:\n        return {len(text.encode())}\n'
    generated+='    return 0\n\ndef literal(w:mutbuf, at:u64, index:u64) -> u64:\n'
    for index,text in texts.items():
        raw=text.encode();generated+=f'    if index == {index}:\n'
        upto=len(raw)//8*8
        for i in range(0,upto,8):generated+=f'        put(w, at + {i}, {int.from_bytes(raw[i:i+8],"little")})\n'
        for i in range(upto,len(raw)):generated+=f'        store(w, at + {i}, {raw[i]})\n'
        generated+=f'        return {len(raw)}\n'
    generated+='    return 0\n'
    constants={**common,'STATE_MAGIC':WORD('HBLCST01'),'REQUEST_MAGIC':WORD('HBLCLQ01'),'RESULT_MAGIC':WORD('HBLCLR01'),
        'PARAMS_REQUEST':WORD('HBLPAR01'),'PARAMS_RESULT':WORD('HBLPAT01'),'DIAGNOSTIC_RESULT':WORD('HBLPDR01'),
        'GRAPH_MAGIC':WORD('HIABELL1'),'WORKER_REQUEST':WORD('HBWKRQ01'),'WORKER_RESULT':WORD('HBPMSR01'),
        'POOL_RESULT':WORD('HBPWRS01'),'BODY_RESULT':WORD('HBWKBOD1'),'CORE_RESULT':WORD('HIABPLN1'),
        'COMMIT_RESULT':WORD('HBCMTRES'),'RENDER_RESULT':WORD('HBLMRS01'),
        'ACTION':256,'ACTION_MAGIC':WORD('HBLCAC01'),'PHASE':8,'SEQUENCE':16,
        'INPUT_LENGTH':64,'OUTPUT_LENGTH':72,'WORK_LENGTH':80}
    lower('bellman_call',(ROOT/'caller.pseudo').read_text()+'\n'+helpers+generated+PRIMITIVES,constants)

if __name__=='__main__':main()
