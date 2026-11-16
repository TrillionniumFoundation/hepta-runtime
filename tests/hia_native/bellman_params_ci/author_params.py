"""Lower typed HIA owners; imports preserve the qualified arithmetic graphs."""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
SERDE_SHA='ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18'
FIELDS={1:'states',2:'actions',3:'kind',4:'value',5:'branches',6:'probability',7:'successor',8:'reward',9:'fee',10:'terminal',11:'continue'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def parser_source(path):
    raw=path.read_bytes();source=raw.decode()
    old='''            if get(w, node(parent)) == 6:
                old = find_key(s, w, parent, get(w, 48), get(w, 56), get(w, 64))
                if old != 0:
                    unlink(w, parent, old)
'''
    new='''            if get(w, node(parent)) == 6:
                last = get(w, node(parent) + 32)
                if last != 0:
                    if key_order(s, w, get(w, node(last) + 56), get(w, node(last) + 64), get(w, 48), get(w, 56)) == 0:
                        return fail(w)
'''
    assert source.count(old)==1;source=source.replace(old,new)
    source=source.replace('    identifier = get(w, 0) + 1\n','    identifier = get(w, 0) + 1\n    if identifier > get(w, META + 80):\n        return fail(w)\n')
    source=source.replace('                    kh = key_hash(s, w, kp, ke)\n','')
    wanted=('read64','get','put','fail','space','hex_digit','hex4','decoded','string_end','digit','number_end','append','value','close_container','parse')
    nodes=[node for node in ast.parse(source).body if isinstance(node,ast.FunctionDef) and node.name in wanted]
    assert {node.name for node in nodes}==set(wanted)
    class Relocate(ast.NodeTransformer):
        def visit_Call(self,node):
            self.generic_visit(node)
            if node.func.id=='node':node.args.insert(0,ast.Name('w',ast.Load()))
            if node.func.id in ('get','put') and isinstance(node.args[1],ast.Constant) and node.args[1].value in range(0,80,8):
                node.args[1]=ast.BinOp(ast.Name('P',ast.Load()),ast.Add(),node.args[1])
            if node.func.id=='fill_range' and isinstance(node.args[1],ast.Constant) and node.args[1].value==0:
                assert node.args[2].value==7168;node.args[1]=ast.Name('P',ast.Load());node.args[2]=ast.Constant(80)
            return node
        def visit_Compare(self,node):
            self.generic_visit(node)
            if isinstance(node.left,ast.Name) and node.left.id=='depth' and len(node.comparators)==1 and isinstance(node.comparators[0],ast.Constant) and node.comparators[0].value==128:
                node.comparators[0]=ast.parse('get(w, META + 88)',mode='eval').body
            return node
        def visit_Assign(self,node):
            self.generic_visit(node)
            if len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='frame':
                assert isinstance(node.value,ast.BinOp) and node.value.left.value==1024
                node.value.left.value=65536
            return node
    adapted=[Relocate().visit(node) for node in nodes]
    return '\n\n'.join(ast.unparse(ast.fix_missing_locations(node)) for node in adapted)+'\n',sha(raw)

def init_fields():
    source='\ndef init_fields(w:mutbuf) -> u64:\n';at=33792
    for index,text in FIELDS.items():
        raw=text.encode();source+=f'    put(w, FIELDS + {index*16}, {at})\n    put(w, FIELDS + {index*16+8}, {len(raw)})\n'
        for pos in range(0,len(raw),8):source+=f'    put(w, {at+pos}, {int.from_bytes(raw[pos:pos+8].ljust(8,b"\0"),"little")})\n'
        at+=(len(raw)+7)//8*8
    return source+'    return 0\n'

def generate(args):
    sys.dont_write_bytecode=True;sys.path.insert(0,str(args.hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    parser,parser_sha=parser_source(args.catalog)
    source=(ROOT/'params.pseudo').read_text()+'\n'+parser+init_fields()
    constants={'P':16384,'META':8192,'FIELDS':32768,'INPUT_MAGIC':int.from_bytes(b'HBLPAR01','little'),
               'OUTPUT_MAGIC':int.from_bytes(b'HBLPAT01','little'),'GRAPH_MAGIC':int.from_bytes(b'HIABELL1','little')}
    class Constants(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in constants:return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
    nodes=[Constants().visit(node) for node in ast.parse(source).body]
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([p.annotation.id for p in node.args.args],node.returns.id) for node in nodes}
    raw=(args.runtime/'native/serde_json.hepta').read_bytes();assert sha(raw)==SERDE_SHA
    originals={fn['name']:fn for fn in assemble_program(raw).as_dict()['functions']}
    closure={'f3'};pending=['f3']
    while pending:
        for block in originals[pending.pop()]['blocks']:
            for op in block['ops']:
                if op['op']=='call' and op['attrs']['function'] not in closure:
                    closure.add(op['attrs']['function']);pending.append(op['attrs']['function'])
    relocation={old:'f'+str(len(nodes)+i) for i,old in enumerate(sorted(closure,key=lambda name:int(name[1:])))}
    names['classify']=relocation['f3'];signatures['classify']=([p['type'] for p in originals['f3']['params']],originals['f3']['returns'][0])
    imported=[]
    for old,new in relocation.items():
        fn=copy.deepcopy(originals[old]);fn['name']=new
        for block in fn['blocks']:
            for op in block['ops']:
                if op['op']=='call':op['attrs']['function']=relocation[op['attrs']['function']]
        imported.append(fn)
    class Bulk(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call) and node.func.id=='copy_workspace':
                dst,src,dp,sp,count=[self.expr(value) for value in node.args]
                loan=self.op('borrow.read',[src],'readbuf')
                self.op('buffer.copy_range',[dst,loan,self.cast(dp,'usize'),self.cast(sp,'usize'),self.cast(count,'usize')])
                self.op('loan.end',[loan]);return None
            return super().expr(node)
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Bulk(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    doc=compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'bellman_params','functions':functions+imported})
    doc['functions']=doc['functions'][:len(functions)]+imported
    encoded=render_assembly(doc).encode();assert assemble_program(encoded).as_dict()==doc
    stats={'functions':len(doc['functions']),'blocks':sum(len(f['blocks']) for f in doc['functions']),
           'operations':sum(len(b['ops']) for f in doc['functions'] for b in f['blocks'])}
    assert stats['functions']<=128 and stats['blocks']<=1536 and stats['operations']<=8192,stats
    assert all(len(f['blocks'])<=256 for f in doc['functions'])
    assert all(len(b['params'])<=16 for f in doc['functions'] for b in f['blocks'])
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'bellman_params.hepta').write_bytes(encoded)
    (args.output/'bellman_params.author.txt').write_text(source)
    (args.output/'bellman_params.names.json').write_text(json.dumps(names,indent=2)+'\n')
    proof={'schema':'hepta.runtime.bellman-params-composition.v1','source_sha256':sha(encoded),'source_bytes':len(encoded),
           'catalog_parser_author_sha256':parser_sha,'serde_source_sha256':SERDE_SHA,'numeric_relocation':relocation,
           'numeric_original_functions':{name:sha(canonical(originals[name])) for name in relocation},
           'numeric_import_changes':['function names and direct call targets'],
           'parser_changes':['dynamic stack/node arena','canonical unique ascending map keys','count bound preflight','parser state relocation'],
           'native_qualified':False,'whole_runtime_replaced':False,**stats}
    (args.output/'bellman_params.composition.json').write_text(json.dumps(proof,indent=2)+'\n')
    return proof
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('hepta','runtime','catalog','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(json.dumps(generate(args),sort_keys=True))
