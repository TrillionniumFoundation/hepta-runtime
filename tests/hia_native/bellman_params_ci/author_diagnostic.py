"""Author exact typed diagnostic bytes using the existing Unicode and f64 owners."""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from author_params import parser_source,FIELDS,SERDE_SHA
EXECUTION_SHA='d1e1610120fcadd72960f04b742ad6bfcfc3bc430a2b828463f3ab2af1268f14'
TEXT={1:'invalid type: ',2:'invalid value: ',3:'invalid length ',4:'missing field `',
      5:'unknown field `',6:'unknown variant `',7:', expected ',9:'integer `',10:'floating point `',
      11:'null',12:'boolean `false`',13:'boolean `true`',14:'string ',15:'sequence',16:'map'}
EXPECTED={1:'struct BellmanPlanParams',2:'a sequence',3:'struct BellmanState',4:'an array of length 6',
          5:'internally tagged enum BellmanAction',6:'variant identifier',7:'f64',8:'struct BellmanBranch',9:'u32',
          10:'struct variant BellmanAction::Terminal',11:'struct variant BellmanAction::Continue',
          12:'struct BellmanPlanParams with 1 element',13:'struct BellmanState with 1 element',
          14:'struct BellmanBranch with 4 elements',15:'struct variant BellmanAction::Terminal with 1 element',
          16:'struct variant BellmanAction::Continue with 1 element',17:'fewer elements in array',
          18:'1 element in sequence',19:'4 elements in sequence'}
TEXT.update({100+k:v for k,v in EXPECTED.items()})
TEXT.update({200+k:v for k,v in FIELDS.items() if k<=9})
TEXT.update({301:'`states`',302:'`actions`',303:'`value`',304:'`branches`',
             305:'one of `probability`, `successor`, `reward`, `fee`',306:'`terminal` or `continue`'})
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def literals():
    source='\ndef init_literals(w:mutbuf) -> u64:\n';at=40960
    for index,text in sorted(TEXT.items()):
        raw=text.encode();source+=f'    put(w, {32768+index*16}, {at})\n    put(w, {32776+index*16}, {len(raw)})\n'
        for pos in range(0,len(raw),8):source+=f'    put(w, {at+pos}, {int.from_bytes(raw[pos:pos+8].ljust(8,b"\0"),"little")})\n'
        at+=(len(raw)+7)//8*8
    assert at<65536
    return source+'    return 0\n'
def generate(args):
    sys.path.insert(0,str(args.hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    parser,parser_sha=parser_source(args.catalog)
    helpers=[node for node in ast.parse(parser).body if node.name in ('read64','get','put','hex_digit','hex4','decoded')]
    class HexRename(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id=='hex_digit':node.id='hex_input'
            return node
        def visit_FunctionDef(self,node):
            self.generic_visit(node)
            if node.name=='hex_digit':node.name='hex_input'
            return node
    helpers=[HexRename().visit(node) for node in helpers]
    source=(ROOT/'diagnostic.pseudo').read_text()+'\n'+'\n\n'.join(ast.unparse(node) for node in helpers)+literals()
    constants={'P':16384,'PARAMS_MAGIC':int.from_bytes(b'HBLPAT01','little'),'INPUT_MAGIC':int.from_bytes(b'HBLPAR01','little'),
               'OUTPUT_MAGIC':int.from_bytes(b'HBLPDR01','little')}
    class Constants(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in constants:return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
    nodes=[Constants().visit(node) for node in ast.parse(source).body]
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([p.annotation.id for p in node.args.args],node.returns.id) for node in nodes}
    imports=[];proof=[]
    for filename,aliases,expected in [('serde_json.hepta',{'format_bits':'f16'},SERDE_SHA),
        ('execution_json.hepta',{'needs_escape':'f13','short_escape':'f14','hex_digit':'f15','unicode_table':'f17'},EXECUTION_SHA)]:
        raw=(args.runtime/'native'/filename).read_bytes();assert sha(raw)==expected
        original={fn['name']:fn for fn in assemble_program(raw).as_dict()['functions']}
        closure=set(aliases.values());pending=list(closure)
        while pending:
            for block in original[pending.pop()]['blocks']:
                for op in block['ops']:
                    if op['op']=='call' and op['attrs']['function'] not in closure:
                        closure.add(op['attrs']['function']);pending.append(op['attrs']['function'])
        relocation={old:'f'+str(len(nodes)+len(imports)+i) for i,old in enumerate(sorted(closure,key=lambda n:int(n[1:])))}
        for alias,old in aliases.items():
            names[alias]=relocation[old];signatures[alias]=([p['type'] for p in original[old]['params']],original[old]['returns'][0])
        for old,new in relocation.items():
            fn=copy.deepcopy(original[old]);fn['name']=new
            for block in fn['blocks']:
                for op in block['ops']:
                    if op['op']=='call':op['attrs']['function']=relocation[op['attrs']['function']]
            imports.append(fn)
        proof.append({'source':filename,'sha256':expected,'relocation':relocation,
                      'original_functions':{name:sha(canonical(original[name])) for name in relocation}})
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
    doc=compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'bellman_params_diagnostic','functions':functions+imports})
    doc['functions']=doc['functions'][:len(functions)]+imports
    raw=render_assembly(doc).encode();assert assemble_program(raw).as_dict()==doc
    stats={'functions':len(doc['functions']),'blocks':sum(len(f['blocks']) for f in doc['functions']),
           'operations':sum(len(b['ops']) for f in doc['functions'] for b in f['blocks'])}
    assert stats['functions']<=128 and stats['blocks']<=1536 and stats['operations']<=8192,stats
    assert all(len(f['blocks'])<=256 for f in doc['functions'])
    assert all(len(b['params'])<=16 for f in doc['functions'] for b in f['blocks'])
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'bellman_params_diagnostic.hepta').write_bytes(raw)
    (args.output/'bellman_params_diagnostic.author.txt').write_text(source)
    (args.output/'bellman_params_diagnostic.names.json').write_text(json.dumps(names,indent=2)+'\n')
    result={'schema':'hepta.runtime.bellman-params-diagnostic-composition.v1','source_sha256':sha(raw),'source_bytes':len(raw),
            'catalog_parser_author_sha256':parser_sha,'imports':proof,'allowed_import_changes':['function names and direct call targets'],
            'native_qualified':False,'whole_runtime_replaced':False,**stats}
    (args.output/'bellman_params_diagnostic.composition.json').write_text(json.dumps(result,indent=2)+'\n')
    return {k:v for k,v in result.items() if k!='imports'}
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('hepta','runtime','catalog','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(json.dumps(generate(args),sort_keys=True))
