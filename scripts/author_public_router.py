#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Development authoring of the fixed installed-config tool registry."""
from pathlib import Path
import ast,copy,hashlib,json,re,sys
ROOT=Path(__file__).resolve().parents[1]
if '--hepta' in sys.argv:
    sys.path.insert(0, str(Path(sys.argv[sys.argv.index('--hepta') + 1]).resolve(strict=True)))
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from hepta.hia_agent_assembly import assemble_program,render_assembly
sha=lambda b:hashlib.sha256(b).hexdigest()
canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()

class BulkBuilder(Builder):
    def expr(self,node):
        if isinstance(node,ast.BinOp) and isinstance(node.op,(ast.FloorDiv,ast.Mod)):
            a,b=self.expr(node.left),self.expr(node.right)
            return self.op('int.div.checked' if isinstance(node.op,ast.FloorDiv) else 'int.rem.checked',[a,b],a[1])
        if isinstance(node,ast.Call) and node.func.id=='copy_range':
            a=[self.expr(v) for v in node.args]
            if a[0]==a[1]:return self.op('buffer.move_within',[a[0],*(self.cast(v,'usize') for v in a[2:])])
            source=a[1]
            if source[1]=='mutbuf':source=self.op('borrow.read',[source],'readbuf')
            result=self.op('buffer.copy_range',[a[0],source,*(self.cast(v,'usize') for v in a[2:])])
            if a[1][1]=='mutbuf':self.op('loan.end',[source])
            return result
        borrowed={'work_utf8':'utf8','work_next':'next_scalar','work_hashed':'hashed'}
        if isinstance(node,ast.Call) and node.func.id in borrowed:
            a=[self.expr(v) for v in node.args];source=self.op('borrow.read',[a[0]],'readbuf')
            name=borrowed[node.func.id]
            result=self.op('call',[source,*a[1:]],self.signatures[name][1],function=self.names[name])
            self.op('loan.end',[source]);return result
        return super().expr(node)

def emit(source,literals,dependencies):
    data=bytearray();positions={}
    for key,value in literals.items():
        raw=value.encode();positions[key]=(4096+len(data),len(raw));data.extend(raw)
    while len(data)%8:data.append(0)
    assert len(data)+4096<32768
    lines=['def install_literals(w:mutbuf) -> u64:']
    for start in range(0,len(data),1024):lines.append(f'    literal_chunk_{start}(w)')
    lines+=['    return 0','']
    for start in range(0,len(data),1024):
        lines.append(f'def literal_chunk_{start}(w:mutbuf) -> u64:')
        for at in range(start,min(start+1024,len(data)),8):lines.append(f'    put(w, {4096+at}, {int.from_bytes(data[at:at+8],"little")})')
        lines+=['    return 0','']
    for name,col in [('literal_start',0),('literal_size',1)]:
        lines.append(f'def {name}(code:u64) -> u64:')
        for key,span in positions.items():lines += [f'    if code == {key}:',f'        return {span[col]}']
        lines+=['    return 0','']
    lines+=['def literal(o:mutbuf, w:mutbuf, code:u64) -> u64:',
            '    return append_span(o, o, w, 2, literal_start(code), literal_size(code))']
    # append_span takes readbuf first, so use direct workspace-copy emitter.
    lines=lines[:-2]+['def literal(o:mutbuf, w:mutbuf, code:u64) -> u64:',
          '    start = literal_start(code)','    size = literal_size(code)','    at = get(w, CURSOR)',
          '    if get(w, WRITING) == 1:','        copy_range(o, w, at, start, size)',
          '    put(w, CURSOR, at + size)','    return 0','']
    source+='\n'+'\n'.join(lines)
    constants={'INVALID':0xffffffff,'CAPACITY':0xfffffffe,'CALL':0xffffffe0,'PLAN':512,'CURSOR':256,'WRITING':264,
       'CHILD_REQUEST':33550336,'CHILD_RESULT':100667392,'CANONICAL_FRAME':33554432,'CANONICAL_DATA':33554456,
       **{name:int.from_bytes(value,'little')for name,value in {'ADMISSION_MAGIC':b'HRCNS001','PROJECTION_MAGIC':b'HRCJR001','OWNER_QUERY':b'HRCFGQ01','OWNER_RESULT':b'HRCFGM01','CALL_MAGIC':b'HIACAL01','EXECUTION_MAGIC':b'HXSREQ01'}.items()}}
    source=re.sub(r'\b('+'|'.join(constants)+r')\b',lambda m:str(constants[m[0]]),source)
    nodes=ast.parse(source).body;names={n.name:'f'+str(i)for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id)for n in nodes}
    raw=(ROOT/'native/text_budget.hepta').read_bytes();old={f['name']:f for f in assemble_program(raw).as_dict()['functions']}
    aliases={'read64':'f14','get':'f15','put':'f16'};relocation={f:'f'+str(len(nodes)+i)for i,f in enumerate(aliases.values())};imports=[]
    for alias,name in aliases.items():
        f=copy.deepcopy(old[name]);f['name']=relocation[name];imports.append(f);names[alias]=f['name'];signatures[alias]=([p['type']for p in f['params']],f['returns'][0])
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=BulkBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(p)for p in b.params],returns=[b.returns],effects=['read','write','trap'],entry='b0',blocks=b.blocks))
    doc=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module='public_tool_dispatch',functions=functions+imports));doc['functions']=doc['functions'][:len(functions)]+imports
    output=render_assembly(doc).encode();parsed=assemble_program(output).as_dict()
    for name,new in relocation.items():
        f=copy.deepcopy(next(f for f in parsed['functions']if f['name']==new));f['name']=name;assert f==old[name]
    (ROOT/'native/public_tool_dispatch.hepta').write_bytes(output)
    (ROOT/'scripts/public_tool_dispatch_authoring.txt').write_text(source)
    record={'schema':'hepta.runtime.public-registry-source.v1','source_sha256':sha(output),'functions':names,
      'imports':[{'source':'native/text_budget.hepta','source_sha256':sha(raw),'relocation':relocation,'functions':{k:sha(canonical(old[k]))for k in relocation}}],
      'source_dependencies':dependencies,'literals':literals,'fixed_children':[0,6],'public_request_audit_closed':False,'production_activated':False}
    (ROOT/'native/public_tool_dispatch_composition.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'source_sha256':sha(output),'bytes':len(output),'functions':len(parsed['functions']),'blocks':sum(len(f['blocks'])for f in parsed['functions'])}))

def main():
    common_path=ROOT/'scripts/public_emitter_source.py.txt';common=common_path.read_text()
    names={'emit','append_span','quoted','span_byte'}
    common='\n\n'.join(ast.get_source_segment(common,n)for n in ast.parse(common).body if n.name in names)
    literals={11:'{"jsonrpc":"2.0","id":',12:',"result":',13:',"error":',25:'{"code":-32601,"message":',
      30:'{}',31:'{"completion":{"values":[]}}',32:'{"prompts":[]}',33:'{"resources":[]}',34:'{"resourceTemplates":[]}',
      40:'{}',41:'{"resultType":"complete","completion":{"values":[]}}',42:'{"resultType":"complete","prompts":[]}',
      43:'{"resultType":"complete","ttlMs":0,"cacheScope":"private","resources":[]}',
      44:'{"resultType":"complete","resourceTemplates":[]}',
      50:'{"content":[{"type":"text","text":',51:'{"resultType":"complete","content":[{"type":"text","text":',
      52:'}],"isError":false}',53:'}],"isError":true}',54:'{"code":-32602,"message":"tool not found in this runtime mode"}',
      60:'host_list',61:'effective_config',62:'execution_shadow_admit',
      63:'failed to deserialize parameters: unknown field `',64:'`, there are no fields'}
    catalog=ROOT/'tests/hia_native/public_registry_catalog.json';data=json.loads(catalog.read_bytes());literals[35]=data['legacy'];literals[45]=data['modern']
    emit((ROOT/'scripts/public_router_source.py.txt').read_text()+'\n'+common,literals,
         [{'path':common_path.relative_to(ROOT).as_posix(),'sha256':sha(common_path.read_bytes())},{'path':'tests/hia_native/public_registry_catalog.json','sha256':sha(catalog.read_bytes())}])
if __name__=='__main__':main()
