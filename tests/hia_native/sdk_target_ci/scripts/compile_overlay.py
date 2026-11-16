"""Compile selected HIA functions while retaining exact other function ASTs."""
from pathlib import Path
import ast, copy, hashlib, json, re, sys
sys.dont_write_bytecode=True
# The caller supplies the exact compiler path before importing this helper.
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from hepta.hia_agent_assembly import assemble_program,render_assembly

class NativeBuilder(Builder):
 def expr(self,node):
  if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
   name=node.func.id
   if name=='copy_range':
    args=[self.expr(arg) for arg in node.args];source=args[1]
    if source[1]=='mutbuf':source=self.op('borrow.read',[source],'readbuf')
    result=self.op('buffer.copy_range',[args[0],source,*(self.cast(v,'usize') for v in args[2:])])
    if args[1][1]=='mutbuf':self.op('loan.end',[source])
    return result
   if name in ('div','rem'):return self.op('int.'+name+'.checked',[self.expr(v) for v in node.args],'u64')
   if name in self.signatures:
    args=[self.expr(arg) for arg in node.args];loans=[];converted=[];signature=self.signatures[name]
    for value,kind in zip(args,signature[0]):
     if value[1]=='mutbuf' and kind=='readbuf':value=self.op('borrow.read',[value],'readbuf');loans.append(value)
     converted.append(self.cast(value,kind) if value[1]!=kind else value)
    result=self.op('call',converted,signature[1],function=self.names[name])
    for loan in loans:self.op('loan.end',[loan])
    return result
  return super().expr(node)

def compile_source(source,document,names,constants):
 source=re.sub(r'\b('+'|'.join(constants)+r')\b',lambda m:str(constants[m[0]]),source) if constants else source
 nodes=ast.parse(source).body;before={f['name']:f for f in document['functions']};names=dict(names)
 next_id=len(before)
 for node in nodes:
  if node.name not in names:names[node.name]='f'+str(next_id);next_id+=1
 signatures={alias:([p['type'] for p in before[name]['params']],before[name]['returns'][0]) for alias,name in names.items() if name in before}
 signatures.update({n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes})
 total=total_scalar_functions(nodes);generated=[]
 for node in nodes:
  b=NativeBuilder(node,names,signatures,total);b.statements(node.body)
  generated.append(dict(name=names[node.name],params=[b.param(v) for v in b.params],returns=[b.returns],effects=['read','write','trap'],entry='b0',blocks=b.blocks))
 own={f['name'] for f in generated};imports=[copy.deepcopy(f) for f in document['functions'] if f['name'] not in own]
 combined=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module=document['module'],functions=generated+imports))
 functions={f['name']:f for f in combined['functions'] if f['name'] in own};functions.update({f['name']:f for f in imports})
 combined['functions']=[functions[name] for name in sorted(functions,key=lambda x:int(x[1:]))]
 raw=render_assembly(combined).encode();assemble_program(raw)
 return raw,combined,names

def proof(before_raw,after_raw):
 before=assemble_program(before_raw).as_dict();after=assemble_program(after_raw).as_dict()
 old={f['name']:f for f in before['functions']};new={f['name']:f for f in after['functions']}
 sha=lambda raw:hashlib.sha256(raw).hexdigest()
 return {'schema':'hepta.runtime.string-performance-source.v1','baseline_sha256':sha(before_raw),'source_sha256':sha(after_raw),'source_bytes':len(after_raw),'changed_functions':[n for n in old if old[n]!=new[n]],'added_functions':[n for n in new if n not in old],'unchanged_functions':{n:sha(json.dumps(f,sort_keys=True,separators=(',',':')).encode()) for n,f in old.items() if f==new[n]},'functions':len(new),'blocks':sum(len(f['blocks']) for f in new.values()),'private_frames_changed':False,'deadlines_changed':False,'semantic_execution_qualified':False}
