from pathlib import Path
import json,sys,hashlib
import argparse
p=argparse.ArgumentParser(description='Inspect all source-registered routes without claiming runtime qualification')
p.add_argument('--source',type=Path,required=True);p.add_argument('--hepta',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
args=p.parse_args();R=args.source.resolve(strict=True)
if args.output.exists():raise ValueError('fresh source inspection output required')
sys.path.insert(0,str(args.hepta.resolve(strict=True)))
from hepta.hia_agent_assembly import assemble_program
raw=(R/'native/runtime_mcp.hepta').read_bytes();program=assemble_program(raw).as_dict();functions={f['name']:f for f in program['functions']}
needed=set();todo=['f29']
while todo:
 name=todo.pop()
 if name in needed:continue
 needed.add(name)
 for block in functions[name]['blocks']:
  for op in block['ops']:
   if op['op']=='call':todo.append(op['attrs']['function'])
allowed={'f29','f31','f43','f70','f75','f83','f84','f94','f97'}
if needed!=allowed:raise ValueError('exact classifier closure changed')
steps=0
def execute(name,args):
 global steps
 fn=functions[name];blocks={b['id']:b for b in fn['blocks']};at=fn['entry'];env={}
 while True:
  b=blocks[at]
  if len(args)!=len(b['params']):raise ValueError('classifier phi arity')
  env.update({p['name']:v for p,v in zip(b['params'],args)})
  for op in b['ops']:
   steps+=1
   if steps>2000000:raise ValueError('source classifier inspection bound')
   tag=op['op'];a=[env[n]for n in op['args']]
   if tag=='const':value=op['attrs']['value']
   elif tag=='call':value=execute(op['attrs']['function'],a)
   elif tag=='buffer.load':
    if not 0<=a[1]<len(a[0]):raise ValueError('source classifier bounds')
    value=a[0][a[1]]
   elif tag=='compare.eq':value=a[0]==a[1]
   elif tag=='compare.ne':value=a[0]!=a[1]
   elif tag=='compare.lt':value=a[0]<a[1]
   elif tag=='bit.or':value=a[0]|a[1]
   elif tag=='int.add.wrap':value=a[0]+a[1]
   elif tag=='int.mul.wrap':value=a[0]*a[1]
   elif tag=='int.shl.checked':
    if not 0<=a[1]<64:raise ValueError('checked classifier shift')
    value=a[0]<<a[1]
   elif tag=='int.cast':value=a[0]
   elif tag=='select':value=a[1]if a[0]else a[2]
   else:raise ValueError('unhandled source classifier op '+tag)
   if len(op['out'])!=1:raise ValueError('classifier output arity')
   item=op['out'][0];typ=item['type']
   if typ in ('u8','u32','u64','usize'):value=int(value)&((1<<{'u8':8,'u32':32,'u64':64,'usize':64}[typ])-1)
   elif typ!='bool':raise ValueError('unhandled classifier output type '+typ)
   env[item['name']]=value
  term=b['term'];tag=term['op']
  if tag=='ret':return env[term['values'][0]]
  if tag=='branch':term=term['then']if env[term['cond']]else term['else']
  elif tag!='jump':raise ValueError('classifier terminator '+tag)
  args=[env[n]for n in term['args']];at=term['target']
catalog=(R/'tests/hia_native/catalog_policy_ci/source/catalog-input.json').read_bytes()
tools=json.loads(catalog);rows=[]
for tool in tools:
 name=tool['name'];b=name.encode();kind=execute('f29',[b,0,len(b)])
 rows.append({'name':name,'source_kind':kind,'source_registered':kind!=0})
registered=[r for r in rows if r['source_registered']];missing=[r['name']for r in rows if not r['source_registered']]
if len(rows)!=136 or len(registered)!=16 or len(missing)!=120:raise ValueError(('exact source route domain',len(rows),registered))
doc={'schema':'hepta.runtime.public-read.source-route-frontier.v1','source_sha256':hashlib.sha256(raw).hexdigest(),'complete_declaration_sha256':hashlib.sha256(catalog).hexdigest(),'declaration_count':136,'source_registered_count':16,'source_unregistered_count':120,'source_classifier_entry':'f29','source_classifier_complete_function_closure':sorted(needed),'inspection_operation_count':steps,'method':'bounded read-only evaluation of the actual complete HIA classifier AST; not runtime qualification','full_136_handlers_qualified':False,'source_registered':registered,'source_unregistered':missing,'rows':rows}
args.output.write_text(json.dumps(doc,sort_keys=True,indent=2)+'\n')
print('ACTUAL_SOURCE_ROUTES',json.dumps(registered,sort_keys=True),'UNREGISTERED',len(missing))
