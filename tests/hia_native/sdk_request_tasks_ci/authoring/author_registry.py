"""Generate the private SDK task registry without reading expected wire data."""
from pathlib import Path
import argparse, ast, hashlib, json, re, sys
sys.dont_write_bytecode = True
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CONSTANTS = {name:int.from_bytes(value,'little') for name,value in {
    'INPUT_MAGIC':b'HRTKRQ02','OUTPUT_MAGIC':b'HRTKRS02','STATE_MAGIC':b'HRTKST02',
    'MESSAGE_MAGIC':b'HRCJR001','GROW_MAGIC':b'HGRWS002','REQUEST_ID_WORD':b'requestI'}.items()}
CONSTANTS.update(INVALID=0xffffffff,BUSY=0xfffffff8,RESOURCE=0xfffffffc,GROW=0xffffffd0)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','hepta'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--check',action='store_true');a=p.parse_args();source=a.source.resolve(strict=True)
    sys.path.insert(0,str(a.hepta.resolve(strict=True)));sys.path.insert(0,str(Path(__file__).parent))
    from tools.generate_hia_selfhost import Builder
    from lower_support import compile_delta, substitute
    previous=Builder.expr
    def expr(self,node):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='copy_range':
            values=[self.expr(x) for x in node.args]
            return self.op('buffer.copy_range',values[:2]+[self.cast(x,'usize') for x in values[2:]])
        return previous(self,node)
    Builder.expr=expr
    pseudo_path=source/'authoring/request_tasks.txt';pseudo=substitute(pseudo_path.read_text(),CONSTANTS)
    nodes=ast.parse(pseudo).body;assert all(isinstance(x,ast.FunctionDef) for x in nodes)
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)};assert names['entry']=='f0'
    empty=b'hia-asm.v1 hepta.hia.program.v8 sdk_request_tasks\nfn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\nblock b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n  v3:u32 = const() {"value":0}\n  ret(v3)\nend\n'
    raw,functions,retained=compile_delta(a.hepta,empty,{},pseudo,{'entry':'f0'},
        {name:value for name,value in names.items() if name!='entry'})
    assert not retained
    receipt=dict(schema='hepta.sdk-request-tasks.composition.v1',source_sha256=SHA(raw),source_bytes=len(raw),
        author_sha256=SHA(Path(__file__).read_bytes()),pseudo_sha256=SHA(pseudo_path.read_bytes()),
        lower_support_sha256=SHA((source/'authoring/lower_support.py').read_bytes()),functions=names,
        function_count=len(functions),constants=CONSTANTS,
        blocks=sum(len(f['blocks']) for f in functions.values()),
        instructions=sum(len(b['ops']) for f in functions.values() for b in f['blocks']),sdk='3.9.0',
        original_wire_used_as_implementation=False,
        required_message_source_sha256='e1ef0dd6bb5993f6ad07499ee68e5a63b1fbd4a97ebf0e17b89aec1234af6a6b',
        public_registry_integrated=False,full_async_runtime_qualified=False,full_sdk_qualified=False,
        production_activated=False,old_path_removed=False)
    outputs={'native/sdk_request_task_registry.hepta':raw,'native/sdk_request_task_composition.json':
        (json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()}
    for name,value in outputs.items():
        path=source/name
        if a.check:assert path.read_bytes()==value,name
        else:assert not path.exists();path.write_bytes(value)
    print(json.dumps(receipt,sort_keys=True))
if __name__=='__main__':main()
