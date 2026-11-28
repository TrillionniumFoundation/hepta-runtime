"""Fixed packer and artifact-refusal domains for the Local composition."""
import json
import struct
Q=lambda n:struct.pack('<Q',n)

def packer_cases(wire,extent):
    cases=[('exact',wire,extent,extent),('tail',wire,extent+37,extent),
           ('short-output',wire,extent-1,0xfffffffe),('zero-output',wire,0,0xfffffffe),
           ('magic',b'X'+wire[1:],extent,0xffffffff),
           ('opaque-child-byte',wire[:-1]+bytes([wire[-1]^1]),extent,extent)]
    cases.extend(('truncated-'+str(n),wire[:n],extent,0xffffffff)for n in(0,1,7,8,15,16,63,64,70))
    for index in range(7):
        at=8+8*index
        size=struct.unpack_from('<Q',wire,at)[0]
        for label,value in(('empty',0),('over-capacity',1048577),('wrong-sum',size+1)):
            cases.append((label+'-'+str(index),wire[:at]+Q(value)+wire[at+8:],extent,0xffffffff))
    cases.append(('trailing-byte',wire+b'x',extent,0xffffffff))
    assert len(cases)==37
    return cases

def artifact_mutations(members):
    edits=[('schema','manifest.json','json','schema','changed'),
           ('activation-bool','manifest.json','json','production_activated',True),
           ('activation-number','manifest.json','json','production_activated',0),
           ('compiler','manifest.json','json','compiler_sha256','0'*64)]
    for role in members:
        edits.extend([(role+'-source',role+'.hepta','append',None,None),
                      (role+'-image',role+'.image.bin','flip-last',None,None),
                      (role+'-capacity',role+'.json','json','workspace_capacity',0)])
    edits.extend([('elf','local-create-spec.elf','flip-first',None,None),
                  ('pack-input','pack.input.bin','flip-first',None,None),
                  ('pack-output-tail','pack.output.bin','flip-last',None,None),
                  ('pack-workspace-tail','pack.workspace.bin','flip-last',None,None),
                  ('pack-custody','pack.receipt.json','json','source_unchanged',False)])
    assert len(edits)==33
    return edits

def source_mutations(names):
    return [(name,name,'json','whole_runtime_replaced',True)if name.endswith('_component.json')
            else(name,name,'append',None,None)for name in names]

def mutated(raw,operation,field,value):
    if operation=='json':
        content=json.loads(raw);content[field]=value
        return(json.dumps(content,sort_keys=True,indent=2)+'\n').encode()
    if operation=='append':return raw+b'\n'
    if operation=='flip-first':return bytes([raw[0]^1])+raw[1:]
    if operation=='flip-last':return raw[:-1]+bytes([raw[-1]^1])
    raise ValueError(operation)

def packed(component,wire):
    prefix=bytes.fromhex(component['prefix_hex'])
    result=bytearray(prefix+wire[64:]);struct.pack_into('<QQ',result,96,len(result),len(result))
    result[component['table_offset']:component['table_offset']+56]=wire[8:64]
    return bytes(result)
