"""Assemble fixed syscall plumbing and author an HIA-only five-image ELF packer."""
from __future__ import annotations
import argparse, ast, hashlib, json, os, shutil, struct, sys
from pathlib import Path

ROLES = {
    'pool': ('worker-pool', 'native/blocking_worker_pool.hepta', '47ee7d912dcdef231934090b92e2e5c7ec63dfec92b48dfea6fb32e952af86e4', 'f1ef21c80442877a00462f51cca30eecd291d603dcc8fcd6c5e81bc8d7d74bf6'),
    'core': ('timed-core', 'native/bellman_timed_core.hepta', '048a68392e6613d4dee375ca24791a541642ac10921756e32bcd7184e9f259b2', 'bf835df621e40e7cff65430c06bb292fd3f0323c0c2fc1870c0947ee1b0ca99d'),
    'commitment': ('timed-commitment', 'native/bellman_timed_commitment.hepta', '1129c2b35925ae3dc320af0521ff2740271a651e88fdf91bed821a5781e81019', 'e9c8af4b96683fed62d6c26093c20d65f7c395b4d4de3164248a8e3c64c5a5f7'),
    'elapsed': ('elapsed', 'native/bellman_elapsed.hepta', '7efb6b08505c79958437e97177e8e432bddc40f04e5f00b50b6a6a79c3c9de2b', '65e86c61bc305d495a423c8fa5551d3cbb8ca47eee7e90cec75095e9981c8dcd'),
    'result': ('result', 'native/bellman_result.hepta', '1d4ad5aaeab526a76509f3f330f2561b7fce69c64818fcfae6a5826e32fe733d', '187e206bba4a33e636490c4049fcc690c354e1f1525a08e4a58b8423d43d50aa'),
}
ASSEMBLY = ['scripts/bellman_worker_adapter.S', 'scripts/bellman_worker_common.S', 'scripts/bellman_worker_run.S', 'scripts/bellman_worker_callable_api.S']
MAGIC = int.from_bytes(b'HBPWPK01','little')

def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,x):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(x if isinstance(x,bytes) else (json.dumps(x,indent=2,sort_keys=True)+'\n').encode())

def member_inputs(root,build):
    members={}
    for role,(name,source,source_sha,image_sha) in ROLES.items():
        path=build/'modules'/name/'manifest.json';raw=path.read_bytes();m=json.loads(raw)
        source_bytes=(root/source).read_bytes();image=(path.parent/m['image']).read_bytes()
        assert sha(source_bytes)==source_sha==m['source_sha256']
        assert (path.parent/m['source']).read_bytes()==source_bytes
        assert sha(image)==image_sha==m['image_sha256']
        assert m['standalone'] is None and m['compiler_commit']=='d3e2c90173cf733e42b299d0c4274df4b593a12f'
        assert m['compiler_sha256']=='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
        members[role]={'manifest':m,'manifest_sha256':sha(raw),'source':source,'source_sha256':source_sha,
                       'image_sha256':image_sha,'image_bytes':len(image),'path':path.parent/m['image'],'raw':image}
    return members

def make_packer(root,hepta,prefix,members,gaps,extent):
    sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import render_assembly,_parse_assembly_document
    source='def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n'
    source+=f'    if length(s) != {48+sum(m["image_bytes"] for m in members.values())} or get(s, 0) != {MAGIC}:\n        return 4294967295\n'
    for i,m in enumerate(members.values()):
        source+=f'    if get(s, {8+i*8}) != {m["image_bytes"]}:\n        return 4294967295\n'
    source+=f'    if length(o) < {extent}:\n        return 4294967294\n'
    chunks=[prefix[i:i+512] for i in range(0,len(prefix),512)]
    for i in range(len(chunks)):source+=f'    prefix_{i}(o)\n'
    for begin,end in gaps:
        for i in range(begin,end):source+=f'    store(o, {i}, 0)\n'
    at=48
    for role,m in members.items():
        source+='    index = 0\n'
        source+=f'    while index < {m["image_bytes"]}:\n        store(o, {m["offset"]} + index, byte(s, {at} + index))\n        index = index + 1\n'
        at+=m['image_bytes']
    source+=f'    return {extent}\n'
    for i,chunk in enumerate(chunks):
        source+=f'\ndef prefix_{i}(o:mutbuf) -> u64:\n'
        j=0
        while j+8<=len(chunk):
            source+=f'    put(o, {i*512+j}, {int.from_bytes(chunk[j:j+8],"little")})\n';j+=8
        for n in range(j,len(chunk)):source+=f'    store(o, {i*512+n}, {chunk[n]})\n'
        source+='    return 0\n'
    source+='''
def get(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result
def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''
    nodes=ast.parse(source).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],'returns':[b.returns],
                          'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    doc=compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'bellman_worker_packer','functions':functions})
    raw=render_assembly(doc).encode();assert _parse_assembly_document(raw)==doc
    put(root/'native/bellman_worker_packer.hepta',raw)
    put(root/'native/bellman_worker_packer.author.txt',source.encode())
    return {'bytes':len(raw),'sha256':sha(raw),'functions':len(functions),'blocks':sum(len(f['blocks']) for f in doc['functions'])}

def author(root,hepta,build,output):
    output.mkdir(mode=0o700)
    sys.path.insert(0,str(root/'tests/hia_native/blocking_worker_ci'))
    from capture_writer_trace import run
    members=member_inputs(root,build)
    closure={}
    for path in ASSEMBLY:
        raw=(root/path).read_bytes();put(output/'source'/path,raw);closure[path]={'bytes':len(raw),'sha256':sha(raw)}
    generated='.intel_syntax noprefix\n.include "bellman_worker_adapter.S"\n'
    for role,m in members.items():
        generated+=f'\n.p2align 4,0\n.global bwx_{role}_entry\nbwx_{role}_entry:\n.incbin "{m["path"]}"\n'
    generated+='\n.section .note.GNU-stack,"",@progbits\n'
    put(output/'assembled.S',generated.encode())
    env=dict(os.environ);env.update(LC_ALL='C',LANG='C')
    tools={}
    for name in ['as','ld','objcopy','nm']:
        path=Path(shutil.which(name)).resolve(strict=True)
        tools[name]={'path':str(path),'sha256':sha(path.read_bytes())}
        run(output,name+'-version',[str(path),'--version'],env,limit=30)
    run(output,'assemble',[tools['as']['path'],'--64','-I',str(output/'source/scripts'),str(output/'assembled.S'),'-o',str(output/'adapter.o')],env,limit=60)
    run(output,'link',[tools['ld']['path'],'--build-id=none','-e','_start','-Ttext=0x4000b0','-o',str(output/'adapter-linked.elf'),str(output/'adapter.o')],env,limit=60)
    run(output,'flat',[tools['objcopy']['path'],'-O','binary','--only-section=.text',str(output/'adapter-linked.elf'),str(output/'flat.bin')],env,limit=60)
    run(output,'symbols',[tools['nm']['path'],'-n','-P',str(output/'adapter-linked.elf')],env,limit=30)
    symbols={row[0]:int(row[2],16) for line in (output/'processes/symbols.stdout').read_text().splitlines() if len(row:=line.split())>=3 and row[1].lower() in {'t','a'}}
    assert symbols['_start']==0x4000b0
    flat=(output/'flat.bin').read_bytes();extent=176+len(flat)
    header=b'\x7fELF\x02\x01\x01'+bytes(9)
    header+=struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
    header+=struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,extent,extent,4096)
    header+=struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16)
    assert len(header)==176
    expected=header+flat;cursor=symbols['bwx_pool_entry']-0x400000;prefix=expected[:cursor];gaps=[]
    for role,m in members.items():
        offset=symbols['bwx_'+role+'_entry']-0x400000;m['offset']=offset
        if offset>cursor:
            assert expected[cursor:offset]==bytes(offset-cursor);gaps.append([cursor,offset])
        assert expected[offset:offset+m['image_bytes']]==m['raw']
        cursor=offset+m['image_bytes']
    assert cursor==extent
    packer=make_packer(root,hepta,prefix,members,gaps,extent)
    component={'schema':'hepta.runtime.bellman-worker.component-development.v1','status':'SOURCE_ONLY_PASS',
               'sources':closure,'members':{role:{k:v for k,v in m.items() if k not in {'path','raw'}} for role,m in members.items()},
               'prefix_hex':prefix.hex(),'prefix_bytes':len(prefix),'prefix_sha256':sha(prefix),'gaps':gaps,
               'executable_bytes':extent,'executable_sha256':sha(expected),'packer':packer,'assembler_tools':tools,
               'source_author_sha256':sha(Path(__file__).read_bytes()),'runtime_python_required':False,'runtime_rust_required':False,
               'dynamic_loader':False,'actual_worker_qualified':False,'public_handler_qualified':False,
               'exports':{name:{'offset':symbols[name]-0x400000} for name in ['bellman_worker_init', 'bellman_worker_control', 'bellman_worker_poll', 'bellman_worker_receive', 'bellman_worker_release', 'bellman_worker_wake_fd', 'bellman_worker_shutdown', 'bellman_worker_destroy']}}
    put(output/'expected.bin',expected);put(output/'component.json',component);put(root/'native/bellman_worker_component.json',component)
    return {k:component[k] for k in ['status','prefix_bytes','prefix_sha256','executable_bytes','executable_sha256','packer']}

def pack(root,hepta,build,output):
    sys.path.insert(0,str(root/'scripts'))
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    component=json.loads((output/'component.json').read_bytes());members=member_inputs(root,build)
    for path,pin in component['sources'].items():
        raw=(root/path).read_bytes();assert len(raw)==pin['bytes'] and sha(raw)==pin['sha256']
    assert sha((root/'native/bellman_worker_packer.hepta').read_bytes())==component['packer']['sha256']
    frame=b'HBPWPK01'+struct.pack('<5Q',*[m['image_bytes'] for m in members.values()])+b''.join(m['raw'] for m in members.values())
    builder=NativeBuild(hepta,build)
    p=builder.compile('worker-packer-'+output.name,root/'native/bellman_worker_packer.hepta',standalone=None)
    with NativeModule(p,manifest_sha256=sha(p.read_bytes())) as module:
        code,out,workspace=module.invoke_raw(frame,output_capacity=component['executable_bytes']+4096,workspace_capacity=64,output_fill=0xa5,workspace_fill=0x5a)
        put(output/'pack.input.bin',frame);put(output/'pack.output.bin',out);put(output/'pack.workspace.bin',workspace)
        assert code==component['executable_bytes'] and out[:code]==(output/'expected.bin').read_bytes()
        assert sha(out[:code])==component['executable_sha256'] and out[code:]==bytes([0xa5])*4096 and workspace==bytes([0x5a])*64
        receipt={'status':'ACTUAL_HIA_PACK_PASS','code':code,'input_bytes':len(frame),'input_sha256':sha(frame),
                 'output_bytes':len(out),'output_sha256':sha(out),'workspace_sha256':sha(workspace),
                 'packer_manifest_sha256':sha(p.read_bytes()),'packer_image_sha256':module.metadata['image_sha256'],
                 'executable_sha256':sha(out[:code]),'actual_worker_qualified':False,'public_handler_qualified':False}
        put(output/'pack.receipt.json',receipt);put(output/'bellman-worker.elf',out[:code]);(output/'bellman-worker.elf').chmod(0o500)
        return receipt

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--phase',choices=['author','pack'],required=True)
    for name in ['source-root','hepta','build','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();args=[a.source_root.resolve(),a.hepta.resolve(),a.build.resolve(),a.output.resolve()]
    print(json.dumps((author if a.phase=='author' else pack)(*args),sort_keys=True))
