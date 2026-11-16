"""Complete source, compiler process and actual packed bytes; no execution."""
from __future__ import annotations
import json,struct
from pathlib import Path
from worker_common import BASE,COMPILER_COMMIT,COMPILER_IMAGE,document,read,require,sha,source_evidence,process_evidence
from worker_compiler_custody import compiler_sources,compile_receipt
from author_worker_bridge import ROLES,ASSEMBLY
from worker_export_evidence import source_evidence as export_source_evidence

EXPECTED_EXTRA={'old-core':('native/bellman_core.hepta','209775ceec2d22211b88d68b2a0ca7004d3eb8b4309f2512ed51775f50475288'),
                'commitment':('native/bellman_commitment.hepta','06ecade6dea623d3a88825b757bbf411889eb66b1c3b49a7bc223e38d425dff2'),
                'worker-packer-bridge':('native/bellman_worker_packer.hepta','c6288c2cc14cb0d43d0c571ed31ae97da2d6494fd056d1fba1a6d105e7abc21c')}

def verify_build(capture,root,pins):
    sources=source_evidence(root,pins);export_source_evidence(root)
    record=document(capture/'native-build.json');require(record['source_pins_sha256']==pins,'build source binding')
    require(record['status']=='FRESH_HIA_AND_ACTUAL_PACK_PASS' and record['public_handler_qualified'] is False,'build status/scope')
    require(record['fresh_bootstrap'] is not record['reused_verified_bootstrap'] and record['matching_source_cold_qualified'] is False,'bootstrap claims')
    bootstrap=document(capture/'build/bootstrap/bootstrap.json');dependency=bootstrap['dependency']
    require(record['compiler_source_identity']==dependency,'fresh compiler dependency')
    compiler=compiler_sources(capture,dependency)
    compiler_input=read(capture/'compiler-source/examples/hia_bootstrap/selfhost.hepta')
    require(bootstrap['compiler_source_sha256']==sha(compiler_input),'compiler actual source')
    previous=read(capture/'build/bootstrap/B0.so');seed=document(capture/'build/bootstrap/B0.receipt.json')
    require(bootstrap['seed_receipt']==seed and seed['artifact_sha256']==sha(previous) and seed['artifact_bytes']==len(previous),'seed complete bytes')
    for i in range(1,4):
        stage='B'+str(i);receipt=compile_receipt(capture,'build/bootstrap',stage,previous,compiler_input,stage+'.image.bin','seed-shared' if i==1 else 'flat-x86-64')
        require(receipt==bootstrap['generation_receipts'][i-1],'bootstrap actual generation receipt')
        previous=read(capture/'build/bootstrap'/(stage+'.image.bin'));require(sha(previous)==COMPILER_IMAGE,'bootstrap fixed point')
    require(bootstrap['generation_sha256']==COMPILER_IMAGE and bootstrap['matching_source_cold_qualified'] is False,'bootstrap fixed domain')
    expected={v[0]:(v[1],v[3]) for v in ROLES.values()}|EXPECTED_EXTRA
    require(set(record['modules'])==set(expected),'exact native image set')
    require({p.name for p in (capture/'build/modules').iterdir()}==set(expected),'unclaimed native image directory')
    manifests={};images={}
    for name,(source,image_sha) in expected.items():
        row=record['modules'][name];folder='build/modules/'+name
        require(row=={'source':source,'manifest':folder+'/manifest.json'},'image path binding')
        manifest=document(capture/row['manifest']);body=read(root/source)
        profile=None if name=='worker-packer-bridge' else 'serde-json.v1'
        limits=(8<<20,8<<20,32<<20) if profile is None else (16<<20,64<<20,256<<20)
        expected_manifest={'schema':'hepta.runtime.native-module.v1','abi':'hepta.runtime.borrowed-bytes.linux-x86_64.v1',
                         'name':name,'source':name+'.hepta','source_sha256':sha(body),'image':'module.image.bin','image_sha256':image_sha,
                         'compiler_sha256':COMPILER_IMAGE,'compiler_commit':COMPILER_COMMIT,'standalone':None,'target':'linux-x86_64',
                         'input_capacity':limits[0],'output_capacity':limits[1],'workspace_capacity':limits[2],
                         'qualification':'development_fixed_point'}
        if profile is not None:expected_manifest['buffer_profile']=profile
        require(manifest==expected_manifest,'module manifest differs: '+name)
        require(read(capture/folder/(name+'.hepta'))==body,'retained module source')
        receipt=compile_receipt(capture,folder,'module',previous,body,'module.image.bin','flat-x86-64')
        build=document(capture/folder/'build.json')
        require(build=={'compile_receipt':receipt,'compiler_dependency':dependency,'whole_runtime_replaced':False},'module actual build receipt')
        image=read(capture/folder/'module.image.bin');require(sha(image)==image_sha,'module exact image')
        manifests[name]=manifest;images[name]=image
    bridge=capture/'bridge';actual=document(bridge/'component.json');fixed=document(root/'native/bellman_worker_component.json')
    require(sha(read(bridge/'component.json'))==record['component_sha256'],'component receipt identity')
    for key in ['schema','status','prefix_hex','prefix_bytes','prefix_sha256','gaps','executable_bytes','executable_sha256','exports','sources','packer','source_author_sha256','runtime_python_required','runtime_rust_required','dynamic_loader','actual_worker_qualified','public_handler_qualified']:
        require(actual[key]==fixed[key],'fixed bridge semantic profile changed: '+key)
    for path in ASSEMBLY:
        raw=read(bridge/'source'/path);require(raw==read(root/path),'assembler input changed')
    for role,(name,source,source_sha,image_sha) in ROLES.items():
        member=actual['members'][role];require(member['manifest']==manifests[name],'assembler runtime manifest')
        require(member['manifest_sha256']==sha(read(capture/record['modules'][name]['manifest'])),'assembler manifest bytes')
        for key in ['source','source_sha256','image_sha256','image_bytes','offset']:require(member[key]==fixed['members'][role][key],'member layout differs')
    labels=['as-version','ld-version','objcopy-version','nm-version','assemble','link','flat','symbols']
    require({p.stem for p in (bridge/'processes').glob('*.json')}==set(labels),'assembler process set')
    records={name:document(bridge/'processes'/(name+'.json')) for name in labels};origin=records['assemble']['cwd'];tools=actual['assembler_tools']
    generated='.intel_syntax noprefix\n.include "bellman_worker_adapter.S"\n'
    for role,(name,source,source_sha,image_sha) in ROLES.items():
        member_path=Path(origin).parent/'build/modules'/name/'module.image.bin'
        generated+=f'\n.p2align 4,0\n.global bwx_{role}_entry\nbwx_{role}_entry:\n.incbin "{member_path}"\n'
    generated+='\n.section .note.GNU-stack,"",@progbits\n'
    require(read(bridge/'assembled.S')==generated.encode(),'complete assembler source differs')
    commands={name+'-version':[tools[name]['path'],'--version'] for name in ['as','ld','objcopy','nm']}
    commands.update(assemble=[tools['as']['path'],'--64','-I',origin+'/source/scripts',origin+'/assembled.S','-o',origin+'/adapter.o'],
                    link=[tools['ld']['path'],'--build-id=none','-e','_start','-Ttext=0x4000b0','-o',origin+'/adapter-linked.elf',origin+'/adapter.o'],
                    flat=[tools['objcopy']['path'],'-O','binary','--only-section=.text',origin+'/adapter-linked.elf',origin+'/flat.bin'],
                    symbols=[tools['nm']['path'],'-n','-P',origin+'/adapter-linked.elf'])
    for name in labels:
        r=process_evidence(bridge,name,commands[name],30 if name.endswith('-version') or name=='symbols' else 60)
        require(r['cwd']==origin and r['parent_pid']==record['pid'],'actual assembler parent custody')
    symbols={row[0]:int(row[2],16) for line in read(bridge/'processes/symbols.stdout').decode().splitlines() if len(row:=line.split())>=3 and row[1].lower() in {'t','a'}}
    require(symbols['_start']==0x4000b0,'fixed ELF entry')
    for name,entry in actual['exports'].items():require(entry=={'offset':symbols[name]-0x400000},'callable export actual symbol')
    prefix=bytes.fromhex(actual['prefix_hex']);require(len(prefix)==actual['prefix_bytes'] and sha(prefix)==actual['prefix_sha256'],'fixed mechanical prefix')
    executable=bytearray(prefix);cursor=len(prefix)
    for role,(name,source,source_sha,image_sha) in ROLES.items():
        offset=actual['members'][role]['offset'];require(symbols['bwx_'+role+'_entry']-0x400000==offset,'actual member symbol')
        require(offset>=cursor,'overlapping member');executable.extend(bytes(offset-cursor));executable.extend(images[name]);cursor=len(executable)
    executable=bytes(executable)
    require(len(executable)==actual['executable_bytes'] and sha(executable)==record['executable_sha256']==actual['executable_sha256'],'actual complete ELF identity')
    require(read(bridge/'expected.bin')==read(bridge/'bellman-worker.elf')==executable,'actual HIA output differs from assembler')
    require(read(bridge/'flat.bin')==executable[176:],'assembler flat body differs')
    require(read(bridge/'adapter.o')[:4]==read(bridge/'adapter-linked.elf')[:4]==b'\x7fELF','actual assembler products')
    expected_input=b'HBPWPK01'+struct.pack('<5Q',*[len(images[v[0]]) for v in ROLES.values()])+b''.join(images[v[0]] for v in ROLES.values())
    frame=read(bridge/'pack.input.bin');output=read(bridge/'pack.output.bin');workspace=read(bridge/'pack.workspace.bin');pack=document(bridge/'pack.receipt.json')
    require(frame==expected_input and output==executable+bytes([0xa5])*4096 and workspace==bytes([0x5a])*64,'complete actual HIA pack buffers')
    require(pack=={'status':'ACTUAL_HIA_PACK_PASS','code':len(executable),'input_bytes':len(frame),'input_sha256':sha(frame),
                  'output_bytes':len(output),'output_sha256':sha(output),'workspace_sha256':sha(workspace),
                  'packer_manifest_sha256':sha(read(capture/record['modules']['worker-packer-bridge']['manifest'])),
                  'packer_image_sha256':EXPECTED_EXTRA['worker-packer-bridge'][1],'executable_sha256':sha(executable),
                  'actual_worker_qualified':False,'public_handler_qualified':False},'actual HIA pack receipt differs')
    return {'status':'READ_ONLY_BUILD_PASS','runtime_images':5,'reference_images':2,'packer_images':1,
            'compiler_source_files':len(compiler['files']),'source_files':len(sources['files']),
            'complete_executable_bytes':len(executable),'executable_sha256':sha(executable),
            'fresh_bootstrap':record['fresh_bootstrap'],'reused_verified_bootstrap':record['reused_verified_bootstrap'],
            'native_or_rust_executed':False,'public_handler_qualified':False}
