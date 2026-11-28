"""Strict actual compiler, assembler and HIA pack evidence for the shared port."""
import hashlib,json,pathlib,struct,sys
sys.dont_write_bytecode=True
WORKER_PIN='3d9990db99ea9050696006d1ce2878558db38af31ac3b7ee5a3f69f6e1af16c3'
COMPILER='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
COMMIT='d3e2c90173cf733e42b299d0c4274df4b593a12f'
ROLES={
 'caller':('bellman_call','60fd0e797f20fb083de3d7d85c85750f5978284adf7eea5b04334c0bbb77c387','4d9563850062d4b88195d7a98d00477088c8576e68a6c997a083e1e6708c153e'),
 'params':('bellman_params_callable','239087c423062939a622bfda7d0ab1df3ae89a12079952c1d4abd84cdac3dea8','06cc0b09264353899946a28775a37162374cc9006ba5b54d1bb591f5ce8625d7'),
 'diagnostic':('bellman_diagnostic_callable','d35d8cd75e9ef0f8318ce907a835699e5a9b118c89b7b28fcd0ccf3757eabe08','2568407a2a207e9edc7ba433b7a12e0ab5756fd6f663546aadc2562ce68f5ac3'),
 'packer':('bellman_port_packer','162c02dc56de6d9fe977bab72ecea934e5fc091b1ea586cdba876ea66a42f532','e1d3fc8f240c273c9230b183b4b22c9b31901dae3e366b32927e4c8562eadd90'),
}
EXPORTS={'create':359,'attach':580,'detach':756,'service':1481,'wake_fd':1598,'ready_receive':1668,'ready_release':1845,'shutdown':2000,'destroy':2127,'invoke':2450,'owned':2469}
def sha(b):return hashlib.sha256(b).hexdigest()

def verify_build(build,source,worker_build,worker_source):
 sys.path.insert(0,str(worker_source/'tests/hia_native/blocking_worker'))
 from worker_build_evidence import verify_build as verify_worker
 from worker_compiler_custody import compiler_sources,compile_receipt
 from worker_common import read,document,process_evidence
 worker=verify_worker(worker_build,worker_source,WORKER_PIN)
 c=document(build/'component.json');assert c['source_sha256']=='e889fb0d5a4470cad7a5a92e91fb5a3b3dd15c422da261210f653328bca7444e'
 assert c['exports']==EXPORTS and c['runtime_hia_images']==8 and c['public_handler_qualified'] is False
 assert c['status']=='ASSEMBLED_DEVELOPMENT_CANDIDATE' and c['actual_hia_packer_pending'] is True
 assert read(build/'source/runtime_mcp_bellman_port.S')==read(source/'scripts/runtime_mcp_bellman_port.S')
 assert sha(read(source/'scripts/runtime_mcp_bellman_port.S'))==c['source_sha256']
 bootstrap=document(build/'build/bootstrap/bootstrap.json');dependency=bootstrap['dependency']
 compiler=compiler_sources(build,dependency);b3=read(build/'build/bootstrap/B3.image.bin')
 assert sha(b3)==COMPILER and b3==read(worker_build/'build/bootstrap/B3.image.bin')
 assert bootstrap['generation_sha256']==COMPILER and bootstrap['matching_source_cold_qualified'] is False
 for n in (1,2):assert read(build/f'build/bootstrap/B{n}.image.bin')==b3
 manifests={};images={}
 for role,(name,source_sha,image_sha) in ROLES.items():
  module='port-'+role;folder='build/modules/'+module
  manifest=document(build/folder/'manifest.json');body=read(source/'native'/(name+'.hepta'))
  assert sha(body)==source_sha and read(build/folder/(module+'.hepta'))==body
  limits=(8<<20,8<<20,32<<20) if role=='packer' else (16<<20,64<<20,256<<20)
  expected={'schema':'hepta.runtime.native-module.v1','abi':'hepta.runtime.borrowed-bytes.linux-x86_64.v1','name':module,'source':module+'.hepta','source_sha256':source_sha,'image':'module.image.bin','image_sha256':image_sha,'compiler_sha256':COMPILER,'compiler_commit':COMMIT,'standalone':None,'target':'linux-x86_64','input_capacity':limits[0],'output_capacity':limits[1],'workspace_capacity':limits[2],'qualification':'development_fixed_point'}
  if role!='packer':expected['buffer_profile']='serde-json.v1'
  assert manifest==expected
  receipt=compile_receipt(build,folder,'module',b3,body,'module.image.bin','flat-x86-64')
  assert document(build/folder/'build.json')=={'compile_receipt':receipt,'compiler_dependency':dependency,'whole_runtime_replaced':False}
  image=read(build/folder/'module.image.bin');assert sha(image)==image_sha;images[role]=image;manifests[role]=manifest
  if role!='packer':
   member=c['members'][role]
   assert member['manifest_sha256']==sha(read(build/folder/'manifest.json')) and member['source_sha256']==source_sha and member['image_sha256']==image_sha and member['bytes']==len(image)
 images['worker']=read(worker_build/'bridge/bellman-worker.elf');assert sha(images['worker'])=='6e68e9bb5a95513402e8555ba452d954a0fc51789b709d5a8d06523449a517c8'
 assert c['members']['worker']['verified_build']==worker and c['members']['worker']['image_sha256']==sha(images['worker']) and c['members']['worker']['bytes']==len(images['worker'])
 assert {p.name for p in (build/'build/modules').iterdir()}=={'port-'+k for k in ROLES}
 labels=['as-version','ld-version','objcopy-version','nm-version','assemble','link','flat','symbols']
 assert {p.stem for p in (build/'processes').glob('*.json')}==set(labels)
 records={name:document(build/'processes'/(name+'.json')) for name in labels};origin=records['assemble']['cwd'];parent=records['assemble']['parent_pid']
 tools={name:records[name+'-version']['command'][0] for name in ['as','ld','objcopy','nm']}
 commands={name+'-version':[path,'--version'] for name,path in tools.items()}
 commands.update(assemble=[tools['as'],'--64','-I',origin+'/source',origin+'/assembled.S','-o',origin+'/port.o'],link=[tools['ld'],'--build-id=none','-e','_start','-Ttext=0x4000b0','-o',origin+'/linked.elf',origin+'/port.o'],flat=[tools['objcopy'],'-O','binary','--only-section=.text',origin+'/linked.elf',origin+'/flat.bin'],symbols=[tools['nm'],'-n','-P',origin+'/linked.elf'])
 for name in labels:
  r=process_evidence(build,name,commands[name],60);assert r['cwd']==origin and r['parent_pid']==parent
 symbols={row[0]:int(row[2],16) for line in read(build/'processes/symbols.stdout').decode().splitlines() if len(row:=line.split())>=3 and row[1].lower() in {'t','a'}}
 assert symbols['_start']==0x4000b0
 for name,offset in EXPORTS.items():assert symbols['runtime_bellman_'+name]-0x400000==offset
 wc=document(worker_build/'bridge/component.json')
 generated='.intel_syntax noprefix\n.section .text\n.global _start\n_start:\n mov edi,64\n mov eax,231\n syscall\n ud2\n'
 for name,value in wc['exports'].items():generated+=f'.equ BWX_{name.removeprefix("bellman_worker_")}, {value["offset"]}\n'
 generated+='.include "runtime_mcp_bellman_port.S"\n'
 for role in ['caller','params','diagnostic','worker']:generated+=f'\n.p2align 4,0\n.global runtime_bellman_{role}_image\nruntime_bellman_{role}_image:\n.incbin "{c["members"][role]["path"]}"\n'
 generated+='\n.section .note.GNU-stack,"",@progbits\n';assert read(build/'assembled.S')==generated.encode()
 elf=read(build/'bellman-port.elf');extent=len(elf)
 header=b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
 header+=struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,extent,extent,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16)
 assert elf[:176]==header and elf[176:]==read(build/'flat.bin')
 assert sha(elf)==c['executable_sha256']=='006f3635c31ed8ac4a590933ce9081604d1353bebaacfb19ac92a0f91b243536' and extent==c['executable_bytes']
 cursor=c['members']['caller']['offset']
 for role in ['caller','params','diagnostic','worker']:
  member=c['members'][role];offset=member['offset'];assert offset==symbols['runtime_bellman_'+role+'_image']-0x400000 and offset>=cursor
  assert elf[cursor:offset]==bytes(offset-cursor) and elf[offset:offset+member['bytes']]==images[role];cursor=offset+member['bytes']
 assert cursor==len(elf) and read(build/'bellman-port-packed.elf')==elf
 pack=document(build/'pack.receipt.json')
 assert pack['manifest_sha256']==sha(read(build/'build/modules/port-packer/manifest.json')) and pack['image_sha256']==ROLES['packer'][2]
 return {'status':'READ_ONLY_PORT_BUILD_PASS','source_sha256':c['source_sha256'],'executable_sha256':sha(elf),'compiler_source_files':len(compiler['files']),'new_runtime_images':3,'frozen_worker_runtime_images':5,'actual_hia_packer_images':1,'reused_verified_bootstrap':True,'matching_source_cold_qualified':False,'native_or_rust_executed':False,'public_handler_qualified':False}
