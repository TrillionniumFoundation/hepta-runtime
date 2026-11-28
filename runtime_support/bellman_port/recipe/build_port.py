"""Build the fixed public Bellman port with unchanged caller and worker images."""
import argparse,hashlib,json,os,pathlib,shutil,struct,sys
sys.dont_write_bytecode=True
BASE=pathlib.Path(__file__).resolve().parent
PIN='6b5983d351b380b53f5838dc7ca8adac523d6c95ac12df51c3f975faf60d53c2'
ROLE={'caller':'bellman_call','params':'bellman_params_callable','diagnostic':'bellman_diagnostic_callable'}
EXPORTS=['create','attach','owned','invoke','service','wake_fd','ready_receive','ready_release','detach','shutdown','destroy']
def sha(b):return hashlib.sha256(b).hexdigest()
def write(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(v if isinstance(v,bytes) else (json.dumps(v,indent=2,sort_keys=True)+'\n').encode())
def main():
 p=argparse.ArgumentParser()
 for name in ['package','hepta','worker-build','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 a=p.parse_args();package=a.package.resolve();out=a.output.resolve();out.mkdir()
 root=package/'source';proof=json.loads((package/'caller-source-pins.json').read_bytes());WORK_SOURCE=package/'worker-source';HEPTA=a.hepta.resolve()
 sys.path.insert(0,str(WORK_SOURCE/'tests/hia_native/blocking_worker'));sys.path.insert(0,str(WORK_SOURCE/'tests/hia_native/blocking_worker_ci'))
 from worker_build_evidence import verify_build
 from capture_writer_trace import run
 worker_capture=a.worker_build.resolve();worker_proof=verify_build(worker_capture,WORK_SOURCE,PIN)
 worker=worker_capture/'bridge/bellman-worker.elf';component=json.loads((worker_capture/'bridge/component.json').read_bytes())
 assert sha(worker.read_bytes())==component['executable_sha256']=='033876f0263be071c421723dea17d97dbcc188caa37c85506fd0c344cb547304'
 sys.path.insert(0,str(root/'scripts'))
 from hia_native_build import NativeBuild
 build=out/'build';build.mkdir();shutil.copytree(worker_capture/'build/bootstrap',build/'bootstrap')
 for name in ['compiler-source','compiler-git']:
  shutil.copytree(worker_capture/name,out/name)
 shutil.copy2(worker_capture/'compiler-source.json',out/'compiler-source.json')
 builder=NativeBuild(HEPTA,build);members={}
 for role,name in ROLE.items():
  source=root/'native'/(name+'.hepta');raw=source.read_bytes();assert proof[name]=={'bytes':len(raw),'sha256':sha(raw)}
  manifest=builder.compile('port-'+role,source,standalone=None,buffer_profile='serde-json.v1');m=json.loads(manifest.read_bytes());image=manifest.parent/m['image']
  members[role]={'manifest':str(manifest),'manifest_sha256':sha(manifest.read_bytes()),'source_sha256':sha(raw),'image_sha256':sha(image.read_bytes()),'bytes':image.stat().st_size,'path':str(image)}
 members['worker']={'path':str(worker),'bytes':worker.stat().st_size,'image_sha256':component['executable_sha256'],'verified_build':worker_proof}
 body=(root/'scripts/runtime_mcp_bellman_port.S').read_bytes();write(out/'source/runtime_mcp_bellman_port.S',body)
 asm='.intel_syntax noprefix\n.section .text\n.global _start\n_start:\n mov edi,64\n mov eax,231\n syscall\n ud2\n'
 for name,value in component['exports'].items():asm+=f'.equ BWX_{name.removeprefix("bellman_worker_")}, {value["offset"]}\n'
 asm+='.include "runtime_mcp_bellman_port.S"\n'
 for role,row in members.items():asm+=f'\n.p2align 4,0\n.global runtime_bellman_{role}_image\nruntime_bellman_{role}_image:\n.incbin "{row["path"]}"\n'
 asm+='\n.section .note.GNU-stack,"",@progbits\n';write(out/'assembled.S',asm.encode())
 env=dict(os.environ);env.update(LC_ALL='C',LANG='C');tools={name:str(pathlib.Path(shutil.which(name)).resolve()) for name in ['as','ld','objcopy','nm']}
 commands={'as-version':[tools['as'],'--version'],'ld-version':[tools['ld'],'--version'],'objcopy-version':[tools['objcopy'],'--version'],'nm-version':[tools['nm'],'--version'],
 'assemble':[tools['as'],'--64','-I',str(out/'source'),str(out/'assembled.S'),'-o',str(out/'port.o')],
 'link':[tools['ld'],'--build-id=none','-e','_start','-Ttext=0x4000b0','-o',str(out/'linked.elf'),str(out/'port.o')],
 'flat':[tools['objcopy'],'-O','binary','--only-section=.text',str(out/'linked.elf'),str(out/'flat.bin')],
 'symbols':[tools['nm'],'-n','-P',str(out/'linked.elf')]}
 for label,command in commands.items():run(out,label,command,env,limit=60)
 symbols={row[0]:int(row[2],16) for line in (out/'processes/symbols.stdout').read_text().splitlines() if len(row:=line.split())>=3 and row[1].lower() in {'t','a'}}
 flat=(out/'flat.bin').read_bytes();extent=176+len(flat)
 header=b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
 header+=struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,extent,extent,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16)
 assert len(header)==176;executable=header+flat
 for role,row in members.items():
  row['offset']=symbols['runtime_bellman_'+role+'_image']-0x400000
  assert executable[row['offset']:row['offset']+row['bytes']]==pathlib.Path(row['path']).read_bytes()
 write(out/'bellman-port.elf',executable)
 result={'status':'ASSEMBLED_DEVELOPMENT_CANDIDATE','source_sha256':sha(body),'executable_bytes':len(executable),'executable_sha256':sha(executable),'members':members,'exports':{name:symbols['runtime_bellman_'+name]-0x400000 for name in EXPORTS},'runtime_hia_images':8,'actual_hia_packer_pending':True,'public_handler_qualified':False}
 write(out/'component.json',result);print(json.dumps({k:v for k,v in result.items() if k!='members'},sort_keys=True))
if __name__=='__main__':main()
