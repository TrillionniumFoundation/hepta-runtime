"""Actually compile and invoke the four-member HIA packer for the fixed port."""
import argparse,ast,hashlib,inspect,json,pathlib,struct,sys
sys.dont_write_bytecode=True
BASE=pathlib.Path(__file__).resolve().parent

def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,x):p.write_bytes(x if isinstance(x,bytes) else (json.dumps(x,sort_keys=True,indent=2)+'\n').encode())

def main():
 p=argparse.ArgumentParser()
 for name in ['package','hepta','build']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 a=p.parse_args();package=a.package.resolve();build=a.build.resolve();HEPTA=a.hepta.resolve()
 sys.path.insert(0,str(package/'worker-source/tests/hia_native/blocking_worker'))
 import author_worker_bridge as original
 sys.path.insert(0,str(package/'source/scripts'))
 from hia_native_build import NativeBuild
 from hia_native_loader import NativeModule
 c=json.loads((build/'component.json').read_bytes());elf=(build/'bellman-port.elf').read_bytes()
 assert sha(elf)==c['executable_sha256'] and len(elf)==c['executable_bytes']
 source=package/'source'
 assert sha((source/'scripts/runtime_mcp_bellman_port.S').read_bytes())==c['source_sha256']
 members={k:dict(v,image_bytes=v['bytes']) for k,v in sorted(c['members'].items(),key=lambda kv:kv[1]['offset'])}
 assert list(members)==['caller','params','diagnostic','worker']
 gaps=[];at=next(iter(members.values()))['offset'];prefix=elf[:at]
 for role,m in members.items():
  raw=pathlib.Path(m['path']).read_bytes();assert len(raw)==m['bytes'] and sha(raw)==m['image_sha256']
  assert elf[m['offset']:m['offset']+m['bytes']]==raw
  if at<m['offset']:
   assert not any(elf[at:m['offset']]);gaps.append((at,m['offset']))
  at=m['offset']+m['bytes']
 assert at==len(elf)
 author=inspect.getsource(original.make_packer).replace('bellman_worker_packer','bellman_port_packer')
 old="    source+=f'    if length(o) < {extent}:"
 assert author.count(old)==1
 author=author.replace(old,"    source+='    if get(s, 40) != 0:\\n        return 4294967295\\n'\n"+old)
 ast.parse(author);put(build/'packer-author.py',author.encode())
 namespace=dict(original.__dict__);namespace['MAGIC']=int.from_bytes(b'HBLPPK01','little')
 exec(compile(author,'<fixed-port-packer-author>','exec'),namespace)
 generated=build/'packer-authoring';(generated/'native').mkdir(parents=True)
 authored=namespace['make_packer'](generated,HEPTA,prefix,members,gaps,len(elf))
 for name in ['bellman_port_packer.hepta','bellman_port_packer.author.txt']:
  assert (generated/'native'/name).read_bytes()==(source/'native'/name).read_bytes()
 builder=NativeBuild(HEPTA,build/'build')
 manifest=builder.compile('port-packer',source/'native/bellman_port_packer.hepta',standalone=None)
 m=json.loads(manifest.read_bytes())
 frame=b'HBLPPK01'+struct.pack('<5Q',*[v['image_bytes'] for v in members.values()],0)+b''.join(pathlib.Path(v['path']).read_bytes() for v in members.values())
 module=NativeModule(manifest,manifest_sha256=sha(manifest.read_bytes()))
 code,out,work=module.invoke_raw(frame,output_capacity=len(elf)+4096,workspace_capacity=64,output_fill=0xA5,workspace_fill=0x5A)
 assert code==len(elf) and out==elf+bytes([0xA5])*4096 and work==bytes([0x5A])*64
 for name,raw in [('pack.input.bin',frame),('pack.output.bin',out),('pack.workspace.bin',work),('bellman-port-packed.elf',out[:code])]:put(build/name,raw)
 (build/'bellman-port-packed.elf').chmod(0o500)
 result={'status':'ACTUAL_HIA_PORT_PACK_PASS','source':authored,'manifest_sha256':sha(manifest.read_bytes()),'image_sha256':m['image_sha256'],'code':code,'executable_sha256':sha(out[:code]),'input':{'bytes':len(frame),'sha256':sha(frame)},'output':{'bytes':len(out),'sha256':sha(out)},'workspace':{'bytes':len(work),'sha256':sha(work)},'public_handler_qualified':False}
 put(build/'pack.receipt.json',result);print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
