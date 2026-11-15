"""Fresh fixed text publication graph; no host-language runtime fallback."""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,signal,struct,subprocess,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild,write_new,json_bytes
from hia_native_loader import NativeModule
sha=lambda b:hashlib.sha256(b).hexdigest()
SOURCES=['scripts/text_publication_fixture.S','scripts/text_publication_engine.S',
         'scripts/text_publication_effects.S','scripts/text_publication_children.S','scripts/text_publication_transport.S']
MEMBERS=[('text-publication','text_publication.hepta'),('text-publication-codec','binary_codec.hepta'),('text-publication-error','view_error.hepta')]
PACKER_PROOF='native/text_publication_packer_composition.json'

def run_boundary_command(folder,index,arguments):
    executable=shutil.which(arguments[0])
    if executable is None:raise ValueError('missing native build executable: '+arguments[0])
    command=[str(Path(executable).resolve()),*arguments[1:]]
    started=time.monotonic_ns();pid=None;code=None;timed_out=False;start_error=None
    out=folder/f'boundary-{index}.stdout';err=folder/f'boundary-{index}.stderr'
    env=dict(os.environ);env['LC_ALL']='C'
    with out.open('xb') as stdout,err.open('xb') as stderr:
        try:
            process=subprocess.Popen(command,cwd=folder,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
            pid=process.pid
            try:code=process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out=True;os.killpg(pid,signal.SIGKILL);code=process.wait(timeout=10)
        except BaseException:start_error=traceback.format_exc()
    ended=time.monotonic_ns()
    record={'command':command,'cwd':str(folder),'pid':pid,'timeout_seconds':180,
        'started_monotonic_ns':started,'finished_monotonic_ns':ended,
        'elapsed_seconds':(ended-started)/1e9,'timed_out':timed_out,'start_error':start_error,
        'exit_code':code,'controlled_env':{'LC_ALL':'C'},
        'executable_sha256':sha(Path(command[0]).read_bytes()),
        'stdout':{'bytes':out.stat().st_size,'sha256':sha(out.read_bytes())},
        'stderr':{'bytes':err.stat().st_size,'sha256':sha(err.read_bytes())}}
    write_new(folder/f'boundary-{index}.process.json',json_bytes(record))
    if timed_out or start_error is not None or code!=0:
        raise ValueError('native assembly failed; complete process and streams retained')
    return out.read_bytes()

def source_boundary(root):
    return {name:sha((root/name).read_bytes()) for name in SOURCES}

def assemble_boundary(root,folder):
    raw='\n'.join((root/name).read_text() for name in SOURCES)
    write_new(folder/'combined.S',raw.encode())
    commands=[['as','--64','-o',str(folder/'boundary.o'),str(folder/'combined.S')],
              ['readelf','-r',str(folder/'boundary.o')],
              ['objcopy','-O','binary','-j','.text',str(folder/'boundary.o'),str(folder/'boundary.bin')],
              ['nm','-n',str(folder/'boundary.o')]]
    outputs=[run_boundary_command(folder,index,command) for index,command in enumerate(commands)]
    if b'There are no relocations' not in outputs[1]:raise ValueError('native boundary has unresolved relocations')
    table=176+int(re.search(rb'^([0-9a-f]+) T text_publication_image_table$',outputs[3],re.M)[1],16)
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
      +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
      +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    prefix=header+(folder/'boundary.bin').read_bytes()
    assert prefix[table:table+24]==bytes(24)
    write_new(folder/'prefix.bin',prefix)
    return prefix,table

def build_text_publication(hepta,output,*,source_root=ROOT):
    root=Path(source_root).resolve();output=Path(output).resolve()
    output.mkdir(parents=True,exist_ok=False)
    prefix,table=assemble_boundary(root,output)
    proof=json.loads((root/PACKER_PROOF).read_bytes())
    actual={'prefix_bytes':len(prefix),'prefix_sha256':sha(prefix),'table_offset':table,
            'slots':[0,1,2],'sources':source_boundary(root)}
    if proof.get('schema')!='hepta.runtime.text-publication-packer-composition.v1' or proof.get('boundary')!=actual:
        raise ValueError('assembled native boundary differs from exact frozen HIA packer contract')
    if proof.get('source_sha256')!=sha((root/'native/text_publication_packer.hepta').read_bytes()):
        raise ValueError('HIA packer source differs')
    for item in proof['imports']:
        if sha((root/item['source']).read_bytes())!=item['source_sha256']:raise ValueError('packer import source differs')
    write_new(output/'boundary.json',json_bytes(actual))
    write_new(output/'packer-composition.json',(root/PACKER_PROOF).read_bytes())
    write_new(output/'builder.py',Path(__file__).read_bytes())
    build=NativeBuild(hepta,output/'build');build.bootstrap()
    members=[];images=[]
    for name,filename in MEMBERS:
        path=build.compile(name,root/'native'/filename,standalone=None)
        manifest=json.loads(path.read_bytes());image=(path.parent/manifest['image']).read_bytes()
        members.append({'name':name,'source':'native/'+filename,'manifest':str(path.relative_to(output)),
          'manifest_sha256':sha(path.read_bytes()),'source_sha256':manifest['source_sha256'],
          'image_sha256':sha(image),'image_bytes':len(image)})
        images.append(image)
    packer=build.compile('text-publication-packer',root/'native/text_publication_packer.hepta',standalone=None,buffer_profile='history.v1')
    frame=b'HTXTELF1'+struct.pack('<3Q',len(prefix),3,table)+struct.pack('<3Q',*map(len,images))+prefix+b''.join(images)
    expected=bytearray(prefix);positions=[]
    for image in images:
        expected+=bytes((-len(expected))%16);positions.append(len(expected));expected+=image
    struct.pack_into('<QQ',expected,96,len(expected),len(expected))
    for slot,position in enumerate(positions):struct.pack_into('<Q',expected,table+slot*8,0x400000+position)
    with NativeModule(packer,manifest_sha256=sha(packer.read_bytes())) as module:
        elf=module.invoke(frame,output_capacity=len(expected),workspace_capacity=4096)
    if elf!=expected:raise ValueError('actual HIA packed ELF differs from complete independent build bytes')
    write_new(output/'packer.input.bin',frame);write_new(output/'packer.output.bin',elf)
    write_new(output/'text-publication.elf',elf,0o500)
    result={'schema':'hepta.runtime.text-publication-build.v1','elf':'text-publication.elf','elf_sha256':sha(elf),
      'members':members,'slots':[0,1,2],'packer_manifest':str(packer.relative_to(output)),
      'packer_manifest_sha256':sha(packer.read_bytes()),'prefix_bytes':len(prefix),'prefix_sha256':sha(prefix),
      'table_offset':table,'image_offsets':positions,'sources':source_boundary(root),
      'builder_source':'scripts/hia_native_text_publication_build.py','builder_sha256':sha(Path(__file__).read_bytes()),
      'packer_composition':PACKER_PROOF,'packer_composition_sha256':sha((root/PACKER_PROOF).read_bytes()),
      'input_frame_sha256':sha(frame),'runtime_python_required':False,'runtime_rust_required':False,
      'runtime_libc_required':False,'public_handler_replaced':False,'whole_runtime_replaced':False}
    path=output/'manifest.json';write_new(path,json_bytes(result));return path

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--hepta',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--source',type=Path,default=ROOT)
    args=parser.parse_args();print(build_text_publication(args.hepta,args.output,source_root=args.source))

