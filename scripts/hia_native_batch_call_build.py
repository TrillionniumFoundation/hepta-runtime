"""Fresh fixed local batch graph; build Python never participates at runtime."""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,signal,struct,subprocess,sys,time,traceback

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild,write_new,json_bytes
from hia_native_loader import NativeModule

sha=lambda b:hashlib.sha256(b).hexdigest()
SOURCES=['scripts/batch_call_fixture.S','scripts/batch_call_fixture_controls.S','scripts/batch_call_native_support.S',
         'scripts/batch_call_engine.S','scripts/batch_call_tree_bridge.S',
         'scripts/batch_call_atomic_bridge.S','scripts/batch_call_atomic_effects.S','scripts/batch_call_atomic_observer.S',
         'scripts/batch_call_driver.S','scripts/batch_call_retire.S','scripts/batch_call_async.S','scripts/batch_call_shared.S','scripts/batch_call_fixture_sessions.S',
         'scripts/view_call_read_bridge.S','scripts/view_call_key_bridge.S',
         'scripts/view_call_scope_bridge.S']
MEMBERS=['batch_call','view_read','line_endpoint','file_lock_key',
         'request_scope_lifecycle','request_cache_lease','view_cache','batch_line_verify',
         'request_context','view_error','batch_plan_input','batch_plan','batch_apply',
         'editable_content','batch_diff','history','file_lock_state','atomic_write',
         'batch_edit_params','serde_json_span']
SLOTS=[0,1,1,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19]
PACKER_PROOF='native/batch_call_packer_composition.json'

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

def validate_packer(root,prefix,table):
    proof=json.loads((root/PACKER_PROOF).read_bytes())
    if proof.get('schema')!='hepta.runtime.batch-call-packer-composition.v1':
        raise ValueError('unexpected frozen HIA packer contract')
    if proof.get('source_sha256')!=sha((root/'native/batch_call_packer.hepta').read_bytes()):
        raise ValueError('frozen HIA packer source changed')
    actual={'prefix_bytes':len(prefix),'prefix_sha256':sha(prefix),'table_offset':table,
            'slots':SLOTS,'sources':source_boundary(root)}
    if proof.get('boundary')!=actual:
        raise ValueError('assembled native boundary differs from the frozen HIA packer contract')
    for item in proof.get('imports',[]):
        if sha((root/item['source']).read_bytes())!=item['source_sha256']:
            raise ValueError('HIA packer imported source changed')
    return actual

def assemble_boundary(root,folder):
    raw='\n'.join((root/n).read_text() for n in SOURCES)
    for name in re.findall(r'^\.global ([A-Za-z_][A-Za-z_0-9]*)$',raw,re.M):
        if name=='_start':continue
        alias=name+'_flat'
        if '\n'+alias+':' not in raw:raw=raw.replace('\n'+name+':','\n'+name+':\n'+alias+':')
        raw=re.sub(r'\b(call|jmp) '+re.escape(name)+r'\b',lambda m:m[1]+' '+alias,raw)
        raw=raw.replace('[rip + '+name+']','[rip + '+alias+']')
    write_new(folder/'combined.S',raw.encode())
    commands=[['as','--64','-o',str(folder/'boundary.o'),str(folder/'combined.S')],
              ['readelf','-r',str(folder/'boundary.o')],
              ['objcopy','-O','binary','-j','.text',str(folder/'boundary.o'),str(folder/'boundary.bin')],
              ['nm','-n',str(folder/'boundary.o')]]
    outputs=[run_boundary_command(folder,i,command) for i,command in enumerate(commands)]
    if b'There are no relocations' not in outputs[1]:raise ValueError('native boundary has relocations')
    table=176+int(re.search(rb'^([0-9a-f]+) T batch_image_table$',outputs[3],re.M)[1],16)
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
      +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
      +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    prefix=header+(folder/'boundary.bin').read_bytes()
    assert prefix[table:table+len(SLOTS)*8]==bytes(len(SLOTS)*8)
    write_new(folder/'prefix.bin',prefix)
    return prefix,table

def build_batch_call(hepta,output,*,source_root=ROOT):
    root=Path(source_root).resolve();output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    prefix,table=assemble_boundary(root,output)
    write_new(output/'boundary.json',json_bytes(validate_packer(root,prefix,table)))
    write_new(output/'packer-composition.json',(root/PACKER_PROOF).read_bytes())
    write_new(output/'builder.py',Path(__file__).read_bytes())
    build=NativeBuild(hepta,output/'build');build.bootstrap()
    members=[];images=[]
    for name in MEMBERS:
        path=build.compile(name.replace('_','-'),root/'native'/f'{name}.hepta',standalone=None,buffer_profile='batch-plan.v1')
        m=json.loads(path.read_bytes());image=(path.parent/m['image']).read_bytes();images.append(image)
        members.append({'name':name,'manifest':str(path.relative_to(output)), 'manifest_sha256':sha(path.read_bytes()),
                        'source_sha256':m['source_sha256'],'image_sha256':sha(image),'image_bytes':len(image)})
    packer=build.compile('batch-call-packer',root/'native/batch_call_packer.hepta',standalone=None,buffer_profile='history.v1')
    frame=b'HBCCELF2'+struct.pack('<3Q',len(prefix),len(images),table)+struct.pack('<20Q',*map(len,images))+prefix+b''.join(images)
    expected=bytearray(prefix);positions=[]
    for image in images:
        expected+=bytes((-len(expected))%16);positions.append(len(expected));expected+=image
    struct.pack_into('<QQ',expected,96,len(expected),len(expected))
    for slot,index in enumerate(SLOTS):struct.pack_into('<Q',expected,table+8*slot,0x400000+positions[index])
    with NativeModule(packer,manifest_sha256=sha(packer.read_bytes())) as module:
        elf=module.invoke(frame,output_capacity=len(expected),workspace_capacity=4096)
    if elf!=expected:raise ValueError('actual HIA packed ELF differs from complete independently constructed bytes')
    write_new(output/'packer.input.bin',frame);write_new(output/'packer.output.bin',elf)
    write_new(output/'batch-call.elf',elf,0o500)
    manifest={'schema':'hepta.runtime.batch-call-build.v1','elf':'batch-call.elf','elf_sha256':sha(elf),
        'members':members,'slots':SLOTS,'packer_manifest':str(packer.relative_to(output)),
        'packer_manifest_sha256':sha(packer.read_bytes()),'prefix_bytes':len(prefix),'prefix_sha256':sha(prefix),
        'table_offset':table,'image_offsets':positions,'sources':{n:sha((root/n).read_bytes()) for n in SOURCES},
        'builder_source':'scripts/hia_native_batch_call_build.py',
        'builder_sha256':sha(Path(__file__).read_bytes()),
        'packer_composition':PACKER_PROOF,
        'packer_composition_sha256':sha((root/PACKER_PROOF).read_bytes()),
        'input_frame_sha256':sha(frame),'runtime_python_required':False,'runtime_rust_required':False,
        'runtime_libc_required':False,'public_route_replaced':False,'whole_runtime_replaced':False}
    path=output/'manifest.json';write_new(path,json_bytes(manifest));return path

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source',type=Path,default=ROOT)
    a=p.parse_args();print(build_batch_call(a.hepta,a.output,source_root=a.source))
