"""Real callable native boundary, private buffers and Linux resource failures.

These controls add no original filesystem cases and execute no Rust reference.
The shared object contains exactly the four callable assembly sources used by
the static ELF; its three HIA entries come from the admitted fresh build.
"""
from pathlib import Path
import argparse,ctypes,gzip,hashlib,json,os,resource,struct,sys,traceback
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import write_new,json_bytes
from hia_native_loader import NativeModule
from hia_native_text_publication_build import run_boundary_command

SOURCES=['scripts/text_publication_engine.S','scripts/text_publication_effects.S',
         'scripts/text_publication_children.S','scripts/text_publication_transport.S']
INVALID=0xffffffff;STATE=0xfffffff9;RESOURCE=0xfffffffc
def sha(raw):return hashlib.sha256(raw).hexdigest()
def word(address,offset=0):return ctypes.c_uint64.from_address(address+offset).value
def put(address,offset,value):ctypes.c_uint64.from_address(address+offset).value=value
def memory(address,size):return ctypes.string_at(address,size)
def frame(path,text=b'body\n'):
    return b'HTXTQ001'+struct.pack('<7Q',1,1,len(path),len(text),6,0,0)+path+b'absent'+text
def drop(generation):return b'HTXTQ001'+struct.pack('<7Q',2,0,0,0,0,generation,0)
def virtual_size():
    with open('/proc/self/status') as handle:
        for row in handle:
            if row.startswith('VmSize:'):return int(row.split()[1])*1024
    raise AssertionError('actual process VmSize is absent')
def descriptors():return sorted(int(name) for name in os.listdir('/proc/self/fd'))

class Capture:
    def __init__(self,path):
        self.file=path.open('xb');self.stream=gzip.GzipFile(filename='',fileobj=self.file,mode='wb',mtime=0,compresslevel=1)
        self.count=0;self.size=0;self.digest=hashlib.sha256();self.rows=[]
    def add(self,label,code,wire,before,after,engine_before,engine_after):
        self.count+=1;parts=(wire,before[0],before[1],after[0],after[1])
        header=b'HTXTCAP1'+struct.pack('<8Q',self.count,0,code,*map(len,parts))
        start=self.size
        for raw in (header,*parts):self.stream.write(raw);self.size+=len(raw);self.digest.update(raw)
        self.rows.append({'index':self.count,'label':label,'code':code,'offset':start,'extent':self.size-start,
          'spans':[{'bytes':len(raw),'sha256':sha(raw)} for raw in parts],
          'engine_before':engine_before,'engine_after':engine_after})
    def close(self):
        self.stream.close();self.file.close()
        return {'calls':self.count,'raw_bytes':self.size,'raw_sha256':self.digest.hexdigest(),'rows':self.rows}

class Engine:
    def __init__(self,library,table,capture):
        self.library=library;self.capture=capture;self.pointer=library.text_publication_create(table)
        assert self.pointer>0,self.pointer
    def state(self):
        p=self.pointer;w=word(p,32)
        return {'engine':p,'workspace':w,'workspace_capacity':word(p,40),'output':word(p,48),
          'output_capacity':word(p,56),'input':word(p,64),'input_capacity':word(p,72),
          'busy':word(p,88),'last_sequence':word(p,96),'last_generation':word(p,104),
          'last_code':word(p,112),'payload_len':word(p,120),'fd_mask':word(p,136),
          'pending_output_growth':word(p,256),'poisoned':word(p,264),'phase':word(w),'generation':word(w,64),'sequence':word(w,56),
          'grow_need':word(w,40),'output_need':word(w,48),
          'fd_slots':[[ctypes.c_int64.from_address(p+160+16*i).value,word(p,168+16*i)] for i in range(4)]}
    def buffers(self):
        return memory(word(self.pointer,48),word(self.pointer,56)),memory(word(self.pointer,32),word(self.pointer,40))
    def invoke(self,label,wire,*,address_space=None):
        borrowed=ctypes.create_string_buffer(wire);before=self.buffers();state_before=self.state()
        limit=resource.getrlimit(resource.RLIMIT_AS)
        try:
            if address_space is not None:resource.setrlimit(resource.RLIMIT_AS,(address_space,limit[1]))
            code=self.library.text_publication_call(self.pointer,borrowed,len(wire))
        finally:
            if address_space is not None:resource.setrlimit(resource.RLIMIT_AS,limit)
        after=self.buffers();state_after=self.state()
        self.capture.add(label,code,wire,before,after,state_before,state_after)
        assert state_after['busy']==0 and state_after['fd_mask']==0
        assert state_after['fd_slots']==[[-1,0]]*4
        return code,after[0][:state_after['payload_len']],before,after,state_before,state_after
    def destroy(self):
        if self.pointer:
            result=self.library.text_publication_destroy(self.pointer);self.pointer=0
            assert result==0,result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads(args.manifest.read_bytes());pins={name:sha((ROOT/name).read_bytes()) for name in SOURCES}
    assert all(manifest['sources'][name]==digest for name,digest in pins.items())
    boundary=output/'callable';boundary.mkdir()
    write_new(boundary/'combined.S','\n'.join((ROOT/name).read_text() for name in SOURCES).encode())
    run_boundary_command(boundary,0,['as','--64','-o',str(boundary/'callable.o'),str(boundary/'combined.S')])
    relocations=run_boundary_command(boundary,1,['readelf','-r',str(boundary/'callable.o')])
    assert b'There are no relocations' in relocations
    run_boundary_command(boundary,2,['ld','-shared','-z','noexecstack','-o',str(boundary/'callable.so'),str(boundary/'callable.o')])
    modules=[];engine=None;capture=Capture(output/'calls.bin.gz');result=None
    try:
        for item in manifest['members']:
            path=args.manifest.parent/item['manifest'];assert sha(path.read_bytes())==item['manifest_sha256']
            assert sha((ROOT/item['source']).read_bytes())==item['source_sha256']
            modules.append(NativeModule(path,manifest_sha256=item['manifest_sha256']))
        assert [item['name'] for item in manifest['members']]==['text-publication','text-publication-codec','text-publication-error']
        table=(ctypes.c_void_p*3)(*(ctypes.cast(module._entry,ctypes.c_void_p).value for module in modules))
        library=ctypes.CDLL(str(boundary/'callable.so'))
        library.text_publication_create.argtypes=[ctypes.c_void_p];library.text_publication_create.restype=ctypes.c_int64
        library.text_publication_call.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64];library.text_publication_call.restype=ctypes.c_uint32
        library.text_publication_destroy.argtypes=[ctypes.c_void_p];library.text_publication_destroy.restype=ctypes.c_int64
        files=output/'files';files.mkdir();first=files/'first';second=files/'second'
        first_wire=frame(os.fsencode(first));second_wire=frame(os.fsencode(second))
        initial_fds=descriptors();engine=Engine(library,table,capture)
        # A nonzero byte in the original fixed state is a refusal, not an
        # instruction to clear private memory. No output/workspace byte changes.
        put(word(engine.pointer,32),8,1)
        code,body,before,after,_,_=engine.invoke('dirty-initial-state',first_wire)
        assert code==STATE and body==b'' and before==after
        put(word(engine.pointer,32),8,0)
        # Input capacity was already acquired by the preceding rejected call.
        # The next real mmap failure is the HIA-requested owned workspace growth.
        before_pointer=word(engine.pointer,32)
        code,body,_,_,_,state=engine.invoke('workspace-enomem',first_wire,address_space=virtual_size()+65536)
        assert code==RESOURCE and body==b'' and state['workspace']==before_pointer
        assert state['phase']==0 and state['grow_need']>state['workspace_capacity'] and not first.exists()
        code,body,_,_,_,state=engine.invoke('workspace-retry',first_wire)
        assert code==160 and body[:8]==b'HTXTR001' and body[120:152]==hashlib.sha256(b'body\n').digest()
        assert first.read_bytes()==b'body\n'
        generation=state['generation']
        code,body,before,after,_,_=engine.invoke('wrong-drop-generation',drop(generation+1))
        assert code==STATE and body==b'' and before==after
        code,body,_,_,_,_=engine.invoke('explicit-drop',drop(generation))
        assert code==64 and body[:16]==b'HTXTR001'+struct.pack('<Q',2)
        # Private borrowed-capacity control: the physical output page remains
        # owned, while its admitted extent is reduced before the next operation.
        put(engine.pointer,56,64)
        bad=bytearray(second_wire);struct.pack_into('<Q',bad,8,99)
        code,body,before,after,_,_=engine.invoke('warm-input-with-invalid-op',bytes(bad))
        assert code==INVALID and body==b'' and before==after
        code,body,_,_,_,state=engine.invoke('post-publication-output-enomem',second_wire,address_space=virtual_size())
        assert code==RESOURCE and body==b'' and state['phase']==100 and state['output_need']==160
        assert second.read_bytes()==b'body\n';info=second.stat()
        identity=(info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns,info.st_size)
        sequence=state['sequence']
        wrong=bytearray(second_wire);wrong[-1]^=1
        code,body,before,after,_,_=engine.invoke('pending-output-different-input',bytes(wrong))
        assert code==STATE and body==b'' and before==after
        code,body,before,after,_,_=engine.invoke('pending-output-wrong-drop',drop(state['generation']+1))
        assert code==STATE and body==b'' and before==after
        code,body,_,_,_,state=engine.invoke('output-only-retry',second_wire)
        assert code==160 and body[120:152]==hashlib.sha256(b'body\n').digest() and state['sequence']==sequence
        info=second.stat();assert identity==(info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns,info.st_size)
        code,body,_,_,_,_=engine.invoke('second-explicit-drop',drop(state['generation']))
        assert code==64
        third=files/'third';third_wire=frame(os.fsencode(third))
        put(engine.pointer,56,64)
        code,body,_,_,_,state=engine.invoke('terminal-result-discard-enomem',third_wire,address_space=virtual_size())
        assert code==RESOURCE and body==b'' and state['phase']==100 and state['output_need']==160
        assert third.read_bytes()==b'body\n'
        code,body,_,_,_,state=engine.invoke('terminal-result-discard-drop',drop(state['generation']))
        assert code==64 and state['phase']==0 and state['pending_output_growth']==0
        engine.destroy();engine=None;assert descriptors()==initial_fds
        # Real allocation budgets fail at different partial-create positions.
        # No HIA operation or filesystem effect is part of these five controls.
        allocations=[]
        for budget in (0,4096,8192,12288,16384):
            limit=resource.getrlimit(resource.RLIMIT_AS);vm_before=virtual_size()
            try:
                resource.setrlimit(resource.RLIMIT_AS,(vm_before+budget,limit[1]))
                address=library.text_publication_create(table)
            finally:resource.setrlimit(resource.RLIMIT_AS,limit)
            vm_after=virtual_size()
            if address>0:library.text_publication_destroy(address)
            allocations.append({'extra_address_space':budget,'actual_return':address,'vmsize_before':vm_before,'vmsize_after':vm_after})
            assert address==-12 and vm_after==vm_before,allocations[-1]
        write_new(output/'allocations.json',json_bytes(allocations))
        assert pins=={name:sha((ROOT/name).read_bytes()) for name in SOURCES}
        result={'status':'PASS','test_groups':3,'actual_hia_requests':capture.count,
          'allocation_controls':len(allocations),'source_sha256':pins,'manifest_sha256':sha(args.manifest.read_bytes()),
          'callable_sha256':sha((boundary/'callable.so').read_bytes()),'original_cases_added':0,
          'original_reference_executed':False,'production_mcp_route_replaced':False}
    except BaseException:
        result={'status':'FAIL','error':traceback.format_exc(),'original_reference_executed':False}
    finally:
        if engine is not None:engine.destroy()
        for module in modules:module.close()
        write_new(output/'capture.json',json_bytes(capture.close()))
    write_new(output/'RESULT.json',json_bytes(result));print(json.dumps(result),flush=True)
    if result['status']!='PASS':raise SystemExit(1)
if __name__=='__main__':main()
