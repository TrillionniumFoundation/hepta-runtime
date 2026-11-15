"""Actual HIA packer refusals and fixed Linux FD-serial boundary controls."""
from pathlib import Path
import argparse,ctypes,errno,gzip,hashlib,json,os,struct,sys,traceback
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import write_new,json_bytes
from hia_native_loader import NativeModule
from hia_native_text_publication_build import run_boundary_command
SOURCES=['scripts/text_publication_engine.S','scripts/text_publication_effects.S',
         'scripts/text_publication_children.S','scripts/text_publication_transport.S']
def sha(raw):return hashlib.sha256(raw).hexdigest()
def word(p,at=0):return ctypes.c_uint64.from_address(p+at).value
def put(p,at,v):ctypes.c_uint64.from_address(p+at).value=v

class Records:
    def __init__(self,path):
        self.file=path.open('xb');self.stream=gzip.GzipFile(filename='',fileobj=self.file,mode='wb',mtime=0,compresslevel=1)
        self.rows=[];self.size=0;self.digest=hashlib.sha256()
    def add(self,label,code,parts,extra=None):
        index=len(self.rows)+1;header=b'HTXTBND1'+struct.pack('<3Q',index,code&((1<<64)-1),len(parts))+struct.pack('<'+'Q'*len(parts),*map(len,parts))
        start=self.size
        for raw in (header,*parts):self.stream.write(raw);self.digest.update(raw);self.size+=len(raw)
        self.rows.append({'index':index,'label':label,'return':code,'offset':start,'extent':self.size-start,
          'spans':[{'bytes':len(raw),'sha256':sha(raw)} for raw in parts],**(extra or {})})
    def close(self):
        self.stream.close();self.file.close()
        return {'records':self.rows,'raw_bytes':self.size,'raw_sha256':self.digest.hexdigest()}

def packer_controls(manifest_path,manifest,records):
    folder=manifest_path.parent;wire=(folder/'packer.input.bin').read_bytes();expected=(folder/'packer.output.bin').read_bytes()
    path=folder/manifest['packer_manifest'];assert sha(path.read_bytes())==manifest['packer_manifest_sha256']
    cases=[('complete',wire,len(expected),4096,len(expected))]
    def mutated(name,offset,value,code=0xffffffff):
        altered=bytearray(wire);struct.pack_into('<Q',altered,offset,value)
        cases.append((name,bytes(altered),len(expected),4096,code))
    mutated('magic',0,0);mutated('prefix-size',8,struct.unpack_from('<Q',wire,8)[0]+1)
    mutated('member-count',16,2);mutated('table-offset',24,manifest['table_offset']+8)
    cases.append(('short-header',wire[:55],len(expected),4096,0xffffffff))
    cases.append(('short-workspace',wire,len(expected),23,0xfffffffe))
    prefix=struct.unpack_from('<Q',wire,8)[0]
    cases.append(('truncated-prefix',wire[:56+prefix-1],len(expected),4096,0xfffffffe))
    for slot in range(3):mutated('empty-image-'+str(slot),32+8*slot,0)
    mutated('overflow-image-size',32,(1<<64)-1)
    cases.append(('trailing-input',wire+b'x',len(expected),4096,0xffffffff))
    cases.append(('truncated-image',wire[:-1],len(expected),4096,0xffffffff))
    cases.append(('short-output',wire,len(expected)-1,4096,0xfffffffe))
    bad=bytearray(wire);bad[56+prefix-1]^=1
    cases.append(('prefix-fingerprint',bytes(bad),len(expected),4096,0xffffffff))
    cases.append(('empty-output',wire,0,4096,0xfffffffe))
    cases.append(('empty-workspace',wire,len(expected),0,0xfffffffe))
    with NativeModule(path,manifest_sha256=manifest['packer_manifest_sha256']) as module:
        for name,request,output_capacity,workspace_capacity,wanted in cases:
            before_output=bytes([0xa5])*output_capacity;before_work=bytes([0x3c])*workspace_capacity
            code,after_output,after_work=module.invoke_raw(request,output_capacity=output_capacity,
                workspace_capacity=workspace_capacity,output_fill=0xa5,workspace_fill=0x3c)
            records.add('packer:'+name,code,(request,before_output,before_work,after_output,after_work))
            assert code==wanted,(name,code,wanted)
            if name=='complete':assert after_output==expected and after_work==bytes(24)+before_work[24:]
            else:assert after_output==before_output,name
    return len(cases)

def descriptor_controls(manifest_path,manifest,output,records):
    folder=output/'descriptor-boundary';folder.mkdir()
    wrapper='''\n.global text_publication_test_dispatch
text_publication_test_dispatch:
    TXT_ENTER
    mov r15, rdi
    call txt_dispatch_effect
    TXT_LEAVE
'''
    source='\n'.join((ROOT/name).read_text() for name in SOURCES)+wrapper
    write_new(folder/'combined.S',source.encode())
    run_boundary_command(folder,0,['as','--64','-o',str(folder/'boundary.o'),str(folder/'combined.S')])
    relocations=run_boundary_command(folder,1,['readelf','-r',str(folder/'boundary.o')]);assert b'There are no relocations' in relocations
    run_boundary_command(folder,2,['ld','-shared','-z','noexecstack','-o',str(folder/'boundary.so'),str(folder/'boundary.o')])
    modules=[];engines=[];count=0;refusals=0
    try:
        for row in manifest['members']:
            path=manifest_path.parent/row['manifest'];modules.append(NativeModule(path,manifest_sha256=row['manifest_sha256']))
        table=(ctypes.c_void_p*3)(*(ctypes.cast(module._entry,ctypes.c_void_p).value for module in modules))
        library=ctypes.CDLL(str(folder/'boundary.so'))
        library.text_publication_create.argtypes=[ctypes.c_void_p];library.text_publication_create.restype=ctypes.c_int64
        library.text_publication_destroy.argtypes=[ctypes.c_void_p];library.text_publication_destroy.restype=ctypes.c_int64
        library.text_publication_test_dispatch.argtypes=[ctypes.c_void_p];library.text_publication_test_dispatch.restype=ctypes.c_int64
        for _ in range(2):
            p=library.text_publication_create(table);assert p>0;engines.append(p)
        a,b=engines
        def effect(p,kind,args,changes=()):
            work=word(p,32);seq=word(p,96)+1;gen=1
            raw=bytearray(b'HTXTFX01'+struct.pack('<15Q',seq,gen,kind,*args,0,0,0,0,0,0))
            assert len(raw)==128
            put(work,56,seq);put(work,64,gen)
            for offset,value in changes:struct.pack_into('<Q',raw,offset,value)
            ctypes.memmove(work+512,bytes(raw),128)
            return bytes(raw)
        def call(name,p,wire,reject=False):
            nonlocal count,refusals
            w=word(p,32);before=(ctypes.string_at(p,4096),ctypes.string_at(w,word(p,40)))
            code=library.text_publication_test_dispatch(p)
            after=(ctypes.string_at(p,4096),ctypes.string_at(w,word(p,40)))
            records.add('fd:'+name,code,(wire,*before,*after));count+=1
            if reject:assert code==-22 and before==after;refusals+=1
            else:assert code==0
            return code
        opening=(1,720896,0,0,0,0)
        invalid=[('magic',0,0),('stale-sequence',8,0),('future-sequence',8,2),('zero-generation',16,0),
                 ('other-generation',16,2),('unknown-effect',24,20),('wrong-slot',32,2),('wrong-open-flags',40,0)]
        invalid += [('nonzero-'+str(offset),offset,1) for offset in (48,56,64,72,80,88,96,104,112,120)]
        for name,at,value in invalid:call(name,a,effect(a,1,opening,[(at,value)]),True)
        call('open-a',a,effect(a,1,opening));afd=word(a,160);assert os.fstat(afd).st_ino>0
        call('open-b',b,effect(b,1,opening));bfd=word(b,160);assert afd!=bfd and os.fstat(bfd).st_ino>0
        call('already-owned-slot',a,effect(a,1,opening),True)
        serial=word(a,168)
        call('stale-close-serial',a,effect(a,3,(1,serial+1,0,0,0,0)),True);os.fstat(afd);os.fstat(bfd)
        call('unowned-close-slot',a,effect(a,3,(2,serial,0,0,0,0)),True);os.fstat(afd);os.fstat(bfd)
        call('real-close-a',a,effect(a,3,(1,serial,0,0,0,0)))
        try:os.fstat(afd);raise AssertionError('actual descriptor remained open')
        except OSError as error:assert error.errno==errno.EBADF
        os.fstat(bfd)
        call('reopen-a',a,effect(a,1,opening));new_fd=word(a,160);new_serial=word(a,168)
        assert new_serial!=serial
        call('old-serial-after-reopen',a,effect(a,3,(1,serial,0,0,0,0)),True);os.fstat(new_fd)
        assert library.text_publication_destroy(a)==0;engines.remove(a)
        try:os.fstat(new_fd);raise AssertionError('destroy leaked its descriptor')
        except OSError as error:assert error.errno==errno.EBADF
        os.fstat(bfd)
        assert library.text_publication_destroy(b)==0;engines.remove(b)
        try:os.fstat(bfd);raise AssertionError('second destroy leaked its descriptor')
        except OSError as error:assert error.errno==errno.EBADF
        return {'actual_dispatch_calls':count,'refusals':refusals,'actual_hia_calls':0,
                'opened_descriptors':3,'closed_descriptors':3,'two_engine_ownership':True}
    finally:
        for p in engines:library.text_publication_destroy(p)
        for module in modules:module.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads(args.manifest.read_bytes());pins={name:sha((ROOT/name).read_bytes()) for name in SOURCES}
    assert all(manifest['sources'][name]==value for name,value in pins.items())
    capture=Records(output/'calls.bin.gz')
    try:
        packer=packer_controls(args.manifest,manifest,capture)
        fds=descriptor_controls(args.manifest,manifest,output,capture)
        assert pins=={name:sha((ROOT/name).read_bytes()) for name in SOURCES}
        result={'status':'PASS','test_groups':2,'packer_calls':packer,'fd_controls':fds,
          'source_sha256':pins,'manifest_sha256':sha(args.manifest.read_bytes()),'original_cases_added':0,'original_reference_executed':False}
    except BaseException:result={'status':'FAIL','error':traceback.format_exc(),'original_reference_executed':False}
    finally:write_new(output/'capture.json',json_bytes(capture.close()))
    write_new(output/'RESULT.json',json_bytes(result));print(json.dumps(result),flush=True)
    if result['status']!='PASS':raise SystemExit(1)
if __name__=='__main__':main()
