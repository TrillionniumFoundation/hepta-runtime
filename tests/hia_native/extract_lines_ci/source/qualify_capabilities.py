"""Actual exported native capability and wait controls; no original async claim."""
from pathlib import Path
import ctypes as C
import argparse,fcntl,hashlib,json,mmap,os,struct,subprocess,sys,time,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
SOURCE_ROOT=ROOT
MANIFEST=None
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT))
from hia_native_loader import (NativeModule,F_SEAL_WRITE,F_SEAL_GROW,F_SEAL_SHRINK,
                              F_SEAL_SEAL,F_ADD_SEALS,F_GET_SEALS)
from common import loads as decode,read,encoded,require
from read_builds import native as verify_build
import cases
sha=lambda raw:hashlib.sha256(raw).hexdigest()
q=lambda *v:struct.pack('<'+'Q'*len(v),*v)
word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
LIB=C.CDLL(None,use_errno=True)
LIB.mmap.argtypes=[C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long];LIB.mmap.restype=C.c_void_p
LIB.mprotect.argtypes=[C.c_void_p,C.c_size_t,C.c_int];LIB.mprotect.restype=C.c_int
LIB.munmap.argtypes=[C.c_void_p,C.c_size_t];LIB.munmap.restype=C.c_int
CALLBACK=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_void_p,C.c_uint64,C.c_void_p)
GROW=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_uint64,C.c_uint64)


def bound_build():
    verify_build(MANIFEST.parent)
    built=decode(read(MANIFEST))
    return dict(elf_sha256=built['executable']['sha256'],
        members=[dict(row,manifest=str(MANIFEST.parent/row['manifest']),manifest_sha256=row['manifest_pin']['sha256'])
                 for row in built['members']])


class Region:
    def __init__(self,size):
        self.size=(size+4095)&-4096
        self.memory=mmap.mmap(-1,self.size+4096,prot=mmap.PROT_READ|mmap.PROT_WRITE)
        self.address=C.addressof(C.c_char.from_buffer(self.memory))
        assert LIB.mprotect(self.address+self.size,4096,0)==0
    def raw(self):return C.string_at(self.address,self.size)
    def close(self):self.memory.close()


class Harness:
    def __init__(self,output):
        self.output=output;self.vault=output/'blobs';self.vault.mkdir()
        self.events=[];self.modules=[];self.regions={};self.hints=[];self.failure=None
        self.bad_cache=0;self.refuse_growth=False;self.lie_growth=False;self.growth=[]
        built=bound_build()
        assert built['elf_sha256']=='a7472dcb30aa50629d4a2fd523fb1792a5da06a6d18f5813713cf7715fa08325'
        self.built=built
        for row in built['members']:
            self.modules.append(NativeModule(row['manifest'],manifest_sha256=row['manifest_sha256']))
        self.entries=(C.c_uint64*14)(*(module._address for module in self.modules))
        self.slots={i:(C.c_uint64*8)() for i in (3,6,8)}
        for i,record in self.slots.items():
            record[0]=self.modules[i]._address
            self.resize(i,4096,4096)
        self.raw_call(3,b'HRFLOCK1'+bytes(56))
        self.raw_call(6,b'HHISTQ01'+bytes(56))
        self.raw_call(8,b'HVCACH01'+bytes(40))
        self.statx=C.c_uint8(0)
        self.cache_cb=CALLBACK(self.cache)
        self.hint_cb=CALLBACK(self.hint)
        self.grow_cb=GROW(self.grow)
        self.hint_result=C.create_string_buffer(b'HLTBHP01'+bytes(24))
        self.contexts=[]
        self.target=None
        self.frame_buffers=[]
    def blob(self,raw):
        digest=sha(raw);p=self.vault/(digest+'.bin')
        if p.exists():assert p.read_bytes()==raw
        else:p.write_bytes(raw)
        return {'path':p.name,'bytes':len(raw),'sha256':digest}
    def resize(self,index,work,out):
        record=self.slots[index]
        for kind,need,ptr,cap in (('work',work,1,2),('out',out,3,4)):
            if need<=record[cap]:continue
            old=self.regions.get((index,kind));new=Region(need)
            if old and kind=='work':
                raw=old.raw();C.memmove(new.address,old.address,old.size)
                assert C.string_at(new.address,len(raw))==raw
            self.regions[index,kind]=new;record[ptr]=new.address;record[cap]=new.size
            if old:old.close()
    def state(self,index):return self.regions[index,'work'].raw()
    def raw_call(self,index,frame):
        record=self.slots[index];source=C.create_string_buffer(frame);before=self.state(index)
        for _ in range(20):
            code=int(self.modules[index]._entry(C.addressof(source),len(frame),record[3],record[4],record[1],record[2]))
            assert 0<=code<=0xffffffff
            if code==0xfffffffe:
                assert self.state(index)==before
                self.resize(index,record[2]*2,record[4]*2);continue
            break
        else:raise AssertionError('owner growth did not terminate')
        assert code>=0xffff0000 or code<=record[4]
        raw=C.string_at(record[3],code) if code<0xffff0000 else b''
        self.events.append(dict(kind='owner',owner=index,code=code,input=self.blob(frame),
            workspace_before=self.blob(before),workspace_after=self.blob(self.state(index)),output=self.blob(raw)))
        assert source.raw==frame+b'\0'
        record[5]=code
        return code,raw
    def cache(self,opaque,frame,size,pair):
        try:
            if self.bad_cache==1:return 0
            if self.bad_cache==2:
                view=(C.c_uint64*2).from_address(pair);view[0]=C.addressof(self.hint_result);view[1]=32
                return 32
            code,_=self.raw_call(8,C.string_at(frame,size));record=self.slots[8]
            view=(C.c_uint64*2).from_address(pair);view[0]=record[3];view[1]=code
            return code
        except BaseException as e:self.failure=repr(e);return 0
    def hint(self,opaque,frame,size,pair):
        try:
            raw=C.string_at(frame,size);assert raw[:8]==b'HLTBHQ01' and len(raw)>=32
            selector,n,zero=struct.unpack_from('<3Q',raw,8)
            assert selector in (1,2) and n==len(raw)-32 and zero==0
            raw[32:].decode('utf-8')
            if selector==1:self.hints.append(raw[32:])
            view=(C.c_uint64*2).from_address(pair);view[0]=C.addressof(self.hint_result);view[1]=32
            self.events.append(dict(kind='hint',input=self.blob(raw)))
            return 32
        except BaseException as e:self.failure=repr(e);return 0
    def grow(self,opaque,index,work,out):
        try:
            assert index in (3,6)
            self.growth.append(dict(owner=index,workspace=work,output=out,refused=self.refuse_growth))
            if self.refuse_growth:return 1
            if self.lie_growth:return 0
            self.resize(index,work,out);return 0
        except BaseException as e:self.failure=repr(e);return 1
    def context(self):
        context=(C.c_uint64*24)()
        context[0]=int.from_bytes(b'HEXTCI01','little');context[1]=192
        context[2]=C.addressof(self.entries)
        context[3]=C.cast(self.cache_cb,C.c_void_p).value
        context[5]=C.cast(self.hint_cb,C.c_void_p).value
        context[7]=C.addressof(self.slots[3]);context[8]=C.addressof(self.slots[6])
        context[9]=C.cast(self.grow_cb,C.c_void_p).value
        context[11]=C.addressof(self.statx)
        self.contexts.append(context);return context
    def call(self,name,context,frame=None):
        before=bytes(context)
        if frame is not None:
            source=C.create_string_buffer(frame);self.frame_buffers.append(source)
            code=int(self.exports[name](C.addressof(context),C.addressof(source),len(frame)))
            assert source.raw==frame+b'\0'
        else:code=int(self.exports[name](C.addressof(context)))
        result=C.string_at(context[14],context[15]) if context[14] and context[15] else b''
        self.events.append(dict(kind='export',function=name,code=code,input=self.blob(frame or b''),
            context_before=self.blob(before),context_after=self.blob(bytes(context)),output=self.blob(result),
            lock_state=self.blob(self.state(3)),history_state=self.blob(self.state(6)),cache_state=self.blob(self.state(8)),
            target=None if self.target is None else self.blob(self.target.read_bytes()),
            target_mode=None if self.target is None else self.target.stat().st_mode & 0o7777))
        assert self.failure is None,self.failure
        return code,result
    def close(self):
        for region in self.regions.values():region.close()
        for module in self.modules:module.close()


def body(path,generation=1):
    return cases.request(cases.operation(source=str(path.parent/'source'),target=str(path),append=0),
                         path.parent,generation)


def lock_frame(op,lease=0,key=b''):
    return b'HRFLOCK1'+q(op,lease,len(key),0,0,0,0)+key


def prepare_code(output):
    built=decode(read(MANIFEST));source=ROOT/'native/local_extract_lines_callable.S';raw=read(source)
    symbols={('local_extract_lines_'+name):at for name,at in built['exports'].items()}
    (output/'export.bin').write_bytes(read(MANIFEST.parent/'export.bin'))
    commands=[]
    code=(output/'export.bin').read_bytes();fd=os.memfd_create('hia-text-body-export-controls',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
    try:
        assert os.write(fd,code)==len(code)
        seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL
        fcntl.fcntl(fd,F_ADD_SEALS,seals);assert fcntl.fcntl(fd,F_GET_SEALS)&seals==seals
        address=LIB.mmap(None,len(code),mmap.PROT_READ|mmap.PROT_EXEC,mmap.MAP_PRIVATE,fd,0)
        assert address not in (None,C.c_void_p(-1).value)
    finally:os.close(fd)
    exports={}
    for name in ('run','resume','cancel_wait','release'):
        args=[C.c_void_p,C.c_void_p,C.c_uint64] if name=='run' else [C.c_void_p]
        exports[name]=C.CFUNCTYPE(C.c_uint32,*args)(address+symbols['local_extract_lines_'+name])
    proof=dict(source_sha256=sha(raw),code_sha256=sha(code),code_bytes=len(code),commands=commands,
        exports={name:symbols['local_extract_lines_'+name]for name in exports},mapping_kernel_sealed=True)
    (output/'code-proof.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    return address,len(code),exports,proof


def main():
    global MANIFEST,SOURCE_ROOT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,default=ROOT)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    MANIFEST=args.manifest.resolve(strict=True);SOURCE_ROOT=args.source_root.resolve(strict=True)
    output=args.output.resolve();output.mkdir(exist_ok=False)
    verified_build=verify_build(MANIFEST.parent)
    address,size,exports,proof=prepare_code(output)
    h=Harness(output);h.exports=exports;rows=[];report=dict(status='RUNNING',cases=rows,
        code_proof=proof,build_verification=verified_build,original_processes=0,full_body_async_qualified=False,public_handler_qualified=False)
    started=time.monotonic()
    def save(name):
        rows.append(dict(name=name,status='PASS',actual_calls=len(h.events)))
        (output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        print(json.dumps(rows[-1],sort_keys=True),flush=True)
    def release(context):
        code,_=h.call('release',context);assert code==0 and context[19]==context[14]==context[15]==0
    work=output/'fixtures';work.mkdir()
    target=work/'file';target.write_bytes(b'alpha\n');(work/'source').write_bytes(b'beta\n');request=body(target)
    h.target=target
    try:
        # Refused bindings are all valid mapped capabilities or explicit nulls.
        for field,value in ((0,0),(1,191),(2,0),(3,0),(5,0),(7,0),(8,0),(9,0),(11,0),(12,2),(13,1),(14,1),(17,1),(21,1)):
            context=h.context();context[field]=value;before=bytes(context)
            states={i:h.state(i)for i in h.slots}
            assert h.call('run',context,request)[0]==0xffffffff
            assert bytes(context)==before and target.read_bytes()==b'alpha\n'
            assert states=={i:h.state(i)for i in h.slots}
            save('binding-refusal-'+str(field))
        for label,malformed in (('empty',b''),('magic',b'HEXTRQ01'),('short',request[:-1]),('long',request+b'x')):
            context=h.context();states={i:h.state(i)for i in h.slots}
            assert h.call('run',context,malformed)[0]==0xffffffff
            assert context[17]==context[18]==1 and states=={i:h.state(i)for i in h.slots}
            release(context);save('request-refusal-'+label)
        # A real held lock makes the body return its genuine WAIT.
        key=os.fsencode(target.resolve())
        _,raw=h.raw_call(3,lock_frame(1,key=key));held=word(raw,24)
        assert h.raw_call(3,lock_frame(3,held))[0]==64
        before_history=h.state(6);context=h.context();code,wait=h.call('run',context,request)
        assert code==0xffffffdf and wait[:8]==b'HLTBWT01' and len(wait)==48
        waiter=word(wait,24);assert waiter and waiter!=held and word(h.state(3),72)==2
        retained=bytes(context);assert h.call('release',context)[0]==16 and bytes(context)==retained
        assert h.call('run',context,request)[0]==0xffffffff and bytes(context)==retained
        last_sequence=word(wait,16)
        for _ in range(3):
            code,wait=h.call('resume',context)
            assert code==0xffffffdf and word(wait,24)==waiter and word(wait,16)>last_sequence
            last_sequence=word(wait,16)
            assert word(h.state(3),72)==2 and target.read_bytes()==b'alpha\n' and h.state(6)==before_history
        assert h.call('cancel_wait',context)[0]==0xfffffff7
        assert context[17]==context[18]==1 and word(h.state(3),72)==1
        release(context)
        assert h.call('resume',context)[0]==h.call('cancel_wait',context)[0]==0xffffffff
        assert h.raw_call(3,lock_frame(6,held))[0]==64 and word(h.state(3),72)==0
        save('wait-three-resumes-cancel-drain-release')
        # Release the predecessor and resume the existing waiter to completion.
        _,raw=h.raw_call(3,lock_frame(1,key=key));held=word(raw,24)
        assert h.raw_call(3,lock_frame(3,held))[0]==64
        context=h.context();assert h.call('run',context,request)[0]==0xffffffdf
        assert h.raw_call(3,lock_frame(6,held))[0]==64
        code,result=h.call('resume',context)
        assert code==len(result) and result[:8]==b'HEXTRP01' and word(result,16)==0
        assert target.read_bytes()==b'beta\nalpha\n' and word(h.state(3),72)==0
        release(context);save('existing-waiter-resumes-to-completion')
        # Two actual suspended contexts share one canonical file-lock queue.
        # Cancelling one waiter leaves the other lease live and resumable.
        target.write_bytes(b'alpha\n')
        _,raw=h.raw_call(3,lock_frame(1,key=key));held=word(raw,24)
        assert h.raw_call(3,lock_frame(3,held))[0]==64
        first,second=h.context(),h.context()
        assert h.call('run',first,body(target,generation=101))[0]==0xffffffdf
        assert h.call('run',second,body(target,generation=102))[0]==0xffffffdf
        assert word(h.state(3),72)==3 and target.read_bytes()==b'alpha\n'
        assert h.call('cancel_wait',first)[0]==0xfffffff7
        release(first)
        assert word(h.state(3),72)==2 and target.read_bytes()==b'alpha\n'
        assert h.raw_call(3,lock_frame(6,held))[0]==64
        code,result=h.call('resume',second)
        assert code==len(result) and word(result,16)==0
        assert target.read_bytes()==b'beta\nalpha\n' and word(h.state(3),72)==0
        release(second);save('two-real-waiters-one-cancel-one-completes')
        # Typed callback refusals occur after the physical atomic write.
        for mode in (1,2):
            target.write_bytes(b'alpha\n');before_cache=h.state(8);h.bad_cache=mode
            context=h.context();code,_=h.call('run',context,request)
            assert code==0xfffffffc and context[20]==70 and context[17]==context[18]==1
            assert target.read_bytes()==b'beta\nalpha\n' and h.state(8)==before_cache and word(h.state(3),72)==0
            release(context);h.bad_cache=0;save('callback-refusal-drains-lease-'+str(mode))
        # Refusal or a lying allocator cannot repeat the pending history push.
        large=b'alpha\n'+b'x'*8192
        for mode in ('refuse','lie'):
            target.write_bytes(large);before_history=h.state(6)
            h.refuse_growth=mode=='refuse';h.lie_growth=mode=='lie'
            context=h.context();code,_=h.call('run',context,request)
            assert code==0xfffffffc and context[20]==(71 if mode=='refuse' else 70)
            assert context[17]==context[18]==1 and target.read_bytes()==large
            assert h.state(6)==before_history and word(h.state(3),72)==0
            release(context);h.refuse_growth=h.lie_growth=False;save('shared-growth-'+mode)
        context=h.context();code,result=h.call('run',context,request)
        assert code==len(result) and word(result,16)==0 and target.read_bytes()==b'beta\n'+large
        assert word(h.state(3),72)==0 and h.growth and h.slots[6][2]>=16384
        release(context);save('shared-growth-preserves-complete-history')
        report.update(status='PASS',actual_export_calls=sum(e['kind']=='export'for e in h.events),
            actual_explicit_owner_calls=sum(e['kind']=='owner'for e in h.events),growth=h.growth,
            complete_retained_blobs=len(list(h.vault.iterdir())),callback_exception=None)
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        report['elapsed_seconds']=time.monotonic()-started
        (output/'events.json').write_text(json.dumps(h.events,sort_keys=True,indent=2)+'\n')
        (output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        h.close();assert LIB.munmap(address,size)==0


if __name__=='__main__':main()
