"""Eight actual kernel engineering cases; no original-Rust equivalence claim."""
import argparse,ctypes as C,fcntl,gzip,os,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import encoded,loads,read,pin,require,source
from read_callable_prepare import verify
from watcher_loader import Callable,CONTEXT_BYTES,OBSERVER,word

class Capture:
    def __init__(self,output):
        self.output=output;self.rows=[];self.errors=[];self.active=None;self.offset=8
        self.raw=(output/"complete-native-buffers.bin.gz").open("xb")
        self.stream=gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=self.raw,mtime=0)
        self.stream.write(b"HNWLOG01");self.callback=OBSERVER(self.observe)
    def record(self,kind,raws,meta):
        row=dict(index=len(self.rows),kind=kind,offset=self.offset,meta=meta,buffers=[pin(raw)for raw in raws])
        header=encoded(row);wire=struct.pack("<Q",len(header))+header
        self.stream.write(wire);self.offset+=len(wire)
        for raw in raws:self.stream.write(raw);self.offset+=len(raw)
        self.rows.append(row)
    def observe(self,user,ctx,size,record,n):
        if self.errors:return
        try:
            require(user in(None,0) and ctx==self.active and size==CONTEXT_BYTES
                and record==ctx+24960 and n==128,"actual exclusive native observation borrow")
            raw=C.string_at(ctx,size);event=raw[24960:25088]
            require(event[:8]in(b"HNWOWN01",b"HNWBN001",b"HNWNCL01") and word(event,8)in(0,1),"exact native observation frame")
            pins=set()
            count=word(raw,104);require(count<=259,"actual bounded native pin set")
            for i in range(count):pins.add(word(raw,512+16*i))
            shared=word(raw,32)
            if shared:pins.add(shared)
            pages=[]
            for ptr in sorted(pins):
                require(ptr>0 and ptr%4096==0,"actual private pin alignment")
                page=C.string_at(ptr,4096)
                require(page[:8]==b"HNWFP001" and word(page,8)>0 and word(page,24)==4096,
                    "complete actual live File reference")
                pages.append((ptr,page))
            self.record("observation",(raw,)+tuple(page for _,page in pages),
                dict(context=ctx,event=event.hex(),pins=[ptr for ptr,_ in pages],observed_ns=time.monotonic_ns()))
        except BaseException as error:self.errors.append(repr(error))
    def close(self,success):
        try:
            if success and not self.errors:self.stream.write(b"HNWEND01"+struct.pack("<Q",len(self.rows)))
            self.stream.close();self.raw.close()
        finally:
            (self.output/"RECORDS.json").write_bytes(encoded(self.rows))
            (self.output/"OBSERVER-ERRORS.json").write_bytes(encoded(self.errors))

def request(cmd,generation,root=0,shared=0,limit=0,content=0,wd=0,mask=0):
    return b"HNWQ0001"+struct.pack("<11Q",cmd,generation,root,shared,limit,content,wd,mask,0,0,0)

def run(build,authored,output):
    identity=source();build_proof=verify(build,authored)
    output.mkdir(parents=True,exist_ok=False);fixture=output/"fixture";fixture.mkdir()
    composition=loads(read(build/"callable/BINDING.json"))
    machine=Callable(build/"callable/manifest.json",composition)
    capture=Capture(output);contexts=[];roots={};results=[];success=False
    (output/"LIBC.bin").write_bytes(machine.libc_bytes)
    (output/"LIBC-BINDINGS.json").write_bytes(encoded(machine.bindings))
    (output/"PROCESS-MAPS.txt").write_bytes(Path("/proc/self/maps").read_bytes())
    (output/"ADMISSION.json").write_bytes(encoded(build_proof))
    def save(kind,before,after,returned,meta):
        capture.record(kind,tuple(before)+tuple(after),dict(meta,returned=returned))
    def init(limit,content=False):
        ctx=machine.new_context();before=(ctx.raw,bytes(machine.table))
        value=int(machine.initialize(C.addressof(ctx),CONTEXT_BYTES,C.addressof(machine.table),
            C.cast(capture.callback,C.c_void_p),None))
        save("initialize",before,(ctx.raw,bytes(machine.table)),value,{})
        require(value==0,"actual mechanical context init")
        contexts.append(ctx)
        result=call(ctx,1,limit=limit,content=int(content))
        require(result[1]==0,"actual inotify init")
        return ctx
    def call(ctx,cmd,**args):
        capture.active=C.addressof(ctx)
        generation=word(ctx.raw,16)+1
        wire=request(cmd,generation,**args)
        value,before,after=machine.run(wire,ctx)
        save("entry",before,after,value,dict(cmd=cmd,generation=generation))
        require(value==128 and not capture.errors,"actual native terminal")
        raw=after[1][:128];require(raw[:8]==b"HNWR0001" and word(raw,16)==generation and word(raw,32)==cmd,
            "actual terminal frame identity")
        words=struct.unpack("<16Q",raw)
        require(words[1]in(0,1) and word(ctx.raw,8)==0,"actual quiescent native result")
        return words
    def open_root(name,file=False):
        path=fixture/name
        if file:path.write_bytes(b"ordinary-file")
        else:path.mkdir()
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
        ptr=int(machine.adopt(fd,machine.table[6],machine.table[7]))
        if ptr==0 or ptr>=(1<<64)-4095:os.close(fd);raise ValueError("actual pin allocation")
        page=C.string_at(ptr,4096)
        capture.record("pin-adopt",(page,),dict(pointer=ptr,fd=fd,path=str(path)))
        roots[ptr]=dict(fd=fd,path=path)
        return ptr,path
    def bind(ctx,ptr,shared=False):
        fd=roots[ptr]["fd"] if ptr else (1<<64)-1
        before=(ctx.raw,)
        value=int(machine.bind(C.addressof(ctx),CONTEXT_BYTES,fd,ptr if shared else None))
        save("bind",before,(ctx.raw,),value,dict(root=ptr,shared=shared))
        require(value==0,"actual borrowed directory bind")
    def version(ctx,ptr,shared=False):
        bind(ctx,ptr,shared)
        return call(ctx,2,root=1,shared=3 if shared else 0)
    def release(ptr):
        page=C.string_at(ptr,4096);out=C.create_string_buffer(b"\xa5"*80,80)
        before=(page,out.raw);value=int(machine.release(ptr,C.addressof(out)))
        require(value==0 and out.raw[:8]==b"HNWFPR01" and out.raw[64:]==b"\xa5"*16,
            "actual native File release and entire output")
        remaining=word(out.raw,16)
        after=(C.string_at(ptr,4096) if remaining else b"",out.raw)
        save("pin-release",before,after,value,dict(pointer=ptr))
        roots.pop(ptr,None)
        return remaining
    def drop(ctx):
        bind(ctx,0)
        value=call(ctx,4);require(value[1]==0 and word(ctx.raw,96)==(1<<64)-1 and word(ctx.raw,104)==0,"actual Watcher drop")
        before=(ctx.raw,);raw=int(machine.dispose(C.addressof(ctx),CONTEXT_BYTES))
        save("dispose",before,(ctx.raw,),raw,{})
        require(raw==0 and ctx.raw[:CONTEXT_BYTES]==bytes(CONTEXT_BYTES),"actual context disposal")
        contexts.remove(ctx)

    try:
        # 1. Ordinary membership changes; payload replacement alone is ignored.
        p,path=open_root("ordinary");ctx=init(4)
        first=version(ctx,p);require(first[1]==0 and first[11:13]==(1,1),"first actual watch token")
        require(version(ctx,p)[11:13]==first[11:13],"stable ordinary token")
        (path/"record").write_bytes(b"a");created=version(ctx,p);require(created[11:13]!=first[11:13],"actual create observed")
        (path/"record").write_bytes(b"changed");require(version(ctx,p)[11:13]==created[11:13],"ordinary payload ignored")
        os.rename(path/"record",path/"moved");moved=version(ctx,p);require(moved[11:13]!=created[11:13],"actual rename observed")
        os.unlink(path/"moved");removed=version(ctx,p);require(removed[11:13]!=moved[11:13],"actual unlink observed")
        drop(ctx);require(release(p)==0,"ordinary root final release");results.append("ordinary")
        # 2. Content mode observes data and permission changes.
        p,path=open_root("content");(path/"record").write_bytes(b"a");ctx=init(4,True)
        first=version(ctx,p);(path/"record").write_bytes(b"changed");changed=version(ctx,p)
        require(changed[11:13]!=first[11:13],"actual content modification")
        os.chmod(path/"record",0o600);require(version(ctx,p)[11:13]!=changed[11:13],"actual attribute modification")
        drop(ctx);release(p);results.append("content")
        # 3. Real LRU eviction and rearm never reuse an old token.
        pins=[open_root("lru-"+str(i))[0]for i in range(3)];ctx=init(2)
        first=version(ctx,pins[0]);version(ctx,pins[1]);version(ctx,pins[2]);last=version(ctx,pins[0])
        require(last[11:13]!=first[11:13] and last[14]==2,"actual two-record LRU")
        drop(ctx)
        for p in pins:release(p)
        results.append("lru")
        # 4. Original limit0 still retains one new record.
        pins=[open_root("zero-"+str(i))[0]for i in range(2)];ctx=init(0)
        require(version(ctx,pins[0])[14]==1 and version(ctx,pins[1])[14]==1,"actual original zero-limit behavior")
        drop(ctx)
        for p in pins:release(p)
        results.append("zero-limit")
        # 5. Shared pin survives caller release, then closes at Watcher drop.
        p,path=open_root("shared");fd=roots[p]["fd"];ctx=init(1)
        version(ctx,p,True);require(word(C.string_at(p,4096),8)==2,"actual shared clone")
        bind(ctx,0);require(release(p)==1,"running Watcher retains last reference")
        require(fcntl.fcntl(fd,fcntl.F_GETFD)>=0,"held actual File remains open")
        call(ctx,3);drop(ctx)
        try:fcntl.fcntl(fd,fcntl.F_GETFD);raise AssertionError("final shared FD still live")
        except OSError as error:require(error.errno==9,"actual final close")
        results.append("shared-caller-release")
        # 6. Metadata non-directory is the original business error.
        p,path=open_root("regular",True);ctx=init(4)
        value=version(ctx,p);require(value[1]==1 and value[9:11]==(2,8) and value[14]==0,"actual non-directory error")
        drop(ctx);release(p);results.append("non-directory")
        # 7. One real Arc-like pin shared by two independently owned Watchers.
        p,path=open_root("two");fd=roots[p]["fd"];a=init(1);b=init(1)
        version(a,p,True);version(b,p,True);require(word(C.string_at(p,4096),8)==3,"actual three holders")
        bind(a,0);bind(b,0);require(release(p)==2,"caller release keeps both watchers")
        drop(a);require(word(C.string_at(p,4096),8)==1,"first Watcher release preserves second")
        drop(b)
        try:fcntl.fcntl(fd,fcntl.F_GETFD);raise AssertionError("last pin not closed")
        except OSError as error:require(error.errno==9,"last of two Watchers actually closes")
        results.append("two-watchers")
        # 8. Drop followed by a fresh instance obtains a real fresh event FD.
        for _ in range(2):
            ctx=init(1);call(ctx,3);drop(ctx)
        results.append("drop-reinit")
        require(not capture.errors and not contexts and not roots,"complete actual native probe cleanup")
        success=True
    finally:
        for ctx in list(contexts):
            try:drop(ctx)
            except BaseException as error:capture.errors.append("cleanup:"+repr(error))
        for ptr in list(roots):
            try:release(ptr)
            except BaseException as error:capture.errors.append("root-cleanup:"+repr(error))
        capture.close(success)
        machine.close()
        result=dict(schema="hepta.namespace-watcher.native-engineering-probe.v1",
            status="PASS"if success and not capture.errors else"FAIL",cases=results,
            complete_record_count=len(capture.rows),source_manifest_sha256=identity,
            native_entry_calls=sum(x["kind"]=="entry"for x in capture.rows),
            actual_hia_owner_calls=sum(x["kind"]=="observation"and bytes.fromhex(x["meta"]["event"])[:16]==b"HNWOWN01"+struct.pack("<Q",1) for x in capture.rows),
            actual_native_boundaries=sum(x["kind"]=="observation"and bytes.fromhex(x["meta"]["event"])[:16]==b"HNWBN001"+struct.pack("<Q",1) for x in capture.rows),
            build=build_proof,observations=sum(x["kind"]=="observation"for x in capture.rows),
            errors=capture.errors,original_rust_executions=0,original_comparison_qualified=False,
            namespace_version_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
        (output/"PROBE.json").write_bytes(encoded(result));print(encoded(result).decode(),end="")
    require(success and not capture.errors and len(results)==8,"all actual native engineering cases")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--build",type=Path,required=True)
    p.add_argument("--authored",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.build.resolve(strict=True),a.authored.resolve(strict=True),a.output.absolute())
