"""Persistent real HIA/native Watcher. Test code owns inputs, never actual effect ACKs."""
import argparse,ctypes as C,fcntl,os,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import encoded,loads,read,pin,require,source
from protocol import line,require_semantic
from legacy_build import verify as admit
from watcher_loader import Callable,CONTEXT_BYTES,word
from capture_native import Capture
import environment_policy as env
OWNER=C.CFUNCTYPE(C.c_uint64,*([C.c_void_p,C.c_uint64]*3))
def request(cmd,generation,root=0,shared=0,limit=0,content=0,wd=0,mask=0):
    return b"HNWQ0001"+struct.pack("<11Q",cmd,generation,root,shared,limit,content,wd,mask,0,0,0)
def success():return dict(kind=0,family=0,code=0,version=None)
def semantic(raw):
    require(len(raw)==128 and raw[:8]==b"HNWR0001"and word(raw,8)in(0,1),"complete final native response")
    result=dict(kind=word(raw,8),family=word(raw,72),code=word(raw,80),
        version=[word(raw,88),word(raw,96)]if word(raw,8)==0 and word(raw,32)==2 else None)
    return require_semantic(result)
def emit(value):sys.stdout.buffer.write(line(value));sys.stdout.buffer.flush()
def mark(tag,case,step):os.write(2,tag+struct.pack("<2Q",case,step))
def run(retained,output,group,observer):
    identity=source();admission=admit(retained)
    output.mkdir(parents=True,exist_ok=False);build=retained/"complete/run/build"
    machine=Callable(build/"callable/manifest.json",loads(read(build/"callable/BINDING.json")))
    capture=Capture(output);watchers={};roots={};paths=[];selected=None;next_step=0;passed=False;owned_contexts={}
    loaded_address=machine.module._address
    core=OWNER(loaded_address+machine.composition["offsets"]["owner"])
    (output/"LIBC.bin").write_bytes(machine.libc_bytes)
    (output/"LIBC-BINDINGS.json").write_bytes(encoded(machine.bindings))
    (output/"PROCESS-MAPS.txt").write_bytes(Path("/proc/self/maps").read_bytes())
    (output/"ADMISSION.json").write_bytes(encoded(admission))
    layout=env.reserve();saved=env.limit()
    def save(kind,before,after,returned,meta):
        capture.record(kind,tuple(before)+tuple(after),dict(meta,returned=returned))
    def open_root(index):
        require(index not in roots and index<len(paths),"fresh owned root")
        fd=env.open_root(paths[index],index);ptr=int(machine.adopt(fd,machine.table[6],machine.table[7]))
        if ptr==0 or ptr>=(1<<64)-4095:os.close(fd);raise ValueError("actual native pin allocation")
        page=C.string_at(ptr,4096);require(page[:8]==b"HNWFP001" and word(page,16)==fd,"actual owned pin")
        roots[index]=dict(pointer=ptr,fd=fd)
        capture.record("pin-adopt",(page,),dict(pointer=ptr,fd=fd,root=index,path_hex=paths[index].hex()))
    def bind(ctx,index=None,shared=False):
        value=roots[index]if index is not None else None
        before=(ctx.raw,);ret=int(machine.bind(C.addressof(ctx),CONTEXT_BYTES,
            value["fd"]if value else (1<<64)-1,value["pointer"]if value and shared else None))
        save("bind",before,(ctx.raw,),ret,dict(context=C.addressof(ctx),root=index,shared=shared))
        require(ret==0,"actual directory capability bind")
    def invoke(ctx,cmd,**args):
        capture.active=C.addressof(ctx);wire=request(cmd,int(capture.step)+1,**args)
        ret,before,after=machine.run(wire,ctx)
        save("entry",before,after,ret,dict(context=C.addressof(ctx),cmd=cmd,generation=int(capture.step)+1))
        require(ret==128 and not capture.errors and word(ctx.raw,8)==0,"actual native terminal and callback custody")
        raw=after[1][:128];require(word(raw,16)==int(capture.step)+1 and word(raw,32)==cmd,"actual complete turn identity")
        return raw
    def dispose(ctx):
        before=(ctx.raw,);ret=int(machine.dispose(C.addressof(ctx),CONTEXT_BYTES))
        save("dispose",before,(ctx.raw,),ret,dict(context=C.addressof(ctx)))
        require(ret==0 and ctx.raw[:CONTEXT_BYTES]==bytes(CONTEXT_BYTES),"actual complete context disposal")
        owned_contexts.pop(C.addressof(ctx),None)
    def release(index):
        value=roots[index];ptr=value["pointer"]
        # No persistent borrowed context is allowed to outlive this caller reference.
        for ctx in watchers.values():bind(ctx)
        before_page=C.string_at(ptr,4096);out=C.create_string_buffer(b"\xa5"*80,80)
        before=(before_page,out.raw);ret=int(machine.release(ptr,C.addressof(out)))
        require(ret==0 and out.raw[:8]==b"HNWFPR01"and out.raw[64:]==b"\xa5"*16,"actual pin release frame/guard")
        left=word(out.raw,16);page=C.string_at(ptr,4096)if left else b""
        save("pin-release",before,(page,out.raw),ret,dict(root=index,pointer=ptr,fd=value["fd"]))
        del roots[index]
    def checkpoint():
        ptrs={r["pointer"]for r in roots.values()};contexts=[];states=[];root_rows=[]
        for wid,ctx in sorted(watchers.items()):
            raw=ctx.raw;require(word(raw,8)==0 and word(raw,152)==0,"quiescent actual native transport")
            require(word(raw,32768+8)==1,"same live original Watcher")
            count=word(raw,32768+88);require(count<=258,"bounded actual watch set")
            watches=[]
            for i in range(count):
                at=32768+1024+i*64;ptr=word(raw,at);page=C.string_at(ptr,4096);ptrs.add(ptr)
                require(page[:8]==b"HNWFP001"and word(page,8)>0,"actual held File pin")
                watches.append(dict(device=word(raw,at+8),inode=word(raw,at+16),wd=word(raw,at+24),
                    id=word(raw,at+32),generation=word(raw,at+40),dead=bool(word(raw,at+48)),
                    pin_fd=word(page,16),strong_count=word(page,8)))
            states.append(dict(wid=wid,state=dict(event_fd=word(raw,96),next=word(raw,32768+80),
                limit=word(raw,32768+56),content=bool(word(raw,32768+64)),watches=watches)))
            contexts.append(dict(wid=wid,pointer=C.addressof(ctx)))
        for index,value in sorted(roots.items()):
            page=C.string_at(value["pointer"],4096);info=os.fstat(value["fd"])
            root_rows.append(dict(root=index,fd=value["fd"],strong_count=word(page,8),
                device=info.st_dev,inode=info.st_ino,mode=info.st_mode))
        pins=sorted(ptrs);state=dict(watchers=states,roots=root_rows)
        capture.record("checkpoint",tuple(watchers[x["wid"]].raw for x in contexts)+
            tuple(C.string_at(ptr,4096)for ptr in pins),
            dict(contexts=contexts,pins=pins,roots={str(i):v for i,v in roots.items()},state=state))
        return state
    def callback(ctx,op):
        # This is solely the explicit test-owned original callback contract.
        # Actual kernel operations always go through machine.entry above.
        command=3 if op["root"]is None else 2;generation=int(capture.step)+1
        wire=request(command,generation,root=0 if command==3 else 1,
            shared=3 if command==2 and op["shared"]else 0)
        buffer=bytearray(16384);records=[];index=0
        while True:
            inp=C.create_string_buffer(wire+b"\xc3"*16,len(wire)+16);out=C.create_string_buffer(b"\xa5"*144,144)
            work=C.addressof(ctx)+32768
            before=(inp.raw,out.raw,C.string_at(work,65552))
            ret=int(core(C.addressof(inp),len(wire),C.addressof(out),128,work,65536))
            after=(inp.raw,out.raw,C.string_at(work,65552))
            save("private-owner",before,after,ret,dict(context=C.addressof(ctx),command=command,generation=generation))
            require(ret==128 and before[0]==after[0]and out.raw[128:]==b"\xa5"*16 and
                after[2][65536:]==b"\x5a"*16,"entire private HIA callback buffers")
            response=out.raw[:128];require(response[:8]==b"HNWR0001"and word(response,16)==generation,"private actual response")
            if word(response,8)!=2:return response,records
            require(word(response,40)==2 and word(response,48)==2 and word(response,56)==16384,
                "private script supplies only the original read callback, never other effects")
            rows=op["script"]["reads"]
            if index<len(rows):selected_index=index
            else:
                require(op["script"]["repeat_last"]and rows,"complete exact callback script")
                selected_index=len(rows)-1
            item=rows[selected_index];old_buffer=bytes(buffer);status=0;error=0;count=0;payload=b""
            if "errno"in item:status=1;error=item["errno"]
            elif "kind"in item:status=1;error={"Interrupted":4,"WouldBlock":11}[item["kind"]]
            else:
                payload=bytes.fromhex(item["bytes"]);count=item["count"]
                require(len(payload)<=16384,"bounded exact callback bytes")
                buffer[:len(payload)]=payload
            records.append(dict(index=index,script_row=selected_index,before_hex=old_buffer.hex(),
                after_hex=bytes(buffer).hex(),result=dict(errno=error)if status else dict(count=count)))
            index+=1
            wire=b"HNWAK001"+struct.pack("<11Q",generation,word(response,24),2,status,error,
                count,0,0,len(payload),96+len(payload),0)+payload
    try:
        emit(dict(command="ready",role="native-"+("observed"if observer else"off"),
            pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),uid=os.geteuid(),gid=os.getegid(),group=group,layout=layout))
        for line_in in sys.stdin.buffer:
            require(line_in.endswith(b"\n")and len(line_in)<=1<<20,"bounded whole private control")
            command=loads(line_in);case=command["case"];capture.case=case;kind=command["cmd"]
            if kind=="prepare":
                require(selected is None and not watchers and not roots,"exact previous native scope released")
                env.clear();paths[:]=[bytes.fromhex(r["path_hex"])for r in command["roots"]]
                capture.step=None;capture.operation="prepare"
                for index,row in enumerate(command["roots"]):
                    if not row["late"]:open_root(index)
                selected=case;next_step=0;emit(dict(command=kind,case=case,state=checkpoint()))
            elif kind=="run":
                step=command["step"];require(selected==case and step==next_step,"same ordered actual native operation")
                next_step+=1;op=command["operation"];operation=op["op"];capture.step=step;capture.operation=operation
                raw=None;result=success();callbacks=[]
                mark(b"HNWNATB1",case,step)
                if operation=="new":
                    wid=op["wid"];require(wid not in watchers,"new independent native Watcher")
                    ctx=machine.new_context();before=(ctx.raw,bytes(machine.table))
                    observed=C.cast(capture.callback,C.c_void_p)if observer else None
                    ret=int(machine.initialize(C.addressof(ctx),CONTEXT_BYTES,C.addressof(machine.table),observed,None))
                    save("initialize",before,(ctx.raw,bytes(machine.table)),ret,dict(wid=wid,context=C.addressof(ctx),observer=observer))
                    require(ret==0,"actual native Watcher initialization")
                    owned_contexts[C.addressof(ctx)]=ctx
                    raw=invoke(ctx,1,limit=op["limit"],content=int(op["content"]))
                    if word(raw,8)==0:watchers[wid]=ctx
                    else:dispose(ctx)
                elif operation=="version":
                    ctx=watchers[op["wid"]];bind(ctx,op["root"],op["shared"])
                    raw=invoke(ctx,2,root=1,shared=3 if op["shared"]else 0)
                elif operation=="drain":raw=invoke(watchers[op["wid"]],3)
                elif operation=="changed":raw=invoke(watchers[op["wid"]],5,wd=op["wd"]&0xffffffff,mask=op["mask"])
                elif operation=="seed":
                    ctx=watchers[op["wid"]];value=int(op["next_decimal"]);require(0<=value<1<<63,"private epoch seed")
                    before=(ctx.raw,);struct.pack_into("<Q",ctx,32768+80,value)
                    save("private-seed",before,(ctx.raw,),0,dict(context=C.addressof(ctx),next=value))
                elif operation=="callback":raw,callbacks=callback(watchers[op["wid"]],op)
                elif operation=="drop":
                    ctx=watchers[op["wid"]];bind(ctx);raw=invoke(ctx,4)
                    require(word(raw,8)==0,"actual drop completes");dispose(ctx);del watchers[op["wid"]]
                elif operation=="release-root":release(op["root"])
                elif operation=="open-root":open_root(op["root"])
                elif operation=="limit":env.set_limit(op["soft"],saved[1])
                elif operation=="restore-limit":env.set_limit(*saved)
                else:raise ValueError("unlisted native operation")
                mark(b"HNWNATE1",case,step)
                if raw is not None:result=semantic(raw)
                emit(dict(command=kind,case=case,step=step,operation=operation,semantic=result,
                    state=checkpoint(),callback=callbacks,native_frame_hex=None if raw is None else raw.hex()))
            elif kind=="finish":
                require(selected==case and not watchers,"all native Watchers explicitly dropped")
                capture.step=None;capture.operation="finish"
                for index in list(roots):release(index)
                paths.clear();env.set_limit(*saved);env.clear();selected=None
                emit(dict(command=kind,case=case,all_owned_descriptors_closed=True))
            else:raise ValueError("unlisted private command")
        require(selected is None and not watchers and not owned_contexts and not roots and not capture.errors,"complete native scope at EOF")
        env.clear();passed=True
    finally:
        # Real cleanup remains independent of whether any report write succeeds.
        try:env.set_limit(*saved)
        except BaseException as error:capture.errors.append("restore-limit:"+repr(error))
        for pointer,ctx in list(owned_contexts.items()):
            try:
                capture.step=max(int(capture.step or 0),word(ctx.raw,16),word(ctx.raw,32768+24))+1
                capture.operation="failed-cleanup"
                bind(ctx)
                if word(ctx.raw,32768+8)==1:invoke(ctx,4)
                dispose(ctx)
                for wid,value in list(watchers.items()):
                    if value is ctx:del watchers[wid]
            except BaseException as error:capture.errors.append("cleanup:"+repr(error))
        for index in list(roots):
            try:release(index)
            except BaseException as error:capture.errors.append("root-cleanup:"+repr(error))
        try:capture.close(passed)
        finally:
            core=None;machine.close()
        report=dict(schema="hepta.namespace-watcher.native-role.v1",status="PASS"if passed and not capture.errors else"FAIL",
            role="native-"+("observed"if observer else"off"),group=group,source_manifest_sha256=identity,
            pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),uid=os.geteuid(),gid=os.getegid(),
            source_root=str(ROOT),retained_root=str(retained),output_root=str(output),
            callable=machine.composition["callable_image"],loaded_image=dict(address=loaded_address,bytes=machine.composition["offsets"]["end"]),
            admission=admission,observer=observer,records=len(capture.rows),errors=capture.errors,
            native_entry_calls=sum(r["kind"]=="entry"for r in capture.rows),
            private_owner_calls=sum(r["kind"]=="private-owner"for r in capture.rows),
            actual_hia_calls=sum(r["kind"]=="observation"and bytes.fromhex(r["meta"]["event"])[:16]==b"HNWOWN01"+struct.pack("<Q",1)for r in capture.rows),
            actual_boundaries=sum(r["kind"]=="observation"and bytes.fromhex(r["meta"]["event"])[:16]==b"HNWBN001"+struct.pack("<Q",1)for r in capture.rows),
            original_rust_executions=0,namespace_version_qualified=False,public_handler_qualified=False)
        (output/"NATIVE.json").write_bytes(encoded(report))
    require(passed and not capture.errors,"whole native role completed")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in("retained","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);p.add_argument("--observer",choices=("on","off"),required=True)
    a=p.parse_args();run(a.retained.resolve(strict=True),a.output.absolute(),a.group,a.observer=="on")
