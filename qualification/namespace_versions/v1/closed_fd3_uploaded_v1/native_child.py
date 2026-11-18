"""Actual process-global HIA lifecycle; fixtures own inputs and never produce effect acknowledgements."""
import argparse,ctypes as C,os,struct,sys,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import encoded,loads,read,pin,require,source
from protocol import line,require_semantic
from admission import native as admit
from versions_loader import Callable,word
from capture_native import Capture
import environment_policy as env
from fd_floor import run as closed_standard_watcher
def request(cmd,kind,fd=0,members=()):
    payload=b"".join(struct.pack("<2Q",v["fd"],v["pointer"])for v in members)if len(members)<=258 else b""
    return b"HNVSQ001"+struct.pack("<11Q",cmd,1,kind,fd,len(members),0,0,0,0,len(payload),0)+payload
def success():return dict(kind=0,family=0,code=0,version=None,digest=None)
def semantic(raw):
    require(len(raw)==128 and raw[:8]==b"HNVSR001"and word(raw,8)in range(6),"entire native terminal")
    kind=word(raw,8)
    result=dict(kind=kind if kind<4 else 0,family=word(raw,40),code=word(raw,48),
        version=[word(raw,56),word(raw,64)]if kind==1 else None,digest=raw[80:112].hex()if kind==2 else None)
    return require_semantic(result)
def emit(value):sys.stdout.buffer.write(line(value));sys.stdout.buffer.flush()
def mark(tag,case,step):os.write(2,tag+struct.pack("<2Q",case,step))
def run(retained,output,group,observer):
    identity=source();admission=admit(retained);output.mkdir(parents=True,exist_ok=False)
    build=retained/"native/run/build"
    machine=Callable(build/"callable/manifest.json",loads(read(build/"callable/BINDING.json")))
    capture=Capture(output,machine.environment)
    roots={};sets={};paths=[];selected=None;finished=False;next_step=0;passed=False
    loaded_address=machine.module._address
    capture.record("loaded-image",(C.string_at(loaded_address,machine.composition["offsets"]["end"]),),
        dict(address=loaded_address,bytes=machine.composition["offsets"]["end"]))
    (output/"LIBC.bin").write_bytes(machine.libc_bytes)
    (output/"LIBC-BINDINGS.json").write_bytes(encoded(machine.bindings))
    (output/"PROCESS-MAPS.txt").write_bytes(Path("/proc/self/maps").read_bytes())
    (output/"ADMISSION.json").write_bytes(encoded(admission))
    def save(kind,before,after,returned,meta):
        capture.record(kind,tuple(before)+tuple(after),dict(meta,returned=returned,before_count=len(before),after_count=len(after)))
    returned,before,after=machine.initialize_environment(capture.callback if observer else None)
    save("initialize",before,after,returned,dict(environment=machine.environment,observer=observer))
    globals_={"ordinary":machine.environment+256,"content":machine.environment+512}
    layout=env.reserve();saved=env.limit()
    def pin_clone(value,reason):
        p=value["pointer"];before=(C.string_at(p,4096),);returned=int(machine.clone(p))
        save("pin-clone",before,(C.string_at(p,4096),),returned,dict(pointer=p,fd=value["fd"],reason=reason))
        require(returned==p,"actual caller File clone");return dict(value)
    def pin_release(value,reason):
        p=value["pointer"];result=C.create_string_buffer(b"\xa5"*80,80);before=(C.string_at(p,4096),result.raw)
        returned=int(machine.release(p,C.addressof(result)))
        require(returned==0 and result.raw[:8]==b"HNWFPR01"and result.raw[64:]==b"\xa5"*16,"actual complete File release")
        left=word(result.raw,16);after=(C.string_at(p,4096)if left else b"",result.raw)
        save("pin-release",before,after,returned,dict(pointer=p,fd=value["fd"],reason=reason))
    def open_root(index):
        require(index not in roots and 0<=index<len(paths),"fresh caller root")
        fd=env.open_root(paths[index],index);p=int(machine.adopt(fd,machine.pointers[6],machine.pointers[7]))
        if not 0<p<(1<<64)-4095:os.close(fd);raise ValueError("actual native File allocation")
        page=C.string_at(p,4096);require(page[:8]==b"HNWFP001"and word(page,16)==fd,"actual adopted root descriptor")
        roots[index]=dict(pointer=p,fd=fd);capture.record("pin-adopt",(page,),dict(root=index,pointer=p,fd=fd,path_hex=paths[index].hex()))
    def invoke(obj,cmd,kind,fd=0,members=()):
        capacity=4096 if kind==3 else 256;wire=request(cmd,kind,fd,members)
        returned,before,after=machine.run(wire,obj,capacity)
        save("entry",before,after,returned,dict(object=obj,object_bytes=capacity,cmd=cmd,generation=1,kind=kind))
        require(returned==128 and not capture.errors,"actual HIA/native terminal without transport quarantine")
        frame=after[1][:128];require(frame[:8]==b"HNVSR001"and word(frame,16)==1 and word(frame,24)==cmd,"actual turn identity")
        return frame
    def dispose(obj,sid,reason):
        before=(C.string_at(obj,4096),machine.env.raw);returned=int(machine.dispose(obj,4096))
        save("set-dispose",before,(machine.env.raw,),returned,dict(object=obj,sid=sid,reason=reason))
        require(returned==0,"actual exclusive set disposal after all owned child resources")
    def make_set(sid,members,clone_members=True):
        require(sid not in sets,"fresh scope identity")
        held=[pin_clone(v,"constructor-member")for v in members]if clone_members else members
        obj=int(machine.allocate(machine.environment))
        require(0<obj<(1<<64)-4095 and obj%4096==0,"actual set mmap and mutex initialization")
        capture.record("set-allocate",(C.string_at(obj,4096),machine.env.raw),dict(object=obj,sid=sid,returned=obj))
        raw=invoke(obj,3,3,members=held);kind=word(raw,8)
        require(kind in(0,4),"original optional set constructor")
        if kind==4:sets[sid]=obj
        else:dispose(obj,sid,"unavailable-constructor")
        if clone_members:
            for value in held:pin_release(value,"constructor-member")
        return raw,dict(constructed=kind==4,sid=sid)
    def watcher(ptr,pins,contexts):
        raw=C.string_at(ptr,131072);require(raw[:8]==b"HNWCTX01"and word(raw,8)==0 and word(raw,152)==0,
            "complete quiescent child transport")
        count=word(raw,32768+88);require(count<=258 and word(raw,32768+8)==1,"live original Watcher")
        values=[]
        for index in range(count):
            at=32768+1024+index*64;p=word(raw,at);page=C.string_at(p,4096);pins.add(p)
            require(page[:8]==b"HNWFP001"and word(page,8)>0,"complete owned File page")
            values.append(dict(device=word(raw,at+8),inode=word(raw,at+16),wd=word(raw,at+24),
                id=word(raw,at+32),generation=word(raw,at+40),dead=bool(word(raw,at+48)),
                pin_fd=word(page,16),strong_count=word(page,8)))
        contexts[ptr]=raw
        return dict(event_fd=word(raw,96),next=word(raw,32768+80),limit=word(raw,32768+56),
            content=bool(word(raw,32768+64)),watches=values)
    def checkpoint():
        pinset={v["pointer"]for v in roots.values()};contexts={};objects={};global_rows=[];scope_rows=[]
        for kind,obj in globals_.items():
            raw=C.string_at(obj,256);objects[obj]=raw
            require(raw[:8]==b"HNVOBJ01"and word(raw,176)==word(raw,184)==word(raw,192)==word(raw,56)==0,
                "quiescent complete global native owner")
            child=word(raw,48);require(child==word(raw,80),"actual global child matches shared state")
            global_rows.append(dict(kind=kind,initialized=bool(word(raw,104)),poison=bool(word(raw,40)),
                watcher=watcher(child,pinset,contexts)if child else None))
        for sid,obj in sorted(sets.items()):
            raw=C.string_at(obj,4096);objects[obj]=raw
            require(raw[:8]==b"HNVOBJ01"and word(raw,24)==3 and word(raw,104)==1 and
                word(raw,176)==word(raw,184)==word(raw,192)==word(raw,56)==0,"complete live quiescent scope")
            child=word(raw,48);require(child==word(raw,80)and child>0,"actual set child custody")
            scope_rows.append(dict(sid=sid,id=word(raw,88),poison=bool(word(raw,40)),invalid=bool(word(raw,96)),
                watcher=watcher(child,pinset,contexts)))
        root_rows=[]
        for index,value in sorted(roots.items()):
            page=C.string_at(value["pointer"],4096);m=os.fstat(value["fd"])
            root_rows.append(dict(root=index,fd=value["fd"],strong_count=word(page,8),
                device=m.st_dev,inode=m.st_ino,mode=m.st_mode))
        state=dict(globals=global_rows,sets=scope_rows,next=word(machine.env.raw,24),roots=root_rows)
        p=sorted(pinset)
        capture.record("checkpoint",(machine.env.raw,*objects.values(),*contexts.values(),*(C.string_at(x,4096)for x in p)),
            dict(environment=machine.environment,objects=[dict(pointer=x,bytes=len(raw))for x,raw in objects.items()],
                children=list(contexts),pins=p,roots={str(i):v for i,v in roots.items()},sets={str(s):v for s,v in sets.items()},state=state))
        return state
    def selected_object(op):
        return sets[op["sid"]]if op.get("sid")is not None else globals_[op["kind"]]
    def locked_fixture(obj,operation):
        cap=4096 if word(C.string_at(obj,256),24)==3 else 256
        before=(C.string_at(obj,cap),machine.env.raw);returned=int(machine.lock(obj+128))
        save("fixture-lock",before,(C.string_at(obj,cap),machine.env.raw),returned,dict(object=obj,capacity=cap,operation=operation))
        require(returned==0,"real private fixture mutex acquisition");return cap
    def unlock_fixture(obj,cap,operation):
        before=(C.string_at(obj,cap),machine.env.raw);returned=int(machine.unlock(obj+128))
        save("fixture-unlock",before,(C.string_at(obj,cap),machine.env.raw),returned,dict(object=obj,capacity=cap,operation=operation))
        require(returned==0,"real private fixture mutex release")
    def changed(op):
        obj=sets[op["sid"]];cap=locked_fixture(obj,"changed")
        try:
            p=word(C.string_at(obj,256),48);before=C.string_at(p,131072)
            returned=int(machine.child_bind(p,131072,(1<<64)-1,None))
            save("fixture-child-bind",(before,),(C.string_at(p,131072),),returned,dict(object=obj,child=p))
            require(returned==0,"real qualified child binding clear")
            generation=word(C.string_at(p,131072),16)+1
            wire=b"HNWQ0001"+struct.pack("<11Q",5,generation,0,0,0,0,op["wd"]&0xffffffff,op["mask"],0,0,0)
            inp=C.create_string_buffer(wire+b"\xc3"*16,len(wire)+16);out=C.create_string_buffer(b"\xa5"*144,144)
            before=(inp.raw,out.raw,C.string_at(p,131072),C.string_at(obj,cap))
            returned=int(machine.child(C.addressof(inp),96,C.addressof(out),128,p,131072))
            after=(inp.raw,out.raw,C.string_at(p,131072),C.string_at(obj,cap))
            save("fixture-changed",before,after,returned,dict(object=obj,child=p,generation=generation,wd=op["wd"],mask=op["mask"]))
            require(returned==128 and inp.raw==before[0]and out.raw[128:]==b"\xa5"*16 and out.raw[:8]==b"HNWR0001",
                "entire actual qualified Watcher changed fixture")
            raw=out.raw[:128]
            return require_semantic(dict(kind=3 if word(raw,8)==1 else 0,family=word(raw,72),code=word(raw,80),version=None,digest=None))
        finally:unlock_fixture(obj,cap,"changed")
    def parallel(op):
        workers=op["workers"];barrier=threading.Barrier(workers);results=[None]*workers;errors=[];threads=[]
        require(2<=workers<=32,"bounded real thread group")
        root=roots.get(op.get("root"));outer=pin_clone(root,"parallel-outer")if root is not None and op["op"]=="parallel-read"else None
        held=[pin_clone(root,"parallel-worker")for _ in range(workers)]if root is not None else [None]*workers
        def worker(index):
            tid=threading.get_native_id();capture.threads[tid]=index
            try:
                barrier.wait(timeout=30);rows=[]
                if op["op"]=="parallel-new":
                    raw,control=make_set(op["sid"]+index,[held[index]],False)
                    rows.append(dict(worker=index,sid=op["sid"]+index,tid=tid,constructed=control["constructed"],native_frame_hex=raw.hex()))
                else:
                    for number in range(op["count"]):
                        kind=op["kind"]
                        if kind=="set":raw=invoke(sets[op["sid"]],4,3)
                        else:raw=invoke(globals_[kind],1 if kind=="ordinary"else 2,1 if kind=="ordinary"else 2,held[index]["fd"])
                        rows.append(dict(worker=index,index=number,tid=tid,semantic=semantic(raw),native_frame_hex=raw.hex()))
                results[index]=rows
            except BaseException as error:errors.append(repr(error));barrier.abort()
            finally:
                if held[index]is not None:pin_release(held[index],"parallel-worker")
                capture.threads.pop(tid,None)
        for i in range(workers):
            thread=threading.Thread(target=worker,args=(i,),name="namespace-worker-"+str(i));threads.append(thread);thread.start()
        for thread in threads:thread.join()
        if outer is not None:pin_release(outer,"parallel-outer")
        require(not errors and all(x is not None for x in results),"complete real worker lifetimes: "+repr(errors))
        return [row for worker_rows in results for row in worker_rows]
    try:
        emit(dict(command="ready",role="native-"+("observed"if observer else"off"),pid=os.getpid(),parent_pid=os.getppid(),
            pgid=os.getpgrp(),uid=os.geteuid(),gid=os.getegid(),group=group,layout=layout))
        for line_in in sys.stdin.buffer:
            require(line_in.endswith(b"\n")and len(line_in)<=1<<20,"whole bounded private control")
            command=loads(line_in);case=command["case"];capture.case=case;kind=command["cmd"]
            if kind=="prepare":
                require(selected is None and not finished and not sets and not roots,"one fresh physical case; globals never reset")
                paths[:]=[bytes.fromhex(r["path_hex"])for r in command["roots"]];capture.step=None;capture.operation="prepare"
                for index,row in enumerate(command["roots"]):
                    if not row["late"]:open_root(index)
                selected=case;emit(dict(command=kind,case=case,state=checkpoint()))
            elif kind=="run":
                step=command["step"];require(selected==case and step==next_step,"complete ordered original/native operation")
                next_step+=1;op=command["operation"];operation=op["op"];capture.step=step;capture.operation=operation
                raw=None;result=success();control=None;parallel_rows=[]
                mark(b"HNVNATB1",case,step)
                if operation in("version","watched","content"):
                    ordinary=operation!="content";cmd={"version":1,"content":2,"watched":6}[operation]
                    raw=invoke(globals_["ordinary"if ordinary else"content"],cmd,1 if ordinary else 2,roots[op["root"]]["fd"])
                elif operation=="set-new":raw,control=make_set(op["sid"],[roots[i]for i in op["roots"]])
                elif operation=="set-version":raw=invoke(sets[op["sid"]],4,3)
                elif operation=="set-drop":
                    obj=sets[op["sid"]];raw=invoke(obj,5,3);require(word(raw,8)==5,"actual complete set drop")
                    dispose(obj,op["sid"],"final-owner");del sets[op["sid"]]
                elif operation=="closed-standard-watcher":
                    control=closed_standard_watcher(machine,capture,observer,roots[op["first"]]["fd"],roots[op["second"]]["fd"],op["mask"],op["content"])
                elif operation=="seed-next":
                    value=int(op["value_decimal"]);require(0<=value<1<<64,"actual bounded fixture atomic seed")
                    before=(machine.env.raw,);C.c_uint64.from_address(machine.environment+24).value=value
                    save("fixture-seed-next",before,(machine.env.raw,),0,dict(value=value,atomic_address=machine.environment+24))
                elif operation=="seed-watcher":
                    value=int(op["value_decimal"]);require(0<=value<1<<63,"actual bounded Watcher epoch seed")
                    obj=selected_object(op);cap=locked_fixture(obj,"seed")
                    try:
                        p=word(C.string_at(obj,256),48);before=(C.string_at(p,131072),)
                        C.c_uint64.from_address(p+32768+80).value=value
                        save("fixture-seed-watcher",before,(C.string_at(p,131072),),0,dict(object=obj,child=p,value=value))
                    finally:unlock_fixture(obj,cap,"seed")
                elif operation=="changed-set":result=changed(op)
                elif operation=="poison":
                    obj=selected_object(op);cap=locked_fixture(obj,"poison");unwound=False
                    try:
                        try:raise RuntimeError("qualification actual held namespace mutex unwind")
                        except RuntimeError as error:
                            before=(C.string_at(obj,cap),);C.c_uint64.from_address(obj+40).value=1;unwound=True
                            save("fixture-poison",before,(C.string_at(obj,cap),),0,dict(object=obj,exception=repr(error),actual_unwind=True))
                    finally:unlock_fixture(obj,cap,"poison")
                    control=dict(actual_unwind=unwound)
                elif operation in("parallel-read","parallel-new"):parallel_rows=parallel(op)
                elif operation=="release-root":pin_release(roots.pop(op["root"]),"caller-root")
                elif operation=="open-root":open_root(op["root"])
                elif operation=="limit":env.set_limit(op["soft"],saved[1])
                elif operation=="restore-limit":env.set_limit(*saved)
                else:raise ValueError("unlisted exact native operation")
                mark(b"HNVNATE1",case,step)
                if raw is not None:result=semantic(raw)
                emit(dict(command=kind,case=case,step=step,operation=operation,semantic=result,state=checkpoint(),
                    control=control,parallel=parallel_rows,native_frame_hex=None if raw is None else raw.hex()))
            elif kind=="finish":
                require(selected==case and not sets,"every native scope explicitly dropped")
                capture.step=None;capture.operation="finish"
                for index in list(roots):pin_release(roots.pop(index),"caller-root")
                paths.clear();env.set_limit(*saved);selected=None;finished=True
                emit(dict(command=kind,case=case,all_sets_and_caller_roots_dropped=True,globals_live_until_process_exit=True,state=checkpoint()))
            else:raise ValueError("unlisted complete control")
        require(selected is None and finished and not sets and not roots and not capture.errors,"complete actual process lifetime")
        passed=True
    finally:
        try:env.set_limit(*saved)
        except BaseException as error:capture.errors.append("restore-limit:"+repr(error))
        # A failed or unknown call is never replayed. The OS owns final process cleanup.
        try:capture.close(passed)
        finally:machine.close()
        report=dict(schema="hepta.namespace-versions.native-role.v1",status="PASS"if passed and not capture.errors else"FAIL",
            role="native-"+("observed"if observer else"off"),group=group,source_manifest_sha256=identity,pid=os.getpid(),
            parent_pid=os.getppid(),pgid=os.getpgrp(),uid=os.geteuid(),gid=os.getegid(),source_root=str(ROOT),retained_root=str(retained),
            output_root=str(output),callable=machine.composition["callable_image"],loaded_image=dict(address=loaded_address,bytes=machine.composition["offsets"]["end"]),
            admission=admission,observer=observer,records=len(capture.records),objects=len(capture.objects),logical_bytes=capture.logical_bytes,
            errors=capture.errors,entry_calls=sum(r["kind"]=="entry"for r in capture.records),
            original_rust_executions=0,application_replays=0,globals_reset=False,globals_live_until_process_exit=True,
            namespace_version_qualified=False,public_handler_qualified=False)
        (output/"NATIVE.json").write_bytes(encoded(report))
    require(passed and not capture.errors,"whole native process completed")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in("retained","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);p.add_argument("--observer",choices=("on","off"),required=True)
    a=p.parse_args();run(a.retained.resolve(strict=True),a.output.absolute(),a.group,a.observer=="on")
