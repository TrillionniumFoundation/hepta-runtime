"""Actual standalone qualified Watcher calls while selected standard descriptors are closed."""
import ctypes as C,fcntl,os,struct
from common import require
from versions_loader import word
OBSERVER=C.CFUNCTYPE(None,C.c_void_p,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
INIT=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_void_p,C.c_void_p)
DISPOSE=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_uint64)
def run(machine,capture,observer,first,second,mask,content):
    require(type(mask)is int and 1<=mask<=7 and type(content)is bool,"whole frozen closed-standard-descriptor operation")
    base=machine.module._address+machine.composition["offsets"]["watcher"]
    initialize=INIT(base+5072);dispose=DISPOSE(base+5536)
    table=(C.c_uint64*9)(*machine.pointers[:8],0)
    context=C.create_string_buffer(bytes(131072)+b"\x5a"*16,131088);pointer=C.addressof(context)
    saved=[];flags=[]
    def absent(fd):
        try:fcntl.fcntl(fd,fcntl.F_GETFD)
        except OSError as error:require(error.errno==9,"actual closed fixture descriptor");return True
        return False
    def save(kind,before,after,returned,meta):
        capture.record(kind,tuple(before)+tuple(after),dict(meta,context=pointer,mask=mask,content=content,returned=returned,
            before_count=len(before),after_count=len(after)))
    def observe(user,ctx,size,record,record_size):
        if capture.errors:return
        try:
            require(user in(None,0)and ctx==pointer and size==131072 and record_size==128 and record==pointer+24960,
                "whole actual independent closed-fd Watcher callback")
            raw=C.string_at(ctx,131088);event=C.string_at(record,128)
            require(raw[24960:25088]==event and event[:8]in(b"HNWOWN01",b"HNWBN001"),"all real qualified Watcher callback bytes")
            require(word(raw,104)<=259,"complete actual direct Watcher pin ledger")
            pins={word(raw,512+16*i)for i in range(word(raw,104))}
            if word(raw,32):pins.add(word(raw,32))
            pages=[C.string_at(p,4096)for p in sorted(pins)]
            capture.record("fd-watcher-observation",(raw,event,*pages),dict(context=pointer,record=record,mask=mask,
                content=content,pins=sorted(pins),event=event.hex(),observer=True))
        except BaseException as error:capture.errors.append("closed-fd-observer:"+repr(error))
    hook=OBSERVER(observe)
    def bind(fd):
        before=(context.raw,);ret=int(machine.child_bind(pointer,131072,fd,None))
        save("fd-watcher-bind",before,(context.raw,),ret,dict(fd=fd));require(ret==0,"actual closed-fd Watcher binding")
    def view():
        raw=context.raw;w=raw[32768:98304];values=[]
        require(raw[:8]==b"HNWCTX01"and word(raw,8)==0 and word(w,8)==1,"real quiescent direct Watcher")
        for i in range(word(w,88)):
            at=1024+i*64;page=C.string_at(word(w,at),4096)
            require(page[:8]==b"HNWFP001","whole direct Watcher File page")
            values.append(dict(device=word(w,at+8),inode=word(w,at+16),wd=word(w,at+24),id=word(w,at+32),
                generation=word(w,at+40),dead=bool(word(w,at+48)),pin_fd=word(page,16),strong_count=word(page,8)))
        return dict(event_fd=word(raw,96),next=word(w,80),limit=word(w,56),content=bool(word(w,64)),watches=values)
    def invoke(command,generation,action,fd=None):
        if fd is not None:bind(fd)
        elif command in(3,4):bind((1<<64)-1)
        wire=b"HNWQ0001"+struct.pack("<11Q",command,generation,1 if command==2 else 0,0,
            128 if command==1 else 0,int(content)if command==1 else 0,0,0,0,0,0)
        inp=C.create_string_buffer(wire+b"\xc3"*16,112);out=C.create_string_buffer(b"\xa5"*144,144)
        before=(inp.raw,out.raw,context.raw)
        ret=int(machine.child(C.addressof(inp),96,C.addressof(out),128,pointer,131072))
        after=(inp.raw,out.raw,context.raw)
        pins=sorted({word(context.raw,512+16*i)for i in range(word(context.raw,104))})
        capture.record("fd-watcher-entry",before+after+tuple(C.string_at(p,4096)for p in pins),
            dict(context=pointer,mask=mask,content=content,command=command,generation=generation,action=action,fd=fd,
                pins=pins,returned=ret,before_count=3,after_count=3))
        raw=out.raw[:128]
        require(ret==128 and inp.raw==before[0]and out.raw[128:]==b"\xa5"*16 and context.raw[131072:]==b"\x5a"*16
            and raw[:8]==b"HNWR0001"and word(raw,8)==0 and word(raw,16)==generation and word(raw,32)==command
            and not capture.errors,"real complete direct Watcher terminal")
        return dict(action=action,token=[word(raw,88),word(raw,96)]if command==2 else None,
            watcher=view()if command!=4 else None)
    result=None
    try:
        for fd in range(3):
            flags.append(fcntl.fcntl(fd,fcntl.F_GETFD));copy=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,900+fd)
            require(copy==900+fd,"unique actual high standard descriptor copy");saved.append(copy)
        for fd in range(3):
            if mask&(1<<fd):os.close(fd);require(absent(fd),"selected standard descriptor actually absent")
        before=(context.raw,bytes(table));ret=int(initialize(pointer,131072,C.addressof(table),
            C.cast(hook,C.c_void_p)if observer else None,None))
        save("fd-watcher-initialize",before,(context.raw,bytes(table)),ret,dict(observer=observer,table=C.addressof(table)))
        require(ret==0,"actual direct Watcher transport initialization")
        rows=[invoke(1,1,"new")];event_fd=word(context.raw,96)
        for i,fd in enumerate((first,first,second,second)):rows.append(invoke(2,i+2,"version-"+str(i),fd))
        rows.append(invoke(3,6,"drain"));duplicates=[x["pin_fd"]for x in view()["watches"]]
        require(len(duplicates)==2 and all(fd>=3 for fd in duplicates),"every real native File duplicate honors floor three")
        owned=[event_fd,*duplicates];rows.append(invoke(4,7,"drop"))
        require(all(absent(fd)for fd in owned),"every actual event and duplicate descriptor closed")
        before=(context.raw,);ret=int(dispose(pointer,131072));save("fd-watcher-dispose",before,(context.raw,),ret,{})
        require(ret==0 and context.raw==bytes(131072)+b"\x5a"*16,"entire actual child disposed while caller still owns its buffer")
        result=dict(mask=mask,content=content,rows=rows,event_fd=event_fd,duplicate_fds=duplicates,
            closed_owned_fds=owned,all_duplicates_at_least_three=True)
    finally:
        # Resource restoration is not a retry of any completed or failed Watcher call.
        for fd,copy in enumerate(saved):
            os.dup2(copy,fd);fcntl.fcntl(fd,fcntl.F_SETFD,flags[fd]);os.close(copy)
    restored=[fcntl.fcntl(fd,fcntl.F_GETFD)for fd in range(3)]
    require(result is not None and restored==flags,"complete direct Watcher lifetime and exact std descriptor flags")
    result.update(restored=True,restored_flags=restored)
    capture.record("fd-fixture-result",(context.raw,),dict(context=pointer,mask=mask,content=content,control=result))
    return result
