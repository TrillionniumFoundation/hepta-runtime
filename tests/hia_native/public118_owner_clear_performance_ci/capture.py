"""Execute only fixed native images in fresh CI processes; retain trap-prefix buffers."""
from pathlib import Path
import fcntl,json,os,resource,signal,struct,subprocess,time
from retained_pairs import pin,save
def memfd(name,raw,immutable):
    fd=os.memfd_create(name,os.MFD_ALLOW_SEALING);os.ftruncate(fd,max(1,len(raw)))
    at=0
    while at<len(raw):
        n=os.pwrite(fd,raw[at:],at);assert n>0;at+=n
    mask=15 if immutable else 7;fcntl.fcntl(fd,fcntl.F_ADD_SEALS,mask);assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)&mask==mask
    return fd
def read_all(fd,size):
    chunks=[];at=0
    while at<size:
        raw=os.pread(fd,min(1<<20,size-at),at);assert raw;chunks.append(raw);at+=len(raw)
    return b''.join(chunks)
def limits():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(10,10))
    resource.setrlimit(resource.RLIMIT_AS,(512<<20,512<<20));resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
def invoke(root,side,image,observer,initial):
    assert os.environ.get('GITHUB_ACTIONS')=='true'
    image=Path(image);observer=Path(observer);image_pin=pin(image);observer_pin=pin(observer)
    fds=[];child=None;stdout=stderr=b'';timed=False;killed=False;failure=None;started=time.monotonic();code=None;post=None
    try:
        fds=[memfd('fixed-owner-image',image.read_bytes(),True)]
        for name,raw in zip(('input','output','workspace'),initial,strict=True):fds.append(memfd('owner-'+name,raw,name=='input'))
        seals=[fcntl.fcntl(fd,fcntl.F_GET_SEALS) for fd in fds]
        frame=b'HCALL001'+struct.pack('<8Q',fds[0],image_pin['bytes'],fds[1],len(initial[0]),fds[2],len(initial[1]),fds[3],len(initial[2]))
        child=subprocess.Popen([str(observer.resolve())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=tuple(fds),cwd=root,env={'PATH':'','LC_ALL':'C'},start_new_session=True,preexec_fn=limits)
        try:stdout,stderr=child.communicate(frame,timeout=60)
        except BaseException as error:
            failure=error;timed=isinstance(error,subprocess.TimeoutExpired);killed=True
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            stdout,stderr=child.communicate(timeout=5)
        code=child.returncode
        post=[read_all(fd,len(raw)) for fd,raw in zip(fds[1:],initial,strict=True)]
        raw_return=None;native_elapsed=None;framing_error=None
        if code==0 and len(stdout)==48 and stdout[:8]==b'HHCPR001' and not stderr:
            raw_return,s0,n0,s1,n1=struct.unpack_from('<5Q',stdout,8);native_elapsed=(s1-s0)*1000000000+n1-n0
            if not 0<=native_elapsed<60*1000000000:framing_error='native timing framing'
        elif code==0 or (code not in (-4,-6,-11) and not killed):framing_error='native observer failed or malformed complete output'
        row={'side':side,'framing_error':framing_error,'fd_seals':seals,'image':image_pin,'observer':observer_pin,'pid':child.pid,'exit_code':code,'raw_return':raw_return,'native_elapsed_ns':native_elapsed,'elapsed_seconds':time.monotonic()-started,'deadline_seconds':60,'timed_out':timed,'kill_requested':killed,'failure':None if failure is None else repr(failure),'request':save(root,side+'-request.gz',frame),'stdout':save(root,side+'-stdout.gz',stdout),'stderr':save(root,side+'-stderr.gz',stderr),'buffers':{name:save(root,side+'-'+name+'.gz',raw) for name,raw in zip(('input','output','workspace'),post,strict=True)},'parent_owned_size_sealed_shared_observation':True}
        assert pin(image)==image_pin and pin(observer)==observer_pin and post[0]==initial[0]
        (root/(side+'.json')).write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
        if failure is not None:raise failure
        assert framing_error is None,framing_error
        return row
    finally:
        if child is not None and child.poll() is None:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.communicate(timeout=5)
        for fd in fds:os.close(fd)
