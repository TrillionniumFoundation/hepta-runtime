"""Actual Linux HIA foreground composition and pure retained-evidence reader."""
from __future__ import annotations
import argparse, fcntl, hashlib, json, os, selectors, signal, stat, struct
import subprocess, sys, time, traceback
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'scripts'), str(ROOT/'tests/hia_native')]
from hia_native_shell_foreground_build import read_evidence as read_build
from shell_output_original_io import io_specs, command_for, expected_reads, GATE_PREFIX
from shell_output_io import decode_trace as decode_io_trace, inspect_stat
SCHEMA = 'hepta.runtime.shell-foreground-io.v1'
U64 = (1 << 64)-1
PENDING = 0xfffffff0
SCOPE = dict(production_activation_qualified=False, whole_runtime_qualified=False,
             old_stack_removal_qualified=False, original_rust_comparison_qualified=False)
SOURCE_NAMES = ('tests/hia_native/shell_foreground_io.py',
                'tests/hia_native/shell_output_original_io.py',
                'tests/hia_native/shell_output_io.py')

def require(value, message):
    if not value: raise ValueError(message)

def pairs(rows):
    result = {}
    for key,value in rows:
        require(key not in result, 'duplicate JSON key: '+key); result[key]=value
    return result

def decode(raw):
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def encoded(obj):
    return (json.dumps(obj,ensure_ascii=True,sort_keys=True,indent=2)+'\n').encode()

def ordinary(path):
    path=Path(path)
    require(stat.S_ISREG(path.lstat().st_mode),'not a regular retained file: '+str(path))
    return path.read_bytes()

def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(path):
    raw=ordinary(path); return dict(bytes=len(raw),sha256=sha(raw))

def save(path, raw):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream: stream.write(raw)
    return dict(bytes=len(raw),sha256=sha(raw))

def qwords(raw, count=None):
    require(len(raw)%8 == 0 and (count is None or len(raw)==count*8),'Q-word extent')
    return struct.unpack('<'+'Q'*(len(raw)//8),raw)

def request(command=b'',cwd=b'',op=1):
    return b'HSHFGQ01'+struct.pack('<4Q',op,1,len(command),len(cwd))+command+cwd
def frame(wire): return struct.pack('<Q',len(wire))+wire

def specifications():
    rows=io_specs()
    extras=[('outcome_output_growth','growth',b'A'*6000,b''),
            ('cancel_pending_wait','cancel_wait',b'alpha\n',b'beta\n'),
            ('cancel_pending_io','cancel_io',b'alpha\n',b'beta\n'),
            ('stdout_backpressure','backpressure',b'alpha\n',b'beta\n'),
            ('echld_before_process_retire','echld',b'alpha\n',b'beta\n'),
            ('promotion_cancel','promotion',b'promoted\n',b'')]
    for name,scenario,out,err in extras:
        rows.append(dict(name=name,scenario=scenario,exit_code=0,faults=[],
                         stdout_hex=out.hex(),stderr_hex=err.hex()))
    return rows

def command_bytes(spec):
    if spec.get('scenario')=='promotion':
        return (GATE_PREFIX+"/usr/bin/python3 -c 'import os,time; time.sleep(10.2); "
                "os.write(1,b\"promoted\\n\")'; exit 0").encode()
    return command_for(spec).encode()

def decode_controller(raw, *, partial=False):
    records,at=[],0
    while at<len(raw):
        if len(raw)-at<128:
            if partial: break
            raise ValueError('truncated controller header')
        require(raw[at:at+8]==b'HSHFGTR1','controller trace magic/fatal marker')
        q=struct.unpack_from('<16Q',raw,at)
        require(q[10]<=1048576 and q[15]==0 and q[13]<=q[14]
                and q[10]<=q[14]-q[13],'controller chunk bounds')
        end=at+128+q[10]
        if end>len(raw):
            if partial: break
            raise ValueError('truncated controller payload')
        records.append(dict(offset=at,q=q,payload=raw[at+128:end]));at=end
    assembled,index=[],0
    while index<len(records):
        first=records[index];q=first['q'];data=bytearray()
        require(q[13]==0,'controller payload starts with nonzero chunk')
        while True:
            row=records[index];r=row['q']
            require(r[2:6]==q[2:6] and r[7:10]==q[7:10] and r[11:13]==q[11:13]
                    and r[14]==q[14] and r[13]==len(data),'controller chunk identity')
            data.extend(row['payload']);index+=1
            if len(data)==q[14]: break
            if index==len(records):
                if partial: return assembled
                raise ValueError('unfinished controller chunk group')
        assembled.append(dict(offset=first['offset'],q=q,payload=bytes(data),
                              last_seq=records[index-1]['q'][1]))
    return assembled

def decode_transport(raw, *, partial=False):
    if len(raw)<64:
        if partial: return None,[],False
        raise ValueError('short READY')
    require(raw[:8]==b'HSHFGRD1','foreground READY magic')
    ready=struct.unpack_from('<8Q',raw);at=64;pubs=[];final=False
    while at<len(raw):
        if len(raw)-at<16:
            if partial: break
            raise ValueError('short output frame')
        ret,extent=struct.unpack_from('<2Q',raw,at)
        if ret==extent==0:
            at+=16;final=True;require(at==len(raw),'bytes after retirement');break
        require(ret==64 and extent>=64,'output return or extent')
        if extent>len(raw)-at-16:
            if partial: break
            raise ValueError('truncated output body')
        body=raw[at+16:at+16+extent];d=qwords(body[:64],8)
        require(body[:8]==b'HSHFGD01' and d[1]==len(pubs)+1 and d[2]==1
                and d[3] in (1,2) and d[5]==extent-64 and d[6] in (1,2,3)
                and d[7]==0,'foreground descriptor')
        pubs.append(dict(offset=at,descriptor=body[:64],q=d,body=body[64:]));at+=16+extent
    if not partial: require(final,'missing retirement frame')
    return ready,pubs,final

def decode_process(raw, *, partial=False):
    rows=[];at=0
    while raw[at:at+8]==b'HSHPRTR1':
        if len(raw)-at<128:
            if partial: return rows,None
            raise ValueError('truncated process effect')
        rows.append(dict(offset=at,q=struct.unpack_from('<16Q',raw,at)));at+=128
    if partial: return rows,None
    require(len(raw)-at==128 and raw[at:at+8]==b'HSHPAUD1','missing process footer')
    return rows,struct.unpack_from('<16Q',raw,at)

def process_identity(pid):
    try:
        raw=Path(f'/proc/{pid}/stat').read_text(); status=Path(f'/proc/{pid}/status').read_text()
    except FileNotFoundError: return None
    f=raw.rsplit(') ',1)[1].split()
    return dict(pid=pid,ppid=int(f[1]),pgid=int(f[2]),sid=int(f[3]),
                starttime_ticks=int(f[19]),state=f[0],raw_stat=raw,raw_status=status)

def file_state(path):
    try: s=Path(path).lstat()
    except FileNotFoundError: return None
    kind=('file' if stat.S_ISREG(s.st_mode) else 'directory' if stat.S_ISDIR(s.st_mode)
          else 'fifo' if stat.S_ISFIFO(s.st_mode) else 'symlink' if stat.S_ISLNK(s.st_mode) else 'special')
    return dict(kind=kind,mode=s.st_mode,dev=s.st_dev,ino=s.st_ino,size=s.st_size,nlink=s.st_nlink)

def take_faults(spec,capture,initial):
    mutations=[];faults=list(spec['faults'])
    if spec.get('scenario')=='cancel_io': faults.append(dict(stream='stdout',op='replace_fifo'))
    for fault in faults:
        path=capture/(fault['stream']+'.log');before=file_state(path)
        require(before==initial[fault['stream']]['state'],'controlled path changed before mutation')
        started=time.monotonic_ns();d=os.open(capture,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.unlink(path.name,dir_fd=d)
            if fault['op']=='replace_dir': os.mkdir(path.name,0o700,dir_fd=d)
            elif fault['op']=='replace_fifo': os.mkfifo(path.name,0o600,dir_fd=d)
            elif fault['op']=='replace_file':
                fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
                try:
                    data=bytes.fromhex(fault['replacement_hex']);at=0
                    while at<len(data): at+=os.write(fd,data[at:])
                finally: os.close(fd)
            else: require(fault['op']=='unlink','unregistered fault')
        finally: os.close(d)
        mutations.append(dict(fault=fault,before=before,after=file_state(path),
                              started_monotonic_ns=started,finished_monotonic_ns=time.monotonic_ns()))
    return mutations

def stream_read(fd):
    data=bytearray();at=0
    while True:
        block=os.pread(fd,1048576,at)
        if not block: return bytes(data)
        data.extend(block);at+=len(block)

def live_trace(capture,name):
    try: return (capture/name).read_bytes()
    except FileNotFoundError: return b''

def live_io(capture):
    raw=live_trace(capture,'io-effects.bin');rows=[];at=0
    while raw[at:at+8]==b'HSHOITR1' and len(raw)-at>=128:
        q=struct.unpack_from('<16Q',raw,at);end=at+128+q[14]
        if end>len(raw): break
        rows.append(dict(offset=at,q=q,payload=raw[at+128:end]));at=end
    return rows

def sigchld_ignored(): signal.signal(signal.SIGCHLD,signal.SIG_IGN)

def run_case(folder,spec,executable):
    folder.mkdir(parents=True,exist_ok=False)
    capture=folder/'capture';work=folder/'work';capture.mkdir();work.mkdir()
    ready_path=work/'capture.ready';command=command_bytes(spec)
    env=dict(PATH='/usr/bin:/bin',HOME=str(work),LANG='C',LC_ALL='C',TMPDIR=str(work),
             HIA_FIXTURE_CAPTURE_READY=str(ready_path))
    argv=[str(executable),'--foreground-fixture',str(capture)]
    initial=request(command,os.fsencode(work));pending=bytearray(frame(initial));delivered=bytearray()
    scenario=spec.get('scenario');out=bytearray();err=bytearray();controls=[];observations=[]
    observers={};owned={};setup=None;gate=None;cancel=None;fifo_fd=None;fifo_release=None
    failure=None;drain=None;preload=b'';pipe_size=None;readfd=None;writefd=None
    selector=selectors.DefaultSelector();started=time.monotonic_ns();unix=time.time_ns()
    if scenario=='backpressure':
        readfd,writefd=os.pipe2(os.O_CLOEXEC);pipe_size=fcntl.fcntl(writefd,fcntl.F_SETPIPE_SZ,4096)
        preload=b'\xd6'*pipe_size;require(os.write(writefd,preload)==len(preload),'pipe preload')
    process=subprocess.Popen(argv,cwd=work,env=env,stdin=subprocess.PIPE,
                             stdout=writefd if writefd is not None else subprocess.PIPE,
                             stderr=subprocess.PIPE,preexec_fn=sigchld_ignored if scenario=='echld' else None)
    if writefd is not None: os.close(writefd);writefd=None
    outstream=os.fdopen(readfd,'rb',buffering=0) if readfd is not None else process.stdout
    identity=process_identity(process.pid);controller_pidfd=os.pidfd_open(process.pid)
    actual_executable=os.readlink(f'/proc/{process.pid}/exe')
    for stream,label in ((process.stdin,'in'),(outstream,'out'),(process.stderr,'err')):
        os.set_blocking(stream.fileno(),False)
        if label!='out' or scenario!='backpressure':
            selector.register(stream,selectors.EVENT_WRITE if label=='in' else selectors.EVENT_READ,label)
    def send_cancel(trigger):
        nonlocal cancel
        require(cancel is None,'duplicate cancellation scheduling')
        wire=request(op=3);pending.extend(frame(wire))
        if process.stdin not in [k.fileobj for k in selector.get_map().values()]:
            selector.register(process.stdin,selectors.EVENT_WRITE,'in')
        cancel=dict(trigger=trigger,scheduled_monotonic_ns=time.monotonic_ns(),wire_hex=wire.hex())
        controls.append(cancel)
    try:
        while True:
            now=time.monotonic_ns()
            require(now-started<25_000_000_000,'foreground actual OS deadline')
            ctrl=decode_controller(live_trace(capture,'controller-effects.bin'),partial=True)
            proc,_=decode_process(live_trace(capture,'process-effects.bin'),partial=True)
            body=bytes(out[len(preload):]) if scenario=='backpressure' else bytes(out)
            ready,pubs,final=decode_transport(body,partial=True) if body else (None,[],False)
            if scenario=='backpressure' and ready is None:
                r=[x for x in ctrl if x['q'][2]==20]
                if r: ready=qwords(r[0]['payload'],8)
            for row in proc:
                q=row['q']
                if q[1]==1 and q[5]==5 and q[14]==1 and q[9]>0 and q[10]==0:
                    pid=q[9]
                    if pid not in owned:
                        ident=process_identity(pid)
                        if ident and ident['ppid']==process.pid:
                            try: fd=os.pidfd_open(pid)
                            except ProcessLookupError: continue
                            confirmed=process_identity(pid)
                            fdinfo=Path(f'/proc/self/fdinfo/{fd}').read_text()
                            fdfields=dict(x.split(':',1) for x in fdinfo.splitlines() if ':' in x)
                            if (not confirmed or confirmed['ppid']!=process.pid or
                                    confirmed['starttime_ticks']!=ident['starttime_ticks'] or
                                    int(fdfields.get('Pid','-1'))!=pid):
                                os.close(fd);raise ValueError('child pidfd failed post-acquisition ownership binding')
                            owned[pid]=(fd,ident)
                            observations.append(dict(event='child_bound',monotonic_ns=now,identity=ident,
                                                     confirmed_identity=confirmed,pidfd_info=fdinfo))
            registered=any(x['q'][1]==1 and x['q'][5]==14 and x['q'][6:9]==(1,1,0)
                           and x['q'][14]==1 for x in proc)
            if setup is None and ready is not None and registered and owned:
                require(ready[1]==1 and ready[2]==process.pid and ready[7]==0,'READY identity')
                child=process_identity(next(iter(owned)))
                require(child and child['ppid']==process.pid and child['pgid']==child['pid']
                        and child['sid']==child['pid'],'actual shell session ownership')
                initial_paths={}
                for i,name in enumerate(('stdout','stderr')):
                    p=capture/(name+'.log');s=file_state(p)
                    require(s and s['kind']=='file' and s['ino']==ready[5+i] and s['size']==0,
                            'READY inode/current empty capture')
                    fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);observers[name]=fd
                    require(os.fstat(fd).st_ino==s['ino'],'observer inode')
                    link=os.readlink(f'/proc/{process.pid}/fd/{ready[3+i]}')
                    require(link==str(p),'native writer descriptor path')
                    initial_paths[name]=dict(path=str(p),state=s,writer_fd=ready[3+i],writer_link=link)
                mutations=take_faults(spec,capture,initial_paths)
                setup=dict(initial=initial_paths,mutations=mutations,child=child,
                           monotonic_ns=time.monotonic_ns())
                if scenario!='cancel_wait':
                    t=time.monotonic_ns();save(ready_path,b'ready\n')
                    gate=dict(started_monotonic_ns=t,finished_monotonic_ns=time.monotonic_ns(),state=file_state(ready_path))
            if setup and scenario=='cancel_wait' and cancel is None:
                issued=[x for x in proc if x['q'][1]==1 and x['q'][5]==17 and x['q'][14]==0]
                if issued:
                    seq=issued[-1]['q'][4]
                    if not any(x['q'][1]==1 and x['q'][4]==seq and x['q'][14]==1 for x in proc):
                        send_cancel(dict(kind='pending_process_wakeup',effect_seq=seq))
            if setup and scenario=='promotion' and cancel is None:
                promoted=[x for x in pubs if x['q'][6]==2 and x['body'][:8]==b'HSHPRR01'
                          and qwords(x['body'],12)[1]==3]
                if promoted: send_cancel(dict(kind='observed_promotion',publication_seq=promoted[0]['q'][1]))
            if setup and scenario=='cancel_io':
                io=live_io(capture)
                if fifo_fd is None and fifo_release is None and any(x['q'][2:4]==(2,0) for x in io):
                    try: fifo_fd=os.open(capture/'stdout.log',os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC)
                    except OSError as error:
                        if error.errno!=6: raise
                if fifo_fd is not None and cancel is None:
                    reads=[x for x in io if x['q'][2:4]==(5,0)]
                    if reads:
                        row=reads[-1];q=row['q']
                        if not any(x['q'][1]==q[1] and x['q'][3]==1 for x in io):
                            try: syscall=Path(f'/proc/{process.pid}/task/{q[5]}/syscall').read_text()
                            except FileNotFoundError: syscall=''
                            values=syscall.split()
                            if len(values)>=4 and values[0]=='0' and int(values[1],0)==q[7]:
                                observation=dict(kind='blocked_owned_read',effect_seq=q[1],tid=q[5],
                                                 fd=q[7],syscall=syscall,monotonic_ns=time.monotonic_ns(),
                                                 controller_identity=process_identity(process.pid),
                                                 fd_link=os.readlink(f'/proc/{process.pid}/fd/{q[7]}'))
                                observations.append(observation);send_cancel(observation)
                ack=[x for x in pubs if x['q'][6]==3]
                if fifo_fd is not None and cancel and ack:
                    t=time.monotonic_ns();data=b'fifo-out\n'
                    require(os.write(fifo_fd,data)==len(data),'FIFO release write')
                    os.close(fifo_fd);fifo_fd=None
                    fifo_release=dict(started_monotonic_ns=t,finished_monotonic_ns=time.monotonic_ns(),
                                      bytes_hex=data.hex(),ack_publication_seq=ack[0]['q'][1])
            if scenario=='backpressure' and drain is None and any(x['q'][2]==255 for x in ctrl):
                require(process.poll() is None,'backpressure controller exited before draining')
                raw=live_trace(capture,'controller-effects.bin');save(folder/'before-drain-controller.bin',raw)
                drain=dict(monotonic_ns=time.monotonic_ns(),controller_identity=process_identity(process.pid),
                           child_identities=[process_identity(pid) for pid in owned],trace_pin=pin(folder/'before-drain-controller.bin'))
                selector.register(outstream,selectors.EVENT_READ,'out')
            for key,mask in selector.select(0.005):
                if key.data=='in':
                    n=os.write(key.fileobj.fileno(),pending)
                    delivered.extend(pending[:n]);del pending[:n]
                    if not pending: selector.unregister(key.fileobj)
                else:
                    raw=os.read(key.fileobj.fileno(),1048576)
                    if not raw: selector.unregister(key.fileobj)
                    elif key.data=='out': out.extend(raw)
                    else: err.extend(raw)
            if process.poll() is not None and not any(k.data in ('out','err') for k in selector.get_map().values()):
                break
        require(not pending,'initial/control input was not fully written')
    except BaseException as error:
        failure=dict(type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
    finally:
        cleanup=[]
        if failure:
            for pid,(fd,ident) in owned.items():
                try: signal.pidfd_send_signal(fd,signal.SIGKILL);cleanup.append(dict(pid=pid,method='owned_pidfd',errno=0))
                except ProcessLookupError: cleanup.append(dict(pid=pid,method='owned_pidfd',errno=3))
            if process.poll() is None:
                try: signal.pidfd_send_signal(controller_pidfd,signal.SIGKILL)
                except ProcessLookupError: pass
        if fifo_fd is not None: os.close(fifo_fd)
        try: process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            signal.pidfd_send_signal(controller_pidfd,signal.SIGKILL);process.wait()
        for fd,ident in owned.values(): os.close(fd)
        os.close(controller_pidfd)
        for stream in (process.stdin,outstream,process.stderr):
            try: stream.close()
            except Exception: pass
        selector.close()
    for name,fd in observers.items():
        save(folder/('old-'+name+'.bin'),stream_read(fd));os.close(fd)
    save(folder/'stdin.bin',bytes(delivered));save(folder/'stdout.bin',bytes(out));save(folder/'stderr.bin',bytes(err))
    save(folder/'spec.json',encoded(spec))
    data=dict(schema=SCHEMA+'.case',name=spec['name'],recorded_directory=str(folder),
              argv=argv,cwd=str(work),environment=env,command_hex=command.hex(),
              initial_hex=initial.hex(),pid=process.pid,controller_identity=identity,
              actual_executable=actual_executable,executable_pin=pin(executable),
              started_unix_ns=unix,finished_unix_ns=time.time_ns(),started_monotonic_ns=started,
              finished_monotonic_ns=time.monotonic_ns(),deadline_ns=25_000_000_000,
              returncode=process.returncode,failure=failure,cleanup=cleanup,
              setup=setup,gate_release=gate,controls=controls,observations=observations,
              fifo_release=fifo_release,backpressure_drain=drain,pipe_size=pipe_size,
              preloaded_stdout_hex=preload.hex(),sigchld_ignored=scenario=='echld',
              final_controller_identity=process_identity(process.pid),
              final_child_identities=[dict(pid=pid,identity=process_identity(pid)) for pid in owned])
    save(folder/'execution.json',encoded(data))
    require(failure is None and process.returncode==0,'actual native case failed: '+str(failure))
    return data

def retire_case(folder):
    """Retire only three exact verified fixture leaves; retain all ordinary traces."""
    receipt=[]
    for rel in ('capture/stdout.log','capture/stderr.log','work/capture.ready'):
        path=folder/rel;before=file_state(path);payload=None
        if before is not None:
            require(before['kind'] in ('file','directory','fifo'),'unexpected fixture leaf kind')
            if before['kind']=='file': payload=ordinary(path)
            if before['kind']=='directory': require(list(path.iterdir())==[],'nonempty owned directory replacement')
            require(file_state(path)==before,'fixture identity changed before exact retirement')
            if before['kind']=='directory': path.rmdir()
            else: path.unlink()
        require(file_state(path) is None,'fixture leaf survived retirement')
        receipt.append(dict(path=rel,before=before,payload_hex=payload.hex() if payload is not None else None,
                            after=None,observed_monotonic_ns=time.monotonic_ns()))
    require(list((folder/'work').iterdir())==[],'unregistered working-directory members')
    work=file_state(folder/'work');(folder/'work').rmdir()
    value=dict(schema=SCHEMA+'.retirement',recorded_directory=str(folder),leaves=receipt,
               work_before=work,work_after=None,execution_pin=pin(folder/'execution.json'))
    save(folder/'retirement.json',encoded(value));return value

def verify_controller(rows,receipt,publications,*,child=False,inherited_job=None):
    require(rows,'empty controller trace')
    prior=rows[0]['q'][1]-1 if child else 0;lasttime=-1;caps=[];calls=[];jobs=[];events=[]
    current=None;invocation=None;published=[];worker_start={};worker_join={};controls=[]
    active_jobs={1:None,2:None};last_job=0;last_cap=None;retired=False;footer=None
    process_event_seq=0
    if child:
        require(inherited_job and inherited_job['e'][2]==5,'missing inherited fork job')
        job={**inherited_job,'done':None};active_jobs[1]=job;jobs.append(job);last_job=job['token']
    for row in rows:
        q,p=row['q'],row['payload'];kind=q[2]
        require(q[1]==prior+1 and row['last_seq']>=q[1],'controller sequence')
        prior=row['last_seq']
        require(q[6]>=lasttime and receipt['started_monotonic_ns']<=q[6]<=receipt['finished_monotonic_ns'],
                'controller clock receipt bounds');lasttime=q[6]
        require(q[3] in ((2,) if child else (0,1)) and q[4]==q[5]
                and (child or q[4]==receipt['pid']),'controller actual role/PID/TID')
        if kind==0:
            require(invocation is None and not retired,'overlapping controller f0 calls')
            require(p[:8]==b'HSHFGQ01','controller raw input magic');iv=qwords(p[:40],5)
            require(iv[2]==1 and iv[1] in (1,2,3,4) and len(p)==40+iv[3]+iv[4],'controller raw input')
            if iv[1]==1: require(p.hex()==receipt['initial_hex'],'controller initial bytes')
            else: require(p==request(op=iv[1]),'controller control bytes')
            invocation=row
        elif kind==1:
            require(invocation is not None and len(p)==96 and p[:16]==b'A'*16 and p[-16:]==b'B'*16,
                    'controller actual guarded output')
            require(q[9] in (PENDING,64,0),'controller refusal/failure was recorded as success')
            if q[9]==64: published.append((p[16:80],row))
            else: require(p[16:80]==b'\xa7'*64,'pending/retirement modified controller output')
            retired=q[9]==0;invocation=None
        elif kind==2:
            require(current is None and not retired,'overlapping capability')
            e=qwords(p,12)
            require(p[:8]==b'HSHFGFX1' and e[1]==q[7] and e[2]==q[8]
                    and 1<=e[2]<=13 and e[6:]==(0,)*6,'issued capability canonical fields')
            if last_cap is not None: require(e[1]==last_cap+1,'capability sequence')
            elif not child: require(e[1]==1,'initial capability sequence')
            if e[2] in (4,8):
                owner=1 if e[2]==4 else 2
                require(active_jobs[owner] and e[3]==active_jobs[owner]['token'] and e[4:6]==(0,0),
                        'poll referenced an unowned job')
            if e[2]==2: require(active_jobs[1] is None,'process invoked before private mailbox completion')
            if e[2]==12:
                require(e[5]==0 and (e[3] or e[4]) and e[3:5]==tuple(
                    active_jobs[k]['token'] if active_jobs[k] else 0 for k in (1,2)),
                    'activity wait referenced different jobs')
            last_cap=e[1];current=dict(issue=row,e=e,inside=[],
                                     pending_io=active_jobs[2]['token'] if active_jobs[2] else None)
        elif kind==3:
            if current is None:
                require(child and not caps,'only fork child may begin with inherited completion')
                e=qwords(p,12);require(e[2]==3 and e[10]==1,'inherited fork completion')
                last_cap=e[1];continue
            e=qwords(p,12);a=current['e']
            require(e[:7]==a[:7] and e[8:]==(0,0,1,0) and e[7]==q[9]
                    and q[7]==e[1] and q[8]==e[2],'capability completion canonical identity')
            if a[2] in (3,7):
                issued=[r for r in current['inside'] if r['q'][2]==(10 if a[2]==3 else 12)]
                require(len(issued)==1 and e[7]==issued[0]['q'][9],'dispatch returned a different job')
            if a[2] in (4,8):
                joined=[r for r in current['inside'] if r['q'][2]==(11 if a[2]==4 else 13)]
                require(e[7] in (0,1) and len(joined)==e[7],'poll fabricated or omitted job completion')
            current.update(done=row,result=e[7]);caps.append(current);current=None
        elif kind in (10,12):
            owner=1 if kind==10 else 2;e=qwords(p,12)
            require(current and current['e'][2]==(3 if owner==1 else 7)
                    and active_jobs[owner] is None and e[6:]==(0,)*6,'duplicate/malformed job submission')
            require(p[:8]==(b'HSHPRFX1' if owner==1 else b'HSHOIFX1'),'job mailbox magic')
            require(q[9]>last_job and q[9]==q[10+owner],'unique dispatched owned job')
            last_job=q[9];job=dict(owner=owner,token=q[9],issue=row,e=e,done=None)
            active_jobs[owner]=job;jobs.append(job)
        elif kind in (11,13):
            owner=1 if kind==11 else 2;job=active_jobs[owner];e=qwords(p,12)
            require(current and current['e'][2]==(4 if owner==1 else 8) and job
                    and current['e'][3]==job['token']==q[9] and e[:7]==job['e'][:7]
                    and e[10:]==(1,0),'job completion/custody')
            job['done']=row;active_jobs[owner]=None
        elif kind in (23,24):
            owner,tid=qwords(p,2);table=worker_start if kind==23 else worker_join
            require(owner in (1,2) and tid>0 and tid!=receipt['pid'] and owner not in table,'worker identity')
            table[owner]=dict(tid=tid,row=row)
        elif kind==22:
            require(p==request(op=3),'unregistered controller control');controls.append(row)
        elif kind==255:
            require(not child and retired and current is None and invocation is None and row is rows[-1],
                    'early/misplaced footer')
            footer=qwords(p,16)
            require(p[:8]==b'HSHFGAU1' and footer[1]==receipt['pid'] and footer[2]==row['last_seq']
                    and footer[3]==last_cap and footer[4]==len(published) and footer[5:7]==(0,0)
                    and footer[7:13]==(U64,0,U64,0,0,footer[12]) and footer[12] in (0,1,2)
                    and footer[14:]==(0,0),'controller final custody/error counters')
        elif kind not in (4,5,6,7,8,9,14,15,16,17,18,19,20,21,25):
            raise ValueError('unregistered controller audit kind')
        if current is not None and kind!=2: current['inside'].append(row)
    if not child:
        require(footer is not None and not any(active_jobs.values()),'missing final footer/live job')
        require(set(worker_start)==set(worker_join) and all(worker_start[k]['tid']==worker_join[k]['tid']
                and worker_start[k]['row']['q'][1]<worker_join[k]['row']['q'][1] for k in worker_start),
                'worker join is absent or changed identity')
        require([x[0] for x in published]==[x['descriptor'] for x in publications],'actual output descriptor publication')
    else:
        require(current is not None and current['e'][2]==3 and active_jobs[1] is not None
                and active_jobs[1]['e'][2]==11 and active_jobs[2] is None,
                'child did not end at actual exec attempt')
    return dict(caps=caps,jobs=jobs,published=published,worker_start=worker_start,
                worker_join=worker_join,footer=footer,controls=controls,unfinished=current)

def module_calls(controller,receipt):
    process=[];io=[];outcome=[]
    for cap in controller['caps']:
        action=cap['e'][2];inside=cap['inside'];kinds=[x['q'][2] for x in inside]
        if action in (2,5):
            expected=[4,5,14] if action==2 else [6,7,15]
            require(kinds==expected,'module call audit completeness/order')
            before,after,again=inside
            require(before['payload']==again['payload'] and after['q'][9]==again['q'][9]==cap['result'],
                    'module input immutability/actual return')
            wire=before['payload'];ret=cap['result'];body=after['payload']
            if action==5 and cap['pending_io'] is not None:
                require(qwords(wire,5)[1]==3,'IO entered pending worker with an ordinary resume')
            require(ret in ((PENDING,96,0) if action==2 else (PENDING,64,0)),'module refusal/failure')
            if ret in (PENDING,0): require(body==b'\xa7'*len(body),'module pending/zero changed output')
            row=dict(cap=cap,input=wire,output=body,ret=ret,before=before,after=after)
            (process if action==2 else io).append(row)
        elif action==10:
            require(kinds==[8,16,17,9,18,19],'outcome complete guarded arrays/order')
            by={x['q'][2]:x for x in inside};ret=cap['result']
            require(by[8]['payload']==by[19]['payload'] and ret in (40,0xfffffffe),
                    'outcome immutable input/registered return')
            require(all(by[k]['q'][9]==ret for k in (9,18,19)),'outcome actual returns disagree')
            for before,after,left,right in ((16,9,b'A',b'B'),(17,18,b'Q',b'R')):
                a,b=by[before]['payload'],by[after]['payload']
                require(len(a)==len(b) and len(a)>=32 and a[:16]==b[:16]==left*16
                        and a[-16:]==b[-16:]==right*16,'outcome guarded array identity')
            out_before,out_after=by[16]['payload'][16:-16],by[9]['payload'][16:-16]
            require(out_before==b'\xa7'*len(out_before) and by[17]['payload'][16:-16]==b'\xb8'*128,
                    'outcome actual initialized arrays')
            body=None
            if ret==40:
                h=qwords(out_after[:40],5)
                require(out_after[:8]==b'HSHOUR01' and h[1] in (0,1) and h[4]==0,'outcome header')
                extent=40+h[2]+h[3];require(extent<=len(out_after),'outcome extent bounds')
                body=out_after[:extent]
                require(out_after[extent:]==out_before[extent:],'outcome output tail modified')
            else: require(out_after==out_before,'outcome capacity refusal wrote output')
            outcome.append(dict(cap=cap,input=by[8]['payload'],body=body,ret=ret,
                                output_capacity=len(out_before),arrays=by))
    require(process and process[0]['input']==b'HSHPRQ01'+bytes.fromhex(receipt['initial_hex'])[8:],
            'actual process input differs from controller command/cwd')
    for row in process[1:]:
        require(row['input'] in (b'HSHPRQ01'+request(op=2)[8:],b'HSHPRQ01'+request(op=3)[8:],
                                 b'HSHPRQ01'+request(op=4)[8:]),'unregistered process control input')
    events=[]
    for row in process:
        if row['ret']==96:
            q=qwords(row['output'],12)
            require(row['output'][:8]==b'HSHPRR01' and 1<=q[1]<=6 and q[2]==q[3]==1
                    and q[4]>0 and q[7] in (0,1,2) and q[9]==len(events)+1
                    and q[10] in (0,1) and q[11]<=7,'process result canonical fields')
            events.append(dict(q=q,raw=row['output'],call=row))
    return dict(process=process,io=io,outcome=outcome,events=events)

def verify_process(rows,footer,controller,child_controller,receipt,calls):
    parent=[r for r in rows if r['q'][1] in (0,1)];child=[r for r in rows if r['q'][1]==2]
    require(len(parent)+len(child)==len(rows) and len(parent)%2==0,'process role/pair count')
    parent_pairs=[]
    for n in range(0,len(parent),2):
        a,b=parent[n:n+2];x,y=a['q'],b['q']
        require(x[4]==y[4]==n//2+1 and x[5:9]==y[5:9] and x[14]==0 and y[14]==1
                and x[2]==y[2]==receipt['pid'] and x[3]==y[3]==1
                and x[9:12]==(0,0,0),'process parent effect pair')
        parent_pairs.append((a,b))
    forks=[p for p in parent_pairs if p[0]['q'][5]==5]
    require(len(forks)==1 and forks[0][1]['q'][9]>0 and forks[0][1]['q'][10]==0,'one actual fork')
    pid=forks[0][1]['q'][9];forkseq=forks[0][0]['q'][4]
    require(forks[0][1]['q'][15]==pid,'fork raw kernel result')
    require(child and child[0]['q'][4:6]==(forkseq,5) and child[0]['q'][14]==1
            and child[0]['q'][9:11]==(0,0),'fork child completion')
    by_child={};previous=forkseq
    for row in child:
        q=row['q'];require(q[2]==pid and q[3]==1 and q[4]>=previous,'child identity/order')
        by_child.setdefault(q[4],[]).append(row);previous=q[4]
    require(sorted(by_child)==list(range(forkseq,max(by_child)+1)),'child missing effect sequence')
    for seq,group in by_child.items():
        if seq==forkseq: require(len(group)==1,'duplicate child fork')
        elif seq==max(by_child):
            require(len(group)==1 and group[0]['q'][5]==11 and group[0]['q'][14]==0,
                    'child final exec must not claim returning success')
        else:
            require(len(group)==2 and group[0]['q'][14]==0 and group[1]['q'][14]==1
                    and group[0]['q'][4:9]==group[1]['q'][4:9],'child effect pair')
    pjobs=[j for j in controller['jobs'] if j['owner']==1]
    require(len(pjobs)==len(parent_pairs),'submitted process jobs differ from actual effects')
    for job,(a,b) in zip(pjobs,parent_pairs):
        require(job['e'][1:6]==(a['q'][4],a['q'][5],*a['q'][6:9]) and job['done']
                and qwords(job['done']['payload'],12)[7:10]==b['q'][9:12],
                'process mailbox differs from real kernel effect')
    cjobs=child_controller['jobs'];require(len(cjobs)==len(by_child),'child job count')
    for job,group in zip(cjobs,by_child.values()):
        q=group[0]['q'];require(job['e'][1:6]==(q[4],q[5],*q[6:9]),'child mailbox input identity')
        if q[5]==11 and len(group)==1: require(job['done'] is None,'successful exec has completion')
        else:
            require(job['done'] and qwords(job['done']['payload'],12)[7:10]==group[-1]['q'][9:12],
                    'child mailbox completion identity')
    require(footer[1:3]==(len(parent),len(child)) and footer[3:5]==(0,0)
            and footer[5:7]==(128,128) and footer[7:10]==(0,0,0) and footer[12]==pid
            and footer[13:]==(0,0,0),'process audit final counts/errors/custody')
    waits=[p for p in parent_pairs if p[0]['q'][5]==16];require(waits,'missing actual wait')
    lost=False
    for a,b in waits:
        q=b['q'];require(q[9] in (0,1) and q[11]<=0xffffffff,'wait completion domain')
        if lost:
            require(q[9:12]==(0,10,0) and q[15]==0,'lost-custody wait guard invoked stale PID')
        elif q[10]:
            require(q[9]==0 and q[15]==((-q[10])&U64),'wait errno/raw syscall')
            lost=q[10]==10
        else: require(q[15]==(pid if q[9] else 0),'wait raw child identity')
    for event in calls['events']:
        q=event['q'];require(q[4]==pid,'event changed actual child PID')
        prior=[j for j in pjobs if j['done']['q'][1]<event['call']['before']['q'][1] and j['e'][2]==16]
        if q[1] in (2,4):
            require(prior,'result before actual wait');w=qwords(prior[-1]['done']['payload'],12)
            if q[7]==0:
                require(w[7]==1 and w[8]==0 and q[6]==w[9] and q[11]&2,'result differs from reaped wait')
                expected_exit=(w[9]>>8)&255 if w[9]&127==0 else U64
                require(q[5]==expected_exit,'result exit projection')
            else: require(q[7]==1 and q[8]==w[8] and w[8]!=0,'wait error projection')
            unregister=[j for j in pjobs if j['e'][2:6]==(14,1,0,0)
                        and prior[-1]['done']['q'][1]<j['done']['q'][1]<event['call']['before']['q'][1]]
            require(unregister and q[10]==0,'foreground/background result before unregister')
    return dict(pid=pid,pairs=parent_pairs,waits=waits,footer=footer)

def verify_io(records,footer,controller,receipt,ready,spec):
    require(len(records)>=2 and (len(records)-2)%2==0,'IO effect pair count')
    for i,row in enumerate(records[:2]):
        q=row['q'];s=inspect_stat(row['payload'])
        require(q[1:4]==(0,0,1) and q[4]==q[5]==receipt['pid'] and q[6]==1
                and q[7]==ready[3+i] and q[8:14]==(i,0,0,0,0,3)
                and s['ino']==ready[5+i] and stat.S_ISREG(s['mode']) and s['size']==0,
                'actual original capture fstat/inode')
    jobs=[j for j in controller['jobs'] if j['owner']==2];pairs=[]
    require(len(jobs)==(len(records)-2)//2,'IO dispatched jobs/effects count')
    results={};buffers={'stdout':bytearray(),'stderr':bytearray()};active=None
    next_stream=0;serial=0;discards=[];metadata=[];workspace=8192;availability=0
    admitted=False;retry=None
    for number,job in enumerate(jobs,1):
        a,b=records[2*number:2*number+2];x,y=a['q'],b['q'];action=x[2];args=x[8:11];error=y[12]
        tid=receipt['pid'] if action in (1,7) else controller['worker_start'][2]['tid']
        require(x[1]==y[1]==number and x[2]==y[2] and x[3]==0 and y[3]==1
                and x[4:7]==y[4:7]==(receipt['pid'],tid,1) and x[8:11]==y[8:11]
                and x[11:13]==(0,0),'IO actual issue/completion/TID pair')
        require(job['e'][1:6]==(number,action,*args) and job['done'],'IO mailbox issue')
        completion=qwords(job['done']['payload'],12)
        require(completion[8]==error and completion[9]==0,'IO mailbox errno/aux')
        if error: require(y[11]==((-error)&U64) and completion[7]==0,'IO raw syscall errno')
        else: require(y[11]<(1<<63),'IO negative success')
        if action in (2,8):
            require(args[0]==1 and args[1] in (0,1) and args[2]==0 and x[13]==1
                    and a['payload']==os.fsencode(Path(receipt['argv'][2])/('stdout.log' if args[1]==0 else 'stderr.log'))+b'\0',
                    'IO exact owned capture path')
        else: require(x[13:15]==(0,0),'unexpected IO issue payload')
        if retry is not None:
            require((action,args,x[7])==retry,'EINTR was not retried by HIA');retry=None
        if action==1:
            require(number==1 and not admitted and args==(1,0,0) and not error and completion[7]==0,'IO admission')
            admitted=True
        elif action==2:
            require(admitted and active is None and not discards and next_stream<2
                    and args==(1,next_stream,0),'stdout/stderr open order')
            name=('stdout','stderr')[next_stream]
            if error==4: retry=(action,args,x[7])
            elif error: results[name]=(2,error,b'');next_stream+=1
            else:
                serial+=1;require(y[7]>2 and y[11]==y[7] and completion[7]==serial,'open FD/opaque handle')
                active=dict(name=name,fd=y[7],handle=serial,meta=False,next='fstat' if availability==2 else 'statx',
                            ended=False,error=0)
        elif action in (3,4):
            require(active and not active['meta'] and not active['ended'] and not discards
                    and active['next']==('statx' if action==3 else 'fstat') and x[7]==y[7]==active['fd']
                    and args==(active['handle'],*((384,256) if action==3 else (640,144)))
                    and (action!=4 or availability==2),'metadata custody/order/span')
            if not error:
                require(y[11]==completion[7]==0 and y[13]==3,'metadata success result')
                metadata.append(dict(stream=active['name'],effect_seq=number,**inspect_stat(b['payload'],action==3)))
                active['meta']=True;active['next']=None
                if action==3: availability=1
            elif action==4 or availability==1: active['meta']=True;active['next']=None
            else: active['next']='probe'
        elif action==9:
            require(active and not active['meta'] and not active['ended'] and active['next']=='probe'
                    and availability==0 and args==(0,0,0),'statx availability probe order')
            if error==14: availability=1;active['meta']=True;active['next']=None
            else: availability=2;active['next']='fstat'
        elif action==5:
            require(active and active['meta'] and not active['ended'] and x[7]==y[7]==active['fd']
                    and args[0]==active['handle'] and args[2]>0 and args[1]+args[2]<=workspace
                    and (args[1:] == (800,32) or args[1]>=4208),'read custody/order/span')
            if error==4: retry=(action,args,x[7])
            elif error: active['ended']=True;active['error']=error
            else:
                require(y[13]==2 and completion[7]==y[11]==len(b['payload'])<=args[2],'read full payload')
                buffers[active['name']].extend(b['payload'])
                if not b['payload']: active['ended']=True
        elif action==6:
            require(active and active['ended'] and x[7]==y[7]==active['fd']
                    and args==(active['handle'],0,0),'close custody/EOF order')
            name=active['name'];err=active['error']
            results[name]=(2,err,b'') if err else (0,0,bytes(buffers[name]))
            active=None;next_stream+=1
        elif action==7:
            require(active and active['meta'] and not active['ended'] and args[1:]==(0,0)
                    and args[0]>workspace and not error and y[11]%4096==0,'actual IO capacity growth')
            workspace=(args[0]+4095)&~4095
            require(completion[7]==workspace,'grown capacity differs')
        elif action==8:
            require(active is None and next_stream==2 and len(discards)<2
                    and args==(1,len(discards),0),'discard skipped/reordered complete reads')
            discards.append(error)
        else: raise ValueError('unregistered IO primitive in corpus')
        if action not in (2,5,7) and not error: require(completion[7]==y[11],'IO raw/result identity')
        pairs.append((a,b))
    require(active is None and retry is None,'live IO custody/unretried interruption')
    require(footer[1]==receipt['pid'] and footer[2]==len(records) and footer[3]==footer[4]==len(jobs)
            and footer[5:7]==(0,0) and footer[7:10]==(U64,U64,U64) and footer[10:]==(0,)*6,
            'IO final custody/errors/counts')
    scenario=spec.get('scenario')
    if scenario in ('cancel_wait','promotion'):
        require(not jobs and not results and not discards,'nonforeground path started foreground IO')
    elif scenario=='cancel_io':
        require(results=={'stdout':(0,0,b'fifo-out\n')} and not discards,
                'canceled IO did not finish only its started file task')
    else:
        expected={k:(2,v['errno'],b'') if v['errno'] else (0,0,bytes.fromhex(v['bytes_hex']))
                  for k,v in expected_reads(spec).items()}
        require(results==expected and len(discards)==2,'actual two read Results differ from owned paths')
        expected_unlinks=[2 if any(x['stream']==name and x['op']=='unlink' for x in spec['faults'])
                          else 21 if any(x['stream']==name and x['op']=='replace_dir' for x in spec['faults'])
                          else 0 for name in ('stdout','stderr')]
        require(discards==expected_unlinks,'raw unlink results differ')
    return dict(results=results,pairs=pairs,metadata=metadata,workspace=workspace,availability=availability)

def expected_loan(event,results):
    q=event['q'];wk=2 if q[7]==1 else 0;wv=q[8] if wk else q[6]
    if not wk and wv&(1<<31): wv|=U64^0xffffffff
    out,err=results['stdout'],results['stderr']
    header=[1,wk,wv,out[0],out[1],err[0],err[1],0,0,len(out[2]),len(err[2]),0,0]
    return b'HSHOUT01'+struct.pack('<13Q',*header)+out[2]+err[2]

def verify_causality(controller,calls,io,process,rows,receipt,pubs,spec):
    scenario=spec.get('scenario');fg=[e for e in calls['events'] if e['q'][1]==2]
    outs=[p for p in pubs if p['q'][6]==1];acks=[p for p in pubs if p['q'][6]==3]
    observations=[p['body'] for p in pubs if p['q'][6]==2]
    require(observations==[e['raw'] for e in calls['events'] if e['q'][1]!=2],
            'published process observation differs from actual module result')
    accepted=controller['controls'];controls=receipt['controls']
    require(len(accepted)==len(controls)==(1 if scenario in ('cancel_wait','cancel_io','promotion') else 0),
            'registered caller controls differ')
    if controls:
        require(accepted[0]['payload'].hex()==controls[0]['wire_hex'] and
                accepted[0]['q'][6]>=controls[0]['scheduled_monotonic_ns'],'control causality')
    loan=outcome=eventbytes=None;causal=dict(actual_native_process_wait=True,
        actual_native_io_effects=bool(io['pairs']),actual_native_outcome_entry=bool(calls['outcome']),
        production_foreground_deadline_ns=10_000_000_000,
        live_orphan_os_continuation_qualified=False,native_phase_cases_added_by_reference=0)
    if scenario in ('cancel_wait','promotion'):
        require(not fg and not calls['io'] and not calls['outcome'] and not outs,'nonforeground path fabricated foreground')
        kinds=[e['q'][1] for e in calls['events']]
        if scenario=='cancel_wait':
            require(kinds==[5] and not acks,'caller cancel process observation sequence')
            signals=[p for p in process['pairs'] if p[0]['q'][5]==18]
            require(len(signals)==1 and signals[0][0]['q'][6:9]==(1,1,9),'caller cancel direct signal')
            trigger=controls[0]['trigger'];require(trigger['kind']=='pending_process_wakeup','cancel wait trigger')
            job=next(j for j in controller['jobs'] if j['owner']==1 and j['e'][1]==trigger['effect_seq'])
            require(job['e'][2]==17 and job['issue']['q'][6]<controls[0]['scheduled_monotonic_ns']
                    and accepted[0]['q'][6]<=job['done']['q'][6],'pending WAIT cancellation timing')
            ctrl_calls=[c for c in calls['process'] if qwords(c['input'][:40],5)[1]==3]
            require(len(ctrl_calls)==1 and job['done']['q'][1]<ctrl_calls[0]['before']['q'][1],
                    'process control did not wait for admitted completion')
        else:
            require(kinds==[3,4] and not acks and not any(p[0]['q'][5]==18 for p in process['pairs']),
                    'post-promotion cancellation killed or canceled background')
            promoted=next(e for e in calls['events'] if e['q'][1]==3)
            clock=[j for j in controller['jobs'] if j['owner']==1 and j['e'][2]==15
                   and j['done']['q'][1]<promoted['call']['before']['q'][1]]
            require(len(clock)>=2 and qwords(clock[-1]['done']['payload'],12)[7]-
                    qwords(clock[0]['done']['payload'],12)[7]>=10_000_000_000,
                    'promotion did not use real production deadline')
            require(promoted['call']['after']['q'][6]<controls[0]['scheduled_monotonic_ns'],
                    'post-promotion control preceded promotion')
        return loan,outcome,eventbytes,causal
    require(len(fg)==1,'missing/duplicate actual foreground event');event=fg[0];eventbytes=event['raw']
    first=calls['io'][0];q=event['q'];wk=2 if q[7] else 0;wv=q[8] if wk else q[6]
    require(first['input']==b'HSHOIQ01'+struct.pack('<4Q',1,1,wk,wv),
            'IO typed request not derived from actual wait result')
    require(event['call']['after']['q'][1]<first['before']['q'][1],'IO started before actual foreground event')
    submits=[j for j in controller['jobs'] if j['owner']==2]
    require(submits[0]['e'][2]==1 and submits[1]['e'][2]==2,'first IO admission/open sequence')
    later_process=[c for c in calls['process'] if c['before']['q'][1]>event['call']['after']['q'][1]]
    require(later_process and submits[1]['issue']['q'][1]<later_process[0]['before']['q'][1],
            'IO waited for process arena retirement')
    causal.update(process_kind2_sequence=event['call']['after']['q'][1],
                  io_start_sequence=first['before']['q'][1],io_open_dispatch_sequence=submits[1]['issue']['q'][1],
                  next_process_call_sequence=later_process[0]['before']['q'][1],
                  process_wait_errno=q[8] if q[7] else None,process_wait_status=q[6] if not q[7] else None)
    if scenario=='cancel_io':
        require(len(acks)==1 and not outs and not calls['outcome'],'IO cancellation fabricated outcome')
        require(acks[0]['body']==b'HSHFGC01'+struct.pack('<3Q',1,1,0),'IO cancellation descriptor')
        trigger=controls[0]['trigger'];release=receipt['fifo_release']
        require(trigger['kind']=='blocked_owned_read' and release is not None,'missing real blocked worker observation')
        job=next(j for j in submits if j['e'][1]==trigger['effect_seq'])
        require(job['e'][2]==5 and trigger['tid']==controller['worker_start'][2]['tid'],
                'blocked observation is not the owned IO worker')
        raw=trigger['syscall'].split()
        require(len(raw)==9 and int(raw[0])==0 and int(raw[1],0)==trigger['fd']
                and int(raw[3],0)==job['e'][5],'real blocked read syscall span')
        ack=next(r for desc,r in controller['published'] if desc==acks[0]['descriptor'])
        require(job['issue']['q'][6]<=trigger['monotonic_ns']<=controls[0]['scheduled_monotonic_ns']
                <=accepted[0]['q'][6]<=ack['q'][6]<release['started_monotonic_ns']
                <=job['done']['q'][6],'cancel ACK did not precede blocked worker completion')
        require(release['bytes_hex']==b'fifo-out\n'.hex() and release['ack_publication_seq']==acks[0]['q'][1],
                'FIFO actual release differs')
        require(any(qwords(c['input'],5)[1]==3 for c in calls['io']), 'IO owner never received cancellation')
        causal.update(cancel_ack_before_started_worker_completion=True,worker_tid=trigger['tid'])
        return loan,outcome,eventbytes,causal
    require(not acks and len(outs)==1 and calls['outcome'],'foreground outcome publication missing')
    expected=expected_loan(event,io['results'])
    require(all(c['input']==expected for c in calls['outcome']),'IO loan does not match actual wait/reads')
    require(calls['outcome'][-1]['ret']==40 and calls['outcome'][-1]['body']==outs[0]['body'],
            'published outcome differs from actual HIA entry')
    require(outs[0]['q'][3:5]==(2,0),'outcome borrowed source identity')
    io_results=[c for c in calls['io'] if c['ret']==64]
    require(len(io_results)==1 and io_results[0]['output'][:8]==b'HSHOID01'
            and qwords(io_results[0]['output'],8)[1:]==(1,1,4096,len(expected),0,0,0),
            'IO owner actual loan descriptor')
    require(submits[-1]['e'][2:6]==(8,1,1,0)
            and submits[-1]['done']['q'][1]<io_results[0]['before']['q'][1]
            <calls['outcome'][0]['cap']['issue']['q'][1], 'outcome executed before both discards')
    if scenario=='growth':
        require([c['ret'] for c in calls['outcome']]==[0xfffffffe,40]
                and calls['outcome'][0]['output_capacity']==4096
                and calls['outcome'][1]['output_capacity']>=6040,'actual outcome grow/retry')
        grows=[c for c in controller['caps'] if c['e'][2]==11]
        require(len(grows)==1 and calls['outcome'][0]['cap']['done']['q'][1]<grows[0]['issue']['q'][1]
                <calls['outcome'][1]['cap']['issue']['q'][1],'HIA capacity decision ordering')
    else: require(len(calls['outcome'])==1,'unexpected outcome retry')
    if scenario=='echld':
        require(q[7:9]==(1,10) and later_process[0]['ret']==0,'actual ECHILD lifecycle scope')
        acquired=[r for r in rows if r['q'][2]==21]
        require(len(acquired)==1 and acquired[0]['q'][9]>2
                and acquired[0]['q'][6]<receipt['gate_release']['started_monotonic_ns'],
                'ECHILD gate released before child pidfd custody')
        ignored=dict(line.split(':',1) for line in receipt['controller_identity']['raw_status'].splitlines()
                     if ':' in line)['SigIgn'].strip()
        require(int(ignored,16)&(1<<(signal.SIGCHLD-1)),'SIGCHLD ignore was not actually inherited')
        causal['echld_io_before_process_retire']=True
    loan=expected;outcome=calls['outcome'][-1]['body']
    causal.update(actual_native_outcome_entry=True,io_complete_sequence=io_results[0]['after']['q'][1],
                  outcome_call_sequence=calls['outcome'][-1]['cap']['issue']['q'][1])
    return loan,outcome,eventbytes,causal

def verify_identity(value):
    require(type(value) is dict,'missing retained process identity')
    f=value['raw_stat'].rsplit(') ',1)[1].split()
    require(int(value['raw_stat'].split(' ',1)[0])==value['pid'] and f[0]==value['state']
            and tuple(int(f[i]) for i in (1,2,3,19))==
            (value['ppid'],value['pgid'],value['sid'],value['starttime_ticks']), 'retained identity fields/raw stat')
    status=dict(line.split(':',1) for line in value['raw_status'].splitlines() if ':' in line)
    require(int(status['Pid'])==int(status['Tgid'])==value['pid'],'retained process/Tgid identity')

def verify_setup(folder,spec,receipt,ready,io,process,rows,*,retired):
    setup=receipt['setup'];require(type(setup) is dict,'missing actual setup')
    verify_identity(receipt['controller_identity']);verify_identity(setup['child'])
    require(receipt['controller_identity']['pid']==receipt['pid'] and setup['child']['pid']==process['pid']
            and setup['child']['ppid']==receipt['pid'] and setup['child']['pgid']==setup['child']['sid']==process['pid'],
            'observed child/parent/session binding')
    bound=[x for x in receipt['observations'] if x.get('event')=='child_bound']
    require(len(bound)==1,'host child custody observation inventory')
    first=bound[0];verify_identity(first['identity']);verify_identity(first['confirmed_identity'])
    fdfields=dict(x.split(':',1) for x in first['pidfd_info'].splitlines() if ':' in x)
    require(first['identity']['pid']==first['confirmed_identity']['pid']==process['pid']
            and first['identity']['ppid']==first['confirmed_identity']['ppid']==receipt['pid']
            and first['identity']['starttime_ticks']==first['confirmed_identity']['starttime_ticks']==setup['child']['starttime_ticks']
            and int(fdfields['Pid'])==process['pid'],'host pidfd post-acquisition actual ownership binding')
    initial=setup['initial'];require(set(initial)=={'stdout','stderr'},'capture setup inventory')
    for i,name in enumerate(('stdout','stderr')):
        row=initial[name];s=row['state'];path=folder/'capture'/(name+'.log')
        require(row['path']==row['writer_link']==str(path) and row['writer_fd']==ready[3+i]
                and s['kind']=='file' and stat.S_ISREG(s['mode']) and s['ino']==ready[5+i]
                and s['size']==0 and s['nlink']==1,'original writer path/inode identity')
    faults=list(spec['faults'])
    if spec.get('scenario')=='cancel_io': faults.append(dict(stream='stdout',op='replace_fifo'))
    mutations=setup['mutations'];require([x['fault'] for x in mutations]==faults,'physical fault registration')
    for row in mutations:
        fault=row['fault'];before=row['before'];after=row['after']
        require(before==initial[fault['stream']]['state'] and
                receipt['started_monotonic_ns']<=row['started_monotonic_ns']<=row['finished_monotonic_ns']
                <=setup['monotonic_ns'],'physical mutation timing/baseline')
        if fault['op']=='unlink': require(after is None,'unlink mutation did not remove path')
        else:
            kind={'replace_dir':'directory','replace_file':'file','replace_fifo':'fifo'}[fault['op']]
            require(after and after['kind']==kind and (after['dev'],after['ino'])!=(before['dev'],before['ino'])
                    and after['nlink']>=1,'replacement did not have a distinct inode')
            if kind=='file': require(after['size']==len(bytes.fromhex(fault['replacement_hex'])),'replacement file size')
    scenario=spec.get('scenario');gate=receipt['gate_release']
    if scenario=='cancel_wait': require(gate is None,'canceled gate was released')
    else:
        require(gate and setup['monotonic_ns']<=gate['started_monotonic_ns']<=gate['finished_monotonic_ns'],
                'command gate preceded controlled path mutation')
    for name in ('stdout','stderr'):
        expected=b'' if scenario=='cancel_wait' else bytes.fromhex(spec[name+'_hex'])
        require(ordinary(folder/('old-'+name+'.bin'))==expected,'actual old-writer bytes differ from command')
    for record in io['metadata']:
        name=record['stream'];replacements=[x for x in mutations if x['fault']['stream']==name]
        expected=replacements[-1]['after'] if replacements else initial[name]['state']
        require(expected and record['ino']==expected['ino'] and record['dev']==expected['dev']
                and stat.S_IFMT(record['mode'])==stat.S_IFMT(expected['mode']),
                'IO opened the old/replaced inode incorrectly')
    prior=receipt['controller_identity'];last=receipt['final_controller_identity']
    require(last is None or last['starttime_ticks']!=prior['starttime_ticks'],'controller remained live')
    require(len(receipt['final_child_identities'])==1,'child final observation inventory')
    for row in receipt['final_child_identities']:
        last=row['identity'];require(row['pid']==process['pid'] and
                                    (last is None or last['starttime_ticks']!=setup['child']['starttime_ticks']),
                                    'direct child remained live at completion')
    if scenario=='backpressure':
        drain=receipt['backpressure_drain'];require(drain and receipt['pipe_size']==4096,'missing actual full-pipe test')
        require(ordinary(folder/'before-drain-controller.bin')==ordinary(folder/'capture/controller-effects.bin'),
                'before-drain trace did not already contain full retirement')
        verify_identity(drain['controller_identity'])
        require(drain['controller_identity']['starttime_ticks']==prior['starttime_ticks'] and
                drain['controller_identity']['pid']==receipt['pid'] and rows[-1]['q'][6]<drain['monotonic_ns'],
                'controller did not remain alive after lifecycle retirement with output blocked')
    else: require(receipt['backpressure_drain'] is None and receipt['pipe_size'] is None,'unregistered backpressure')
    expected_leaves={}
    for name in ('stdout','stderr'):
        alive=scenario in ('cancel_wait','cancel_io','promotion') or any(
            x['stream']==name and x['op']=='replace_dir' for x in spec['faults'])
        rel='capture/'+name+'.log'
        if not alive: expected_leaves[rel]=(None,None);continue
        mutation=[x for x in mutations if x['fault']['stream']==name]
        state=dict(mutation[-1]['after'] if mutation else initial[name]['state'])
        payload=None
        if state['kind']=='file':
            payload=b'' if scenario=='cancel_wait' else bytes.fromhex(spec[name+'_hex'])
            state['size']=len(payload)
        expected_leaves[rel]=(state,payload)
    expected_leaves['work/capture.ready']=(gate['state'],b'ready\n') if gate else (None,None)
    if retired:
        retirement=decode(ordinary(folder/'retirement.json'))
        require(retirement['schema']==SCHEMA+'.retirement' and retirement['recorded_directory']==str(folder)
                and retirement['execution_pin']==pin(folder/'execution.json') and retirement['work_after'] is None,
                'retirement identity/binding')
        require([x['path'] for x in retirement['leaves']]==list(expected_leaves),'retired exact member inventory')
        for row,(rel,(state,payload)) in zip(retirement['leaves'],expected_leaves.items()):
            require(row['before']==state and row['payload_hex']==(payload.hex() if payload is not None else None)
                    and row['after'] is None and row['observed_monotonic_ns']>=receipt['finished_monotonic_ns']
                    and not os.path.lexists(folder/rel),'retired path identity/complete payload')
        require(not os.path.lexists(folder/'work') and retirement['work_before']['kind']=='directory',
                'owned work directory was not retired')
    else:
        for rel,(state,payload) in expected_leaves.items():
            require(file_state(folder/rel)==state,'live final fixture path state')
            if payload is not None: require(ordinary(folder/rel)==payload,'live final fixture complete bytes')

def _read_case(folder,native_manifest,*,retired=True,save_derived=False):
    folder=Path(folder).absolute();native_manifest=Path(native_manifest).absolute()
    spec=decode(ordinary(folder/'spec.json'));known={x['name']:x for x in specifications()}
    require(spec.get('name') in known and spec==known[spec['name']],'unregistered/modified case definition')
    receipt=decode(ordinary(folder/'execution.json'));manifest=decode(ordinary(native_manifest))
    executable=native_manifest.parent/manifest['elf'];work=folder/'work'
    require(receipt['schema']==SCHEMA+'.case' and receipt['name']==spec['name']
            and receipt['recorded_directory']==str(folder) and receipt['argv']==
            [str(executable),'--foreground-fixture',str(folder/'capture')]
            and receipt['cwd']==str(work) and receipt['actual_executable']==str(executable)
            and receipt['executable_pin']==pin(executable),'actual native process identity/argv')
    env=dict(PATH='/usr/bin:/bin',HOME=str(work),LANG='C',LC_ALL='C',TMPDIR=str(work),
             HIA_FIXTURE_CAPTURE_READY=str(work/'capture.ready'))
    command=command_bytes(spec);initial=request(command,os.fsencode(work))
    require(receipt['environment']==env and receipt['command_hex']==command.hex()
            and receipt['initial_hex']==initial.hex() and receipt['returncode']==0
            and receipt['failure'] is None and receipt['cleanup']==[]
            and receipt['deadline_ns']==25_000_000_000 and 0<receipt['finished_monotonic_ns']-
            receipt['started_monotonic_ns']<receipt['deadline_ns']
            and receipt['finished_unix_ns']>=receipt['started_unix_ns']
            and receipt['sigchld_ignored'] is (spec.get('scenario')=='echld'),'actual process receipt/inputs')
    expected_stdin=frame(initial)+b''.join(frame(request(op=3)) for _ in receipt['controls'])
    require(ordinary(folder/'stdin.bin')==expected_stdin and ordinary(folder/'stderr.bin')==b'',
            'actual full stdin or native stderr differs')
    raw_stdout=ordinary(folder/'stdout.bin');preload=bytes.fromhex(receipt['preloaded_stdout_hex'])
    require(preload==(b'\xd6'*4096 if spec.get('scenario')=='backpressure' else b'')
            and raw_stdout.startswith(preload),'registered stdout preload')
    ready,pubs,_=decode_transport(raw_stdout[len(preload):])
    require(ready[1]==1 and ready[2]==receipt['pid'] and ready[3]>2 and ready[4]>2
            and ready[3]!=ready[4] and ready[5]>0 and ready[6]>0 and ready[7]==0,'actual READY custody')
    rows=decode_controller(ordinary(folder/'capture/controller-effects.bin'))
    child_rows=decode_controller(ordinary(folder/'capture/controller-child.bin'))
    controller=verify_controller(rows,receipt,pubs)
    forks=[j for j in controller['jobs'] if j['owner']==1 and j['e'][2]==5]
    require(len(forks)==1,'controller fork job inventory')
    child=verify_controller(child_rows,receipt,[],child=True,inherited_job=forks[0])
    calls=module_calls(controller,receipt)
    prows,pfooter=decode_process(ordinary(folder/'capture/process-effects.bin'))
    process=verify_process(prows,pfooter,controller,child,receipt,calls)
    irows,ifooter=decode_io_trace(ordinary(folder/'capture/io-effects.bin'))
    io=verify_io(irows,ifooter,controller,receipt,ready,spec)
    require(rows[0]['q'][2]==20 and rows[0]['payload']==raw_stdout[len(preload):len(preload)+64],
            'actual READY and controller audit differ')
    require(sum(r['q'][2]==20 for r in rows)==1,'duplicate capture readiness')
    custody=[r for r in rows if r['q'][2]==21];closed=[r for r in rows if r['q'][2]==25]
    require(len(custody)==len(closed)==1 and custody[0]['q'][9]>2 and
            closed[0]['q'][9]==0 and qwords(closed[0]['payload'],1)[0]==custody[0]['q'][9]
            and custody[0]['q'][1]<closed[0]['q'][1]<rows[-1]['q'][1], 'private actual pidfd custody/close')
    require(pfooter[10]==(1 if spec.get('scenario')=='cancel_wait' else 0)
            and pfooter[11]==(2 if spec.get('scenario')=='echld' else 1)
            and controller['footer'][13]==pfooter[11] and controller['footer'][12]==io['availability'],
            'cross-owner final tracker/reap/cache state')
    controller_cancels=[r for r in rows if r['q'][2]==0 and qwords(r['payload'][:40],5)[1]==3]
    require(len(controller_cancels)==len(receipt['controls']) and all(
        accepted['q'][1]<call['q'][1] for accepted,call in zip(controller['controls'],controller_cancels)),
        'actual controller cancellation input/transport delivery')
    verify_setup(folder,spec,receipt,ready,io,process,rows,retired=retired)
    loan,outcome,event,causal=verify_causality(controller,calls,io,process,rows,receipt,pubs,spec)
    files=dict(loan='loan.bin' if loan is not None else None,outcome='outcome.bin' if outcome is not None else None,
               process_event='foreground-event.bin' if event is not None else None,
               controller_trace='capture/controller-effects.bin',process_trace='capture/process-effects.bin',
               io_trace='capture/io-effects.bin')
    for name,value in ((files['loan'],loan),(files['outcome'],outcome),(files['process_event'],event)):
        if name:
            if save_derived: save(folder/name,value)
            else: require(ordinary(folder/name)==value,'derived retained bytes differ from actual entry')
    causal.update(controller_capabilities=len(controller['caps']),process_effects=len(process['pairs']),
                  io_effects=len(io['pairs']),outcome_entries=len(calls['outcome']),retired_fixture=retired)
    return dict(name=spec['name'],spec=spec,command=command,loan=loan,outcome=outcome,
                process_event=event,causal=causal,files=files)

def inventory(folder):
    folder=Path(folder);found={}
    def fail(error): raise error
    for base,dirs,files in os.walk(folder,followlinks=False,onerror=fail):
        for name in dirs:
            p=Path(base)/name;require(stat.S_ISDIR(p.lstat().st_mode),'special/symlink evidence directory')
        for name in files:
            p=Path(base)/name;found[p.relative_to(folder).as_posix()]=pin(p)
    return dict(sorted(found.items()))

def read_case(folder,native_manifest):
    """Strong pure reader; complete actual wire bodies, no native execution."""
    read_build(Path(native_manifest).absolute(),source_root=ROOT)
    return _read_case(folder,native_manifest)

def _read_evidence(folder,native_manifest,*,require_full=True,check_controls=True):
    folder=Path(folder).absolute();native_manifest=Path(native_manifest).absolute()
    build=read_build(native_manifest,source_root=ROOT);report=decode(ordinary(folder/'report.json'))
    names=report.get('case_names');specs=specifications();known={x['name']:x for x in specs}
    require(type(names) is list and names and len(names)==len(set(names)) and
            names==[x['name'] for x in specs if x['name'] in names],'missing/duplicate/unregistered case')
    complete=names==[x['name'] for x in specs]
    require(not require_full or complete,'partial foreground corpus cannot qualify full suite')
    require(report.get('schema')==SCHEMA and report.get('status')=='NATIVE_FOREGROUND_PASS'
            and report.get('recorded_directory')==str(folder) and report.get('complete_registered_corpus') is complete
            and report.get('registered_specs')==[known[n] for n in names]
            and report.get('native_manifest')==str(native_manifest) and report.get('native_manifest_pin')==pin(native_manifest)
            and report.get('native_build')==build and report.get('actual_native_process_wait') is True
            and report.get('native_phase_cases_added_by_reference')==0
            and all(report.get(k) is v for k,v in SCOPE.items()),'corpus report identity/scope')
    require(sorted(p.name for p in (folder/'cases').iterdir())==sorted(names),'actual case directory inventory')
    source_pins={n:pin(ROOT/n) for n in SOURCE_NAMES}
    require(report.get('source_pins')==source_pins,'foreground suite/current source bytes')
    for name in SOURCE_NAMES:
        require(ordinary(folder/'source-snapshots'/name)==ordinary(ROOT/name),'sealed producer/source bytes')
    actual_files={prefix+'/'+name:info for prefix in ('cases','source-snapshots')
                  for name,info in inventory(folder/prefix).items()}
    require(report.get('files')==dict(sorted(actual_files.items())),'complete retained ordinary file inventory')
    cases=[_read_case(folder/'cases'/name,native_manifest) for name in names]
    require(report.get('case_validation')==[x['causal'] for x in cases],'report differs from raw reconstructed causality')
    control_result=read_controls(folder/'reader-controls',native_manifest) if check_controls and complete else None
    if check_controls: require(report.get('reader_controls')==control_result,'reader controls report binding')
    return dict(schema='hepta.runtime.shell-foreground-io-read.v1',status='PASS',recorded_directory=str(folder),
                native=dict(manifest_path=str(native_manifest),manifest_pin=pin(native_manifest),build=build),
                cases=len(cases),retired_fixtures=len(cases),shared_original_io_cases=sum(n in [x['name'] for x in io_specs()] for n in names),
                complete_registered_corpus=complete,actual_native_process_wait=True,
                native_phase_cases_added_by_reference=0,reader_controls=control_result,
                actual_outcome_entries=sum(x['causal']['outcome_entries'] for x in cases),
                report_sha256=sha(ordinary(folder/'report.json')),**SCOPE)

def read_evidence(folder,native_manifest,*,require_full=True):
    return _read_evidence(folder,native_manifest,require_full=require_full)

CONTROL_SPECS=(('raw_input','normal'),('wait_status','normal'),('worker_tid','normal'),
               ('job_result','normal'),('cancel_as_foreground','cancel_pending_io'),
               ('retired_payload','cancel_pending_wait'),('missing_reap','normal'),
               ('backpressure_order','stdout_backpressure'),('echld_io_order','echld_before_process_retire'))

def control_recipe(name,baseline):
    """Pure deterministic byte transformation, also used to reconstruct every negative."""
    result={}
    def use(path): return bytearray(baseline[path])
    if name=='raw_input':
        p='stdin.bin';b=use(p);b[-1]^=1;result[p]=bytes(b)
    elif name=='wait_status':
        p='capture/process-effects.bin';b=use(p);rows,_=decode_process(bytes(b))
        row=next(x for x in rows if x['q'][1]==1 and x['q'][5]==16 and x['q'][14]==1 and x['q'][9]==1)
        struct.pack_into('<Q',b,row['offset']+88,row['q'][11]^256);result[p]=bytes(b)
    elif name=='worker_tid':
        p='capture/io-effects.bin';b=use(p);rows,_=decode_io_trace(bytes(b))
        selected=next(x['q'][1] for x in rows if x['q'][2]==5)
        for row in rows:
            if row['q'][1]==selected: struct.pack_into('<Q',b,row['offset']+40,row['q'][4])
        result[p]=bytes(b)
    elif name=='job_result':
        p='capture/controller-effects.bin';b=use(p);rows=decode_controller(bytes(b))
        row=next(x for x in rows if x['q'][2]==13 and qwords(x['payload'],12)[2]==5)
        value=qwords(row['payload'],12)[7];struct.pack_into('<Q',b,row['offset']+128+56,value+1)
        result[p]=bytes(b)
    elif name=='cancel_as_foreground':
        p='stdout.bin';b=use(p);_,pubs,_=decode_transport(bytes(b))
        pub=next(x for x in pubs if x['q'][6]==3);struct.pack_into('<Q',b,pub['offset']+16+48,1)
        result[p]=bytes(b);p='capture/controller-effects.bin';b=use(p)
        row=next(x for x in decode_controller(bytes(b)) if x['q'][2]==1 and x['q'][9]==64
                 and x['payload'][16:80]==pub['descriptor'])
        struct.pack_into('<Q',b,row['offset']+128+16+48,1);result[p]=bytes(b)
    elif name=='retired_payload':
        p='retirement.json';obj=decode(baseline[p]);obj['leaves'][0]['payload_hex']='41';result[p]=encoded(obj)
    elif name=='missing_reap':
        p='capture/process-effects.bin';rows,footer=decode_process(baseline[p])
        seq=next(x['q'][4] for x in rows if x['q'][1]==1 and x['q'][5]==16 and x['q'][14]==1 and x['q'][9]==1)
        kept=[x for x in rows if not(x['q'][1]==1 and x['q'][4]==seq)]
        f=list(footer);f[1]-=2
        result[p]=b''.join(struct.pack('<16Q',*x['q']) for x in kept)+struct.pack('<16Q',*f)
    elif name=='backpressure_order':
        p='execution.json';obj=decode(baseline[p]);rows=decode_controller(baseline['capture/controller-effects.bin'])
        obj['backpressure_drain']['monotonic_ns']=rows[-1]['q'][6]-1;result[p]=encoded(obj)
        p='retirement.json';obj=decode(baseline[p]);obj['execution_pin']=dict(bytes=len(result['execution.json']),sha256=sha(result['execution.json']))
        result[p]=encoded(obj)
    elif name=='echld_io_order':
        p='capture/controller-effects.bin';rows=decode_controller(baseline[p]);blocks=[];start=0
        for i,row in enumerate(rows):
            if row['q'][2]==0:
                if i>start: blocks.append(rows[start:i])
                start=i
        blocks.append(rows[start:])
        first=next(i for i,b in enumerate(blocks) if any(x['q'][2]==12 and qwords(x['payload'],12)[2]==2 for x in b))
        later=next(i for i,b in enumerate(blocks) if i>first and any(x['q'][2]==5 and x['q'][9]==0 for x in b))
        require(later==first+1,'registered ECHILD adjacent IO-open/process-retire blocks')
        blocks[first],blocks[later]=blocks[later],blocks[first]
        changed=[x for b in blocks for x in b];mapping={};seq=0
        for row in changed:
            if row['q'][2]==2:
                seq+=1;mapping[qwords(row['payload'],12)[1]]=seq
        rewritten=[]
        for i,row in enumerate(changed):
            q=list(row['q']);payload=row['payload'];require(q[13]==0 and q[14]==len(payload),'control chunk extent')
            q[1]=i+1;q[6]=rows[i]['q'][6];q[7]=mapping.get(q[7],q[7])
            if q[2] in (2,3):
                e=list(qwords(payload,12));e[1]=mapping[e[1]];payload=struct.pack('<12Q',*e)
            rewritten.append(struct.pack('<16Q',*q)+payload)
        result[p]=b''.join(rewritten)
    else: raise ValueError('unregistered reader control')
    require(result and all(v!=baseline[k] for k,v in result.items()),'empty named mutation')
    return result

def reader_process(folder,case,native_manifest):
    folder.mkdir(parents=True,exist_ok=False)
    python=Path(sys.executable).resolve(strict=True);script=Path(__file__).resolve()
    argv=[str(python),str(script),'--native-manifest',str(native_manifest),'--verify-case',str(case)]
    env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1'
    before=dict(python=pin(python),script=pin(script));start=time.monotonic_ns();unix=time.time_ns()
    result=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,timeout=30)
    value=dict(argv=argv,cwd=str(ROOT),environment=env,started_unix_ns=unix,
               finished_unix_ns=time.time_ns(),duration_ns=time.monotonic_ns()-start,
               deadline_ns=30_000_000_000,returncode=result.returncode,
               tool_before=before,tool_after=dict(python=pin(python),script=pin(script)),
               stdout=save(folder/'stdout.bin',result.stdout),stderr=save(folder/'stderr.bin',result.stderr))
    save(folder/'execution.json',encoded(value));return value,decode(result.stdout)

def run_controls(folder,native_manifest):
    folder.mkdir(parents=True,exist_ok=False);corpus=folder.parent;rows=[]
    positive,payload=reader_process(folder/'positive',corpus/'cases/normal',native_manifest)
    require(positive['returncode']==0 and payload.get('status')=='PASS','positive actual reader process failed')
    for name,case_name in CONTROL_SPECS:
        case=corpus/'cases'/case_name;before_inventory=inventory(case)
        baseline={n:ordinary(case/n) for n in before_inventory};changes=control_recipe(name,baseline)
        require(all((case/n).lstat().st_nlink==1 for n in changes),
                'physical controls require exclusive ordinary copies, never hard links')
        target=folder/name;target.mkdir()
        for n,b in changes.items(): save(target/'before'/n,baseline[n]);save(target/'after'/n,b)
        process=None;payload=None;after_inventory=None
        try:
            for n,b in changes.items(): (case/n).write_bytes(b)
            after_inventory=inventory(case)
            process,payload=reader_process(target/'reader',case,native_manifest)
            require(process['returncode']==2 and payload.get('status')=='REJECTED','physical mutation accepted: '+name)
            if name=='echld_io_order': require('IO waited for process arena retirement' in payload['error'],
                                               'ECHILD control did not reach causal gate')
        finally:
            for n in changes: (case/n).write_bytes(baseline[n])
        require(inventory(case)==before_inventory,'mutation baseline not restored exactly')
        rows.append(dict(name=name,case=case_name,before_inventory=before_inventory,
                         after_inventory=after_inventory,changes={n:dict(before=dict(bytes=len(baseline[n]),sha256=sha(baseline[n])),
                         after=dict(bytes=len(b),sha256=sha(b))) for n,b in changes.items()},
                         process_pin=pin(target/'reader/execution.json'),rejection=payload))
    value=dict(schema=SCHEMA+'.controls',status='PASS',recorded_directory=str(folder),
               native_manifest=str(native_manifest),native_manifest_pin=pin(native_manifest),
               producer_pin=pin(Path(__file__)),positive_pin=pin(folder/'positive/execution.json'),controls=rows)
    save(folder/'report.json',encoded(value));return read_controls(folder,native_manifest)

def read_controls(folder,native_manifest):
    folder=Path(folder).absolute();native_manifest=Path(native_manifest).absolute()
    report=decode(ordinary(folder/'report.json'));script=Path(__file__).resolve();python=Path(sys.executable).resolve()
    require(report.get('schema')==SCHEMA+'.controls' and report.get('status')=='PASS'
            and report.get('recorded_directory')==str(folder) and report.get('native_manifest')==str(native_manifest)
            and report.get('native_manifest_pin')==pin(native_manifest) and report.get('producer_pin')==pin(script),
            'control report source/manifest identity')
    def check_process(directory,case,expected):
        r=decode(ordinary(directory/'execution.json'))
        require(r['argv']==[str(python),str(script),'--native-manifest',str(native_manifest),'--verify-case',str(case)]
                and r['cwd']==str(ROOT) and r['environment'].get('PYTHONDONTWRITEBYTECODE')=='1'
                and r['tool_before']==r['tool_after']==dict(python=pin(python),script=pin(script))
                and r['returncode']==expected and 0<r['duration_ns']<r['deadline_ns']==30_000_000_000
                and r['finished_unix_ns']>=r['started_unix_ns'] and r['stdout']==pin(directory/'stdout.bin')
                and r['stderr']==pin(directory/'stderr.bin') and ordinary(directory/'stderr.bin')==b'',
                'actual independent reader process receipt')
        payload=decode(ordinary(directory/'stdout.bin'))
        require(payload.get('status')==('PASS' if expected==0 else 'REJECTED'),'reader raw stdout result')
        return payload
    require(report['positive_pin']==pin(folder/'positive/execution.json'),'positive process identity')
    check_process(folder/'positive',folder.parent/'cases/normal',0)
    require([(x['name'],x['case']) for x in report['controls']]==list(CONTROL_SPECS),
            'missing/duplicate/named control inventory')
    for row,(name,case_name) in zip(report['controls'],CONTROL_SPECS):
        case=folder.parent/'cases'/case_name;current=inventory(case)
        require(row['before_inventory']==current,'control restored baseline differs')
        baseline={n:ordinary(case/n) for n in current};expected=control_recipe(name,baseline);target=folder/name
        require(inventory(target/'before')=={n:dict(bytes=len(baseline[n]),sha256=sha(baseline[n])) for n in expected}
                and inventory(target/'after')=={n:dict(bytes=len(b),sha256=sha(b)) for n,b in expected.items()},
                'named physical mutation files differ from deterministic recipe')
        changes={n:dict(before=dict(bytes=len(baseline[n]),sha256=sha(baseline[n])),
                       after=dict(bytes=len(b),sha256=sha(b))) for n,b in expected.items()}
        require(row['changes']==changes and row['after_inventory']=={**current,**{n:x['after'] for n,x in changes.items()}},
                'named physical mutation inventory does not reconstruct')
        for n,b in expected.items():
            require(ordinary(target/'before'/n)==baseline[n] and ordinary(target/'after'/n)==b,'full mutation bytes')
        require(row['process_pin']==pin(target/'reader/execution.json'),'negative process identity')
        payload=check_process(target/'reader',case,2);require(payload==row['rejection'],'raw negative outcome differs')
        if name=='echld_io_order': require('IO waited for process arena retirement' in payload['error'],'missing causal rejection')
    return dict(schema=SCHEMA+'.controls.read',status='PASS',controls=len(CONTROL_SPECS),
                actual_reader_processes=len(CONTROL_SPECS)+1,physical_mutations_reconstructed=True,
                report_sha256=sha(ordinary(folder/'report.json')),**SCOPE)

def run(output,native_manifest,selected=None):
    output=Path(output).absolute();native_manifest=Path(native_manifest).absolute()
    output.mkdir(parents=True,exist_ok=False)
    report=dict(schema=SCHEMA,status='RUNNING',recorded_directory=str(output),**SCOPE)
    (output/'report.json').write_bytes(encoded(report))
    try:
        build=read_build(native_manifest,source_root=ROOT)
        metadata=decode(ordinary(native_manifest));exe=native_manifest.parent/metadata['elf']
        sources={n:pin(ROOT/n) for n in SOURCE_NAMES}
        for name in SOURCE_NAMES: save(output/'source-snapshots'/name,ordinary(ROOT/name))
        all_specs=specifications();specs=[s for s in all_specs if selected is None or s['name'] in selected]
        require(specs and (selected is None or set(selected)=={s['name'] for s in specs}),'unknown/empty selection')
        validations=[]
        for spec in specs:
            folder=output/'cases'/spec['name']
            run_case(folder,spec,exe)
            _read_case(folder,native_manifest,retired=False,save_derived=True)
            retire_case(folder)
            result=_read_case(folder,native_manifest);validations.append(result['causal'])
            print(json.dumps(dict(case=spec['name'],status='ACTUAL_NATIVE_PASS')),flush=True)
        require(sources=={n:pin(ROOT/n) for n in SOURCE_NAMES},'producer source changed during actual execution')
        complete=len(specs)==len(all_specs)
        report.update(status='NATIVE_FOREGROUND_PASS',native_manifest=str(native_manifest),
                      native_manifest_pin=pin(native_manifest),native_build=build,source_pins=sources,
                      case_names=[s['name'] for s in specs],registered_specs=specs,
                      complete_registered_corpus=complete,actual_native_process_wait=True,
                      native_phase_cases_added_by_reference=0,case_validation=validations,
                      reader_controls=None)
        report['files']=dict(sorted((prefix+'/'+n,p) for prefix in ('cases','source-snapshots')
                                   for n,p in inventory(output/prefix).items()))
        (output/'report.json').write_bytes(encoded(report))
        if complete:
            report['reader_controls']=run_controls(output/'reader-controls',native_manifest)
            (output/'report.json').write_bytes(encoded(report))
        return _read_evidence(output,native_manifest,require_full=complete,check_controls=complete)
    except BaseException as error:
        report.update(status='FAIL',error=dict(type=type(error).__name__,message=str(error),traceback=traceback.format_exc()))
        # Only these explicitly created fixture leaves may be sealed and removed.
        cleanup=[]
        for case in (output/'cases').iterdir() if (output/'cases').exists() else []:
            if not (case/'retirement.json').exists() and (case/'execution.json').exists():
                try: retire_case(case);cleanup.append(dict(case=case.name,status='EXACT_FIXTURES_RETIRED'))
                except BaseException as cleanup_error: cleanup.append(dict(case=case.name,error=repr(cleanup_error)))
        report['failure_fixture_cleanup']=cleanup;(output/'report.json').write_bytes(encoded(report));raise

def audit_read(folder,native_manifest):
    events=0
    def hook(event,args):
        nonlocal events
        events+=1
        forbidden=('subprocess.','ctypes.dlopen','ctypes.dlsym','socket.','os.system','os.fork',
                   'os.posix_spawn','os.exec','os.kill','os.remove','os.rmdir','os.rename','os.mkdir','os.chmod',
                   'os.symlink','os.link','os.truncate')
        require(not any(event.startswith(x) for x in forbidden),'forbidden reader audit operation: '+event)
        if event=='open':
            path,mode,flags=args
            require(not isinstance(path,(str,bytes)) or not os.fsdecode(path).startswith('/proc/'),
                    'reader attempted live process inspection')
            require(not isinstance(flags,int) or not flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND),
                    'reader attempted file mutation')
    sys.addaudithook(hook)
    result=read_evidence(folder,native_manifest)
    return dict(schema=SCHEMA+'.pure-audit',status='PASS',audit_events=events,forbidden_calls=0,result=result)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-manifest',type=Path,required=True)
    actions=parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--output',type=Path);actions.add_argument('--verify',type=Path)
    actions.add_argument('--verify-case',type=Path);actions.add_argument('--audit-read-only',type=Path)
    parser.add_argument('--case',action='append');args=parser.parse_args()
    try:
        if args.verify_case:
            r=read_case(args.verify_case,args.native_manifest)
            result=dict(status='PASS',case=r['name'],causal=r['causal'])
        elif args.verify: result=read_evidence(args.verify,args.native_manifest)
        elif args.audit_read_only: result=audit_read(args.audit_read_only,args.native_manifest)
        else: result=run(args.output,args.native_manifest,args.case)
        print(json.dumps(result,sort_keys=True));return 0
    except BaseException as error:
        print(json.dumps(dict(status='REJECTED' if args.verify_case else 'FAIL',
                              error=str(error),type=type(error).__name__),sort_keys=True));return 2

if __name__=='__main__': raise SystemExit(main())
