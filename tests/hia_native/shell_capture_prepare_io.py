"""Actual HIA capture preparation, typed child calls and Linux custody evidence."""
from __future__ import annotations
import argparse,copy,hashlib,importlib,json,os,selectors,stat,struct,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/hia_native'))
import shell_capture_file_io as cf
import shell_capture_mkdir_io as mk
import shell_capture_prepare_state as ps
PENDING,CAPACITY,INVALID=0xfffffffd,0xfffffffe,0xffffffff
MASK=(1<<64)-1
SCOPE=dict(production_activated=False,capture_preparation_qualified=False,
           duplicate_admission_qualified=False,global_sequence_concurrency_qualified=False,
           ambient_observation_qualified=False,tokio_async_cancellation_qualified=False,
           job_construction_qualified=False,error_display_qualified=False,
           whole_runtime_replaced=False,old_stack_removal_qualified=False)
SOURCES=('native/shell_capture_prepare.hepta','native/shell_capture_prepare_abi.md',
         'native/shell_capture_prepare_reuse.json','native/shell_capture_path.hepta',
         'native/shell_capture_path_abi.md','native/shell_capture_path_reuse.json',
         'native/shell_capture_mkdir.hepta','native/shell_capture_mkdir_abi.md',
         'native/shell_capture_mkdir_reuse.json','native/shell_capture_file.hepta',
         'native/shell_capture_file_abi.md','native/shell_capture_file_reuse.json',
         'native/shell_capture_prepare_packer.hepta','native/shell_capture_prepare_layout.json',
         'native/shell_capture_prepare_fixture.md','scripts/shell_capture_prepare_adapter.S',
         'scripts/hia_native_shell_capture_prepare_build.py','tests/hia_native/shell_capture_prepare_io.py',
         'tests/hia_native/shell_capture_file_io.py','tests/hia_native/shell_capture_mkdir_io.py',
         'tests/hia_native/shell_capture_prepare_state.py')
CASE_FILES=('spec.json','input.json','stdin.bin','stdout.bin','stderr.bin','execution.json',
            'observation.json','before.json','after.json','effects.bin','entries.bin','retirement.json')
need,sha,pin,packed,decoded,ordinary,read_json,write_new,plain_dir=(
    cf.need,cf.sha,cf.pin,cf.packed,cf.decoded,cf.ordinary,cf.read_json,cf.write_new,cf.plain_dir)
q,put=cf.q,cf.put
PAYLOAD=b'old\0capture\xff\n'

def case_specs():
    def spec(name,setup='none',tmpdir='normal',stage=0,error=0,seed=1,umask=0o022,hook=False):
        return dict(name=name,setup=setup,tmpdir_kind=tmpdir,error_stage=stage,expected_errno=error,
                    sequence_seed=seed,umask=umask,statx_seed=0,cleanup_directory_hook=hook,
                    native_only_controlled_race=hook)
    return (
        spec('new_capture'),spec('existing_jobs_dir','existing'),spec('truncate_both','truncate'),
        spec('mkdir_missing_ancestors',tmpdir='deep'),spec('raw_tmpdir',tmpdir='raw'),
        spec('empty_tmpdir',tmpdir='empty'),spec('umask027',umask=0o027),
        spec('mkdir_collision_file','collision',stage=1,error=17),
        spec('mkdir_denied_parent',tmpdir='denied',stage=1,error=13),
        spec('stdout_is_directory','stdout_dir',stage=2,error=21),
        spec('stderr_is_directory','stderr_dir',stage=3,error=21),
        spec('stderr_readonly_file','stderr_readonly',stage=3,error=13),
        spec('stderr_readonly_cleanup_directory','stderr_readonly',stage=3,error=13,hook=True),
        spec('stderr_directory_stdout_symlink','stdout_symlink',stage=3,error=21),
        spec('sequence_wrap',seed=MASK),
    )

def tmpdir_for(spec,work):
    kind=spec['tmpdir_kind'];base=os.fsencode(work)
    if kind=='empty': return b''
    suffix={'normal':b'tmp','deep':b'deep/a/b','raw':b'\xfftmp','denied':b'denied'}[kind]
    return base+b'/'+suffix

def joined(base,part):
    return base+(b'/' if base and not base.endswith(b'/') else b'')+part

def capture_paths(tmpdir,pid,sequence):
    directory=joined(tmpdir,b'octofs-jobs-'+str(pid).encode())
    identifier=(str(pid)+'-'+str(sequence)).encode()
    return directory,identifier,joined(directory,identifier+b'.stdout.log'),joined(directory,identifier+b'.stderr.log')

def absolute_owned(raw,work):
    base=os.fsencode(work);path=raw if raw.startswith(b'/') else base+b'/'+raw
    need(path.startswith(base+b'/') and b'\0' not in path,'fixture escaped owned work')
    cf.relative(path[len(base)+1:]);return path

def create_file(path,mode=0o640):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb',closefd=False) as stream: stream.write(PAYLOAD)
    finally: os.close(fd)

def setup_fixture(work,spec,pid):
    tmp=tmpdir_for(spec,work)
    if spec['tmpdir_kind'] not in ('empty','deep'):
        mode=0o500 if spec['tmpdir_kind']=='denied' else 0o755
        os.mkdir(tmp,mode);os.chmod(tmp,mode)
    paths=capture_paths(tmp,pid,spec['sequence_seed'])
    directory,_,out,err=paths
    directory=absolute_owned(directory,work);out=absolute_owned(out,work);err=absolute_owned(err,work)
    setup=spec['setup']
    if setup=='collision': create_file(directory)
    elif setup!='none':
        os.mkdir(directory,0o755);os.chmod(directory,0o755)
        if setup=='truncate': create_file(out);create_file(err)
        elif setup=='stdout_dir': os.mkdir(out,0o755);os.chmod(out,0o755)
        elif setup=='stderr_dir': os.mkdir(err,0o755);os.chmod(err,0o755)
        elif setup=='stderr_readonly': create_file(err,0o400)
        elif setup=='stdout_symlink':
            create_file(os.fsencode(work)+b'/target')
            os.symlink(b'../../target',out);os.mkdir(err,0o755);os.chmod(err,0o755)
        else: need(setup=='existing','unknown registered setup')
    return paths

def request_for(spec,work,pid,operation=1):
    tmp=tmpdir_for(spec,work)
    return b'HSHPPQ01'+struct.pack('<7Q',operation,1,pid,len(tmp),spec['statx_seed'],0,0)+tmp

def decode_response(raw):
    need(len(raw)>=128 and raw[:8]==b'HSHPPR01','complete capture tuple header')
    h=struct.unpack_from('<16Q',raw)
    need(h[1]==len(raw)==128+sum(h[12:]),'complete capture tuple extent')
    at=128;segments=[]
    for n in h[12:]:segments.append(raw[at:at+n]);at+=n
    return h,segments

def mkdir_owned_call(wire,previous):
    """Rebuild the persistent mkdir arena from original two-loop transitions.

    Bytes 0..63 are the retained Path helpers' disposable scratch. They are
    fully recorded and guarded, but are not persistent mkdir input state.
    Every byte from the state magic through the complete allocation is checked.
    """
    path=wire[64:];n=len(path);w=bytearray(previous)
    def finish(kind,value):
        w[96:192]=bytes(96)
        for at,v in ((72,0),(88,0),(192,3),(256,kind),(264,value)):put(w,at,v)
    def issue(action):
        sequence=q(w,80)+1;put(w,72,1);put(w,80,sequence);put(w,88,action)
        current=q(w,200);offset=513+n
        if action!=3:w[offset:offset+current+1]=path[:current]+b'\0'
        w[96:192]=b'HSHMKFX1'+struct.pack('<11Q',sequence,action,0 if action==3 else offset,
            0 if action==3 else current,{1:511,2:4095,3:4095,4:0}[action],0,0,0,0,0,0)
    def parent_size(current):
        parent=mk.rust_parent(path[:current]);return MASK if parent is None else len(parent)
    def descend():
        remaining=q(w,224)
        if remaining==0:finish(0,0);return
        put(w,200,q(w,514+2*n+8*(remaining-1)))
        for at in (208,240,248):put(w,at,0)
        issue(1)
    def found():
        if q(w,192)==1:put(w,192,2);put(w,224,q(w,216))
        else:put(w,224,q(w,224)-1)
        descend()
    if q(wire,8)==1:
        w[:512]=bytes(512);w[64:72]=b'HSHMKW01';w[512:513+n]=path+b'\0'
        for at,v in ((192,1),(200,n),(232,q(wire,16)),(272,n),(280,q(wire,16)),(288,512+10*(n+1)),(208,parent_size(n))):put(w,at,v)
        if n==0 or q(w,208)==MASK:finish(0,0)
        elif b'\0' in path:finish(2,0)
        else:issue(1)
    elif q(w,192)!=3:
        need(q(w,144)==1,'actual mkdir completion readiness')
        action,error,mode=q(w,88),q(w,160),q(w,168)
        w[96:192]=bytes(96);put(w,72,0);put(w,88,0)
        if action==1:
            if error==0:found()
            elif error==2 and q(w,192)==1:
                put(w,514+2*n+8*q(w,216),q(w,200));put(w,216,q(w,216)+1);put(w,200,q(w,208))
                if q(w,200)==0:found()
                else:
                    put(w,208,parent_size(q(w,200)))
                    if q(w,208)==MASK:found()
                    else:issue(1)
            elif error==17:put(w,240,17);issue(4 if q(w,232)==2 else 2)
            else:finish(1,error)
        elif action==2:
            if error==0:
                if q(w,232)==0:put(w,232,1)
                if mode&0o170000==0o040000:found()
                else:finish(1,q(w,240))
            elif q(w,232)==1:finish(1,q(w,240))
            else:put(w,248,error);issue(3)
        elif action==3:
            if error==14:put(w,232,1);finish(1,q(w,240))
            else:put(w,232,2);issue(4)
        else:
            need(action==4,'actual mkdir action domain')
            if error==0 and mode&0o170000==0o040000:found()
            else:finish(1,q(w,240))
    if q(w,192)==3:return 32,b'HSHMKR01'+struct.pack('<3Q',q(w,256),q(w,264),q(w,232)),bytes(w)
    return PENDING,b'',bytes(w)

def parse_effects(raw,footer=True):
    rows=[];at=0
    while raw[at:at+8] in (b'HSPREF01',b'HSPRSC01'):
        need(len(raw)-at>=192,'short effect header')
        h=struct.unpack_from('<24Q',raw,at);start=at;at+=192
        parent=raw[start:start+8]==b'HSPREF01';sizes=(96,0,0) if parent else (h[17],h[16],h[18])
        need(sum(sizes)<=len(raw)-at,'short complete effect payload')
        blobs=[]
        for n in sizes:blobs.append(raw[at:at+n]);at+=n
        rows.append(dict(kind='parent' if parent else 'kernel',header=h,slot=blobs[0],path=blobs[1],stat=blobs[2],offset=start,end=at))
    tail=raw[at:]
    need((len(tail)==256 and tail[:8]==b'HSPRAUD1') if footer else tail==b'','missing effect footer or trailing bytes')
    return rows,tail

def parse_entries(raw,footer=True):
    rows=[];at=0
    while raw[at:at+8]==b'HSPREN01':
        need(len(raw)-at>=192,'short entry header')
        h=struct.unpack_from('<24Q',raw,at);start=at;at+=192
        sizes=(h[22],h[8],h[9]);need(h[7]<=h[22] and sum(sizes)+96<=len(raw)-at,'short complete native allocations')
        arrays=[]
        for n in sizes:arrays.append(raw[at:at+n+32]);at+=n+32
        rows.append(dict(header=h,arrays=arrays,offset=start,end=at))
    tail=raw[at:]
    need((len(tail)==256 and tail[:8]==b'HSPRAUD1') if footer else tail==b'','missing entry footer or trailing bytes')
    return rows,tail

def parse_stdout(raw,requests):
    need(len(raw)>=320 and raw[:8]==b'HSPRRDY1','native ready header')
    ready=struct.unpack_from('<8Q',raw);at=64;gates=[];results=[]
    while len(results)<requests:
        need(len(raw)-at>=16,'short stdout frame')
        if raw[at:at+8]==b'HSPRGT01':
            need(len(raw)-at>=96,'short gate frame')
            gates.append(struct.unpack_from('<12Q',raw,at));at+=96
        else:
            ret,n=struct.unpack_from('<QQ',raw,at);at+=16
            need(ret in (128,INVALID,CAPACITY) and n<=len(raw)-at and (n>=128 if ret==128 else n==0),'native result frame')
            results.append((ret,raw[at:at+n]));at+=n
    need(len(raw)-at==256 and raw[at:at+8]==b'HSPRAUD1','stdout footer')
    return ready,gates,results,raw[at:]

def load_native(manifest):
    manifest=Path(manifest).absolute();sys.path.insert(0,str(ROOT/'scripts'))
    builder=importlib.import_module('hia_native_shell_capture_prepare_build')
    evidence=builder.read_evidence(manifest,source_root=ROOT)
    need(evidence.get('status')=='PASS','strong native build refused')
    metadata=read_json(manifest);executable=manifest.parent/metadata['elf']
    need(sha(ordinary(executable))==metadata['elf_sha256'],'actual executable identity')
    return manifest,metadata,executable,evidence

def environment_for(spec,work):
    return {b'PATH':b'/usr/bin:/bin',b'LANG':b'C',b'LC_ALL':b'C',b'TMPDIR':tmpdir_for(spec,work)}

def environment_record(env):
    return [{'key_hex':key.hex(),'value_hex':value.hex()} for key,value in sorted(env.items())]

def retire(work,final):
    value=cf.retire(work,final)
    value['schema']='hepta.runtime.shell-capture-prepare-retirement.v1'
    return value

def cleanup_hook(folder,spec,pid,gate,records,entries):
    if not spec['cleanup_directory_hook']:return None
    row=records[-1]
    if not(row['kind']=='parent' and row['header'][5]==1 and q(row['slot'],16)==5 and
           q(row['slot'],24)==4 and q(row['slot'],64)==48):return None
    call=entries[-1]
    need(call['header'][3:5]==(4,1) and call['header'][10]==48,'hook actual stderr child call')
    body=call['arrays'][1][16:-16]
    need(q(body,24)==1 and q(body,32)==13,'hook actual stderr errno')
    work=folder/'work';path=capture_paths(tmpdir_for(spec,work),pid,spec['sequence_seed'])[2]
    path=absolute_owned(path,work);backup=path+b'.retained'
    before=cf.tree_snapshot(work);s=os.lstat(path)
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and not os.path.lexists(backup),'owned hook source')
    os.rename(path,backup);os.mkdir(path,0o755);os.chmod(path,0o755)
    after=cf.tree_snapshot(work)
    return dict(gate_sequence=gate[1],parent_record_offset=row['offset'],native_entry=call['header'][2],
                source_hex=path.hex(),destination_hex=backup.hex(),before=before,after=after,
                source_identity=cf.stat_row(s),retained_identity=cf.stat_row(os.lstat(backup)),
                replacement_identity=cf.stat_row(os.lstat(path)),observed_ns=time.monotonic_ns())

def run_case(folder,spec,manifest,metadata,executable):
    folder.mkdir();work=folder/'work';work.mkdir(mode=0o700)
    write_new(folder/'spec.json',packed(spec));env=environment_for(spec,work)
    argv=[str(executable),'--capture-prepare-fixture',str(folder)]
    tool_before=pin(ordinary(executable));started=time.monotonic_ns();unix_started=time.time_ns()
    child=subprocess.Popen(argv,cwd=work,env=env,umask=spec['umask'],stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=0)
    deadline=time.monotonic()+30;selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
    stdin=bytearray();stdout=bytearray();stderr=b'';observed={'gates':[],'requests':[],'mutations':[]}
    failure=None;timed_out=False;drained=False
    def read(n):
        got=bytearray()
        while len(got)<n:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not selector.select(remaining):raise TimeoutError('native process deadline')
            raw=os.read(child.stdout.fileno(),n-len(got))
            need(bool(raw),'unexpected native EOF');got.extend(raw);stdout.extend(raw)
        return bytes(got)
    def write(raw):
        at=0
        while at<len(raw):
            n=os.write(child.stdin.fileno(),raw[at:]);need(n>0,'actual stdin write');at+=n
        stdin.extend(raw)
    try:
        ready=read(64);rh=struct.unpack('<8Q',ready)
        need(ready[:8]==b'HSPRRDY1' and rh[1:3]==(child.pid,child.pid),'actual ready PID/TID')
        observed['initial']=cf.proc_snapshot(child.pid)
        paths=setup_fixture(work,spec,child.pid);before=cf.tree_snapshot(work)
        write_new(folder/'before.json',packed(before));observed['admitted_process']=cf.proc_snapshot(child.pid,observed['initial']['identity'])
        wires=[request_for(spec,work,child.pid,op) for op in (1,2)];n=len(wires[0])-64
        output_capacity,workspace_capacity=384+3*n,1792+4*n
        write_new(folder/'input.json',packed(dict(wires_hex=[w.hex() for w in wires],output_capacity=output_capacity,
             workspace_capacity=workspace_capacity,private_sequence_seed=spec['sequence_seed'],paths_hex=[p.hex() for p in paths])))
        for request_index,wire in enumerate(wires,1):
            sent=time.monotonic_ns();write(struct.pack('<4Q',len(wire),output_capacity,workspace_capacity,spec['sequence_seed'])+wire)
            while True:
                prefix=read(8)
                if prefix!=b'HSPRGT01':break
                gate=struct.unpack('<12Q',prefix+read(88));received=time.monotonic_ns()
                trace=ordinary(folder/'effects.bin');entryraw=ordinary(folder/'entries.bin')
                records,_=parse_effects(trace,False);entries,_=parse_entries(entryraw,False)
                snapshot=cf.proc_snapshot(child.pid,observed['initial']['identity']);tree=cf.tree_snapshot(work)
                mutation=None
                if not observed['mutations']:mutation=cleanup_hook(folder,spec,child.pid,gate,records,entries)
                if mutation:observed['mutations'].append(mutation)
                after_snapshot=cf.proc_snapshot(child.pid,observed['initial']['identity']) if mutation else snapshot
                gate_row=dict(words=list(gate),received_ns=received,observed_ns=time.monotonic_ns(),process=snapshot,tree=tree,
                              process_after_mutation=after_snapshot,effects=pin(trace),entries=pin(entryraw))
                gate_row['ack_started_ns']=time.monotonic_ns();write(b'HSPRACK1'+struct.pack('<Q',gate[1]));gate_row['ack_completed_ns']=time.monotonic_ns()
                observed['gates'].append(gate_row)
            ret=struct.unpack('<Q',prefix)[0];extent=struct.unpack('<Q',read(8))[0]
            need(extent<=output_capacity,'actual publication bounds');body=read(extent);received=time.monotonic_ns()
            observed['requests'].append(dict(request=request_index,sent_ns=sent,received_ns=received,return_value=ret,body_hex=body.hex(),
                 process=cf.proc_snapshot(child.pid,observed['initial']['identity']),tree=cf.tree_snapshot(work),observed_ns=time.monotonic_ns()))
        child.stdin.close();child.stdin=None
        tail,stderr=child.communicate(timeout=max(0.01,deadline-time.monotonic()));stdout.extend(tail);drained=True
    except Exception as error:
        failure={'type':type(error).__name__,'message':str(error)};timed_out=isinstance(error,(TimeoutError,subprocess.TimeoutExpired))
        if child.poll() is None:child.kill()
    finally:
        selector.close()
        if child.stdin is not None:child.stdin.close();child.stdin=None
        if not drained:
            tail,stderr=child.communicate();stdout.extend(tail)
        completed=time.monotonic_ns();observed['completed']={'exit_code':child.returncode,'observed_ns':completed}
        for name,raw in [('stdin.bin',stdin),('stdout.bin',stdout),('stderr.bin',stderr)]:write_new(folder/name,raw)
        write_new(folder/'observation.json',packed(observed))
        receipt=dict(schema='hepta.runtime.shell-capture-prepare-process.v1',argv=argv,cwd=str(work),environment=environment_record(env),
            umask=spec['umask'],pid=child.pid,parent_pid=os.getpid(),uid=os.getuid(),gid=os.getgid(),deadline_seconds=30,timed_out=timed_out,
            failure=failure,exit_code=child.returncode,monotonic_started_ns=started,monotonic_completed_ns=completed,
            unix_started_ns=unix_started,unix_completed_ns=time.time_ns(),native_manifest={'path':str(manifest),**pin(ordinary(manifest))},
            audit_files=cf.audit_files_snapshot(folder),
            executable_before=tool_before,executable_after=pin(ordinary(executable)),streams={name:pin(ordinary(folder/name)) for name in ('stdin.bin','stdout.bin','stderr.bin')})
        write_new(folder/'execution.json',packed(receipt));after=cf.tree_snapshot(work);write_new(folder/'after.json',packed(after))
        write_new(folder/'retirement.json',packed(retire(work,after)))
    need(failure is None and child.returncode==0,'actual native process failed')
    return verify_case(folder,spec,manifest,metadata,executable)

def verify_trace(folder,spec,wires,receipt,observation):
    effects,ef=parse_effects(ordinary(folder/'effects.bin'))
    entries,nf=parse_entries(ordinary(folder/'entries.bin'))
    ready,gates,results,sf=parse_stdout(ordinary(folder/'stdout.bin'),len(wires))
    need(ef==nf==sf,'matching native footer bytes');footer=struct.unpack('<32Q',ef)
    pid=receipt['pid'];need(ready[1:3]==(pid,pid) and ready[5:]==(1,0,0) and ready[3]>2 and ready[4]>2 and ready[3]!=ready[4],'actual ready identity')
    tmp=wires[0][64:];n=len(tmp);ocap,wcap=384+3*n,1792+4*n;p=1280+n
    caps={0:(len(wires[0]),ocap,wcap),1:(256+n,512+3*n,128),2:(256+n,32,1152+10*n)}
    caps.update({r:(256+n,48,640+n) for r in (3,4,5)})
    counter=[0]*9;role_calls=[0]*6;work={r:bytes(caps[r][2]) for r in caps}
    entry_at,effect_at,serial,last_time=0,0,0,receipt['monotonic_started_ns']
    seq=spec['sequence_seed'];initialized=0;mapping=0;nodes={};calls=[];operations=[];gate_states=[];mkdir_ops=[]
    current_cache=spec['statx_seed'];seen_sequence=False;full_paths=False;out_token=0;err_token=0;saved_error=None
    paths=capture_paths(tmp,pid,seq);next_action=('init',0);child_op=1;expected_phase=1
    current_request=1;main_wire=wires[0];main_output=b'\xa7'*ocap;last_main_return=0
    parent_model=ps.Model(dict(tmp_hex=tmp.hex(),present=1,pid=pid,sequence=spec['sequence_seed'],cache=spec['statx_seed']))
    def canonical_parent(returned):
        need(returned==(128 if next_action[0]=='done' else PENDING),'parent return for independent phase')
        parent_model.phase=expected_phase
        parent_model.sequence=(parent_sequence+int(returned==PENDING))&MASK
        parent_model.cache=current_cache;parent_model.observed=seen_sequence;parent_model.full=full_paths
        parent_model.tokens=[token if token in nodes and nodes[token]['live'] else 0 for token in (out_token,err_token)]
        if returned==128 and saved_error is not None:parent_model.tokens=[0,0]
        parent_model.error=[int(saved_error is not None),*(saved_error or (0,0,0))]
        step={}
        if expected_phase in (2,6,10,15):step['operation']=child_op
        return parent_model.work(step)[:wcap]
    def native_entry(role,wire,initial_output,parent_sequence):
        nonlocal entry_at,serial,last_time
        need(entry_at+2<=len(entries),'missing paired native entry')
        before,after=entries[entry_at:entry_at+2];entry_at+=2;serial+=1;role_calls[role]+=1
        bh,ah=before['header'],after['header'];ic,oc,wc=caps[role]
        for h,phase in ((bh,0),(ah,1)):
            need(h[1:10]==(current_request,serial,role,phase,pid,pid,len(wire),oc,wc) and
                 h[12]==parent_sequence and h[13:22]==tuple(counter) and h[22:]==(ic,role_calls[role]),'actual native entry identity/counters')
            need(last_time<=h[11]<=receipt['monotonic_completed_ns'],'actual native entry time');last_time=h[11]
        need(bh[10]==0,'before entry return field')
        for arrays in (before['arrays'],after['arrays']):
            for array,cap,left,right in zip(arrays,(ic,oc,wc),(0xc1,0xa5,0x5a),(0xc2,0xa6,0x5b)):
                need(len(array)==cap+32 and array[:16]==bytes([left])*16 and array[-16:]==bytes([right])*16,'native memory guards')
        b=[a[16:-16] for a in before['arrays']];a=[a[16:-16] for a in after['arrays']]
        expected_input=wire+(b'\xd1'*(ic-len(wire)) if role else b'')
        need(b==[expected_input,initial_output,work[role]],'exact native before arrays')
        need(a[0]==b[0],'native input and unused capacity immutable');returned=ah[10]
        if role in (3,4,5):
            rr,body,ww=cf.model_call(wire,b[2]);oo=body+b[1][len(body):] if rr==48 else b[1]
            need((returned,a[1],a[2])==(rr,oo,ww),'frozen file full state transition')
        elif role==1:
            header=b'HSHCPR01'+struct.pack('<9Q',3,80+sum(map(len,paths)),0,seq,*map(len,paths),0)
            body=header+b''.join(paths)
            need(returned==80 and a[1]==body+b[1][len(body):],'frozen path actual complete projection')
        elif role==2:
            rr,body,ww=mkdir_owned_call(wire,b[2]);oo=body+b[1][len(body):] if rr==32 else b[1]
            need((returned,a[1],a[2][64:])==(rr,oo,ww[64:]),'complete canonical mkdir persistent arena')
        else:
            need(returned in (128,PENDING),'registered owner return')
            if returned==PENDING:need(a[1]==b[1],'pending owner output unchanged')
            need(a[2][:8]==b'HSHPPW01' and q(a[2],24)==n and q(a[2],32)==wcap and q(a[2],40)==ocap and
                 q(a[2],48)==1 and q(a[2],56)==pid and q(a[2],312)==spec['statx_seed'],'owner original request binding')
            need(a[2][320:512]==bytes(192) and a[2][560:1024]==bytes(464),'owner reserved workspace')
            need(a[2]==canonical_parent(returned),'complete canonical parent arena')
        work[role]=a[2]
        calls.append(dict(entry=serial,role=role,parent_sequence=parent_sequence,return_value=returned,
                          input_hex=wire.hex(),output=pin(a[1]),output_hex=a[1].hex(),end=after['end']))
        return returned,a[1]
    def parent_record(phase,slot,parent_sequence):
        nonlocal effect_at
        need(effect_at<len(effects),'missing parent effect');row=effects[effect_at];effect_at+=1;h=row['header']
        need(row['kind']=='parent' and h[1:6]==(current_request,parent_sequence,pid,pid,phase) and
             h[6:15]==tuple(counter) and h[15:20]==(spec['sequence_seed'],seq,last_main_return,initialized,mapping) and
             h[20:]==(0,0,0,0),'parent effect identity/order/counters')
        need(row['slot']==slot,'parent effect from actual HIA workspace')
        return row
    def kernel_effect(role,parent_sequence,owned_token=0):
        nonlocal effect_at
        need(effect_at+2<=len(effects),'missing actual kernel pair')
        issue,done=effects[effect_at:effect_at+2];effect_at+=2;ih,dh=issue['header'],done['header']
        need(issue['kind']==done['kind']=='kernel','kernel pair kind')
        slot_at=96 if role==2 else 128
        slot=work[role][slot_at:slot_at+96] if role else b''
        leaf_sequence=q(slot,8) if role else 0;action=q(slot,16) if role else 3
        need(issue['slot']==slot,'kernel issued from actual leaf workspace')
        if role==2:
            words=struct.unpack('<12Q',slot)
            need(slot[:8]==b'HSHMKFX1' and action in (1,2,3,4) and words[6:]==(0,)*6,'mkdir issued slot')
            arg={1:511,2:4095,3:4095,4:0}[action];need(words[5]==arg,'mkdir fixed mode/mask')
            path=b'' if action==3 else work[role][words[3]:words[3]+words[4]]
            if action==3:need(words[3:5]==(0,0),'NULL statx probe arguments')
            else:need(words[3]==513+len(paths[0]) and words[3]+words[4]<caps[role][2] and work[role][words[3]+words[4]]==0,'canonical mkdir path borrow')
            nr={1:83,2:332,3:332,4:262}[action];fdarg=MASK-99 if action in (2,4) else 0
            fixed=(nr,fdarg,0,arg);statlen={1:0,2:256,3:0,4:144}[action]
        elif role:
            words=struct.unpack('<12Q',slot)
            need(slot[:8]==b'HSHCFFX1' and words[7:]==(0,)*5 and action in (1,2),'prepare file issued slot')
            need(words[3]==512 and words[4]==q(work[role],32) and words[3]+words[4]<caps[role][2] and
                 work[role][words[3]+words[4]]==0,'canonical file path borrow')
            path=work[role][512:512+words[4]]
            need(words[5:7]==((0x80241,438) if action==1 else (0,0)),'file fixed flags/mode')
            fixed=(257,MASK-99,0x80241,438) if action==1 else (87,0,0,0);statlen=0
        else:
            need(owned_token in nodes and nodes[owned_token]['live'] and nodes[owned_token]['owner']==0,'receiver-owned close capability')
            path=b'';fixed=(3,nodes[owned_token]['fd'],0,0);statlen=0
        need(b'\0' not in path and issue['path']==done['path']==path,'complete kernel path bytes')
        counter[2]+=1
        for row,h,phase in ((issue,ih,0),(done,dh,1)):
            need(h[1:12]==(current_request,parent_sequence,role,leaf_sequence,pid,pid,phase,*fixed) and
                 h[16:20]==(len(path),96 if role else 0,statlen,owned_token),'kernel identity/arguments/order')
            need(len(row['stat'])==statlen,'complete actual stat buffer')
        need(ih[12:16]==(0,0,0,0) and ih[20:]==(counter[4],counter[5],counter[7],counter[8]) and
             issue['stat']==bytes(statlen),'kernel issue result/custody')
        raw,error,handle,mode=dh[12:16]
        need((1<=error<=4095 and raw==((-error)&MASK) and mode==0 and handle==0) or
             (error==0 and (raw<=0x7fffffff if fixed[0]==257 else raw==0)),'actual raw syscall result')
        if fixed[0]==257 and not error:
            need(handle==counter[4]+1 and raw not in (0,1,2,ready[3],ready[4]) and
                 raw not in [v['fd'] for v in nodes.values() if v['live']],'actual minted descriptor token')
            nodes[handle]=dict(fd=raw,owner=role,live=True,role=role,path_hex=path.hex())
            counter[4]+=1;counter[7]+=1
        else:need(handle==0,'non-open result token')
        if fixed[0]==3:
            nodes[owned_token]['live']=False;counter[5]+=1;counter[7]-=1;counter[8]-=1
        if statlen and not error:
            actual_mode=struct.unpack_from('<H',done['stat'],28)[0] if fixed[0]==332 else struct.unpack_from('<I',done['stat'],24)[0]
            need(mode==actual_mode,'actual metadata mode bytes')
        elif not error:need(mode==0,'nonmetadata mode result')
        need(dh[20:]==(counter[4],counter[5],counter[7],counter[8]),'kernel completed custody')
        if role:
            before_words=struct.unpack('<12Q',slot);after_words=struct.unpack('<12Q',done['slot'])
            if role==2:
                need(after_words[:6]==before_words[:6] and after_words[6:]==(1,raw,error,mode,0,0),'mkdir mailbox actual completion')
            else:
                need(after_words[:7]==before_words[:7] and after_words[7:]==(1,raw,error,handle,0),'file mailbox actual completion')
            updated=bytearray(work[role]);updated[slot_at:slot_at+96]=done['slot'];work[role]=bytes(updated)
        else:need(done['slot']==b'','receiver close has no leaf slot')
        counter[3]+=1
        row=dict(role=role,action=action,parent_sequence=parent_sequence,leaf_sequence=leaf_sequence,
                 syscall=fixed[0],fd_argument=fixed[1],flags=fixed[2],mode_argument=fixed[3],path_hex=path.hex(),
                 raw=raw,errno=error,token=handle,returned_mode=mode,metadata_hex=done['stat'].hex(),close_token=owned_token)
        operations.append(row)
        if role==2:mkdir_ops.append(dict(action=action,path=path,errno=error,mode=mode,raw=raw,metadata=done['stat']))
        return raw,error
    def call_wire(kind,role=0):
        if kind=='mkdir':
            return b'HSHMKQ01'+struct.pack('<7Q',child_op,spec['statx_seed'] if child_op==1 else 0,len(paths[0]),0,0,0,0)+paths[0]
        if kind=='path':
            return b'HSHCPQ01'+struct.pack('<7Q',3,1,pid,spec['sequence_seed'],n,0,0)+tmp
        path=b'' if kind=='take' else paths[2 if role in (3,5) else 3]
        operation=4 if kind=='take' else (2 if role==5 else 1)
        return b'HSHCFQ01'+struct.pack('<7Q',1 if kind=='take' else child_op,operation,len(path),0,0,0,0)+path
    def expected_response():
        stage,kind,error=(0,0,0) if saved_error is None else saved_error
        body_paths=paths if seen_sequence else (paths[0],b'',b'',b'')
        tokens=(out_token,err_token) if saved_error is None else (0,0)
        return b'HSHPPR01'+struct.pack('<15Q',128+sum(map(len,body_paths)),int(saved_error is not None),stage,kind,error,
            int(seen_sequence),spec['sequence_seed'] if seen_sequence else 0,seq if seen_sequence else 0,current_cache,
            *tokens,*map(len,body_paths))+b''.join(body_paths)
    publication=[];gate_index=0;parent_sequence=0
    for current_request,external_wire in enumerate(wires,1):
        main_wire=external_wire;main_output=b'\xa7'*ocap
        while True:
            before_work=work[0]
            returned,main_output=native_entry(0,main_wire,main_output,0);last_main_return=returned
            if returned==128:
                need(next_action[0]=='done' and q(work[0],8)==17,'premature owner publication')
                body=expected_response()
                need(main_output==body+b'\xa7'*(ocap-len(body)) and results[current_request-1]==(128,body),'published complete capture tuple')
                if current_request>1:need(work[0]==before_work,'terminal resume changed arena')
                publication.append(dict(request=current_request,return_value=128,body_hex=body.hex(),
                    entry=serial,entry_end=entries[entry_at-1]['end'],effect_end=effects[effect_at-1]['end'],
                    live_handles={str(k):copy.deepcopy(v) for k,v in nodes.items()}))
                break
            label,role=next_action
            need(label!='done' and current_request==1,'extraneous owner continuation')
            parent_sequence=(parent_sequence+1)&MASK
            slot=work[0][128:224];sw=struct.unpack('<12Q',slot)
            need(slot[:8]==b'HSHPPFX1' and sw[1]==parent_sequence and sw[7:]==(0,)*5,'canonical issued parent slot')
            need(q(work[0],8)==expected_phase and q(work[0],16)==parent_sequence,'HIA selected phase/sequence')
            child_wire=None
            if label=='init':expected=(1,512+3*n,1152+10*n,640+n,256+n)
            elif label=='mkdir':
                child_wire=call_wire('mkdir');expected=(2,1024,len(child_wire),512,0)
            elif label=='dispatch_mkdir':expected=(3,0,0,0,0)
            elif label=='sequence':expected=(4,0,0,0,0)
            elif label=='path':
                child_wire=call_wire('path');expected=(9,1024,len(child_wire),p,512+3*n)
            elif label in ('file','take'):
                child_wire=call_wire(label,role);expected=(5,role,1024,len(child_wire),512)
            elif label=='dispatch_file':expected=(6,role,0,0,0)
            elif label=='adopt':expected=(7,role,out_token if role==3 else err_token,0,0)
            elif label=='close':expected=(8,out_token,0,0,0)
            else:raise ValueError('unknown independently selected action')
            need(sw[2:7]==expected,'HIA parent order/arguments')
            if child_wire is not None:
                need(work[0][1024:1024+len(child_wire)]==child_wire and work[0][1024+len(child_wire):p]==bytes(p-1024-len(child_wire)),
                     'complete typed child request and unused staging')
                if label!='path':need(work[0][512:560]==bytes(48),'cleared short child destination')
            counter[0]+=1;issue=parent_record(0,slot,parent_sequence);completion=0;error=0
            dest=None;body=None
            if label=='init':
                need(not initialized,'repeated arena initialization')
                initialized=1;mapping=5*(256+n)+(512+3*n)+(1152+10*n)+3*(640+n)+976
                next_action=('mkdir',2);child_op=1;expected_phase=2
            elif label=='mkdir':
                completion,body=native_entry(2,child_wire,work[0][512:544],parent_sequence);dest=512
                if completion==PENDING:next_action=('dispatch_mkdir',2);expected_phase=3
                else:
                    model=mk.replay_policy(paths[0],spec['statx_seed'],mkdir_ops)
                    need(body==b'HSHMKR01'+struct.pack('<3Q',model['kind'],model['value'],model['cache']),'mkdir full original policy result')
                    current_cache=model['cache']
                    if model['kind']:
                        saved_error=(1,model['kind'],model['value']);next_action=('done',0);expected_phase=17
                    else:next_action=('sequence',0);expected_phase=4
            elif label=='dispatch_mkdir':
                kernel_effect(2,parent_sequence);next_action=('mkdir',2);child_op=2;expected_phase=2
            elif label=='sequence':
                need(not seen_sequence,'repeated sequence allocation');seen_sequence=True;completion=seq;seq=(seq+1)&MASK
                next_action=('path',1);expected_phase=5
            elif label=='path':
                need(seen_sequence,'paths before sequence');dest=p
                completion,body=native_entry(1,child_wire,work[0][p:p+caps[1][1]],parent_sequence)
                full_paths=True
                next_action=('file',3);child_op=1;expected_phase=6
            elif label in ('file','take'):
                completion,body=native_entry(role,child_wire,work[0][512:560],parent_sequence);dest=512
                if completion==PENDING:
                    need(label=='file','TAKE issued a syscall');next_action=('dispatch_file',role);expected_phase={3:7,4:11,5:16}[role]
                else:
                    kind,value,token=struct.unpack_from('<3Q',body,24)
                    if role==5:
                        need(saved_error is not None and saved_error[0]==3,'cleanup without saved stderr error')
                        next_action=('done',0);expected_phase=17
                    elif kind:
                        need(label=='file','TAKE failed');saved_error=(role-1,kind,value)
                        next_action=('close',0) if role==4 else ('done',0);expected_phase=14 if role==4 else 17
                    elif label=='take':
                        need(token==(out_token if role==3 else err_token),'TAKE preserved actual token')
                        next_action=('adopt',role);expected_phase=9 if role==3 else 13
                    else:
                        need(token in nodes and nodes[token]['owner']==role and nodes[token]['live'],'CREATE actual owned token')
                        if role==3:out_token=token
                        else:err_token=token
                        next_action=('take',role);expected_phase=8 if role==3 else 12
            elif label=='dispatch_file':
                kernel_effect(role,parent_sequence);next_action=('file',role);child_op=2;expected_phase={3:6,4:10,5:15}[role]
            elif label=='adopt':
                token=out_token if role==3 else err_token
                need(nodes[token]['owner']==role and nodes[token]['live'] and q(work[role],8)==4 and
                     q(work[role],16)==3 and q(work[role],48)==0 and q(work[role],80)==token,'actual TAKE receiver transfer')
                nodes[token]['owner']=0;counter[6]+=1;counter[8]+=1
                next_action=('file',4) if role==3 else ('done',0);child_op=1;expected_phase=10 if role==3 else 17
            elif label=='close':
                need(saved_error is not None and saved_error[0]==3,'close before stderr failure')
                completion,error=kernel_effect(0,parent_sequence,out_token)
                next_action=('file',5);child_op=1;expected_phase=15
            updated=bytearray(work[0])
            if dest is not None:
                updated[dest:dest+len(body)]=body
                if label=='mkdir':updated[544:560]=bytes(16)
            struct.pack_into('<4Q',updated,128+56,1,completion,error,0);work[0]=bytes(updated)
            counter[1]+=1;done=parent_record(1,work[0][128:224],parent_sequence)
            expected_gate=(int.from_bytes(b'HSPRGT01','little'),parent_sequence,expected[0],current_request,serial,
                           counter[3],counter[4],counter[5],counter[6],counter[7],counter[8],seq)
            need(gate_index<len(gates) and gates[gate_index]==expected_gate,'actual completed-effect gate')
            gate_states.append(dict(words=list(expected_gate),effect_end=done['end'],entry_end=entries[entry_at-1]['end'],
                native_entry=serial,parent_issue_offset=issue['offset'],parent_completed_offset=done['offset'],
                action=expected[0],role=role,label=label,operations=len(operations),live_handles={str(k):copy.deepcopy(v) for k,v in nodes.items()}))
            gate_index+=1;main_wire=wires[1]
    need(entry_at==len(entries) and effect_at==len(effects) and gate_index==len(gates),'unconsumed native entries/effects/gates')
    need(saved_error==((spec['error_stage'],1,spec['expected_errno']) if spec['expected_errno'] else None),'registered actual error result')
    expected_footer=(int.from_bytes(b'HSPRAUD1','little'),pid,len(wires),serial,*counter,spec['sequence_seed'],seq,
        0,0,128,ocap,wcap,mapping,initialized,ready[3],ready[4],*role_calls,1,0)
    need(footer==expected_footer,'complete native footer counts/custody')
    framed=bytearray()
    for index,wire in enumerate(wires,1):
        framed.extend(struct.pack('<4Q',len(wire),ocap,wcap,spec['sequence_seed'])+wire)
        for gate in gates:
            if gate[3]==index:framed.extend(b'HSPRACK1'+struct.pack('<Q',gate[1]))
    need(ordinary(folder/'stdin.bin')==framed,'complete actual input frames and acknowledgements')
    return dict(ready=list(ready),results=results,calls=calls,operations=operations,gates=gate_states,publications=publication,
        counts=dict(requests=len(wires),native_entries=serial,complete_native_arrays=serial*6,parent_effects=counter[0],
            kernel_syscalls=counter[2],kernel_records=counter[2]*2,minted_handles=counter[4],closed_handles=counter[5],
            adopted_handles=counter[6],live_handles_at_receiver_exit=counter[7],sequence_observations=int(seen_sequence)))

def relative_owned(raw,work):
    base=os.fsencode(work)
    if raw==base:return b''
    if raw.startswith(b'/'):
        need(raw.startswith(base+b'/'),'syscall escaped owned fixture');raw=raw[len(base)+1:]
    if raw:cf.relative(raw)
    return raw

def resolve_owned(raw,work,tree,follow_final=True):
    rel=relative_owned(raw,work);todo=rel.split(b'/') if rel else [];done=[];links=0
    while todo:
        part=todo.pop(0)
        if part in (b'',b'.'):continue
        if part==b'..':
            need(bool(done),'fixture link escapes owned root');done.pop();continue
        done.append(part);key=b'/'.join(done).hex();row=tree.get(key)
        if row and row['kind']=='symlink' and (todo or follow_final):
            links+=1;need(links<=40,'unexpected fixture symlink loop');done.pop()
            target=bytes.fromhex(row['target_hex'])
            if target.startswith(b'/'):target=relative_owned(target,work);done=[]
            todo=target.split(b'/')+todo
    return b'/'.join(done).hex()

def expected_setup(spec,work,pid):
    result={'':dict(kind='directory',mode=0o700)}
    def add(path,kind,mode,**extra):result[relative_owned(path,work).hex()]=dict(kind=kind,mode=mode,**extra)
    tmp=tmpdir_for(spec,work);paths=capture_paths(tmp,pid,spec['sequence_seed'])
    if spec['tmpdir_kind'] not in ('empty','deep'):add(tmp,'directory',0o500 if spec['tmpdir_kind']=='denied' else 0o755)
    setup=spec['setup']
    if setup=='collision':add(paths[0],'file',0o640,payload_hex=PAYLOAD.hex())
    elif setup!='none':
        add(paths[0],'directory',0o755)
        if setup=='truncate':
            for path in paths[2:]:add(path,'file',0o640,payload_hex=PAYLOAD.hex())
        elif setup=='stdout_dir':add(paths[2],'directory',0o755)
        elif setup=='stderr_dir':add(paths[3],'directory',0o755)
        elif setup=='stderr_readonly':add(paths[3],'file',0o400,payload_hex=PAYLOAD.hex())
        elif setup=='stdout_symlink':
            add(os.fsencode(work)+b'/target','file',0o640,payload_hex=PAYLOAD.hex())
            add(paths[2],'symlink',0o777,target_hex=b'../../target'.hex());add(paths[3],'directory',0o755)
        else:need(setup=='existing','unregistered setup')
    return result

def verify_trees(folder,spec,receipt,observed,native,before,after):
    work=folder/'work';old=cf.check_tree(before);expected=expected_setup(spec,work,receipt['pid'])
    need(set(old)==set(expected),'complete owned setup inventory')
    for key,item in expected.items():
        row=old[key]
        need(row['kind']==item['kind'] and stat.S_IMODE(row['mode'])==item['mode'] and
             (row['uid'],row['gid'])==(receipt['uid'],receipt['gid']),'setup mode/ownership')
        for field in ('payload_hex','target_hex'):
            if field in item:need(row[field]==item[field],'setup complete payload/target')
    need(len(observed['gates'])==len(native['gates']),'complete observed gate inventory')
    need(len(observed['mutations'])==int(spec['cleanup_directory_hook']),'registered controlled-race count')
    previous=before;operation_at=0;hook_used=False
    def changed(previous,current,operation):
        left,right=cf.check_tree(previous),cf.check_tree(current);keys=set(left);target=None;kind=None
        if operation is not None:
            nr,error=operation['syscall'],operation['errno'];path=bytes.fromhex(operation['path_hex'])
            if nr in (83,257,87):target=resolve_owned(path,work,left,nr==257)
            if not error:
                if nr==83:
                    need(target not in left,'successful mkdir target already existed');keys.add(target);kind='directory'
                elif nr==257:
                    need(target not in left or left[target]['kind']=='file','successful open target type');keys.add(target);kind='file'
                elif nr==87:
                    need(target in left and left[target]['kind']!='directory','successful unlink target');keys.remove(target);kind='removed'
                elif nr in (332,262):
                    selected=resolve_owned(path,work,left);need(selected in left,'actual metadata target')
                    row=left[selected];data=bytes.fromhex(operation['metadata_hex'])
                    if nr==332:device=os.makedev(struct.unpack_from('<I',data,136)[0],struct.unpack_from('<I',data,140)[0]);inode=q(data,32)
                    else:device,inode=struct.unpack_from('<QQ',data)
                    need((device,inode,operation['returned_mode'])==(row['device'],row['inode'],row['mode']),'actual metadata inode/mode')
        need(set(right)==keys,'actual syscall tree membership')
        for key,row in left.items():
            if key==target and kind is not None:continue
            actual=right[key]
            if row['kind']=='directory':need(cf.identity(actual)==cf.identity(row),'unrelated directory identity changed')
            else:need(actual==row,'unrelated complete file/link changed')
        if kind in ('file','directory'):
            row=right[target];mode=(0o666 if kind=='file' else 0o777)&~spec['umask']
            need(row['kind']==kind and row['uid']==receipt['uid'] and row['gid']==receipt['gid'],'created object type/ownership')
            if target in left:need(cf.identity(row)==cf.identity(left[target]),'truncate replaced inode/mode')
            else:
                need(stat.S_IMODE(row['mode'])==mode and (row['device'],row['inode']) not in
                     {(r['device'],r['inode']) for r in left.values()},'actual kernel creation mode/inode')
            if kind=='file':need(row['size']==0 and row['payload_hex']=='' and row['nlink']==1,'actual capture truncate bytes')
        if kind is None:need(previous==current,'nonmutating syscall changed fixture')
    for gate,row in zip(native['gates'],observed['gates']):
        need(gate['operations']-operation_at in (0,1),'one primitive per admitted effect')
        operation=None if gate['operations']==operation_at else native['operations'][operation_at]
        operation_at=gate['operations'];changed(previous,row['tree'],operation);previous=row['tree']
        mutation=next((m for m in observed['mutations'] if m['gate_sequence']==gate['words'][1]),None)
        if mutation is not None:
            call=native['calls'][gate['native_entry']-1]
            need(not hook_used and gate['label']=='file' and gate['role']==4 and call['return_value']==48 and
                 bytes.fromhex(call['output_hex'])[24:40]==struct.pack('<QQ',1,13),'controlled hook actual stderr error gate')
            need(mutation['parent_record_offset']==gate['parent_completed_offset'] and mutation['native_entry']==call['entry'] and
                 mutation['before']==row['tree'] and row['received_ns']<=mutation['observed_ns']<=row['ack_started_ns'],
                 'controlled hook causal binding')
            source=capture_paths(tmpdir_for(spec,work),receipt['pid'],spec['sequence_seed'])[2]
            source=absolute_owned(source,work);destination=source+b'.retained'
            need((mutation['source_hex'],mutation['destination_hex'])==(source.hex(),destination.hex()),'registered controlled hook paths')
            left,right=cf.check_tree(mutation['before']),cf.check_tree(mutation['after'])
            key=relative_owned(source,work).hex();backup=relative_owned(destination,work).hex()
            need(key in left and backup not in left and set(right)==set(left)|{backup},'controlled hook exact tree inventory')
            old=left[key];retained=right[backup];replacement=right[key]
            need(old['kind']==retained['kind']=='file' and old['payload_hex']==retained['payload_hex']=='' and
                 cf.identity(old)==cf.identity(retained) and replacement['kind']=='directory' and
                 stat.S_IMODE(replacement['mode'])==0o755 and (replacement['uid'],replacement['gid'])==(receipt['uid'],receipt['gid']) and
                 (replacement['device'],replacement['inode']) not in {(r['device'],r['inode']) for r in left.values()},
                 'controlled hook retained inode and replacement directory')
            for field,item in (('source_identity',old),('retained_identity',retained),('replacement_identity',replacement)):
                need(mutation[field]=={k:item[k] for k in ('device','inode','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')},
                     'controlled hook actual lstat identity')
            for k,item in left.items():
                if k==key:continue
                if item['kind']=='directory':need(cf.identity(item)==cf.identity(right[k]),'hook unrelated directory identity')
                else:need(item==right[k],'hook unrelated complete file')
            previous=mutation['after'];hook_used=True
        else:need(row['process_after_mutation']==row['process'],'unregistered process mutation observation')
    need(operation_at==len(native['operations']) and hook_used==spec['cleanup_directory_hook'],'complete tree operation replay')
    need(after==previous and all(r['tree']==after for r in observed['requests']),'publication and retired complete fixture tree')
    if hook_used:
        close=[r for r in native['operations'] if r['syscall']==3];unlink=[r for r in native['operations'] if r['syscall']==87]
        need(len(close)==len(unlink)==1 and close[0]['errno']==0 and unlink[0]['errno']==21 and
             close[0]['parent_sequence']<unlink[0]['parent_sequence'],'actual cleanup error preservation case')

def verify_retirement(folder,final):
    receipt=read_json(folder/'retirement.json');work=folder/'work';expected=cf.retirement_order(final)
    need(set(receipt)=={'schema','recorded_work','final_snapshot','removed','observed_root_absent'} and
         receipt['schema']=='hepta.runtime.shell-capture-prepare-retirement.v1' and receipt['recorded_work']==str(work) and
         receipt['final_snapshot']==pin(packed(final)),'retirement binding')
    need(len(receipt['removed'])==len(expected),'retirement exact inventory')
    for row,item in zip(receipt['removed'],expected):
        need(set(row)=={'path_hex','before','observed_absent'} and row['path_hex']==item['path_hex'] and
             cf.identity(row['before'])==cf.identity(item) and row['observed_absent'] is True,'retirement exact identity/order')
    need(receipt['observed_root_absent'] is True and not os.path.lexists(work),'owned fixture remains live')

def verify_observations(folder,spec,receipt,observed,native):
    work=folder/'work';ready=native['ready'];initial=observed['initial'];zero_nodes={}
    timeline=[(initial,zero_nodes,0,0,read_json(folder/'before.json')),
              (observed['admitted_process'],zero_nodes,0,0,read_json(folder/'before.json'))]
    trace=ordinary(folder/'effects.bin');entryraw=ordinary(folder/'entries.bin');last=receipt['monotonic_started_ns']
    for gate,row in zip(native['gates'],observed['gates']):
        need(row['words']==gate['words'] and row['effects']==pin(trace[:gate['effect_end']]) and
             row['entries']==pin(entryraw[:gate['entry_end']]),'observed gate raw trace/entry binding')
        need(all(type(row.get(k)) is int for k in ('received_ns','observed_ns','ack_started_ns','ack_completed_ns')) and
             last<=row['received_ns']<=row['observed_ns']<=row['ack_started_ns']<=row['ack_completed_ns']<=receipt['monotonic_completed_ns'],
             'actual gate acknowledgement timing')
        last=row['ack_completed_ns']
        timeline.append((row['process'],gate['live_handles'],gate['effect_end'],gate['entry_end'],row['tree']))
        mutation=next((m for m in observed['mutations'] if m['gate_sequence']==gate['words'][1]),None)
        timeline.append((row['process_after_mutation'],gate['live_handles'],gate['effect_end'],gate['entry_end'],
                         row['tree'] if mutation is None else mutation['after']))
    need(len(observed['requests'])==len(native['publications']),'complete publication observations')
    for index,(step,row) in enumerate(zip(native['publications'],observed['requests']),1):
        need(row['request']==index and row['return_value']==128 and row['body_hex']==step['body_hex'],'actual observed capture tuple')
        need(all(type(row.get(k)) is int for k in ('sent_ns','received_ns','observed_ns')) and
             receipt['monotonic_started_ns']<=row['sent_ns']<=row['received_ns']<=row['observed_ns']<=receipt['monotonic_completed_ns'],
             'actual request timing')
        if index==1:need(row['received_ns']>=last,'publication preceded last effect gate')
        else:need(row['sent_ns']>=observed['requests'][index-2]['observed_ns'],'external requests overlapped')
        timeline.append((row['process'],step['live_handles'],step['effect_end'],step['entry_end'],row['tree']))
    audit_files=cf.verify_audit_files(folder,receipt)
    first_identity=initial['identity'];descriptor_identity={}
    for snapshot,ledger,trace_end,entry_end,tree_rows in timeline:
        ident=cf.process_identity(bytes.fromhex(snapshot['stat_hex']))
        need(snapshot['identity']==ident and ident['pid']==receipt['pid'] and ident['ppid']==receipt['parent_pid'] and
             ident['starttime']==first_identity['starttime'] and ident['state'] not in ('Z','X'),'retained child custody identity')
        need(snapshot['exe_hex']==os.fsencode(receipt['argv'][0]).hex() and snapshot['cwd_hex']==os.fsencode(work).hex(),
             'actual executable/cwd observation')
        rows=snapshot['fds'];names=[r['fd'] for r in rows]
        need(all(type(x) is int and x>=0 for x in names) and names==sorted(set(names)),'complete unique actual FD inventory')
        fds={r['fd']:r for r in rows};live={int(k):v for k,v in ledger.items() if v['live']}
        need(set(fds)=={0,1,2,ready[3],ready[4]}|{v['fd'] for v in live.values()},'actual owned FD custody inventory')
        for fd in (0,1,2):
            original=next(r for r in initial['fds'] if r['fd']==fd)
            need(cf.identity(fds[fd]['stat'])==cf.identity(original['stat']) and fds[fd]['link_hex']==original['link_hex'],
                 'transport FD identity changed')
        for fd,name,extent in ((ready[3],'effects.bin',trace_end),(ready[4],'entries.bin',entry_end)):
            row=fds[fd];info=cf.fdinfo(bytes.fromhex(row['fdinfo_hex']))
            need(cf.identity(row['stat'])==cf.identity(audit_files[name]['stat']) and
                 row['link_hex']==os.fsencode(folder/name).hex(),'audit FD actual file identity')
            need(info['position']==extent and info['inode']==row['stat']['inode'] and row['stat']['size']==extent and
                 info['flags']==0xa8001,'audit FD exact position/flags')
        tree=cf.check_tree(tree_rows)
        for token,node in live.items():
            fd=node['fd'];row=fds[fd];info=cf.fdinfo(bytes.fromhex(row['fdinfo_hex']))
            path=bytes.fromhex(node['path_hex']);selected=resolve_owned(path,work,tree)
            if spec['cleanup_directory_hook'] and node['role']==3 and tree.get(selected,{}).get('kind')=='directory':
                selected=relative_owned(absolute_owned(path,work)+b'.retained',work).hex()
            need(selected in tree and tree[selected]['kind']=='file','live capture descriptor target')
            target=tree[selected];identity=cf.identity(target)
            if token in descriptor_identity:need(descriptor_identity[token]==(fd,identity),'live token changed physical descriptor')
            else:descriptor_identity[token]=(fd,identity)
            need(cf.identity(row['stat'])==identity and row['stat']['size']==0 and info['inode']==target['inode'] and
                 row['link_hex']==(os.fsencode(work)+b'/'+bytes.fromhex(selected)).hex(),'actual live capture FD inode/path')
            need(info['position']==0 and info['flags']==0x88001,'actual capture FD flags/position')
    completed=observed['completed']
    need(type(completed['exit_code']) is int and completed['exit_code']==0 and
         observed['requests'][-1]['observed_ns']<=completed['observed_ns']<=receipt['monotonic_completed_ns'],
         'actual fixture exit observation')

def verify_case(folder,spec,manifest,metadata,executable):
    folder=Path(folder).absolute();plain_dir(folder);work=folder/'work'
    need(read_json(folder/'spec.json')==spec,'registered exact case spec')
    receipt=read_json(folder/'execution.json');observed=read_json(folder/'observation.json')
    need(receipt.get('schema')=='hepta.runtime.shell-capture-prepare-process.v1' and
         receipt.get('argv')==[str(executable),'--capture-prepare-fixture',str(folder)] and receipt.get('cwd')==str(work),
         'actual process recipe')
    need(all(type(receipt.get(k)) is int and receipt[k]>0 for k in
             ('pid','parent_pid','uid','gid','monotonic_started_ns','monotonic_completed_ns','unix_started_ns','unix_completed_ns')),
         'actual process identity/time types')
    need(type(receipt.get('umask')) is int and receipt['umask']==spec['umask'] and
         receipt.get('environment')==environment_record(environment_for(spec,work)),'actual environment/umask')
    need(type(receipt.get('exit_code')) is int and receipt['exit_code']==0 and receipt.get('failure') is None and
         receipt.get('timed_out') is False and type(receipt.get('deadline_seconds')) is int and receipt['deadline_seconds']==30 and
         0<=receipt['monotonic_completed_ns']-receipt['monotonic_started_ns']<=30_000_000_000 and
         receipt['unix_started_ns']<=receipt['unix_completed_ns'],'actual process deadline/result')
    need(receipt.get('executable_before')==receipt.get('executable_after')==pin(ordinary(executable)) and
         receipt.get('native_manifest')=={'path':str(manifest),**pin(ordinary(manifest))},'actual executable/manifest binding')
    need(receipt.get('streams')=={name:pin(ordinary(folder/name)) for name in ('stdin.bin','stdout.bin','stderr.bin')} and
         ordinary(folder/'stderr.bin')==b'','complete actual streams')
    wires=[request_for(spec,work,receipt['pid'],op) for op in (1,2)];n=len(wires[0])-64
    paths=capture_paths(tmpdir_for(spec,work),receipt['pid'],spec['sequence_seed'])
    need(read_json(folder/'input.json')==dict(wires_hex=[w.hex() for w in wires],output_capacity=384+3*n,
        workspace_capacity=1792+4*n,private_sequence_seed=spec['sequence_seed'],paths_hex=[p.hex() for p in paths]),'registered complete input')
    native=verify_trace(folder,spec,wires,receipt,observed)
    before,after=read_json(folder/'before.json'),read_json(folder/'after.json')
    verify_trees(folder,spec,receipt,observed,native,before,after)
    verify_observations(folder,spec,receipt,observed,native);verify_retirement(folder,after)
    need(set(os.listdir(folder))==set(CASE_FILES),'case retained ordinary members')
    return dict(name=spec['name'],status='PASS',requests=[w.hex() for w in wires],
        results=[dict(return_value=ret,body_hex=body.hex()) for ret,body in native['results']],
        operations=native['operations'],calls=native['calls'],gates=native['gates'],publications=native['publications'],
        counts=native['counts'],retired=True,original_prepare_pair_candidate=not spec['native_only_controlled_race'],
        native_only_controlled_race=spec['native_only_controlled_race'])

def source_pins():
    return {name:pin(ordinary(ROOT/name)) for name in SOURCES}

def core_names(names):
    return ['report.json']+['source-snapshots/'+n for n in SOURCES]+[
        'cases/'+name+'/'+file for name in names for file in CASE_FILES]

ordinary_inventory=cf.ordinary_inventory

def read_case(folder,native_manifest):
    manifest,metadata,executable,_=load_native(native_manifest)
    folder=Path(folder).absolute();specs={s['name']:s for s in case_specs()}
    need(folder.name in specs,'unregistered case name');spec=specs[folder.name]
    validation=verify_case(folder,spec,manifest,metadata,executable)
    return dict(validation=validation,spec=spec,requests=[bytes.fromhex(w) for w in validation['requests']],
        results=[(r['return_value'],bytes.fromhex(r['body_hex'])) for r in validation['results']],
        operations=validation['operations'],calls=validation['calls'],gates=validation['gates'],
        before=read_json(folder/'before.json'),after=read_json(folder/'after.json'),
        input=read_json(folder/'input.json'),execution=read_json(folder/'execution.json'))

def _read_corpus(folder,native_manifest,require_controls=True):
    folder=Path(folder).absolute();plain_dir(folder)
    manifest,metadata,executable,build=load_native(native_manifest)
    report=read_json(folder/'report.json');names=[s['name'] for s in case_specs()]
    need(report.get('schema')=='hepta.runtime.shell-capture-prepare-os-report.v1' and report.get('status')=='PASS' and
         report.get('recorded_directory')==str(folder) and report.get('complete_registered_corpus') is True,'complete OS report identity')
    need(report.get('case_names')==names and sorted(os.listdir(folder/'cases'))==sorted(names),'complete registered case inventory')
    need(all(report.get(k) is v for k,v in SCOPE.items()),'qualification scope claims')
    sources=source_pins();need(report.get('sources')==sources,'current source binding')
    need(ordinary_inventory(folder/'source-snapshots')==sorted(SOURCES),'complete source snapshot inventory')
    for name in SOURCES:need(ordinary(folder/'source-snapshots'/name)==ordinary(ROOT/name),'sealed source bytes')
    need(report.get('native_manifest')=={'path':str(manifest),**pin(ordinary(manifest))},'strong manifest identity')
    files=[p for p in core_names(names) if p!='report.json']
    need(report.get('files')=={n:pin(ordinary(folder/n)) for n in files},'complete retained file pins')
    need(not os.listdir(folder/'temporary'),'temporary fixture remains')
    need(set(os.listdir(folder))<={'report.json','readback.json','source-snapshots','cases','temporary','controls'},'unknown corpus member')
    rows=[];counts={}
    for spec in case_specs():
        row=verify_case(folder/'cases'/spec['name'],spec,manifest,metadata,executable);rows.append(row)
        for k,v in row['counts'].items():counts[k]=counts.get(k,0)+v
    counts.update(cases=len(names),retired_fixtures=len(names),original_prepare_pair_candidates=sum(not s['native_only_controlled_race'] for s in case_specs()),
                  native_only_controlled_races=sum(s['native_only_controlled_race'] for s in case_specs()),kernel_errno_injected=0)
    need(report.get('cases')==rows and report.get('counts')==counts and all(type(v) is int for v in report['counts'].values()),
         'reconstructed report results/counts')
    controls=verify_controls(folder,manifest) if require_controls else None
    if require_controls:need(report.get('physical_controls')==controls,'physical controls report binding')
    return dict(schema='hepta.runtime.shell-capture-prepare-os-evidence.v1',status='PASS',recorded_directory=str(folder),
        complete_registered_corpus=True,native_manifest=report['native_manifest'],strong_native_build=build,
        source_files=len(SOURCES),cases=rows,counts=counts,retired_fixtures=len(names),physical_controls=controls,
        verification='current source, exact path, actual ELF, complete parent/child/native syscall and custody replay',**SCOPE)

def read_evidence(folder,native_manifest,*,require_full=True):
    need(require_full is True,'partial corpus is not qualified')
    return _read_corpus(folder,native_manifest,True)

def produce_core(output,native_manifest):
    output=Path(output).absolute();manifest,metadata,executable,_=load_native(native_manifest)
    output.mkdir(parents=True,mode=0o700,exist_ok=False);(output/'cases').mkdir();(output/'temporary').mkdir(mode=0o700)
    sources=source_pins()
    for name in SOURCES:
        path=output/'source-snapshots'/name;path.parent.mkdir(parents=True,exist_ok=True);write_new(path,ordinary(ROOT/name))
    rows=[];counts={}
    for spec in case_specs():
        row=run_case(output/'cases'/spec['name'],spec,manifest,metadata,executable);rows.append(row)
        for k,v in row['counts'].items():counts[k]=counts.get(k,0)+v
        print(json.dumps({'name':spec['name'],'status':'PASS','counts':row['counts']},sort_keys=True),flush=True)
    names=[s['name'] for s in case_specs()]
    counts.update(cases=len(names),retired_fixtures=len(names),original_prepare_pair_candidates=sum(not s['native_only_controlled_race'] for s in case_specs()),
                  native_only_controlled_races=sum(s['native_only_controlled_race'] for s in case_specs()),kernel_errno_injected=0)
    need(source_pins()==sources,'producer source changed during native corpus')
    report=dict(schema='hepta.runtime.shell-capture-prepare-os-report.v1',status='PASS',recorded_directory=str(output),
        complete_registered_corpus=True,native_manifest={'path':str(manifest),**pin(ordinary(manifest))},sources=sources,
        case_names=names,cases=rows,counts=counts,physical_controls=None,
        files={n:pin(ordinary(output/n)) for n in core_names(names) if n!='report.json'},**SCOPE)
    write_new(output/'report.json',packed(report));_read_corpus(output,manifest,False)
    return report

CONTROL_ERRORS={
    'missing_case':'complete registered case inventory',
    'duplicate_case':'complete registered case inventory',
    'input_frame':'complete actual input frames and acknowledgements',
    'parent_order':'complete canonical parent arena',
    'parent_hidden_state':'complete canonical parent arena',
    'mkdir_hidden_state':'complete canonical mkdir persistent arena',
    'sequence_result':'parent effect from actual HIA workspace',
    'child_wire':'complete canonical parent arena',
    'completion_extra_write':'exact native before arrays',
    'child_guard':'native memory guards',
    'kernel_pid':'kernel identity/arguments/order',
    'receiver_lost_fd':'actual owned FD custody inventory',
    'cleanup_error_priority':'published complete capture tuple',
    'fd_flags':'actual capture FD flags/position',
    'retired_payload':'publication and retired complete fixture tree',
    'missing_footer':'missing effect footer or trailing bytes',
    'audit_inode':'audit FD actual file identity',
    'audit_extent':'audit retained bytes/stat',
    'source_snapshot':'sealed source bytes',
}

def mutation(name,baseline):
    """Reconstruct the exact named physical mutation without executing artifacts."""
    need(name in CONTROL_ERRORS,'unregistered physical control');changed={}
    def get(path):return changed.get(path,baseline[path])
    def js(path,value):changed[path]=packed(value)
    report=decoded(baseline['report.json']);folder=Path(report['recorded_directory'])
    case='stderr_readonly_cleanup_directory' if name=='cleanup_error_priority' else ('stderr_readonly_file' if name=='retired_payload' else 'new_capture')
    prefix='cases/'+case+'/'
    def work_start(row):
        h=row['header'];return row['offset']+192+h[22]+32+h[8]+32+16
    def input_start(row):return row['offset']+192+16
    def output_start(row):return row['offset']+192+row['header'][22]+32+16
    def stdout_rows(raw):
        at=64
        while raw[at:at+8]!=b'HSPRAUD1':
            if raw[at:at+8]==b'HSPRGT01':yield 'gate',at,None;at+=96
            else:
                n=q(raw,at+8);yield 'result',at+16,n;at+=16+n
    if name in ('missing_case','duplicate_case'):
        report['case_names']=report['case_names'][:-1] if name=='missing_case' else report['case_names']+[report['case_names'][0]]
    elif name in ('audit_inode','audit_extent'):
        path = 'cases/new_capture/'+('observation.json' if name == 'audit_inode' else 'execution.json')
        value = decoded(get(path))
        if name == 'audit_inode':
            target = os.fsencode(folder/'cases/new_capture/effects.bin').hex()
            row = next(r for r in value['initial']['fds'] if r['link_hex'] == target)
            row['stat']['inode'] += 1
            raw = bytes.fromhex(row['fdinfo_hex'])
            row['fdinfo_hex'] = b''.join(b'ino:\t'+str(row['stat']['inode']).encode()+b'\n' if line.startswith(b'ino:') else line
                                      for line in raw.splitlines(keepends=True)).hex()
        else:
            value['audit_files']['effects.bin']['stat']['size'] += 1
        js(path,value)
    elif name=='input_frame':
        path=prefix+'stdin.bin';raw=bytearray(get(path));raw[96]^=1;changed[path]=bytes(raw)
    elif name in ('parent_order','sequence_result'):
        path=prefix+'effects.bin';raw=bytearray(get(path));rows,_=parse_effects(raw)
        action=2 if name=='parent_order' else 4
        selected=next(r for r in rows if r['kind']=='parent' and r['header'][5]==0 and q(r['slot'],16)==action)
        sequence=selected['header'][2]
        for row in rows:
            if row['kind']=='parent' and row['header'][2]==sequence:
                if name=='parent_order':put(raw,row['offset']+192+16,4)
                elif row['header'][5]==1:put(raw,row['offset']+192+64,(q(row['slot'],64)+1)&MASK)
        changed[path]=bytes(raw);path=prefix+'entries.bin';raw=bytearray(get(path));rows,_=parse_entries(raw)
        for row in rows:
            if row['header'][3]!=0:continue
            at=work_start(row);slot=raw[at+128:at+224]
            if slot[:8]==b'HSHPPFX1' and q(slot,8)==sequence:
                if name=='parent_order':put(raw,at+128+16,4)
                elif q(slot,56)==1:put(raw,at+128+64,(q(slot,64)+1)&MASK)
        changed[path]=bytes(raw)
        if name=='parent_order':
            path=prefix+'stdout.bin';raw=bytearray(get(path))
            for kind,at,_ in stdout_rows(raw):
                if kind=='gate' and q(raw,at+8)==sequence:put(raw,at+16,4)
            changed[path]=bytes(raw);value=decoded(get(prefix+'observation.json'))
            for row in value['gates']:
                if row['words'][1]==sequence:row['words'][2]=4
            js(prefix+'observation.json',value)
    elif name in ('parent_hidden_state','mkdir_hidden_state'):
        path=prefix+'entries.bin';raw=bytearray(get(path));rows,_=parse_entries(raw)
        if name=='parent_hidden_state':selected=[r for r in rows if r['header'][2:5] in ((1,0,1),(2,0,0))]
        else:selected=[r for r in rows if r['header'][3]==2 and (r['header'][23],r['header'][4]) in ((1,1),(2,0))]
        need(len(selected)==2,'hidden parent-state control target')
        for row in selected:
            at=work_start(row)
            if name=='parent_hidden_state':put(raw,at+72,1)
            else:put(raw,at+272,q(raw,at+272)+1)
        changed[path]=bytes(raw)
    elif name in ('child_wire','completion_extra_write','child_guard'):
        path=prefix+'entries.bin';raw=bytearray(get(path));rows,_=parse_entries(raw)
        if name=='child_guard':
            row=next(r for r in rows if r['header'][3]>0);raw[row['offset']+192]^=1
        elif name=='completion_extra_write':
            row=next(r for r in rows if r['header'][3:5]==(0,0) and r['header'][2]>1);raw[work_start(row)+560]^=1
        else:
            for row in rows:
                if row['header'][3]==1:
                    at=input_start(row);put(raw,at+24,q(raw,at+24)+1)
                elif row['header'][3]==0:
                    at=work_start(row);slot=raw[at+128:at+224]
                    if slot[:8]==b'HSHPPFX1' and q(slot,16)==9:put(raw,at+1024+24,q(raw,at+1024+24)+1)
        changed[path]=bytes(raw)
    elif name=='kernel_pid':
        path=prefix+'effects.bin';raw=bytearray(get(path));rows,_=parse_effects(raw)
        selected=next(r for r in rows if r['kind']=='kernel')['header'][2]
        for row in rows:
            if row['kind']=='kernel' and row['header'][2]==selected:put(raw,row['offset']+40,row['header'][5]+1)
        changed[path]=bytes(raw)
    elif name in ('receiver_lost_fd','fd_flags'):
        path=prefix+'observation.json';value=decoded(get(path))
        row=next(r for r in value['gates'] if (r['words'][2]==7 if name=='receiver_lost_fd' else r['words'][2]==6 and r['words'][6]==1))
        target=decoded(baseline[prefix+'input.json'])['paths_hex'][2]
        for field in ('process','process_after_mutation'):
            snap=row[field];fd=next(r for r in snap['fds'] if r['link_hex']==target)
            if name=='receiver_lost_fd':snap['fds']=[r for r in snap['fds'] if r['fd']!=fd['fd']]
            else:
                raw=bytes.fromhex(fd['fdinfo_hex']);flags=cf.fdinfo(raw)['flags']|0x4000
                raw=b''.join(b'flags:\t'+format(flags,'o').encode()+b'\n' if line.startswith(b'flags:') else line
                             for line in raw.splitlines(keepends=True));fd['fdinfo_hex']=raw.hex()
        js(path,value)
    elif name=='cleanup_error_priority':
        path=prefix+'entries.bin';raw=bytearray(get(path));rows,_=parse_entries(raw)
        for row in rows:
            if row['header'][3:5]==(0,1) and row['header'][10]==128:put(raw,output_start(row)+40,21)
        changed[path]=bytes(raw);path=prefix+'stdout.bin';raw=bytearray(get(path))
        for kind,at,_ in stdout_rows(raw):
            if kind=='result':put(raw,at+40,21)
        changed[path]=bytes(raw);path=prefix+'observation.json';value=decoded(get(path))
        for row in value['requests']:
            body=bytearray.fromhex(row['body_hex']);put(body,40,21);row['body_hex']=body.hex()
        js(path,value)
    elif name=='retired_payload':
        path=prefix+'after.json';value=decoded(get(path));row=next(r for r in value if r['kind']=='file')
        raw=bytearray.fromhex(row['payload_hex']);raw[0]^=1;row['payload_hex']=raw.hex();js(path,value)
        path=prefix+'observation.json';observation=decoded(get(path))
        for row in observation['requests']:row['tree']=value
        js(path,observation);path=prefix+'retirement.json';retired=decoded(get(path));retired['final_snapshot']=pin(packed(value));js(path,retired)
    elif name=='missing_footer':
        path=prefix+'effects.bin';changed[path]=get(path)[:-256]
    else:
        path='source-snapshots/native/shell_capture_prepare.hepta';raw=bytearray(get(path));raw[0]^=1;changed[path]=bytes(raw)
    for case in {p.split('/')[1] for p in changed if p.startswith('cases/')}:
        prefix='cases/'+case+'/';path=prefix+'execution.json';receipt=decoded(get(path));touched=False
        for stream in ('stdin.bin','stdout.bin','stderr.bin'):
            target=prefix+stream
            if target in changed:receipt['streams'][stream]=pin(changed[target]);touched=True
        for audit in ('effects.bin','entries.bin'):
            target = 'cases/'+case+'/'+audit
            if target in changed:
                receipt['audit_files'][audit].update(pin(changed[target])); touched = True
        if touched:js(path,receipt)
        if prefix+'effects.bin' in changed or prefix+'entries.bin' in changed:
            path=prefix+'observation.json';value=decoded(get(path))
            for row in value['gates']:
                for field,filename in (('effects','effects.bin'),('entries','entries.bin')):
                    row[field]=pin(get(prefix+filename)[:row[field]['bytes']])
            js(path,value)
    for path,raw in changed.items():report['files'][path]=pin(raw)
    changed['report.json']=packed(report)
    return {k:v for k,v in sorted(changed.items()) if v!=baseline[k]}


# Retained-byte/process audit mechanics shared with the frozen capture-file suite.
replace_ordinary=cf.replace_ordinary

def reader_process(folder, corpus, manifest, inputs):
    folder.mkdir(); interpreter = Path(sys.executable).resolve()
    argv = [str(interpreter), str(ROOT/'tests/hia_native/shell_capture_prepare_io.py'),
            '--native-manifest', str(manifest), '--verify-core', str(corpus)]
    env = {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'PYTHONDONTWRITEBYTECODE':'1'}
    physical_before = cf.control_identities(corpus, inputs)
    before = {name:pin(ordinary(corpus/name)) for name in inputs}
    need(before == {name:pin(raw) for name,raw in inputs.items()}, 'physical reader inputs before')
    tool = pin(ordinary(interpreter)); source = pin(ordinary(ROOT/'tests/hia_native/shell_capture_prepare_io.py'))
    start, unix_start = time.monotonic_ns(), time.time_ns()
    p = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        stdout, stderr = p.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        timed_out = True; p.kill(); stdout, stderr = p.communicate()
    finish = time.monotonic_ns()
    write_new(folder/'stdout.bin', stdout); write_new(folder/'stderr.bin', stderr)
    after = {name:pin(ordinary(corpus/name)) for name in inputs}
    receipt = dict(schema='hepta.runtime.shell-capture-prepare-reader-process.v1', argv=argv, cwd=str(ROOT),
                   environment=env, pid=p.pid, deadline_seconds=30, timed_out=timed_out, exit_code=p.returncode,
                   monotonic_started_ns=start, monotonic_completed_ns=finish,
                   unix_started_ns=unix_start, unix_completed_ns=time.time_ns(),
                   interpreter_before=tool, interpreter_after=pin(ordinary(interpreter)), source=source,
                   physical_inputs_before=physical_before, physical_inputs_after=cf.control_identities(corpus, inputs),
                   inputs_before=before, inputs_after=after, stdout=pin(stdout), stderr=pin(stderr))
    write_new(folder/'execution.json', packed(receipt))
    need(before == after and receipt['physical_inputs_before'] == receipt['physical_inputs_after'] and
         receipt['interpreter_before'] == receipt['interpreter_after'] and not timed_out, 'reader process modified inputs')
    return receipt, decoded(stdout)

def verify_reader_process(folder, corpus, manifest, inputs, physical_identities, expected_error=None):
    receipt = read_json(folder/'execution.json'); interpreter = Path(sys.executable).resolve()
    argv = [str(interpreter), str(ROOT/'tests/hia_native/shell_capture_prepare_io.py'),
            '--native-manifest', str(manifest), '--verify-core', str(corpus)]
    need(receipt.get('schema') == 'hepta.runtime.shell-capture-prepare-reader-process.v1' and
         receipt.get('argv') == argv and receipt.get('cwd') == str(ROOT) and receipt.get('environment') ==
         {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}, 'actual reader process recipe')
    need(type(receipt.get('pid')) is int and receipt['pid'] > 0 and type(receipt.get('deadline_seconds')) is int and
         receipt['deadline_seconds'] == 30 and receipt.get('timed_out') is False and
         all(type(receipt.get(k)) is int and receipt[k] > 0 for k in
             ('monotonic_started_ns','monotonic_completed_ns','unix_started_ns','unix_completed_ns')) and
         0 <= receipt['monotonic_completed_ns']-receipt['monotonic_started_ns'] <= 30_000_000_000, 'actual reader process time')
    need(receipt.get('interpreter_before') == receipt.get('interpreter_after') == pin(ordinary(interpreter)) and
         receipt.get('source') == pin(ordinary(ROOT/'tests/hia_native/shell_capture_prepare_io.py')), 'actual reader executable/source')
    cf.check_control_identities(physical_identities, inputs)
    need(receipt.get('physical_inputs_before') == receipt.get('physical_inputs_after') == physical_identities, 'reader producer physical identities')
    expected = {n:pin(raw) for n,raw in inputs.items()}
    need(receipt.get('inputs_before') == receipt.get('inputs_after') == expected, 'complete reader process input identities')
    stdout, stderr = ordinary(folder/'stdout.bin'), ordinary(folder/'stderr.bin')
    need(receipt.get('stdout') == pin(stdout) and receipt.get('stderr') == pin(stderr) and stderr == b'', 'complete reader process streams')
    need(type(receipt.get('exit_code')) is int and receipt['exit_code'] == (2 if expected_error else 0), 'actual reader process exit')
    value = decoded(stdout)
    if expected_error:
        need(value == {'status':'REJECTED','error_type':'ValueError','error':expected_error}, 'exact named refusal reason')
    else:
        need(value == _read_corpus(corpus, manifest, False), 'restored positive full reader result')

def run_controls(corpus, manifest):
    root = corpus/'controls'; root.mkdir(); names = [s['name'] for s in case_specs()]
    baseline = {name:ordinary(corpus/name) for name in core_names(names)}
    baseline_identities = cf.control_identities(corpus, baseline)
    write_new(root/'baseline-report.json', baseline['report.json']); rows = []
    for name, expected_error in CONTROL_ERRORS.items():
        folder = root/name; changes = mutation(name, baseline); modified = []
        try:
            identities = {}
            for path, raw in changes.items():
                modified.append(path); identities[path] = replace_ordinary(corpus/path, raw)
                need(identities[path] == baseline_identities[path], 'mutation original producer identity')
            inputs = dict(baseline); inputs.update(changes)
            receipt, value = reader_process(folder, corpus, manifest, inputs)
            change_rows = []
            for index, (path, after) in enumerate(changes.items()):
                prefix = f'{index:03d}'
                write_new(folder/(prefix+'.before.bin'), baseline[path]); write_new(folder/(prefix+'.after.bin'), after)
                change_rows.append(dict(path=path, before=pin(baseline[path]), after=pin(after),
                                        physical_identity=identities[path], prefix=prefix))
            write_new(folder/'changes.json', packed(change_rows))
            need(receipt['exit_code'] == 2 and value == {'status':'REJECTED','error_type':'ValueError','error':expected_error}, 'named physical control did not reach expected gate: '+name)
            rows.append(dict(name=name, changes=pin(ordinary(folder/'changes.json')),
                             process={n:pin(ordinary(folder/n)) for n in ('execution.json','stdout.bin','stderr.bin')}))
        finally:
            for path in modified:
                need(replace_ordinary(corpus/path, baseline[path]) == baseline_identities[path], 'restored original producer identity')
    inputs = {name:ordinary(corpus/name) for name in baseline}
    need(inputs == baseline, 'baseline bytes not fully restored')
    reader_process(root/'restored-positive', corpus, manifest, baseline)
    verify_reader_process(root/'restored-positive', corpus, manifest, baseline, baseline_identities)
    report = dict(schema='hepta.runtime.shell-capture-prepare-physical-controls.v1', status='PASS',
                  recorded_directory=str(root), names=list(CONTROL_ERRORS), controls=rows,
                  baseline_identities=baseline_identities,
                  baseline_inputs={n:pin(raw) for n,raw in baseline.items()},
                  restored_positive={n:pin(ordinary(root/'restored-positive'/n)) for n in ('execution.json','stdout.bin','stderr.bin')})
    write_new(root/'report.json', packed(report))
    return verify_controls(corpus, manifest)

def verify_controls(corpus, manifest):
    root = corpus/'controls'; plain_dir(root)
    report = read_json(root/'report.json')
    need(report.get('schema') == 'hepta.runtime.shell-capture-prepare-physical-controls.v1' and
         report.get('status') == 'PASS' and report.get('recorded_directory') == str(root) and
         report.get('names') == list(CONTROL_ERRORS), 'complete physical control report')
    need(set(os.listdir(root)) == {'report.json','baseline-report.json','restored-positive'} | set(CONTROL_ERRORS), 'physical control inventory')
    names = [s['name'] for s in case_specs()]
    baseline = {name:ordinary(corpus/name) for name in core_names(names)}
    current = decoded(baseline['report.json']); current['physical_controls'] = None
    baseline['report.json'] = ordinary(root/'baseline-report.json')
    need(decoded(baseline['report.json']) == current, 'exact restored baseline report')
    need(report.get('baseline_inputs') == {n:pin(raw) for n,raw in baseline.items()}, 'complete baseline byte identities')
    baseline_identities = report.get('baseline_identities')
    cf.check_control_identities(baseline_identities, baseline)
    rows = report['controls']
    need([r.get('name') for r in rows] == list(CONTROL_ERRORS), 'named control coverage')
    for row in rows:
        name = row['name']; folder = root/name; plain_dir(folder)
        expected = mutation(name, baseline); changes = read_json(folder/'changes.json')
        need([r.get('path') for r in changes] == list(expected), 'exact named mutation file recipe')
        members = {'changes.json','execution.json','stdout.bin','stderr.bin'}
        for index, change in enumerate(changes):
            path = change['path']; prefix = f'{index:03d}'
            need(set(change) == {'path','before','after','physical_identity','prefix'} and change['prefix'] == prefix, 'mutation record fields')
            before, after = ordinary(folder/(prefix+'.before.bin')), ordinary(folder/(prefix+'.after.bin'))
            need(before == baseline[path] and after == expected[path] and before != after, 'exact named physical mutation bytes')
            need(change['before'] == pin(before) and change['after'] == pin(after), 'physical changed byte pins')
            need(change['physical_identity'] == baseline_identities[path], 'physical mutation preserved original identity')
            members |= {prefix+'.before.bin',prefix+'.after.bin'}
        need(set(os.listdir(folder)) == members, 'complete physical change evidence')
        inputs = dict(baseline); inputs.update(expected)
        verify_reader_process(folder, corpus, manifest, inputs, baseline_identities, CONTROL_ERRORS[name])
        need(row.get('changes') == pin(ordinary(folder/'changes.json')) and row.get('process') ==
             {n:pin(ordinary(folder/n)) for n in ('execution.json','stdout.bin','stderr.bin')}, 'actual control process pins')
    positive = root/'restored-positive'; plain_dir(positive)
    need(set(os.listdir(positive)) == {'execution.json','stdout.bin','stderr.bin'}, 'restored positive members')
    verify_reader_process(positive, corpus, manifest, baseline, baseline_identities)
    need(report.get('restored_positive') == {n:pin(ordinary(positive/n)) for n in ('execution.json','stdout.bin','stderr.bin')}, 'restored positive pins')
    return dict(status='PASS', physical_negative_controls=len(CONTROL_ERRORS), reader_processes=len(CONTROL_ERRORS)+1,
                exact_named_mutations_reconstructed=True, all_baseline_bytes_restored=True,
                report_sha256=sha(ordinary(root/'report.json')))

def run(output, native_manifest):
    output = Path(output).absolute(); manifest = Path(native_manifest).absolute()
    report = produce_core(output, manifest)
    report['physical_controls'] = run_controls(output, manifest)
    replace_ordinary(output/'report.json', packed(report))
    result = read_evidence(output, manifest)
    write_new(output/'readback.json', packed(result))
    return result

def audit_read_only(folder, native_manifest):
    load_native(native_manifest)
    import ctypes
    enabled, probes = True, False
    forbidden, seen = [], [0]
    def hook(event, args):
        if not enabled:
            return
        seen[0] += 1
        bad = event.startswith(('subprocess.','socket.','ctypes.')) or event in {
            'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill',
            'os.mkdir','os.remove','os.rmdir','os.rename','os.link','os.symlink',
            'os.chmod','os.chown','os.truncate','os.utime','os.setxattr','os.removexattr'}
        if event == 'open':
            path, mode, flags = args
            bad = bool(type(mode) is str and any(x in mode for x in 'wax+')) or bool(type(flags) is int and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            if isinstance(path, (str,bytes,os.PathLike)):
                bad |= os.fsencode(path).startswith(b'/proc/')
        if bad:
            forbidden.append({'event':event,'probe':probes})
            raise PermissionError('read-only audit blocked '+event)
    sys.addaudithook(hook)
    try:
        result = read_evidence(folder, native_manifest)
        need(not forbidden, 'reader attempted forbidden action'); probes = True
        for action in (lambda:subprocess.run(['/bin/true']), lambda:open(Path(folder)/'forbidden-write','wb'),
                       lambda:open('/proc/self/stat','rb'), lambda:ctypes.CDLL(None)):
            try:
                action()
            except PermissionError:
                pass
            else:
                raise ValueError('audit probe not refused')
        need(len(forbidden) == 4 and all(x['probe'] for x in forbidden), 'audit mechanism probes')
    finally:
        enabled = False
    return dict(schema='hepta.runtime.shell-capture-prepare-read-audit.v1', status='PASS',
                reader_status=result['status'], observed_events=seen[0], reader_forbidden_actions=0,
                blocked_negative_probes=4, imports_preloaded=True,
                report_sha256=sha(ordinary(Path(folder)/'report.json')), **SCOPE)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-manifest', type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--output', type=Path)
    modes.add_argument('--verify', type=Path)
    modes.add_argument('--verify-core', type=Path, help=argparse.SUPPRESS)
    modes.add_argument('--verify-case', type=Path)
    modes.add_argument('--audit-read-only', type=Path)
    args = parser.parse_args()
    try:
        if args.output:
            result = run(args.output, args.native_manifest)
        elif args.verify_core:
            result = _read_corpus(args.verify_core, args.native_manifest, False)
        elif args.verify_case:
            result = read_case(args.verify_case, args.native_manifest)['validation']
        elif args.audit_read_only:
            result = audit_read_only(args.audit_read_only, args.native_manifest)
        else:
            result = read_evidence(args.verify, args.native_manifest)
    except Exception as error:
        print(json.dumps({'status':'REJECTED','error_type':type(error).__name__,'error':str(error)},sort_keys=True), flush=True)
        raise SystemExit(2)
    print(json.dumps(result,sort_keys=True), flush=True)

if __name__=='__main__':
    main()
