"""Owned-child ptrace controls at the fixed publisher's real Linux boundary.

Only this process's freshly spawned, manifest-admitted ELF is traced. Short
transfers reduce an actual kernel count. Synthetic errors/zero returns are
explicitly recorded as skipped syscalls; close EINTR is delivered only after
the kernel really consumed the FD. No expected HIA response is substituted.
"""
from pathlib import Path
import argparse,ctypes,errno,gzip,hashlib,json,os,select,signal,struct,subprocess,sys,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_text_publication_elf import frame,envelope,parse,effects
MASK=(1<<64)-1
def sha(raw):return hashlib.sha256(raw).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def signed(value):return value-(1<<64) if value>>63 else value
REG_NAMES='r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()
class Registers(ctypes.Structure):_fields_=[(name,ctypes.c_uint64) for name in REG_NAMES]
LIBC=ctypes.CDLL(None,use_errno=True);LIBC.ptrace.argtypes=[ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_void_p];LIBC.ptrace.restype=ctypes.c_long
def ptrace(request,pid,data=None):
    ctypes.set_errno(0);value=LIBC.ptrace(request,pid,None,data)
    if value==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
    return value
def traceme():ptrace(0,0)
def registers(pid):
    row=Registers();ptrace(12,pid,ctypes.byref(row));return row
def fields(row):return {name:getattr(row,name) for name in REG_NAMES}
def mem(pid,address,size):
    fd=os.open('/proc/'+str(pid)+'/mem',os.O_RDONLY|os.O_CLOEXEC)
    try:
        raw=os.pread(fd,size,address)
        if len(raw)!=size:raise ValueError('short owned-child memory snapshot')
        return raw
    finally:os.close(fd)
def snapshot(pid,pointer,folder,name,wire=b''):
    engine=mem(pid,pointer,4096);u=lambda at:struct.unpack_from('<Q',engine,at)[0]
    assert engine[:8]==b'HTXTEN02' and 4096<=u(40)<=(1<<31)
    assert u(80)<=u(72) and u(120)<=u(56)
    parts=(engine,mem(pid,u(32),u(40)),mem(pid,u(64),u(80)),mem(pid,u(48),u(56)),wire)
    raw=b'HTXTFSP1'+struct.pack('<5Q',*map(len,parts))+b''.join(parts)
    with (folder/(name+'.bin.gz')).open('xb') as file:
        with gzip.GzipFile(filename='',fileobj=file,mode='wb',mtime=0,compresslevel=1) as stream:stream.write(raw)
    work=parts[1];w=lambda at:struct.unpack_from('<Q',work,at)[0]
    info={'raw_bytes':len(raw),'raw_sha256':sha(raw),'spans':[{'bytes':len(x),'sha256':sha(x)} for x in parts],
          'phase':w(0),'error_code':w(176),'error_errno':w(184),'owned':w(192),'published':w(224),
          'generation':w(64),'sequence':w(56),'engine_owned':u(136),'last_code':u(112),'payload_len':u(120),
          'fd_slots':list(struct.unpack_from('<8q',engine,160)),
          'proc_descriptors':{item.name:os.readlink(item) for item in sorted(Path('/proc',str(pid),'fd').iterdir())}}
    dump(folder/(name+'.json'),info);return info

def match(rule,nr,row,tags,published):
    kind=tags.get(row.rdi)
    tests={'read':nr==0 and kind=='source','write':nr==1 and kind=='stage','entropy':nr==318,
      'chmod':nr==91 and kind=='stage','stage-fsync':nr==74 and kind=='stage',
      'parent-fsync':nr==74 and kind=='directory' and published,'rename':nr==316,
      'final-stat':nr==262 and published,'source-stat':nr==5 and kind=='source',
      'stage-stat':nr==5 and kind=='stage','stage-open':nr==257 and row.rdx==655553,
      'source-close':nr==3 and kind=='source','stage-close':nr==3 and kind=='stage',
      'unlink':nr==263}
    return tests[rule['target']]

def execute(elf,folder,wire,rules):
    command=[str(elf),'--trace'];began=time.monotonic_ns();process=None;pid=None;error=None;timed=False;terminal=None
    outbound=envelope(wire);sent=0;stdout=bytearray();stderr=bytearray();events=[];injections=[];tags={};published=False
    pending=None;entry=True;first_snapshot=None;final_snapshot=None;readers={};writer=None;opened=closed=0
    rules=[dict(rule,used=False) for rule in rules]
    try:
        process=subprocess.Popen(command,cwd=folder,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 preexec_fn=traceme,start_new_session=True)
        pid=process.pid;_,status=os.waitpid(pid,0)
        assert os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGTRAP
        ptrace(0x4200,pid,ctypes.c_void_p(1|0x100000))
        writer=process.stdin.fileno();os.set_blocking(writer,False)
        readers={process.stdout.fileno():stdout,process.stderr.fileno():stderr}
        for fd in readers:os.set_blocking(fd,False)
        ptrace(24,pid)
        while terminal is None or readers:
            if time.monotonic_ns()-began>60_000_000_000:timed=True;raise TimeoutError('actual 60 second exchange deadline')
            ready_read,ready_write,_=select.select(list(readers),[writer] if writer is not None else [],[],0.001)
            for fd in ready_read:
                raw=os.read(fd,65536)
                if raw:readers[fd].extend(raw)
                else:readers.pop(fd)
            if ready_write:
                count=os.write(writer,outbound[sent:]);assert count>0;sent+=count
                if sent==len(outbound):process.stdin.close();writer=None
            if terminal is not None:continue
            waited,status=os.waitpid(pid,os.WNOHANG)
            if waited==0:continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                terminal=os.waitstatus_to_exitcode(status);process.returncode=terminal
                if pending is not None:
                    pending['terminal_without_return']=terminal;events.append(pending);pending=None
                continue
            assert os.WIFSTOPPED(status) and os.WSTOPSIG(status)==(signal.SIGTRAP|0x80),status
            row=registers(pid)
            if entry:
                nr=row.orig_rax;before=fields(row);rule=next((r for r in rules if not r['used'] and match(r,nr,row,tags,published)),None)
                pending={'index':len(events)+1,'syscall':nr,'entry':before,'fd_kind':tags.get(row.rdi),
                         'entry_monotonic_ns':time.monotonic_ns(),'rule':None}
                if nr==2 and row.rsi==720896 and first_snapshot is None:
                    first_snapshot=snapshot(pid,row.r15,folder,'first-effect')
                if nr==1 and row.rdi==1 and row.rdx==72:
                    header=mem(pid,row.rsi,72)
                    assert header[8:16]==b'HTXTER01' and final_snapshot is None
                    final_snapshot=snapshot(pid,row.r15,folder,'before-output',header)
                    assert not tags,'owned descriptors remain before result delivery'
                if rule is not None:
                    rule['used']=True;pending['rule']={k:v for k,v in rule.items() if k!='used'}
                    if rule['action']=='short':
                        if nr==318:row.rsi=rule['value']
                        else:row.rdx=rule['value']
                    elif rule['action']=='skip':row.orig_rax=MASK
                    elif rule['action']!='after':raise AssertionError('unknown mechanical action')
                    ptrace(13,pid,ctypes.byref(row));pending['submitted_entry']=fields(row)
            else:
                assert pending is not None
                nr=pending['syscall'];args=pending['entry'];kernel=signed(row.rax);delivered=kernel
                pending['kernel_exit']=fields(row);pending['kernel_result']=kernel
                rule=pending['rule']
                if rule and rule['action'] in ('skip','after'):
                    if rule['action']=='skip':assert kernel==-errno.ENOSYS
                    if rule['action']=='after':assert nr==3 and kernel==0
                    row.rax=rule['value']&MASK;ptrace(13,pid,ctypes.byref(row));delivered=rule['value']
                if kernel>=0 and not (rule and rule['action']=='skip'):
                    if nr==2 and args['rsi']==720896:tags[kernel]='directory';opened+=1
                    if nr==257:
                        kind={720896:'directory',657408:'source',655553:'stage'}.get(args['rdx'])
                        assert kind is not None;tags[kernel]=kind;opened+=1
                    if nr==3 and args['rdi'] in tags:tags.pop(args['rdi']);closed+=1
                    if nr==316:published=True
                pending['delivered_exit']=fields(row);pending['delivered_result']=delivered
                pending['exit_monotonic_ns']=time.monotonic_ns();events.append(pending)
                if rule:injections.append(pending['index'])
                pending=None
            entry=not entry;ptrace(24,pid)
        assert terminal==0 and sent==len(outbound)
        assert all(rule['used'] for rule in rules),rules
        assert first_snapshot is not None and final_snapshot is not None and not tags and opened==closed
    except BaseException:
        error=traceback.format_exc()
        if process is not None and terminal is None:
            try:os.killpg(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            while True:
                try:_,status=os.waitpid(pid,0)
                except ChildProcessError:break
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):terminal=os.waitstatus_to_exitcode(status);process.returncode=terminal;break
                ptrace(24,pid,ctypes.c_void_p(signal.SIGKILL))
        for fd,target in list(readers.items()):
            while True:
                try:raw=os.read(fd,65536)
                except BlockingIOError:break
                if not raw:break
                target.extend(raw)
    finally:
        finished=time.monotonic_ns()
        if process is not None:
            for file in (process.stdin,process.stdout,process.stderr):
                if file is not None and not file.closed:file.close()
        for name,raw in [('stdin.bin',outbound[:sent]),('stdout.bin',stdout),('stderr.bin',stderr)]: (folder/name).write_bytes(raw)
        dump(folder/'syscalls.json',events)
        record={'command':command,'cwd':str(folder),'pid':pid,'started_monotonic_ns':began,'finished_monotonic_ns':finished,
          'elapsed_seconds':(finished-began)/1e9,'timeout_seconds':60,'timed_out':timed,'start_error':None if pid else error,
          'exit_code':terminal,'error':error,'input_bytes_intended':len(outbound),'input_bytes_sent':sent,
          'streams':{name:{'bytes':len(raw),'sha256':sha(raw)} for name,raw in [('stdin',outbound[:sent]),('stdout',stdout),('stderr',stderr)]},
          'executable_sha256':sha(elf.read_bytes()),'syscalls':len(events),'injection_indices':injections,
          'opened_descriptors':opened,'closed_descriptors':closed,'original_reference_executed':False}
        dump(folder/'process.json',record)
    if error:raise AssertionError(error)
    return parse(stdout),effects(stderr),final_snapshot,record

def case_list():
    cases=[{'name':'create','mode':1,'rules':[],'error':0,'published':1},
           {'name':'replace','mode':2,'rules':[],'error':0,'published':1},
           {'name':'append','mode':3,'rules':[],'error':0,'published':1}]
    def add(name,target,action,value,error=0,published=1):
        cases.append({'name':name,'mode':2,'rules':[{'target':target,'action':action,'value':value}],
                      'error':error,'published':published})
    add('read-eintr','read','skip',-4)
    add('read-partial','read','short',17)
    add('read-zero','read','skip',0,18,0)
    add('read-eio','read','skip',-5,14,0)
    add('write-eintr','write','skip',-4)
    add('write-partial','write','short',13)
    add('write-zero','write','skip',0,21,0)
    add('write-eio','write','skip',-5,21,0)
    add('entropy-short','entropy','short',8,10,0)
    add('entropy-zero','entropy','skip',0,10,0)
    add('entropy-eio','entropy','skip',-5,10,0)
    add('entropy-eintr','entropy','skip',-4,10,0)
    add('chmod-eperm','chmod','skip',-1,20,0)
    add('stage-fsync-eio','stage-fsync','skip',-5,22,0)
    add('rename-eacces','rename','skip',-13,24,0)
    add('parent-fsync-eio','parent-fsync','skip',-5,25,1)
    add('final-stat-eio','final-stat','skip',-5,255,1)
    add('source-stat-eio','source-stat','skip',-5,255,0)
    add('stage-stat-eio','stage-stat','skip',-5,255,0)
    add('stage-open-eacces','stage-open','skip',-13,255,0)
    add('source-close-eintr','source-close','after',-4)
    add('stage-close-eintr','stage-close','after',-4)
    cases.append({'name':'write-and-cleanup-error','mode':2,'error':21,'published':0,
      'rules':[{'target':'write','action':'skip','value':-5},{'target':'unlink','action':'skip','value':-13}]})
    return cases

def metadata(path):
    info=path.lstat()
    return {name:getattr(info,name) for name in ['st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_atime_ns','st_mtime_ns','st_ctime_ns']}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--only',choices=[case['name'] for case in case_list()])
    args=parser.parse_args();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads(args.manifest.read_bytes());elf=args.manifest.parent/manifest['elf'];assert sha(elf.read_bytes())==manifest['elf_sha256']
    inputs=case_list()
    if args.only:inputs=[case for case in inputs if case['name']==args.only]
    dump(output/'cases.json',inputs);rows=[];error=None
    old=b'old\n'*257;new=b'new\n'*129
    try:
        for case in inputs:
            folder=output/case['name'];folder.mkdir();files=folder/'files';files.mkdir();target=files/'file'
            if case['mode']!=1:target.write_bytes(old);target.chmod(0o600)
            before=metadata(target) if target.exists() else None
            wire=frame(case['mode'],os.fsencode(target),new,b'absent' if case['mode']==1 else hashlib.sha256(old).hexdigest().encode())
            replies,observations,state,process=execute(elf,folder,wire,case['rules'])
            assert len(replies)==1 and replies[0]['phase']==100
            reply=replies[0];body=reply['body'];assert body[:8]==b'HTXTR001' and reply['code']==len(body)
            tag=struct.unpack_from('<Q',body,8)[0]
            assert tag==int(case['error']!=0) and state['error_code']==case['error']
            assert state['published']==case['published'] and state['owned']==state['engine_owned']==0
            assert state['fd_slots']==[-1,0]*4
            assert set(state['proc_descriptors'])=={'0','1','2'}
            expected=old+new if case['mode']==3 else new
            actual=target.read_bytes();wanted=expected if case['published'] else old
            assert actual==wanted
            after=metadata(target)
            if before is not None:
                if case['published']:assert after['st_ino']!=before['st_ino']
                else:assert all(after[key]==before[key] for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))
            if not case['error']:assert len(body)==160 and body[120:152]==hashlib.sha256(expected).digest()
            leftovers=sorted(item.name for item in files.iterdir() if item.name!='file')
            assert len(leftovers)==(1 if case['name']=='write-and-cleanup-error' else 0)
            tree=[]
            for index,item in enumerate(sorted(files.iterdir())):
                content=item.read_bytes();(folder/('tree-'+str(index)+'.bin')).write_bytes(content)
                tree.append({'name_hex':os.fsencode(item.name).hex(),'metadata':metadata(item),
                  'content_bytes':len(content),'content_sha256':sha(content),'content':'tree-'+str(index)+'.bin'})
            dump(folder/'tree.json',tree)
            (folder/'before.bin').write_bytes(old if before is not None else b'');(folder/'after.bin').write_bytes(actual)
            row={'name':case['name'],'before':before,'after':after,'error_code':state['error_code'],
              'published':state['published'],'reply_bytes':len(body),'reply_sha256':sha(body),'effect_count':len(observations),
              'injected_calls':len(process['injection_indices']),'leftover_names':leftovers,
              'opened_descriptors':process['opened_descriptors'],'closed_descriptors':process['closed_descriptors']}
            rows.append(row);dump(output/'completed.json',rows)
    except BaseException:error=traceback.format_exc()
    result={'status':'PASS' if error is None else 'FAIL','error':error,'cases':len(rows),'intended_cases':len(inputs),
      'actual_elf_processes':len(rows),'effects':sum(row['effect_count'] for row in rows),
      'injected_calls':sum(row['injected_calls'] for row in rows),'cases_completed':rows,
      'manifest_sha256':sha(args.manifest.read_bytes()),'elf_sha256':manifest['elf_sha256'],
      'source_sha256':sha(Path(__file__).read_bytes()),'original_reference_executed':False,'original_cases_added':0,
      'unmodified_kernel_cases':3 if args.only is None else int(not inputs[0]['rules'])}
    dump(output/'RESULT.json',result);print(json.dumps(result),flush=True)
    if error:raise SystemExit(1)
if __name__=='__main__':main()
