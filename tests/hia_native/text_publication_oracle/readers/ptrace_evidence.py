"""Independent full syscall-pair, descriptor and memory-blob admission."""
from pathlib import Path
import struct
from common import require,pin,loads,same,integer
REGS=('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')
NAMES={0:'read',1:'write',2:'open',3:'close',5:'fstat',8:'lseek',9:'mmap',10:'mprotect',11:'munmap',12:'brk',
13:'rt_sigaction',14:'rt_sigprocmask',16:'ioctl',21:'access',59:'execve',60:'exit',63:'uname',72:'fcntl',
73:'flock',74:'fsync',75:'fdatasync',89:'readlink',91:'fchmod',102:'getuid',104:'getgid',107:'geteuid',108:'getegid',
121:'getpgid',158:'arch_prctl',196:'flistxattr',202:'futex',218:'set_tid_address',231:'exit_group',
257:'openat',262:'newfstatat',263:'unlinkat',264:'renameat',273:'set_robust_list',302:'prlimit64',316:'renameat2',318:'getrandom',332:'statx',334:'rseq'}
def blob(files,folder,p):
    require(set(p)=={'bytes','sha256','file'} and p['file']==p['sha256']+'.bin','whole content addressed memory blob')
    return files.raw(Path(folder)/'blobs'/p['file'],{k:p[k] for k in ('bytes','sha256')})
def stat(p):
    require(set(p)=={'version','mode','uid','gid','nlink','raw_hex'},'complete observed stat fields')
    raw=bytes.fromhex(p['raw_hex']);require(raw.hex()==p['raw_hex'] and len(raw)==144,'entire actual Linux stat memory')
    dev,ino,nlink=struct.unpack_from('<3Q',raw);mode,uid,gid=struct.unpack_from('<3I',raw,24)
    size=struct.unpack_from('<q',raw,48)[0];mt,mtn,ct,ctn=struct.unpack_from('<4q',raw,88)
    same(p,{'version':[dev,ino,size,mt,mtn,ct,ctn],'mode':mode,'uid':uid,'gid':gid,'nlink':nlink,'raw_hex':raw.hex()},'full actual stat byte projection')
    require(0<=mtn<10**9 and 0<=ctn<10**9,'actual stat nanoseconds')
def evidence(files,folder,process,ids):
    folder=Path(folder);raw=files.raw(folder/'syscalls.jsonl',process['syscalls'])
    require(raw.endswith(b'\n'),'complete trace lines')
    rows=[loads(x) for x in raw[:-1].split(b'\n')]
    require(len(rows)==process['trace_events'],'all trace records accounted')
    active=None;cases={};seen=[];live={};pending=None;opens=0;closes=0;entries=0;last_time=process['started_monotonic_ns']
    stdin=bytearray();stdout=bytearray();stderr=bytearray();byevent={}
    for i,row in enumerate(rows,1):
        require(type(row['event']) is int and row['event']==i and type(row['pid']) is int and row['pid']==process['pid'],'actual trace event identity')
        current=integer(row['monotonic_ns'],'actual event time',last_time+1);last_time=current
        require(current<process['finished_monotonic_ns'],'actual trace within process interval')
        kind=row['kind'];byevent[i]=row
        if kind=='initial-exec-stop':
            require(i==1 and set(row)=={'event','pid','monotonic_ns','kind','wait_status','registers'},'exact initial exec stop')
            require(row['wait_status']==1407,'actual Linux SIGTRAP exec stop')
        elif kind=='exit':
            require(i==len(rows) and active is None and not live and row['exit_code']==0 and row['wait_status']==0,'actual complete child exit')
            require(pending is not None and pending['number']==231 and row['pending_entry']==pending['event'],'only final exit_group has no syscall return')
            pending=None;continue
        else:
            require(kind in ('entry','exit-syscall'),'known full ptrace event kind')
        registers=row['registers'];require(set(registers)==set(REGS),'all 27 actual x86_64 registers')
        for value in registers.values():integer(value,'actual register')
        if kind=='initial-exec-stop':continue
        info=bytes.fromhex(row['syscall_info_hex']);require(info.hex()==row['syscall_info_hex'],'complete syscall info bytes')
        require(len(info)==(80 if kind=='entry' else 33) and info[0]==(1 if kind=='entry' else 2),'actual syscall info kind/extent')
        require(struct.unpack_from('<I',info,4)[0]==0xc000003e,'actual x86_64 audit architecture')
        require(struct.unpack_from('<2Q',info,8)==(registers['rip'],registers['rsp']),'actual info instruction/stack registers')
        number=integer(row['number'],'actual syscall number');args=row['args']
        require(type(args) is list and len(args)==6,'six complete kernel syscall arguments')
        for value in args:integer(value,'actual syscall argument')
        require(row['name']==NAMES.get(number,'syscall_'+str(number)) and registers['orig_rax']==number,'actual syscall name/number')
        detail=row['details'];require(type(detail) is dict,'actual details object')
        if kind=='entry':
            require(pending is None,'one active syscall entry')
            require(struct.unpack_from('<7Q',info,24)==(number,*args) and args==[registers[k] for k in ('rdi','rsi','rdx','r10','r8','r9')],'whole entry args/info/registers agree')
            expected=set()
            if number==2:expected|={'path_hex','flags','mode'};require(detail['flags']==args[1] and detail['mode']==args[2],'actual open flags')
            elif number in (257,262,263):expected.add('path_hex')
            elif number in (264,316):expected|={'source_hex','destination_hex'}
            if number==1:
                expected.add('data');require(len(blob(files,folder,detail['data']))==args[2],'complete real write input buffer')
            if number in (0,1,3,5,73,74,75,91,196):
                expected.add('fd_owner');same(detail['fd_owner'],live.get(args[0]),'actual descriptor owner at syscall entry')
            require(set(detail)==expected,'exact syscall entry memory observations')
            for key in ('path_hex','source_hex','destination_hex'):
                if key in detail:
                    value=bytes.fromhex(detail[key]);require(value.hex()==detail[key] and b'\0' not in value,'whole actual NUL-terminated pathname bytes')
            pending=row;entries+=1
            if number==121 and args[0]>=900000000:
                cid,end=divmod(args[0]-900000000,2)
                if not end:
                    require(active is None and not live and len(seen)<len(ids) and cid==ids[len(seen)],'strict actual begin marker order')
                    active=cid;cases[cid]={'begin':row,'calls':[]}
                else:require(active==cid and not live,'actual end marker only after all descriptor retirement')
        else:
            require(pending is not None and row['entry_event']==pending['event'] and number==pending['number'] and args==pending['args'],'full actual syscall entry/exit pairing')
            ret=integer(row['return'],'actual raw syscall return',-(1<<63),(1<<63)-1)
            require(struct.unpack_from('<q',info,24)[0]==ret and registers['rax']==ret&((1<<64)-1),'complete exit info/register return')
            require(info[32]==int(-4095<=ret<0) and row['errno']==(-ret if -4095<=ret<0 else 0),'actual raw Linux errno')
            expected=set()
            if ret>=0:
                if number in (0,318) or number==196 and args[1] and ret:
                    expected.add('data');rawdata=blob(files,folder,detail['data']);require(len(rawdata)==ret,'complete actual read/entropy bytes')
                    if number==0:
                        require(ret<=args[2],'read did not exceed actual buffer')
                        if args[0]==0:stdin.extend(rawdata)
                elif number in (5,262):expected.add('stat');stat(detail['stat'])
                if number==1:
                    require(ret<=args[2],'write did not exceed actual input')
                    rawdata=blob(files,folder,pending['details']['data'])[:ret]
                    if args[0]==1:stdout.extend(rawdata)
                    elif args[0]==2:stderr.extend(rawdata)
            require(set(detail)==expected,'exact complete syscall exit memory observations')
            if number in (2,257) and ret>=0:
                require(ret not in live,'newly owned actual descriptor')
                flags=args[1 if number==2 else 2];role='directory' if flags&0o200000 else 'stage' if flags&0o300==0o300 else 'source'
                live[ret]={'opening_event':row['event'],'path_hex':pending['details']['path_hex'],'flags':flags,'role':role};opens+=1
            elif number==3 and ret==0:
                require(args[0] in live,'every actual closed descriptor previously opened')
                del live[args[0]];closes+=1
            if number==121 and args[0]>=900000000:
                cid,end=divmod(args[0]-900000000,2);require(ret==-3,'real marker call completed ESRCH')
                if end:
                    require(active==cid and not live,'actual marker end and zero owned descriptors')
                    cases[cid]['end']=row;seen.append(cid);active=None
                else:require(active==cid,'actual begin marker completion')
            elif active is not None:
                cases[active]['calls'].append({'entry':pending,'exit':row})
            pending=None
    require(pending is None and active is None and not live and seen==list(ids),'all trace pairs/markers/FDs consumed')
    require(entries==process['syscall_entries'] and opens==closes==process['opens']==process['closes'],'actual whole syscall/FD counts')
    require(bytes(stdin)==files.raw(process['stdin']['path'],{k:process['stdin'][k] for k in ('bytes','sha256')}),'every original stdin byte actually read')
    require(bytes(stdout)==files.raw(folder/'stdout',process['stdout']) and bytes(stderr)==files.raw(folder/'stderr',process['stderr']),'every complete response byte actually written')
    return {'cases':cases,'events':byevent,'syscall_entries':entries,'trace_events':len(rows),'opens':opens,'closes':closes,'markers':len(seen)}
