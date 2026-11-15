"""Read-only ptrace syscall observation of our own unchanged reference child.

No POKE, SETREGS, return injection, preload, code breakpoint or syscall substitution
is used. The parent may perform an explicitly recorded external filesystem action
while the child is stopped at a real syscall entry or exit.
"""
from pathlib import Path
import ctypes,hashlib,json,os,signal,struct,subprocess,time
from common import require,pin,save,encoded
LIBC=ctypes.CDLL(None,use_errno=True);LIBC.ptrace.restype=ctypes.c_long
LIBC.ptrace.argtypes=[ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p]
TRACEME=0;GETREGS=12;SYSCALL=24;SETOPTIONS=0x4200;GETINFO=0x420e
REG_NAMES=('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')
NAMES={0:'read',1:'write',2:'open',3:'close',5:'fstat',8:'lseek',9:'mmap',10:'mprotect',11:'munmap',12:'brk',
13:'rt_sigaction',14:'rt_sigprocmask',16:'ioctl',21:'access',59:'execve',60:'exit',63:'uname',72:'fcntl',
73:'flock',74:'fsync',75:'fdatasync',89:'readlink',91:'fchmod',102:'getuid',104:'getgid',107:'geteuid',108:'getegid',
121:'getpgid',158:'arch_prctl',196:'flistxattr',202:'futex',218:'set_tid_address',231:'exit_group',
257:'openat',262:'newfstatat',263:'unlinkat',264:'renameat',273:'set_robust_list',302:'prlimit64',
316:'renameat2',318:'getrandom',332:'statx',334:'rseq'}
def ptrace(request,pid,address=0,data=0):
    ctypes.set_errno(0)
    a=ctypes.c_void_p(address) if type(address) is int else address
    d=ctypes.c_void_p(data) if type(data) is int else data
    ret=LIBC.ptrace(request,pid,a,d)
    if ret==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
    return ret
def stat_projection(raw):
    require(len(raw)==144,'complete x86_64 Linux stat')
    dev,ino,nlink=struct.unpack_from('<3Q',raw);mode,uid,gid=struct.unpack_from('<3I',raw,24)
    size=struct.unpack_from('<q',raw,48)[0];mt,mtn,ct,ctn=struct.unpack_from('<4q',raw,88)
    return {'version':[dev,ino,size,mt,mtn,ct,ctn],'mode':mode,'uid':uid,'gid':gid,'nlink':nlink,'raw_hex':raw.hex()}
def child_setup():
    os.umask(0o077);ptrace(TRACEME,0)
class Tracer:
    def __init__(self,binary,stdin,cwd,output,on_entry,on_exit):
        self.binary=Path(binary);self.stdin=Path(stdin);self.cwd=Path(cwd);self.output=Path(output)
        self.output.mkdir();self.blobs=self.output/'blobs';self.blobs.mkdir()
        self.on_entry=on_entry;self.on_exit=on_exit;self.index=0;self.syscalls=0;self.pid=None;self.mem=None;self.rows=0
        self.fd_live={};self.opens=0;self.closes=0;self.pending=None;self.active=None;self.terminal=None
    def blob(self,raw):
        p=pin(raw);path=self.blobs/(p['sha256']+'.bin')
        if path.exists():require(path.read_bytes()==raw,'trace full data blob collision')
        else:path.write_bytes(raw)
        return {**p,'file':path.name}
    def memory(self,address,length):
        require(type(length) is int and 0<=length<=4259841,'actual bounded original memory span')
        raw=os.pread(self.mem,length,address);require(len(raw)==length,'full tracee memory read');return raw
    def cstring(self,address):
        raw=bytearray()
        while True:
            part=os.pread(self.mem,256,address+len(raw));require(part,'read actual C string')
            pos=part.find(b'\0')
            if pos>=0:return bytes(raw)+part[:pos]
            raw.extend(part);require(len(raw)<=131072,'bounded explicit race fixture path')
    def registers(self):
        buf=(ctypes.c_ulonglong*27)();ptrace(GETREGS,self.pid,0,ctypes.byref(buf));return dict(zip(REG_NAMES,map(int,buf)))
    def info(self):
        buf=ctypes.create_string_buffer(128);used=ptrace(GETINFO,self.pid,len(buf),ctypes.byref(buf))
        require(24<=used<=len(buf),'actual syscall info extent')
        raw=buf.raw[:used];op=raw[0];arch=struct.unpack_from('<I',raw,4)[0]
        require(arch==0xc000003e and op in (1,2),'actual Linux x86_64 syscall entry or exit')
        return op,raw
    def record(self,row):
        self.index+=1;row={'event':self.index,'pid':self.pid,'monotonic_ns':time.monotonic_ns(),**row}
        self.trace.write(encoded(row));self.trace.flush();self.rows+=1;return row
    def details(self,number,args,enter,ret=None):
        d={}
        if enter:
            if number==2:d.update(path_hex=self.cstring(args[0]).hex(),flags=args[1],mode=args[2])
            elif number in (257,262,263):d.update(path_hex=self.cstring(args[1]).hex())
            elif number in (264,316):d.update(source_hex=self.cstring(args[1]).hex(),destination_hex=self.cstring(args[3]).hex())
            if number==1:d['data']=self.blob(self.memory(args[1],args[2]))
            if number in (0,1,3,5,73,74,75,91,196):d['fd_owner']=self.fd_live.get(args[0])
        elif ret is not None and ret>=0:
            if number==0:d['data']=self.blob(self.memory(args[1],ret))
            elif number==5:d['stat']=stat_projection(self.memory(args[1],144))
            elif number==262:d['stat']=stat_projection(self.memory(args[2],144))
            elif number==318:d['data']=self.blob(self.memory(args[0],ret))
            elif number==196 and args[1] and ret:d['data']=self.blob(self.memory(args[1],ret))
        return d
    def wait(self,deadline):
        while True:
            pid,status=os.waitpid(self.pid,os.WNOHANG)
            if pid:return status
            require(time.monotonic()<deadline,'actual original ptrace 180-second deadline')
            time.sleep(0.0002)
    def run(self):
        started=time.monotonic_ns();deadline=time.monotonic()+180;code=None;failure=None;timed=False;child=None
        environment=dict(os.environ,LC_ALL='C',TZ='UTC')
        with self.stdin.open('rb') as stdin,(self.output/'stdout').open('xb') as stdout,(self.output/'stderr').open('xb') as stderr,(self.output/'syscalls.jsonl').open('xb') as trace:
            self.trace=trace
            try:
                child=subprocess.Popen([str(self.binary)],cwd=self.cwd,env=environment,stdin=stdin,stdout=stdout,stderr=stderr,preexec_fn=child_setup,start_new_session=True)
                self.pid=child.pid;status=self.wait(deadline)
                require(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGTRAP,'actual post-exec ptrace stop')
                for name in ('status','cmdline','cgroup','maps'):
                    (self.output/('proc-'+name)).write_bytes((Path('/proc')/str(self.pid)/name).read_bytes())
                actual_exe=(Path('/proc')/str(self.pid)/'exe').read_bytes()
                require(pin(actual_exe)==pin(self.binary.read_bytes()),'kernel-selected actual reference executable')
                save(self.output/'EXECUTABLE.json',{'invocation':str(self.binary),'kernel_exe':os.readlink('/proc/'+str(self.pid)+'/exe'),**pin(actual_exe)})
                self.mem=os.open('/proc/'+str(self.pid)+'/mem',os.O_RDONLY|os.O_CLOEXEC)
                ptrace(SETOPTIONS,self.pid,0,1|0x00100000)
                self.record({'kind':'initial-exec-stop','wait_status':status,'registers':self.registers()})
                while True:
                    ptrace(SYSCALL,self.pid,0,0)
                    status=self.wait(deadline)
                    if os.WIFEXITED(status):
                        code=os.WEXITSTATUS(status);child.returncode=code
                        require(self.pending is None or self.pending['number'] in (60,231),'only actual exit syscall lacks return')
                        self.terminal=self.record({'kind':'exit','wait_status':status,'exit_code':code,'pending_entry':None if self.pending is None else self.pending['event']})
                        break
                    require(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==(signal.SIGTRAP|0x80),'only actual syscall stops, no hidden signals')
                    op,rawinfo=self.info();regs=self.registers()
                    if op==1:
                        require(self.pending is None,'paired complete syscall entries')
                        number,*args=struct.unpack_from('<7Q',rawinfo,24)
                        require(number==regs['orig_rax'] and args==[regs[k] for k in ('rdi','rsi','rdx','r10','r8','r9')],'actual register/syscall info equality')
                        row=self.record({'kind':'entry','number':number,'name':NAMES.get(number,'syscall_'+str(number)),'args':args,
                             'registers':regs,'syscall_info_hex':rawinfo.hex(),'details':self.details(number,args,True)})
                        self.pending=row;self.syscalls+=1;self.on_entry(self,row)
                    else:
                        require(self.pending is not None,'actual syscall exit has entry')
                        ret=struct.unpack_from('<q',rawinfo,24)[0];number=self.pending['number'];args=self.pending['args']
                        require(regs['orig_rax']==number and regs['rax']==(ret&((1<<64)-1)),'actual syscall return register equality')
                        row=self.record({'kind':'exit-syscall','entry_event':self.pending['event'],'number':number,'name':self.pending['name'],
                            'args':args,'return':ret,'errno':-ret if -4095<=ret<0 else 0,'registers':regs,
                            'syscall_info_hex':rawinfo.hex(),'details':self.details(number,args,False,ret)})
                        if number in (2,257) and ret>=0:
                            require(ret not in self.fd_live,'actual new owned descriptor')
                            flags=args[1 if number==2 else 2];name=self.pending['details']['path_hex']
                            role='directory' if flags&0o200000 else 'stage' if flags&0o300==0o300 else 'source'
                            self.fd_live[ret]={'opening_event':row['event'],'path_hex':name,'flags':flags,'role':role};self.opens+=1
                        self.on_exit(self,self.pending,row)
                        if number==3 and ret==0:
                            require(args[0] in self.fd_live,'actual close is traced owned descriptor')
                            del self.fd_live[args[0]];self.closes+=1
                        self.pending=None
                require(code==0 and not self.fd_live,'actual original success with all opened FDs closed')
            except BaseException as error:
                failure=repr(error);timed='deadline' in str(error)
                if child is not None and child.returncode is None:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    try:
                        _,status=os.waitpid(child.pid,0);code=os.waitstatus_to_exitcode(status);child.returncode=code
                    except ChildProcessError:pass
                raise
            finally:
                if self.mem is not None:os.close(self.mem)
                finished=time.monotonic_ns()
                record={'command':[str(self.binary)],'cwd':str(self.cwd),'pid':self.pid,'timeout_seconds':180,'timed_out':timed,
                    'start_error':None if child is not None else failure,'failure':failure,'exit_code':code,
                    'started_monotonic_ns':started,'finished_monotonic_ns':finished,'elapsed_seconds':(finished-started)/1e9,
                    'stdin':{'path':str(self.stdin),**pin(self.stdin.read_bytes())},
                    'stdout':pin((self.output/'stdout').read_bytes()),'stderr':pin((self.output/'stderr').read_bytes()),
                    'syscalls':pin((self.output/'syscalls.jsonl').read_bytes()),'syscall_entries':self.syscalls,'trace_events':self.rows,
                    'opens':self.opens,'closes':self.closes,'remaining_fds':self.fd_live,'recorded_environment':{'LC_ALL':'C','TZ':'UTC'},
                    'ptrace_operations':[TRACEME,GETREGS,SYSCALL,SETOPTIONS,GETINFO],
                    'writes_to_tracee_memory_or_registers':0,'syscall_results_injected':0}
                save(self.output/'PROCESS.json',record)
        return record
