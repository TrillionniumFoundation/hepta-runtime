"""Real installed configuration, repeated reads, retained flock custody and ENOMEM."""
from pathlib import Path
import argparse, fcntl, hashlib, json, os, resource, select, signal, stat, struct, subprocess, time, traceback
PACK=lambda *v:struct.pack('<'+'Q'*len(v),*v)
WORD=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def require(ok,message):
    if not ok:raise AssertionError(message)
def pin(path):
    with path.open('rb')as stream:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}
def write(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def config(path,state,roots):
    path.write_bytes(json.dumps({'state_dir':str(state),'controller_workspace_roots':roots,'hosts':{'h':{'ssh_target':'private-target','remote_state_dir':'/remote'}}},ensure_ascii=False,separators=(',',':')).encode())
def lock_observation(path):
    fd=os.open(path,os.O_RDWR|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);locked=False
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:locked=True
        return {'locked_by_other':locked,'device':st.st_dev,'inode':st.st_ino,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'links':st.st_nlink,'size':st.st_size}
    finally:os.close(fd)
def lock_pair(state):return {name:lock_observation(state/name)for name in ('controller.owner.lock','controller.lock')}
def fd_observation(pid):
    result={}
    for entry in sorted(Path('/proc',str(pid),'fd').iterdir(),key=lambda p:int(p.name)):
        try:result[entry.name]={'target':os.readlink(entry),'fdinfo':(Path('/proc',str(pid),'fdinfo')/entry.name).read_text()}
        except FileNotFoundError:raise AssertionError('native descriptor changed during quiet observation')
    return result
def descriptor_identity(rows):
    return {key:{'target':value['target'],'fdinfo_without_position':'\n'.join(line for line in value['fdinfo'].split('\n')if not line.startswith('pos:'))}for key,value in rows.items()}
class Session:
    def __init__(self,binary,folder,path=None,limit=None):
        self.folder=folder;folder.mkdir();self.command=[str(binary)]+([]if path is None else ['--runtime-config',str(path)]);self.argv=['/usr/bin/strace','-qq','-f','-s','256','-xx','-o',str(folder/'kernel.trace'),'-e','trace=mmap,mremap,munmap,openat,close,flock,read,write,mkdirat,newfstatat',*self.command]
        self.input=(folder/'stdin').open('xb');self.output=(folder/'stdout').open('xb');self.stderr=(folder/'stderr').open('xb');self.rows=[];self.begin=time.monotonic();self.limit=limit
        def preexec():
            os.umask(0o22)
            if limit is not None:resource.setrlimit(resource.RLIMIT_AS,(limit,limit))
        self.p=subprocess.Popen(self.argv,cwd=folder,env={'PATH':''},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,preexec_fn=preexec,start_new_session=True);self.native_pid=None;self.closed=False
    def read(self,n):
        out=bytearray();deadline=time.monotonic()+60
        while len(out)<n:
            left=deadline-time.monotonic();require(left>0 and select.select([self.p.stdout],[],[],left)[0],'actual native response deadline')
            raw=os.read(self.p.stdout.fileno(),min(n-len(out),65536));require(raw,('unexpected actual native EOF',self.p.poll()));self.output.write(raw);out.extend(raw)
        return bytes(out)
    def call(self,index=None):
        frame=b'HRCFGQ01'+PACK(7,0 if index is None else 8)+(b''if index is None else PACK(index));wire=PACK(11,len(frame))+frame;self.input.write(wire);self.input.flush();self.p.stdin.write(wire);self.p.stdin.flush()
        header=self.read(96);require(header[:8]==b'HRGFR002'and WORD(header,8)==11,'actual installed borrow reply');size=WORD(header,24);body=self.read(size)
        require(WORD(header,16)==size and body[:8]==b'HRCFGM01'and WORD(body,24)==len(body)-32,'complete installed owner response')
        if self.native_pid is None:
            children=Path('/proc',str(self.p.pid),'task',str(self.p.pid),'children').read_text().split();require(len(children)==1,'one actual strace child');self.native_pid=int(children[0])
        self.rows.append({'ordinal':len(self.rows),'input_bytes':len(wire),'input_sha256':SHA(wire),'header_hex':header.hex(),'body_bytes':len(body),'body_sha256':SHA(body),'native_pid':self.native_pid});return body
    def close(self,expected=0):
        if self.closed:return
        self.p.stdin.close();timed=False
        try:code=self.p.wait(timeout=60)
        except subprocess.TimeoutExpired:timed=True;os.killpg(self.p.pid,signal.SIGKILL);code=self.p.wait()
        tail=self.p.stdout.read();self.output.write(tail);self.p.stdout.close();self.input.close();self.output.close();self.stderr.close();self.closed=True
        row={'command':self.argv,'executable_command':self.command,'cwd':str(self.folder),'env':{'PATH':''},'pid':self.p.pid,'native_pid':self.native_pid,'timeout_seconds':60,'timed_out':timed,'exit_code':code,'elapsed_seconds':time.monotonic()-self.begin,'rlimit_as':self.limit,'streams':{n:pin(self.folder/n)for n in ('stdin','stdout','stderr','kernel.trace')}};write(self.folder/'process.json',row);write(self.folder/'queries.json',self.rows)
        require(not timed and code==expected,('actual installed process result',code,expected));require(not tail,'no extra stdout after complete calls')
    def abort(self):
        if not self.closed:
            if self.p.poll() is None:os.killpg(self.p.pid,signal.SIGKILL)
            self.p.wait();self.p.stdout.close();self.p.stdin.close();self.input.close();self.output.close();self.stderr.close();self.closed=True
def trace(path,allow_error=False):
    raw=path.read_bytes();at=0;rows=[];native=0;growth=0
    sizes={b'HRCGRO02':80,b'HRGTR002':224,b'HRCNAK02':128,b'HWDIOAK2':160}
    while at<len(raw)and raw[at:at+8]in sizes:
        magic=raw[at:at+8];n=sizes[magic];require(n<=len(raw)-at,'complete actual stderr record');item=raw[at:at+n]
        if magic==b'HRCGRO02':growth+=1;rows.append({'offset':at,'record':list(struct.unpack_from('<9Q',item,8))})
        elif magic==b'HRGTR002':native+=1
        at+=n
    tail=raw[at:];require(allow_error or not tail,'no unaccounted production stderr');return {'configuration_growth':rows,'graph_records':native,'tail_hex':tail.hex(),'tail_bytes':len(tail)}
def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--build-sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir();os.umask(0o077)
    write(a.output/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text()});started=time.monotonic();require(pin(a.build/'result.json')['sha256']==a.build_sha256,'actual graph');built=json.loads((a.build/'result.json').read_bytes());binary=Path(built['binary']);before=pin(binary);require(before['sha256']==built['binary_sha256'],'actual ELF')
    write(a.output/'SOURCE.json',{'producer':pin(Path(__file__)),'build':pin(a.build/'result.json'),'binary':before});sessions=[];observations=[]
    try:
        for name,roots in [('ordinary',[str(a.output/'ordinary-root')]),('wide',['/'+'x'*((33<<20)+17)])]:
            scene=a.output/name;scene.mkdir();state=scene/'state';state.mkdir(mode=0o700);path=scene/'config.json';config(path,state,roots);original=path.read_bytes();(scene/'initial-config.json').write_bytes(original)
            s=Session(binary,scene/'primary',path);sessions.append(s);require(s.call()==b'HRCFGM01'+PACK(0,0,8,len(roots)),'actual root count');first=s.call(0);want=roots[0].encode();require(first==b'HRCFGM01'+PACK(0,0,24+len(want),len(roots),0,len(want))+want,'all actual installed root bytes')
            fds=fd_observation(s.native_pid);locks=lock_pair(state);require(all(row['locked_by_other']for row in locks.values()),'both installed leases held');observations.append({'name':name,'phase':'installed','fd':fds,'locks':locks})
            path.write_bytes(b'not json and not reloaded');require(s.call(0)==first,'config file mutation does not reload installed owner');require(descriptor_identity(fd_observation(s.native_pid))==descriptor_identity(fds),'query descriptor set unchanged')
            renamed=scene/'renamed-state';state.rename(renamed);state.mkdir(mode=0o700);require(s.call(0)==first,'path replacement does not redirect installed owner');after=lock_pair(renamed);require(after==locks and list(state.iterdir())==[],'same inode leases and no replacement-state effects');observations.append({'name':name,'phase':'renamed-live','fd':fd_observation(s.native_pid),'locks':after})
            # A second real process targets the still-locked original directory.
            other_path=scene/'contender-config.json';config(other_path,renamed,roots);contender=Session(binary,scene/'contender',other_path);sessions.append(contender);contender.close(expected=78);failure=trace(contender.folder/'stderr',allow_error=True);require(b'lock acquisition failed because the operation would block'in bytes.fromhex(failure['tail_hex']),'actual second-process lock refusal');write(contender.folder/'trace.json',failure)
            s.close();released=lock_pair(renamed);require(all(not row['locked_by_other']for row in released.values()),'EOF releases both exact installed leases');require(all(released[key]['inode']==locks[key]['inode']for key in locks),'lease inode identity retained');observations.append({'name':name,'phase':'released','locks':released});write(s.folder/'trace.json',trace(s.folder/'stderr'))
            reopened=Session(binary,scene/'reopened',other_path);sessions.append(reopened);require(reopened.call(0)==first,'actual fresh instance after release');reopened.close();write(reopened.folder/'trace.json',trace(reopened.folder/'stderr'))
        scene=a.output/'resource';scene.mkdir();state=scene/'state';path=scene/'config.json';config(path,state,['/'+'r'*((33<<20)+17)]);failed=Session(binary,scene/'limited',path,4<<30);sessions.append(failed);failed.close(expected=75);actual=trace(failed.folder/'stderr');rows=actual['configuration_growth'];bad=[r for r in rows if r['record'][6]==(1<<64)-12];require(len(bad)==1,'one actual mremap ENOMEM receipt');entry=bad[0]['record'];require(entry[3]==entry[5]and entry[7]==entry[8],'failed resize keeps original descriptor');kernel=(failed.folder/'kernel.trace').read_bytes();require(b'mremap('in kernel and b'ENOMEM'in kernel,'actual kernel allocation rejection');require(not state.exists(),'allocation failure precedes installation effects');write(failed.folder/'trace.json',actual)
        require(pin(binary)==before,'exact ELF unchanged');write(a.output/'observations.json',observations)
        result={'status':'PASS','actual_elf_processes':len(sessions),'actual_queries':sum(len(s.rows)for s in sessions),'same_installed_owner':True,'actual_retained_locks':4,'actual_competing_lock_refusals':2,'actual_enomem_processes':1,'new_rust_processes':0,'public_mcp_complete':False,'elapsed_seconds':time.monotonic()-started,'artifacts':{p.relative_to(a.output).as_posix():pin(p)for p in a.output.rglob('*')if p.is_file()and p.name not in ('controller.owner.lock','controller.lock')}};write(a.output/'RESULT.json',result);print(json.dumps({k:v for k,v in result.items()if k!='artifacts'},sort_keys=True),flush=True)
    except BaseException:
        write(a.output/'FAILURE.json',{'traceback':traceback.format_exc(),'processes_started':len(sessions),'elapsed_seconds':time.monotonic()-started});raise
    finally:
        for s in sessions:s.abort()
if __name__=='__main__':main()
