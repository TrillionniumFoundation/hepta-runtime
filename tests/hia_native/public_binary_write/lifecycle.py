#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual owned writer SSH cancellation, EOF destruction and 30-second deadline."""
from pathlib import Path
import argparse,ast,ctypes,hashlib,json,os,pwd,shlex,shutil,signal,socket,subprocess,sys,tempfile,threading,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run import Session,compact,pin,require


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--elf',type=Path)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--business-evidence',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--transport',choices=('loopback','local-command'),required=True)
    args=parser.parse_args();source=args.source.resolve(strict=True);manifest=args.manifest.resolve(strict=True)
    document=json.loads(manifest.read_bytes());elf=(args.elf or manifest.parent/document['elf']).resolve(strict=True)
    require(document['physical_images']==133 and document['runtime_hia_images']==175 and
            pin(elf)=={'bytes':document['elf_bytes'],'sha256':document['elf_sha256']},'exact public I/O graph required')
    require(all(document[name] is False for name in ('private_instance_fixture','private_task_pump_fixture',
        'private_task_pump_trace','actual_fixture_private_selectors')),'actual default entrypoint required')
    business=args.business_evidence.resolve(strict=True);prior=json.loads((business/'EVIDENCE.json').read_bytes())
    require(prior['status']=='PASS' and prior['elf']==pin(elf) and prior['transport']==args.transport,
            'same complete business gate is required first')
    command=json.loads((business/'ssh-arguments.jsonl').read_text().splitlines()[0])[-1]
    helper=document['public_io_dependencies']['write']['executable']
    require(str(helper['bytes']) in command,'actual writer bootstrap extent absent')
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    started=time.monotonic();sessions=[];owned=[];cases=[];server=None;hold_fd=None
    report={'schema':'hepta.runtime.public-binary-write.lifecycle.v1','status':'RUNNING','elf':pin(elf),
        'manifest':pin(manifest),'transport':args.transport,'business_evidence':pin(business/'EVIDENCE.json'),
        'actual_default_entrypoint':True,'whole_runtime_replaced':False,'old_path_removed':False,'cases':cases}
    report['control_sources']={name:pin(Path(__file__).parent/name) for name in ('run.py','lifecycle.py')}
    def save():
        report['elapsed_seconds']=time.monotonic()-started
        (out/'EVIDENCE.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    def proc(pid):
        try:
            raw=Path('/proc/%d/stat'%pid).read_text();values=raw[raw.rfind(')')+2:].split()
            row={'pid':pid,'state':values[0],'ppid':int(values[1]),'start':int(values[19])}
            try:row['exe']=os.readlink('/proc/%d/exe'%pid)
            except OSError as error:row['exe']=None;row['exe_errno']=error.errno
            return row
        except FileNotFoundError:return None
    def live(row):
        current=proc(row['pid']);return current is not None and current['start']==row['start']
    def tree(pid):
        children={}
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal():continue
            try:
                raw=(entry/'stat').read_text();values=raw[raw.rfind(')')+2:].split()
                children.setdefault(int(values[1]),[]).append(int(entry.name))
            except FileNotFoundError:continue
        todo=[pid];seen=set();rows=[]
        while todo:
            pid=todo.pop()
            if pid in seen:continue
            seen.add(pid);require(len(seen)<=40,'owned process tree extent')
            row=proc(pid)
            if row is None:continue
            rows.append(row)
            todo.extend(children.get(pid,[]))
            for thread in Path('/proc/%d/task'%pid).glob('*'):
                try:todo.extend(int(value) for value in (thread/'children').read_text().split())
                except FileNotFoundError:pass
        return rows
    def until(predicate,seconds,label):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            result=predicate()
            if result:return result
            time.sleep(.01)
        raise AssertionError('owned deadline: '+label)
    def reap(rows):
        receipts=[]
        def done():
            remaining=[]
            for row in rows:
                current=proc(row['pid'])
                if current is None or current['start']!=row['start']:continue
                if current['state']=='Z' and current['ppid']==os.getpid():
                    pid,status=os.waitpid(current['pid'],os.WNOHANG)
                    if pid:receipts.append({'pid':pid,'waitstatus':status,'fixture_reaped_already_dead_adoptee':True});continue
                remaining.append(current)
            return not remaining
        until(done,10,'all actual owned subprocesses retired')
        return {'pids':[row['pid'] for row in rows],'all_retired':True,'adoptees':receipts}
    try:
        require(ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)==0,'fixture subreaper unavailable')
        root=out/'files';root.mkdir();read_file=root/'read.txt';read_file.write_bytes(b'unrelated read\n')
        config=out/'config.json';config.write_text(compact({'state_dir':str(out/'state'),'controller_workspace_roots':[str(out)],
            'hosts':{'writer':{'ssh_target':'local-native','remote_state_dir':str(out/'remote'),'execution_mode':'operator','allow_write':True,
                'allowed_read_path_prefixes':[str(root)],'allowed_write_path_prefixes':[str(root)]}}})+'\n')
        # The exact command is regenerated for the different configured root;
        # the HIA bootstrap's only root-dependent part is not inferred here.
        # Select the writer by its exact fixed image byte extent, recorded and
        # admitted from the complete production dependency manifest above.
        (out/'writer-command').write_text(command)
        enabled=out/'hold-enabled';ready=out/'relay-ready';marker=out/'relay-pids';fifo=out/'release.fifo'
        os.mkfifo(fifo,0o600);hold_fd=os.open(fifo,os.O_RDWR|os.O_CLOEXEC)
        if args.transport=='loopback':
            fixture=source/'tests/hia_native/test_native_read_bootstrap.py';raw=fixture.read_text()
            node=next(n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef) and n.name=='LoopbackSSH')
            code=ast.get_source_segment(raw,node);ns=dict(globals());exec(compile(code,str(fixture),'exec'),ns)
            server=ns['LoopbackSSH'](out);client=out/'ssh-client-config'
            client.write_text('\n'.join(['Host local-native',' HostName 127.0.0.1',' Port '+str(server.port),
                ' User '+server.user,' IdentityFile '+str(server.root/'client'),' IdentitiesOnly yes',
                ' UserKnownHostsFile '+str(server.known_hosts),' GlobalKnownHostsFile /dev/null',
                ' StrictHostKeyChecking yes',' BatchMode yes',' LogLevel ERROR','']))
            tail='os.execv('+repr(server.ssh)+',['+repr(server.ssh)+',"-F",'+repr(str(client))+',*args])\n'
        else:tail='os.execv("/bin/sh",["sh","-c",args[-1]])\n'
        shim_dir=out/'bin';shim_dir.mkdir();shim=shim_dir/'ssh'
        relay='''#!/usr/bin/python3 -I
import os,sys,json,signal,ctypes
from pathlib import Path
O=Path(%r);extent=%d;args=sys.argv[1:];command=args[-1]
if (O/'hold-enabled').exists() and str(extent) in command:
 parent=os.getpid();readfd,writefd=os.pipe();child=os.fork()
 if child==0:
  os.close(readfd)
  if ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL,0,0,0)!=0:os._exit(124)
  if os.getppid()!=parent:os._exit(124)
  size=extent+32
  while size:
   part=os.read(0,min(size,65536))
   if not part:os._exit(123)
   size-=len(part);at=0
   while at<len(part):at+=os.write(writefd,part[at:])
  (O/'relay-pids').write_text(json.dumps({'ssh':parent,'relay':os.getpid()}))
  (O/'relay-ready').write_text('ready')
  with (O/'release.fifo').open('rb',buffering=0) as release:release.readline()
  while True:
   part=os.read(0,65536)
   if not part:break
   at=0
   while at<len(part):at+=os.write(writefd,part[at:])
  os.close(writefd);os._exit(0)
 os.close(writefd);os.dup2(readfd,0);os.close(readfd)
'''%(str(out),helper['bytes'])
        shim.write_text(relay+tail);shim.chmod(0o755)
        env={'PATH':str(shim_dir)+':/usr/bin:/bin','HOME':str(out),'LC_ALL':'C'}
        def session(label):
            value=Session(elf,config,out/label,env);sessions.append(value);return value
        def hold(current,identity,path):
            for p in (ready,marker):
                if p.exists():p.unlink()
            enabled.write_text('hold\n')
            current.send({'jsonrpc':'2.0','id':identity,'method':'tools/call','params':{'name':'binary_write',
                'arguments':{'host':'writer','path':str(path),'data_base64':'aGVsZC13cml0ZQ==','expected_version':'absent'}}})
            until(lambda:ready.exists() and marker.exists(),10,'complete helper plus partial writer packet')
            ids=json.loads(marker.read_bytes());relay_row=proc(ids['relay']);require(relay_row is not None,'owned relay absent')
            (out/'relay-process-observations.json').write_text(json.dumps({
                'ssh':proc(ids['ssh']),'relay':relay_row,'runtime':proc(current.process.pid)},indent=2)+'\n')
            remote_root=server.process.pid if server is not None else current.process.pid
            def helper_started():
                observed=tree(remote_root)
                for row in observed:
                    if not row['exe'] or not row['exe'].startswith('/tmp/.hepta-hia-'):continue
                    try:
                        row['actual_exe_sha256']=hashlib.sha256(Path('/proc/%d/exe'%row['pid']).read_bytes()).hexdigest()
                        if row['actual_exe_sha256']!=helper['sha256']:continue
                        waiting=Path('/proc/%d/syscall'%row['pid']).read_text().strip()
                        row['actual_syscall']=waiting
                        if waiting.startswith('0 '):return row,waiting
                    except FileNotFoundError:pass
                (out/'held-tree-observations.json').write_text(json.dumps(observed,indent=2)+'\n')
                return None
            native,waiting=until(helper_started,10,'actual fixed HIA writer blocked on stdin')
            remote=tree(native['ppid']);ssh=proc(ids['ssh']);require(ssh is not None,'actual SSH process absent')
            enabled.unlink();owned.extend([relay_row,ssh,*remote])
            require(not path.exists(),'incomplete packet already published a file')
            return {'writer':native,'read_syscall':waiting,'remote':remote,'ssh':[ssh],'relay':[relay_row]}
        def retired(held):
            return {'ssh':reap(held['ssh']),'remote':reap(held['remote']),'relay':reap(held['relay'])}
        s=session('cancel');path=root/'cancelled.bin';held=hold(s,20,path)
        second=s.call(21,'binary_write',{'host':'writer','path':str(root/'concurrent.bin'),'data_base64':'c2Vjb25k','expected_version':'absent'})
        require(second.get('result',{}).get('isError') is False and (root/'concurrent.bin').read_bytes()==b'second',
                ('held writer blocked another native writer',second))
        s.send({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':20,'reason':'native writer lifecycle'}})
        pong=s.exchange({'jsonrpc':'2.0','id':22,'method':'ping'});require(pong.get('result')=={},pong)
        require(all(live(row) for row in held['ssh']) and live(held['writer']),'ordinary cancellation destroyed handler')
        os.write(hold_fd,b'release\n');terminals=retired(held)
        require(path.read_bytes()==b'held-write','retained cancelled handler did not complete original write')
        code=s.finish();cases.append({'name':'notification-retains-owned-write-and-discards-response','passed':True,
            'held':held,'terminals':terminals,'returncode':code});save()
        s=session('eof');path=root/'eof.bin';held=hold(s,30,path);before=time.monotonic();code=s.finish();terminals=retired(held)
        require(not path.exists(),'EOF-dropped incomplete write published a file')
        cases.append({'name':'EOF-drops-owned-writer-and-reaps-helper','passed':True,'held':held,'terminals':terminals,
            'returncode':code,'seconds':time.monotonic()-before});save()
        s=session('deadline');path=root/'deadline.bin';before=time.monotonic();held=hold(s,40,path)
        reply=s.receive(35);elapsed=time.monotonic()-before
        wanted='direct SSH original deadline expired; no automatic retry'
        require(reply.get('id')==40 and reply.get('result',{}).get('isError') is True and
                reply['result']['content']==[{'type':'text','text':wanted}],('original deadline result',reply))
        require(29<=elapsed<=35,'original 30-second deadline changed');terminals=retired(held)
        require(not path.exists(),'deadline-dropped incomplete write published a file')
        reply=s.call(41,'file_info',{'host':'writer','path':str(read_file)})
        require(reply.get('result',{}).get('isError') is False,'shared caller did not recover after deadline')
        code=s.finish();cases.append({'name':'original-deadline-and-recovery','passed':True,'held':held,'terminals':terminals,
            'returncode':code,'seconds':elapsed})
        require(report['control_sources']=={name:pin(Path(__file__).parent/name) for name in report['control_sources']}
                and report['elf']==pin(elf) and report['manifest']==pin(manifest)
                and report['business_evidence']==pin(business/'EVIDENCE.json'),
                'exact runtime/control/business evidence changed during lifecycle execution')
        report.update(status='PASS',cases_count=3,actual_network_ssh=args.transport=='loopback',
                      full_network_lifecycle_qualified=args.transport=='loopback')
    except BaseException as error:
        report.update(status='FAIL',error=repr(error));traceback.print_exc()
    finally:
        for s in sessions:s.close()
        if hold_fd is not None:os.close(hold_fd)
        if server is not None:
            server.log.flush();(out/'sshd-session.log').write_bytes((server.root/'sshd.log').read_bytes());server.close()
        # Only already-dead children adopted by this fixture are reaped here.
        for row in owned:
            current=proc(row['pid'])
            if current and current['start']==row['start'] and current['state']=='Z' and current['ppid']==os.getpid():
                os.waitpid(current['pid'],os.WNOHANG)
        save()
    print(json.dumps({key:value for key,value in report.items() if key!='cases'},sort_keys=True),flush=True)
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
