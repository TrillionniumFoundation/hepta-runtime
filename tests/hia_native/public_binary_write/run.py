#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual public binary_write, audit ordering and retained read route controls.

The local-command transport is an explicitly limited development fixture. The
loopback mode starts a real OpenSSH server and preserves the runtime's actual
eleven SSH arguments. Original Python runs only as a comparison oracle.
"""
from pathlib import Path
import argparse
import ast
import base64
import hashlib
import json
import os
import pwd
import select
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback


def require(value,label):
    if not value:raise AssertionError(label)


def pin(path):
    raw=Path(path).read_bytes()
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def compact(value):return json.dumps(value,ensure_ascii=False,separators=(',',':'))


class Session:
    def __init__(self,elf,config,folder,env):
        self.folder=folder;folder.mkdir();self.stderr=(folder/'stderr').open('xb')
        self.process=subprocess.Popen([str(elf),'--runtime-config',str(config)],cwd=folder,
            env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,start_new_session=True)
        self.buffer=b'';self.requests=[];self.responses=[]
        result=self.exchange({'jsonrpc':'2.0','id':1,'method':'initialize','params':{
            'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'native-write-gate','version':'1'}}})
        require(result.get('result',{}).get('protocolVersion')=='2025-06-18',('actual SDK initialization',result))
        self.exchange({'jsonrpc':'2.0','method':'notifications/initialized'})

    def send(self,value):
        self.requests.append(value)
        self.process.stdin.write(compact(value).encode()+b'\n');self.process.stdin.flush()

    def receive(self,seconds=45):
        deadline=time.monotonic()+seconds
        while b'\n' not in self.buffer:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.process.stdout],[],[],remaining)[0]:
                raise AssertionError('actual public response deadline')
            part=os.read(self.process.stdout.fileno(),65536)
            if not part:raise AssertionError(('actual public EOF',self.process.poll()))
            self.buffer+=part
        raw,self.buffer=self.buffer.split(b'\n',1)
        (self.folder/('response-%03d.wire'%len(self.responses))).write_bytes(raw+b'\n')
        value=json.loads(raw);self.responses.append(value);return value

    def exchange(self,value):
        self.send(value)
        if 'id' not in value:return None
        response=self.receive();require(response.get('id')==value['id'],('public response identity',response))
        return response

    def call(self,identity,name,args):
        return self.exchange({'jsonrpc':'2.0','id':identity,'method':'tools/call','params':{'name':name,'arguments':args}})

    def finish(self):
        if not self.process.stdin.closed:self.process.stdin.close()
        code=self.process.wait(timeout=40)
        tail=self.buffer+self.process.stdout.read()
        require(code==0 and tail==b'',('normal SDK EOF and owned worker joins',code,tail))
        return code

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=10)
        for file in (self.process.stdin,self.process.stdout,self.stderr):
            if not file.closed:file.close()
        (self.folder/'requests.json').write_text(json.dumps(self.requests,ensure_ascii=False,indent=2)+'\n')


class Original:
    def __init__(self,python,source,folder):
        names=['file_metadata.py','inode_patch.py','binary_file.py']
        self.sources={name:pin(source/'src/mcp/runtime'/name) for name in names}
        worker="""import sys,json
from pathlib import Path
assert sys.version_info[:2]==(3,14),sys.version
root=Path(sys.argv[1]);ns={'__name__':'public_binary_write_original'}
raw='\\n'.join((root/'src/mcp/runtime'/name).read_text() for name in ('file_metadata.py','inode_patch.py','binary_file.py'))
exec(compile(raw,'complete-original-binary-source','exec'),ns)
for line in sys.stdin:
 try:
  query=json.loads(line)
  if query.get('fixture')=='fingerprint':
   descriptor,name=ns['parent'](query['root'],query['path'])
   try:value=ns['fingerprint'](descriptor,name)
   finally:ns['os'].close(descriptor)
  else:value=ns['main'](query)
  result={'ok':True,'value':value}
 except Exception as error:result={'ok':False,'error':type(error).__name__+': '+str(error)}
 print(json.dumps(result,ensure_ascii=False),flush=True)
"""
        self.stderr=(folder/'original.stderr').open('xb')
        self.records=(folder/'original-frames.jsonl').open('x')
        self.process=subprocess.Popen([str(python),'-I','-B','-c',worker,str(source)],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=self.stderr,text=True)

    def call(self,query):
        self.process.stdin.write(compact(query)+'\n');self.process.stdin.flush()
        line=self.process.stdout.readline()
        require(bool(line),('original helper exited',self.process.poll()))
        value=json.loads(line)
        self.records.write(compact({'query':query,'reply':value})+'\n');self.records.flush()
        return value

    def close(self):
        self.process.stdin.close();code=self.process.wait(timeout=5)
        self.process.stdout.close();self.stderr.close();self.records.close()
        require(code==0,('original helper process',code))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--elf',type=Path)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--reference-python',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--transport',choices=('loopback','local-command'),required=True)
    args=parser.parse_args();source=args.source.resolve(strict=True);manifest=args.manifest.resolve(strict=True)
    document=json.loads(manifest.read_bytes())
    require(document['status']=='PASS' and document['physical_images']==133 and
            document['runtime_hia_images']==175 and len(document['members'])==130,'exact new complete graph required')
    require(all(document[name] is False for name in ('private_instance_fixture','private_task_pump_fixture',
        'private_task_pump_trace','actual_fixture_private_selectors')),'private selector carrier cannot substitute for public MCP')
    elf=(args.elf or manifest.parent/document['elf']).resolve(strict=True)
    require(pin(elf)=={'bytes':document['elf_bytes'],'sha256':document['elf_sha256']},'complete actual ELF identity')
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    started=time.monotonic();cases=[];sessions=[];original=None;server=None
    report={'schema':'hepta.runtime.public-binary-write.business.v1','status':'RUNNING','manifest':pin(manifest),
        'elf':pin(elf),'source_binding':document['source_binding']['manifest_sha256'],'transport':args.transport,
        'actual_default_entrypoint':True,'original_full_runtime_rerun':False,'whole_runtime_replaced':False,
        'old_path_removed':False,'public_route_qualified':False,'cases':cases}
    controls={name:pin(Path(__file__).parent/name) for name in ('run.py','lifecycle.py')}
    report['control_sources']=controls
    def save():
        report['elapsed_seconds']=time.monotonic()-started
        (out/'EVIDENCE.json').write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    def record(label,**details):
        cases.append({'name':label,'passed':True,**details});save()
        print('PUBLIC_WRITE_CASE',label,'PASS',flush=True)
    try:
        files=out/'files';files.mkdir();state=out/'state';bin_dir=out/'bin';bin_dir.mkdir()
        config=out/'config.json'
        config.write_text(compact({'state_dir':str(state),'controller_workspace_roots':[str(out)],'hosts':{
            'writer':{'ssh_target':'local-native','remote_state_dir':str(out/'remote'),'execution_mode':'operator','allow_write':True,
                'allowed_read_path_prefixes':[str(files)],'allowed_write_path_prefixes':[str(files)]},
            'isolated':{'ssh_target':'local-isolated','remote_state_dir':str(out/'isolated'),'execution_mode':'isolated',
                'allowed_read_path_prefixes':[],'allowed_write_path_prefixes':[]}}})+'\n')
        argv_file=out/'ssh-arguments.jsonl'
        if args.transport=='loopback':
            fixture=source/'tests/hia_native/test_native_read_bootstrap.py';raw=fixture.read_text()
            node=next(n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef) and n.name=='LoopbackSSH')
            whole_class=ast.get_source_segment(raw,node)
            namespace=dict(globals());exec(compile(whole_class,str(fixture),'exec'),namespace)
            server=namespace['LoopbackSSH'](out)
            client=out/'ssh_client_config'
            client.write_text('\n'.join(['Host local-native',' HostName 127.0.0.1',' Port '+str(server.port),
                ' User '+server.user,' IdentityFile '+str(server.root/'client'),' IdentitiesOnly yes',
                ' UserKnownHostsFile '+str(server.known_hosts),' GlobalKnownHostsFile /dev/null',
                ' StrictHostKeyChecking yes',' BatchMode yes',' LogLevel ERROR','']))
            tail='os.execv('+repr(server.ssh)+',['+repr(server.ssh)+',"-F",'+repr(str(client))+',*args])\n'
            report['ssh_fixture_original_source']=pin(fixture)
            report['ssh_fixture_complete_class_sha256']=hashlib.sha256(whole_class.encode()).hexdigest()
        else:tail='os.execv("/bin/sh",["sh","-c",args[-1]])\n'
        shim=bin_dir/'ssh'
        shim.write_text('#!/usr/bin/python3 -I\nimport os,sys,json\nargs=sys.argv[1:]\n'+
            'fd=os.open('+repr(str(argv_file))+',os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)\n'+
            'os.write(fd,(json.dumps(args,ensure_ascii=False)+"\\n").encode());os.close(fd)\n'+tail)
        shim.chmod(0o755)
        env={'PATH':str(bin_dir)+':/usr/bin:/bin','HOME':str(out),'LC_ALL':'C'}
        original=Original(args.reference_python,source,out);report['original_sources']=original.sources
        session=Session(elf,config,out/'public-session',env);sessions.append(session)
        identity=10
        def invoke(tool,arguments):
            nonlocal identity
            identity+=1;return session.call(identity,tool,arguments)
        def events():
            path=state/'audit/events.jsonl'
            return [json.loads(row) for row in path.read_bytes().splitlines()] if path.exists() else []
        def ssh_rows():return [json.loads(row) for row in argv_file.read_bytes().splitlines()] if argv_file.exists() else []
        def parameters(path,data=b'',prior='absent',host='writer'):
            return {'host':host,'path':str(path),'data_base64':base64.b64encode(data).decode(),'expected_version':prior}
        def result(reply,error=False):
            value=reply.get('result');require(isinstance(value,dict) and value.get('isError') is error,reply)
            content=value.get('content');require(isinstance(content,list) and len(content)==1 and content[0].get('type')=='text',reply)
            return content[0]['text']
        def audit_delta(before,path):
            after=events();require(len(after)==before+1,('audit append count',before,after))
            entry=after[-1]
            require(entry['action']=='native_binary_write' and entry['host']=='writer' and
                    entry['subject']==str(path) and entry['outcome']=={'op':'write'},('complete audit event',entry))
        def success(label,path,data,prior='absent'):
            before=len(events());count=len(ssh_rows())
            text=result(invoke('binary_write',parameters(path,data,prior)))
            require(path.read_bytes()==data,'complete written bytes differ')
            actual=original.call({'fixture':'fingerprint','root':str(files),'path':str(path)})
            require(actual['ok'],actual);expected={'written':len(data),**actual['value']}
            require(text==json.dumps(expected,ensure_ascii=False,sort_keys=True,separators=(',',':')),('full original metadata/Value',text,expected))
            audit_delta(before,path);require(len(ssh_rows())==count+1,'exact single SSH attempt')
            record(label,bytes=len(data),version=expected['version']);return expected['version']
        def remote_error(label,path,data,prior='absent'):
            before=len(events());count=len(ssh_rows())
            query={'op':'write','root':str(files),'path':str(path),'data_base64':data,'expected_version':prior}
            expected=original.call(query);require(not expected['ok'],('expected original refusal',label,expected))
            args=parameters(path);args.update(data_base64=data,expected_version=prior)
            text=result(invoke('binary_write',args),True)
            wanted='remote helper on local-native failed with 1\nstdout:\n\nstderr:\n'+expected['error']
            require(text==wanted,('complete original remote error',label,text,wanted))
            audit_delta(before,path);require(len(ssh_rows())==count+1,'remote refusal SSH attempt count')
            record(label,error=text)
        catalog=session.exchange({'jsonrpc':'2.0','id':2,'method':'tools/list'})
        names=[tool['name'] for tool in catalog['result']['tools']]
        require(len(names)==113 and 'binary_write' in names,'complete configured catalog changed')
        record('configured-catalog',tools=len(names))
        first=files/'first.bin';success('create-empty',first,b'')
        version=success('create-all-byte-values',files/'all.bin',bytes(range(256))*3)
        target=files/'all.bin';os.chmod(target,0o640);os.setxattr(target,'user.public-write',b'preserve-exact')
        current=original.call({'op':'info','root':str(files),'path':str(target)})['value']['version']
        success('replace-current-version-and-metadata',target,b'replaced\0\xff',current)
        require(stat.S_IMODE(target.stat().st_mode)==0o640 and os.getxattr(target,'user.public-write')==b'preserve-exact','rights/xattrs changed')
        success('create-one-MiB',files/'maximum.bin',bytes(range(256))*4096)
        success('unicode-quoted-path',files/'雪"\n.txt','雪 and text\n'.encode())
        remote_error('stale-version',target,'YQ==','stale')
        remote_error('create-only-collision',target,'YQ==')
        for label,value in [('leading-padding','='),('excess-padding','YQ==='),('after-padding','YQ==A'),('invalid-alphabet','!')]:
            remote_error('base64-'+label,files/(label+'.bin'),value)
        remote_error('missing-parent',files/'missing/new.bin','YQ==')
        remote_error('embedded-NUL',files/'bad\0name','YQ==')
        link=files/'hardlinked.bin';target2=files/'hardlinked-alias.bin';link.write_bytes(b'original');os.link(link,target2)
        prior=original.call({'op':'info','root':str(files),'path':str(link)})['value']['version']
        remote_error('hardlink-replacement',link,'YQ==',prior)
        require(link.read_bytes()==b'original' and target2.read_bytes()==b'original','hardlink refusal changed content')
        for label,change in [('missing-version',lambda v:v.pop('expected_version')),
                             ('wrong-type',lambda v:v.update(data_base64=17)),
                             ('unknown-field',lambda v:v.update(extra=True))]:
            before=len(events());count=len(ssh_rows());value=parameters(files/(label+'.bin'));change(value)
            reply=invoke('binary_write',value)
            require(reply.get('error',{}).get('code')==-32602,('original typed boundary',label,reply))
            require(len(events())==before and len(ssh_rows())==count,'typed refusal reached audit/SSH')
            record(label,response=reply)
        for label,value in [('encoded-bound',parameters(files/'oversized.bin')),
                            ('isolated-mode',parameters(files/'isolated.bin',host='isolated')),
                            ('outside-write-root',parameters(out/'outside.bin'))]:
            if label=='encoded-bound':value['data_base64']='A'*1398105
            before=len(events());count=len(ssh_rows());reply=invoke('binary_write',value);text=result(reply,True)
            require(len(events())==before and len(ssh_rows())==count,'local refusal reached audit/SSH')
            require(not Path(value['path']).exists(),'local refusal wrote target')
            record(label,error=text)
        # A real failed audit must block the very first SSH attempt, including
        # when a warm successful audit proof existed just before this request.
        audit=state/'audit/events.jsonl';audit_alias=out/'audit-alias';os.link(audit,audit_alias)
        before=audit.read_bytes();count=len(ssh_rows());blocked=files/'audit-blocked.bin'
        error=result(invoke('binary_write',parameters(blocked,b'blocked')),True)
        require(audit.read_bytes()==before and len(ssh_rows())==count and not blocked.exists(),
                'audit failure allowed remote write or mutated the event')
        record('audit-failure-blocks-SSH',error=error)
        audit_alias.unlink();success('audit-recovery',blocked,b'recovered')
        for tool,query in [('file_info',{'op':'info','root':str(files),'path':str(target)}),
                           ('binary_read',{'op':'read','root':str(files),'path':str(target),'offset':0,'limit':64,'expected_version':None})]:
            before=len(events());args2={'host':'writer','path':str(target)}
            if tool=='binary_read':args2.update(offset=0,limit=64)
            expected=original.call(query);require(expected['ok'],expected)
            text=result(invoke(tool,args2))
            require(text==json.dumps(expected['value'],ensure_ascii=False,sort_keys=True,separators=(',',':')),'retained read result differs')
            require(len(events())==before,'read unexpectedly emitted a write audit')
            record('retained-'+tool)
        rows=ssh_rows();fixed=['-T','-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no']
        require(all(len(row)==11 and row[:9]==fixed and row[9]=='local-native' and row[10] for row in rows),'original SSH argv changed')
        code=session.finish();record('normal-EOF-and-joins',returncode=code)
        require(controls=={name:pin(Path(__file__).parent/name) for name in controls}
                and report['elf']==pin(elf) and report['manifest']==pin(manifest)
                and original.sources=={name:pin(source/'src/mcp/runtime'/name) for name in original.sources},
                'complete runtime/control/original source identity changed during actual qualification')
        report.update(status='PASS',cases_count=len(cases),actual_ssh_invocations=len(rows),audit_events=len(events()),
            actual_network_ssh=args.transport=='loopback',full_network_route_qualified=args.transport=='loopback',
            ssh_argument_file=pin(argv_file))
    except BaseException as error:
        report.update(status='FAIL',error=repr(error));traceback.print_exc()
    finally:
        for session in sessions:session.close()
        if original is not None:original.close()
        if server is not None:
            server.log.flush();(out/'sshd-session.log').write_bytes((server.root/'sshd.log').read_bytes());server.close()
        save()
    print(json.dumps({key:value for key,value in report.items() if key!='cases'},sort_keys=True),flush=True)
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
