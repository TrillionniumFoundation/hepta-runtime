#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Six-real-host native batch-read acceptance using a disposable HTTP controller.
No installed runtime, facade, DC agent, service or business workspace is changed.
The fixed target aliases are administrator-established channels, never RPC inputs.
"""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import time

from runtime_http_acceptance import Client
from dc_parity_release_six_host_acceptance import HOSTS, digest, services

ROOT = pathlib.Path(__file__).resolve().parents[1]

def target_python(ssh, source):
    p = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
        ssh, 'python3 -c ' + shlex.quote(source)], capture_output=True,
        text=True, timeout=40, check=True)
    return json.loads(p.stdout) if p.stdout.strip() else None

def create_fixture(ssh):
    return target_python(ssh, """
import hashlib,json,os,pathlib,tempfile
base=pathlib.Path(os.path.realpath(tempfile.mkdtemp(prefix='hepta-multi-read-native-')))
root=base/'workspace';root.mkdir(mode=0o700)
text='中文α\\n\\0"\\\\'
(root/'a.txt').write_bytes(text.encode())
(root/'b.txt').write_bytes(b'beta\\r\\n')
(root/'empty').write_bytes(b'')
(root/'invalid').write_bytes(b'bad\\xffutf8')
(root/'oversized').write_bytes(b'x'*65537)
(root/'escaped').write_bytes(b'\\\\'*4096)
(base/'protected').mkdir()
(base/'protected'/'secret').write_text('protected-fixture-secret')
outside=base/'outside';outside.mkdir()
(outside/'secret').write_text('outside-fixture-secret')
(root/'link').symlink_to(outside/'secret')
(root/'dir-link').symlink_to(outside,target_is_directory=True)
os.link(outside/'secret',root/'hardlink')
os.mkfifo(root/'fifo')
print(json.dumps({'base':str(base),'root':str(root),'text':text,
 'sha256':hashlib.sha256(text.encode()).hexdigest()}))
""")

def remove_fixture(ssh, base):
    # These are freshly created roots returned from a fixed script and retained by
    # this invocation only. The prefix and owner prevent mistaken broad deletion.
    target_python(ssh, """
import json,os,pathlib,shutil
p=pathlib.Path(""" + repr(base) + """)
if not p.name.startswith('hepta-multi-read-native-') or p.is_symlink() or p.stat().st_uid!=os.geteuid():
 raise ValueError('refusing non-owned fixture cleanup')
shutil.rmtree(p)
print(json.dumps({'removed':True}))
""")

@contextlib.contextmanager
def qualified_controller(binary, fixtures):
    """Fresh candidate controller for read-only tests; fixtures is host-name keyed."""
    with tempfile.TemporaryDirectory(prefix='hepta-multi-read-controller-') as directory:
        base=pathlib.Path(directory).resolve()
        workspace=base/'workspace'; workspace.mkdir(mode=0o700)
        token=base/'token'; token.write_text(secrets.token_hex(32)); token.chmod(0o600)
        hosts={}
        for name,ssh in HOSTS:
            item=fixtures[name]
            hosts[name]={'ssh_target':ssh, 'platform':'macos' if name=='mac' else 'linux',
                'execution_mode':'operator', 'remote_state_dir':item['base']+'/state',
                'allow_execute':False,'allow_pty':False,'allow_write':False,
                'allowed_read_path_prefixes':[item['root']],
                'allowed_write_path_prefixes':[]}
        hosts['isolated-fixture']={**hosts['main'],'execution_mode':'isolated'}
        config=base/'runtime.json'
        config.write_text(json.dumps({'state_dir':str(base/'state'),
            'controller_workspace_roots':[str(workspace)], 'hosts':hosts}))
        with socket.socket() as s:
            s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
        cmd=[str(pathlib.Path(binary).resolve(strict=True)),'mcp','--path',str(workspace),
            '--bind',f'127.0.0.1:{port}','--runtime-config',str(config),
            '--auth-token-file',str(token)]
        with (base/'controller.log').open('wb') as log:
            process=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
            try:
                for _ in range(90):
                    if process.poll() is not None:
                        raise RuntimeError('disposable candidate controller terminated')
                    try:
                        client=Client(f'http://127.0.0.1:{port}/mcp',token.read_text())
                        break
                    except (OSError,RuntimeError):
                        time.sleep(.1)
                else: raise TimeoutError('disposable candidate controller did not start')
                yield client
            finally:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=10)

def qualify_host(client, name, fixture):
    root=fixture['root']; checks=[]
    def read(paths, **kw):
        return client.call('read_multiple_files',{'host':name,'paths':paths,**kw})
    def denied(paths, label, **kw):
        error=client.call('read_multiple_files',{'host':name,'paths':paths,**kw},denied=True)
        assert 'outside-fixture-secret' not in error
        assert 'protected-fixture-secret' not in error
        assert fixture['text'] not in error
        checks.append(label)
    paths=[root+'/a.txt',root+'/b.txt',root+'/empty']
    result=read(paths)
    assert result['atomic_snapshot'] is False and result['truncated'] is False
    assert result['snapshot_scope']=='independent_file'
    assert [x['path'] for x in result['files']]==paths
    assert result['files'][0]['text']==fixture['text']
    assert result['files'][0]['sha256']==fixture['sha256']
    assert result['files'][1]['text']=='beta\r\n' and result['files'][2]['text']==''
    assert all(x['eof'] and x['version'] for x in result['files'])
    checks.append('exact full UTF8/CRLF/NUL, independent version/hash')
    for suffix,label in [('missing','missing path'),('invalid','invalid UTF8'),
            ('oversized','file ceiling'),('link','leaf symlink'),
            ('dir-link/secret','parent symlink'),('hardlink','outside-root hardlink'),
            ('fifo','FIFO regular-file rejection')]:
        denied([paths[0],root+'/'+suffix],label,max_file_bytes=65536)
    denied([paths[0],fixture['base']+'/outside/secret'],'outside root')
    denied([paths[0],fixture['base']+'/protected/secret'],'outside-root protected fixture')
    denied([root+'/./a.txt'],'dot lexical alias')
    denied([root+'/../outside/secret'],'traversal')
    denied([paths[0],paths[0]],'duplicate path')
    denied([],'empty batch')
    denied([paths[0]],'invalid file bound',max_file_bytes=65537)
    denied([paths[0]],'invalid response bound',max_response_bytes=262145)
    denied([root+'/escaped'],'escaped shared wire ceiling',max_response_bytes=4096)
    decoded=read([root+'/escaped'],max_response_bytes=262144)
    wire={'content':[{'type':'text','text':json.dumps(decoded,ensure_ascii=False,
        sort_keys=True,separators=(',',':'))}],'isError':False}
    assert len(json.dumps(wire,ensure_ascii=False,separators=(',',':')).encode())<=262144
    checks.append('quote/backslash wire budget counts JSON escaping')
    return {'host':name,'complete':True,'passed':len(checks),'checks':checks}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binary',required=True)
    ap.add_argument('--out',required=True)
    args=ap.parse_args()
    binary=pathlib.Path(args.binary).resolve(strict=True)
    report={'schema':'hepta-multi-read-six-host-native-v1',
        'recorded_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_head':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],
            text=True).strip(),
        'binary_sha256':digest(binary),'model_origin':False,
        'installed_runtime_changed':False,'dc_changed':False,
        'full_dc_replacement_qualified':False,'results':[],'complete':False}
    fixtures={}; cleanup=[]
    dest=pathlib.Path(args.out)
    if dest.exists(): raise ValueError('receipt path must be absent')
    try:
        report['protected_services_before']=services()
        for name,ssh in HOSTS:
            fixtures[name]=create_fixture(ssh)
        with qualified_controller(binary,fixtures) as client:
            catalog={x['name']:x for x in client.rpc('tools/list',{})['tools']}
            annotations=catalog['read_multiple_files']['annotations']
            assert annotations['readOnlyHint'] is True
            assert annotations['destructiveHint'] is False
            for name,_ in HOSTS:
                row=qualify_host(client,name,fixtures[name])
                report['results'].append(row)
                print('PASS',name,row['passed'],flush=True)
            client.call('read_multiple_files',{'host':'isolated-fixture',
                'paths':[fixtures['main']['root']+'/a.txt']},denied=True)
            client.call('read_multiple_files',{'host':'unregistered',
                'paths':[fixtures['main']['root']+'/a.txt']},denied=True)
            report['isolated_and_unknown_hosts_denied']=True
    except Exception as exc:
        report['error_type']=type(exc).__name__
        report['error']=str(exc)[:1500]
        raise
    finally:
        for name,ssh in HOSTS:
            if name not in fixtures: continue
            try:
                remove_fixture(ssh,fixtures[name]['base'])
                cleanup.append({'host':name,'removed':True})
            except Exception as exc:
                cleanup.append({'host':name,'removed':False,'error_type':type(exc).__name__})
        report['cleanup']=cleanup
        try:
            report['protected_services_after']=services()
            report['service_identity_stable']=report['protected_services_before']==report['protected_services_after']
        except Exception as exc:
            report['service_identity_stable']=False
            report['service_error_type']=type(exc).__name__
        report['complete']=(len(report['results'])==len(HOSTS)
            and report.get('isolated_and_unknown_hosts_denied') is True
            and report.get('service_identity_stable') is True
            and len(cleanup)==len(HOSTS) and all(x['removed'] for x in cleanup))
        with dest.open('x',encoding='utf-8') as f:
            f.write(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        print('MULTI_READ_COMPLETE',report['complete'],flush=True)
    if not report['complete']: sys.exit(1)

if __name__=='__main__':
    main()
