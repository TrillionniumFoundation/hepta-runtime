#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual sudo/PAM password test in a disposable mount namespace only.
Never edits the host passwd, shadow, sudoers or PAM. Uses a synthetic one-use
account/password, not any user credential. The test has no network activity.
"""
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import time

FIXTURE = r'''
import json,os,pathlib,subprocess,sys
work=pathlib.Path(sys.argv[1])
if os.geteuid()!=0:raise SystemExit('already authorized fixture root required')
if os.readlink('/proc/self/ns/mnt')==os.readlink('/proc/1/ns/mnt'):raise SystemExit('refusing host mount namespace')
subprocess.run(['/usr/bin/mount','--make-rprivate','/'],check=True)
etc=work/'etc';run=work/'run'
for entry in etc.rglob('*'):
 if entry.is_file():os.chown(entry,0,0)
mounted=[]
try:
 for source,target in [(etc,'/etc'),(run,'/run')]:
  subprocess.run(['/usr/bin/mount','--bind',str(source),target],check=True);mounted.append(target)
 def drop():os.setgroups([]);os.setgid(60099);os.setuid(60099)
 result=subprocess.run(['/usr/bin/sudo','-k','-p','HEPTA_SYNTHETIC_PASSWORD:','--','/usr/bin/id','-u'],preexec_fn=drop,env={'PATH':'/usr/bin:/bin','TERM':'xterm','LANG':'C','HOME':'/tmp'})
 print('HEPTA_SUDO_FIXTURE_EXIT='+str(result.returncode),flush=True)
finally:
 for target in reversed(mounted):subprocess.run(['/usr/bin/umount',target],check=True)
'''


def main():
    import crypt
    import pwd
    try:pwd.getpwuid(60099)
    except KeyError:pass
    else:raise RuntimeError("synthetic UID already exists; refusing host identity reuse")
    sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
    from runtime_http_acceptance import Client
    if len(sys.argv)!=2:raise SystemExit('usage: sudo_password_namespace.py REPORT.json')
    before={str(p):p.read_bytes() for p in map(pathlib.Path,['/etc/passwd','/etc/group','/etc/sudoers','/etc/pam.d/sudo']) if os.access(p,os.R_OK)}
    conf=pathlib.Path.home()/'.config/hepta-runtime-operator'
    client=Client('http://127.0.0.1:8790/mcp',(conf/'token').read_text().strip())
    password=secrets.token_urlsafe(32)
    hashed=crypt.crypt(password,crypt.mksalt(crypt.METHOD_SHA512))
    with tempfile.TemporaryDirectory(prefix='hepta-password-fixture-') as tmp:
        root=pathlib.Path(tmp);etc=root/'etc';etc.mkdir();(etc/'pam.d').mkdir();(root/'run').mkdir()
        values={'passwd':'root:x:0:0:root:/root:/bin/sh\nhepta_canary:x:60099:60099:Fixture:/tmp:/bin/sh\n','group':'root:x:0:\nhepta_canary:x:60099:\n','shadow':'root:!:20000:0:99999:7:::\nhepta_canary:'+hashed+':20000:0:99999:7:::\n','nsswitch.conf':'passwd: files\ngroup: files\nshadow: files\nhosts: files\n','sudoers':'Defaults env_reset,lecture=never,timestamp_timeout=0\nhepta_canary ALL=(root) PASSWD: /usr/bin/id -u\n','pam.d/sudo':'auth required pam_unix.so\naccount required pam_unix.so\nsession required pam_permit.so\n'}
        for name,text in values.items():
            p=etc/name;p.write_text(text);p.chmod(0o600 if name=='shadow' else 0o440 if name=='sudoers' else 0o644)
        script=root/'fixture.py';script.write_text(FIXTURE);script.chmod(0o700)
        sid=client.call('sudo_start',{'host':'main','executable':'/usr/bin/unshare','args':['--mount','--fork','--','/usr/bin/python3',str(script),str(root)],'non_interactive':True})['session_id']
        try:
            for _ in range(100):
                part=client.call('pty_read',{'host':'main','session_id':sid})
                if 'HEPTA_SYNTHETIC_PASSWORD:' in part['text']:break
                if part['status']['state']!='running':raise AssertionError(part)
                time.sleep(.05)
            else:raise AssertionError('sudo/PAM password prompt was not observed')
            client.call('pty_write',{'host':'main','session_id':sid,'data':password+'\n','request_id':'synthetic-password-once'})
            for _ in range(100):
                part=client.call('pty_read',{'host':'main','session_id':sid})
                if part['status']['state']!='running':break
                time.sleep(.05)
            assert 'HEPTA_SUDO_FIXTURE_EXIT=0' in part['text'] and '\r\n0\r\n' in part['text'],part
            assert password not in part['text'] and part['output_complete']
            assert all(pathlib.Path(name).read_bytes()==data for name,data in before.items())
            report={'passed':True,'actual_sudo_pam_password_prompt':True,'actual_result_uid':0,'synthetic_namespace_account':True,'host_account_password_tested':False,'host_policy_changed':False,'password_echoed':False,'session_id':sid}
            pathlib.Path(sys.argv[1]).write_text(json.dumps(report,indent=2)+'\n')
            print('PASS actual isolated sudo/PAM password transport; host policy unchanged')
        finally:
            client.call('pty_close',{'host':'main','session_id':sid})


if __name__=='__main__':main()
