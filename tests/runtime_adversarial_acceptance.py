#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bounded destructive tests of runtime-owned jobs only; never reboot a host."""
import argparse,json,pathlib,subprocess,time,uuid
from runtime_http_acceptance import Client

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--url',default='http://127.0.0.1:8789/mcp');ap.add_argument('--unit',default='hepta-runtime-canary.service');ap.add_argument('--out',required=True);a=ap.parse_args()
    token=pathlib.Path('/etc/hepta-runtime/mcp-token').read_text().strip()
    c=Client(a.url,token);key=uuid.uuid4().hex;checks=[]
    def passed(name,detail=None):
        checks.append(dict(check=name,detail=detail,result='passed'));print('PASS',name,flush=True)
        pathlib.Path(a.out).write_text(json.dumps(dict(checks=checks,partial=True),indent=2))
    def start(code,**extra):
        return c.call('process_start',dict(host='rog',executable='/usr/bin/python3',args=['-c',code],cwd='/var/lib/hepta-runtime/workspaces',timeout_seconds=180,**extra))['job']['id']
    def wait(j):
        for _ in range(18):
            result=c.call('process_wait',dict(host='rog',job_id=j,timeout_seconds=10))
            if result['state'] not in ('running','launching','pending'):return result
        raise AssertionError('owned test job did not reach terminal state')
    def output(j):return c.call('process_read',dict(host='rog',job_id=j))['stdout']['text']
    # Schema rejects a hidden naked-PID cancellation argument, even with a valid job.
    j=start("print('VALID')");assert wait(j)['state']=='succeeded'
    try:c.call('process_cancel',dict(host='rog',job_id=j,pid=1));raise AssertionError('unknown PID field accepted')
    except RuntimeError:pass
    except AssertionError as e:
        if 'unknown PID field accepted' in str(e):raise
    passed('unknown PID fields rejected at MCP boundary')
    # Failure exit status and stderr are not reclassified as success.
    j=start("import sys;sys.stderr.write('EXPECTED_ERROR');sys.exit(7)")
    r=wait(j);assert r['state']=='failed' and r['exit_code']==7,r
    assert 'EXPECTED_ERROR' in c.call('process_read',dict(host='rog',job_id=j))['stderr']['text']
    passed('nonzero child exit and stderr preserved')
    # Resource requests cannot exceed the independent administrator policy.
    c.call('process_start',dict(host='rog',executable='/usr/bin/true',cpu_quota_percent=1000),denied=True)
    passed('root-helper administrator quota cannot be raised by caller')
    # Child-tree cancellation kills a forked descendant, not merely the parent.
    marker='cancel-descendant-'+key
    child="import pathlib,time; p=pathlib.Path('/workspace/"+marker+"'); n=0\nwhile True:\n p.write_text(str(n));n+=1;time.sleep(.1)"
    j=start("import subprocess,time,pathlib;subprocess.Popen(['/usr/bin/python3','-c',"+repr(child)+"]);p=pathlib.Path('/workspace/"+marker+"')\nwhile not p.exists():time.sleep(.01)\nprint('SPAWNED',flush=True);time.sleep(150)")
    for _ in range(30):
        if 'SPAWNED' in output(j):break
        time.sleep(.1)
    assert 'SPAWNED' in output(j)
    c.call('process_cancel',dict(host='rog',job_id=j));ended=wait(j);assert ended['state']=='cancelled',ended
    # Check a continuous heartbeat has stopped, rather than relying on a
    # fixed delayed marker whose deadline can expire during SSH congestion.
    verify=start("import pathlib,time;p=pathlib.Path('/workspace/"+marker+"');a=p.read_text();time.sleep(1.5);print('STABLE' if p.read_text()==a else 'RUNNING')")
    assert wait(verify)['state']=='succeeded';assert output(verify).strip()=='STABLE'
    passed('cancellation terminates owned descendant cgroup')
    # SIGKILL controller: independent remote job and once-only effect survive.
    marker='crash-once-'+key
    p=dict(host='rog',executable='/usr/bin/python3',args=['-c',"import time;open('"+marker+"','a').write('1');print('STARTED',flush=True);time.sleep(35);print('COUNT='+open('"+marker+"').read(),flush=True)"],cwd='/var/lib/hepta-runtime/workspaces',timeout_seconds=180,idempotency_key=key+'-crash')
    j=c.call('process_start',p)['job']['id']
    for _ in range(30):
        if 'STARTED' in output(j):break
        time.sleep(.1)
    assert 'COUNT=' not in output(j),'test job already finished before crash injection'
    subprocess.run(['systemctl','kill','--kill-whom=main','--signal=KILL',a.unit],check=True,timeout=10)
    connected=False
    for _ in range(100):
        try:c=Client(a.url,token);connected=True;break
        except (OSError,RuntimeError):time.sleep(.2)
    assert connected,'controller did not restart'
    r=c.call('process_start',p);assert r['reused'] and r['job']['id']==j
    assert wait(j)['state']=='succeeded';assert output(j).splitlines().count('COUNT=1')==1
    passed('SIGKILL controller recovery without duplicate side effect',dict(job_id=j))
    # Log storage remains bounded while pipes are drained to avoid deadlock.
    j=start("import sys;sys.stdout.buffer.write(b'x'*(17*1024*1024));sys.stderr.write('DRAINED')")
    assert wait(j)['state']=='succeeded'
    r=c.call('process_read',dict(host='rog',job_id=j,stdout_offset=16*1024*1024,limit=1))
    assert r['stdout']['size']==16*1024*1024 and r['stdout']['eof'],r
    tail=c.call('process_read',dict(host='rog',job_id=j,stdout_offset=16*1024*1024,limit=64))
    assert tail['stderr']['text']=='DRAINED',tail
    passed('16MiB log bound drains producer without deadlock')
    # PTY byte reads preserve Unicode even when one byte splits a code point.
    sid=c.call('pty_start',dict(host='rog',executable='/usr/bin/python3',args=['-q'],cwd='/var/lib/hepta-runtime/workspaces'))['session_id']
    for _ in range(60):
        r=c.call('pty_read',dict(host='rog',session_id=sid))
        if '>>>' in r['text']:break
        time.sleep(.1)
    cursor=r['next_offset'];c.call('pty_write',dict(host='rog',session_id=sid,data="print('中文α')\n"))
    # Wait for actual output rather than assuming the SSH/PTY response is ready
    # after a fixed sleep; an empty page is not an EOF for a live terminal.
    for _ in range(100):
        available=c.call('pty_read',dict(host='rog',session_id=sid,offset=cursor))
        if '\n中文α\r\n' in available['text']:break
        time.sleep(.2)
    assert '\n中文α\r\n' in available['text'],available
    end=available['available_end'];data=b''
    for _ in range(200):
        r=c.call('pty_read',dict(host='rog',session_id=sid,offset=cursor,limit=1));data+=bytes.fromhex(r['bytes_hex']);cursor=r['next_offset']
        if cursor>=end:break
    assert '中文α' in data.decode(errors='strict'),data
    c.call('pty_read',dict(host='rog',session_id=sid,offset=10**12),denied=True)
    c.call('pty_close',dict(host='rog',session_id=sid))
    passed('PTY lossless Unicode bytes and future-cursor rejection')
    pathlib.Path(a.out).write_text(json.dumps(dict(checks=checks,partial=False,passed=len(checks)),indent=2));print('ALL_PASS',len(checks),flush=True)
if __name__=='__main__':main()
