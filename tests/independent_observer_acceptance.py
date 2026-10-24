#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Verify a detached peer observer against one owned test port; no real service outage.
The existing controller SSH server is only read for its banner, never authenticated
or restarted. The initiating SSH process exits before the observation experiment.
"""
import argparse
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import shlex
import socket
import subprocess
import threading
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--peer',required=True);ap.add_argument('--controller-address',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();key=secrets.token_bytes(32)
    ssh=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=6',a.peer]
    first=socket.socket();first.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);first.bind((a.controller_address,0));port=first.getsockname()[1];first.listen(4);first.settimeout(.2)
    up=threading.Event();up.set();done=threading.Event();failures=[]
    def serve():
        server=first
        try:
            while not done.is_set():
                if not up.is_set():
                    if server is not None:server.close();server=None
                    time.sleep(.05);continue
                if server is None:
                    server=socket.socket();server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind((a.controller_address,port));server.listen(4);server.settimeout(.2)
                try:conn,_=server.accept()
                except socket.timeout:continue
                with conn:
                    conn.settimeout(1);challenge=conn.recv(128).decode().strip()
                    if len(challenge)!=32 or any(c not in '0123456789abcdef' for c in challenge):continue
                    message=(challenge+'\0'+boot).encode();proof=hmac.new(key,message,hashlib.sha256).hexdigest()
                    conn.sendall((json.dumps({'boot_id':boot,'proof':proof})+'\n').encode())
        except Exception as error:failures.append(type(error).__name__+': '+str(error))
        finally:
            if server is not None:server.close()
    thread=threading.Thread(target=serve);thread.start();report={'complete':False,'controller_boot_id':boot,'peer':a.peer,'fixture_port':port,'real_services_interrupted':False}
    def remote(code,payload=None):
        return subprocess.run([*ssh,'/usr/bin/python3 -c '+shlex.quote(code)],input=json.dumps(payload) if payload is not None else None,text=True,capture_output=True,timeout=15)
    peer_root=None
    try:
        cfg={'controller_address':a.controller_address,'fixture_port':port,'fixture_key':key.hex(),'expected_controller_boot_id':boot,'samples':30}
        source=(ROOT/'deploy/independent_observer.py').read_text()
        setup="import pathlib,os,json,sys,tempfile,subprocess;q=json.load(sys.stdin);root=pathlib.Path(tempfile.mkdtemp(prefix='hepta-independent-observer-'));root.chmod(0o700);script=root/'observer.py';script.write_text(q['source']);script.chmod(0o600);config=root/'config.json';config.write_text(json.dumps(q['config']));config.chmod(0o600)\nwith (root/'worker.log').open('wb') as log:p=subprocess.Popen(['/usr/bin/python3',str(script),str(config)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,close_fds=True)\nprint(json.dumps({'root':str(root),'pid':p.pid,'bootstrap_pid':os.getpid(),'hostname':__import__('socket').gethostname()}))"
        launch=remote(setup,{'source':source,'config':cfg})
        if launch.returncode:raise RuntimeError(launch.stderr[-1000:])
        started=json.loads(launch.stdout);peer_root=started['root'];report['peer_launch']=started
        if started['hostname']==socket.gethostname():raise ValueError('observer must execute on a different physical host')
        report['initiating_ssh_exited_before_outage']=True
        time.sleep(6);up.clear();report['fixture_unavailable_started']=time.monotonic()
        time.sleep(5);up.set();report['fixture_recovered_started']=time.monotonic()
        deadline=time.monotonic()+45;received=None
        while time.monotonic()<deadline:
            time.sleep(3)
            fetched=remote('import pathlib;path=pathlib.Path('+repr(peer_root)+')/"report.json";print(path.read_text() if path.exists() else "null")')
            if fetched.returncode:continue
            received=json.loads(fetched.stdout)
            if received and received.get('complete'):break
        if not received or not received.get('complete'):raise RuntimeError('peer did not produce a completed independent receipt')
        samples=received['samples'];states=[v['fixture']['reachable'] for v in samples]
        transitions=[v for n,v in enumerate(states) if n==0 or v!=states[n-1]]
        assert transitions==[True,False,True],transitions
        assert all(v['controller_ssh']['reachable'] for v in samples),'real SSH unexpectedly unavailable'
        assert all(v['fixture'].get('identity_matches') is True for v in samples if v['fixture']['reachable'])
        assert not pathlib.Path('/proc',str(started['pid'])).exists() or received['peer_boot_id']!=boot
        assert all(v['parent_pid']!=started['bootstrap_pid'] for v in samples[1:])
        assert not failures,failures
        report.update(complete=True,peer_receipt=received,observed_transitions=transitions,
                      independent_process_outlived_launch_channel=True,actual_controller_boot_changed=False,
                      physical_power_control_verified=False,scope='independent observation only; owned ephemeral port outage/recovery, not controller restart or power removal')
    finally:
        done.set();thread.join(timeout=3)
        output=pathlib.Path(a.out);fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.write('\n')
    print('INDEPENDENT_OBSERVER_PASS '+json.dumps({'peer':a.peer,'samples':len(report['peer_receipt']['samples']),'transitions':report['observed_transitions'],'real_controller_restarted':False,'power_control_verified':False}))


if __name__=='__main__':main()
