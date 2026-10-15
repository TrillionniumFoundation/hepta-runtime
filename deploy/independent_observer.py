#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Finite unprivileged peer observer. No shutdown, wake, SSH execution or service changes.
Observe an explicitly configured LAN health fixture and the controller's SSH
banner. All reports remain on the peer even after the initiating SSH channel ends.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import pathlib
import secrets
import socket
import sys
import time


def probe(address,port,key,expected_boot):
    challenge=secrets.token_hex(16)
    try:
        with socket.create_connection((address,port),timeout=1) as conn:
            conn.settimeout(1);conn.sendall((challenge+'\n').encode());data=b''
            while b'\n' not in data:
                block=conn.recv(4097-len(data))
                if not block or len(data)+len(block)>4096:raise ValueError('bounded response missing')
                data+=block
            value=json.loads(data)
        message=(challenge+'\0'+value['boot_id']).encode()
        valid=hmac.compare_digest(hmac.new(key,message,hashlib.sha256).hexdigest(),value['proof'])
        return {'reachable':valid,'controller_boot_id':value['boot_id'] if valid else None,'identity_matches':valid and value['boot_id']==expected_boot}
    except (OSError,ValueError,KeyError,TypeError) as error:return {'reachable':False,'error':type(error).__name__}


def ssh_banner(address):
    try:
        with socket.create_connection((address,22),timeout=1) as conn:
            conn.settimeout(1);value=conn.recv(256)
        return {'reachable':value.startswith(b'SSH-2.0-'),'banner_sha256':hashlib.sha256(value).hexdigest()}
    except OSError as error:return {'reachable':False,'error':type(error).__name__}


def save(path,result):
    temp=path.with_suffix('.new');fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(result,f,indent=2);f.flush();os.fsync(f.fileno())
    os.replace(temp,path)


def main():
    path=pathlib.Path(sys.argv[1]);cfg=json.loads(path.read_text());root=path.parent
    if path.stat().st_uid!=os.getuid() or path.stat().st_mode&0o077:raise PermissionError('private account-owned observer config required')
    address=ipaddress.IPv4Address(cfg['controller_address'])
    if not address.is_private or address.is_loopback or address.is_unspecified:raise ValueError('explicit private LAN address required')
    count=int(cfg['samples']);port=int(cfg['fixture_port'])
    if not 6<=count<=60 or not 1024<=port<=65535:raise ValueError('bounded sample count/fixture port required')
    key=bytes.fromhex(cfg['fixture_key'])
    if len(key)!=32:raise ValueError('invalid fixture authentication key')
    result={'complete':False,'peer_hostname':socket.gethostname(),'peer_boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'peer_pid':os.getpid(),'peer_uid':os.getuid(),'initial_parent_pid':os.getppid(),'samples':[],
            'power_control_performed':False,'controller_credentials_used':False,'controller_reboot_claimed':False}
    started=time.monotonic()
    try:
        for n in range(count):
            result['samples'].append({'sequence':n,'age_seconds':round(time.monotonic()-started,3),'parent_pid':os.getppid(),
                'fixture':probe(str(address),port,key,cfg['expected_controller_boot_id']),'controller_ssh':ssh_banner(str(address))})
            save(root/'report.json',result)
            if n<count-1:time.sleep(1)
        result['complete']=True;save(root/'report.json',result)
    finally:
        path.unlink(missing_ok=True)  # Ephemeral fixture key, not an account credential.


if __name__=='__main__':main()
