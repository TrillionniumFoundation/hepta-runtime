#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Disposable application-level checkpoint handoff fixture, not PID/pipe migration.
Each effect is durably journalled under a unique command identity. Only one
owner may run at once. CHECKPOINT writes a snapshot then exits normally.
"""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import sys


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--directory',required=True);ap.add_argument('--phase',choices=['dc','runtime'],required=True);a=ap.parse_args()
    root=pathlib.Path(a.directory).resolve(strict=True)
    if root.stat().st_uid!=os.getuid() or root.stat().st_mode & 0o077:raise ValueError('fixture directory must be private and owned')
    with (root/'owner.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        journal=root/'effects.jsonl';effects=[];seen={};total=0
        if journal.exists():
            for line in journal.read_text().splitlines():
                effect=json.loads(line)
                if effect['id'] in seen:raise ValueError('duplicate journal effect')
                seen[effect['id']]=effect;effects.append(effect);total+=effect['add']
        print(json.dumps({'event':'READY','pid':os.getpid(),'phase':a.phase,'total':total,'effects':len(effects)}),flush=True)
        for line in sys.stdin:
            command=json.loads(line)
            if command=={'checkpoint':True}:
                digest=hashlib.sha256(journal.read_bytes() if journal.exists() else b'').hexdigest()
                snapshot={'event':'CHECKPOINT','pid':os.getpid(),'phase':a.phase,'total':total,'effects':len(effects),'journal_sha256':digest}
                tmp=root/('checkpoint-'+a.phase+'.new');dest=root/('checkpoint-'+a.phase+'.json')
                with tmp.open('x') as f:json.dump(snapshot,f);f.flush();os.fsync(f.fileno())
                os.replace(tmp,dest)
                fd=os.open(root,os.O_RDONLY)
                try:os.fsync(fd)
                finally:os.close(fd)
                print(json.dumps(snapshot),flush=True);return
            if set(command)!={'id','add'} or not isinstance(command['id'],str) or not isinstance(command['add'],int):raise ValueError('invalid fixture input')
            reused=command['id'] in seen
            if reused:
                if seen[command['id']]['add']!=command['add']:raise ValueError('command identity changed')
            else:
                effect={**command,'phase':a.phase}
                with journal.open('a') as f:f.write(json.dumps(effect)+'\n');f.flush();os.fsync(f.fileno())
                seen[command['id']]=effect;effects.append(effect);total+=command['add']
            print(json.dumps({'event':'EFFECT','id':command['id'],'total':total,'effects':len(effects),'reused':reused}),flush=True)
        raise RuntimeError('EOF without checkpoint')


if __name__=='__main__':main()
