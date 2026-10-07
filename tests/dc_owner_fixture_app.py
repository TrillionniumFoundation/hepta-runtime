#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Disposable stateful app for actual Desktop Commander owner handoff acceptance."""
import hashlib,json,os,sys
memory=os.urandom(32);total=0
def emit(event):
    print(json.dumps({'event':event,'pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total}),flush=True)
emit('READY')
for line in sys.stdin:
    if line.strip()=='EXIT':break
    total+=int(line);emit('VALUE')
