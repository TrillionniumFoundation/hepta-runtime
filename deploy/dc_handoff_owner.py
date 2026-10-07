#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Handoff-capable ordinary-user owner for future DC-launched pipe applications.

Every child stdout/stderr byte read by this owner is appended to a private history
file before being forwarded to DC. At handoff, raw stdin must have no queued input;
history is fsynced and transferred read-only together with the same live child pipes
to the native stream broker. The child is not stopped or restarted.

This cannot retroactively extract Desktop Commander's own Node.js pipe descriptors
or userspace buffers from arbitrary sessions that were not launched through it.
"""
import argparse
import array
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import selectors
import socket
import stat
import subprocess
import sys
import termios
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('stream_export',ROOT/'deploy/stream_handoff.py')
EXPORT=importlib.util.module_from_spec(spec);spec.loader.exec_module(EXPORT)
MAX_CONTROL=64*1024
MAX_IO=64*1024


def atomic(path,value):
    data=(json.dumps(value,sort_keys=True)+'\n').encode()
    temp=path.with_name(path.name+'.new-'+str(os.getpid()))
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:
        try:temp.unlink()
        except FileNotFoundError:pass


def private_dir(path,create=False):
    path=pathlib.Path(path)
    if create:path.mkdir(parents=True,exist_ok=False,mode=0o700)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise PermissionError('private account-owned owner state required')
    return path


def descendants(pid):
    result=[];queue=[pid]
    while queue:
        parent=queue.pop(0)
        root=pathlib.Path('/proc')/str(parent)
        try:children=list(map(int,(root/'task'/str(parent)/'children').read_text().split()))
        except FileNotFoundError:children=[]
        for child in children:
            if child in result:raise ValueError('cyclic child relationship')
            EXPORT.identity(child);result.append(child);queue.append(child)
            if len(result)>63:raise ValueError('application descendant budget exceeded')
    return result


def write_all(fd,data):
    offset=0
    while offset<len(data):
        n=os.write(fd,data[offset:])
        if n<=0:raise OSError('write made no progress')
        offset+=n
    return offset


def pending_stdin():
    value=array.array('i',[0])
    try:fcntl.ioctl(0,termios.FIONREAD,value,True)
    except OSError:return None
    return value[0]


def control_request(path,value):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as conn:
        conn.settimeout(10);conn.connect(str(path));conn.sendall(json.dumps(value).encode())
        raw=conn.recv(MAX_CONTROL)
    result=json.loads(raw)
    if 'error' in result:raise RuntimeError(result['error'])
    return result


def run_owner(state_dir,argv):
    if os.geteuid()==0:raise RuntimeError('handoff owner must use the normal login')
    if not argv or not pathlib.Path(argv[0]).is_absolute():raise ValueError('absolute child executable required')
    state=private_dir(state_dir,True)
    control_path=state/'control.sock'
    control=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    control.bind(str(control_path));os.chmod(control_path,0o600);control.listen(4);control.setblocking(False)
    history={}
    for name in ('stdout','stderr'):
        history[name]=os.open(state/(name+'.history'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           start_new_session=True,bufsize=0,close_fds=True)
    if child.stdin is None or child.stdout is None or child.stderr is None:raise RuntimeError('child pipe setup failed')
    for stream in (child.stdin,child.stdout,child.stderr):os.set_blocking(stream.fileno(),False)
    os.set_blocking(0,False)
    selector=selectors.DefaultSelector()
    selector.register(control,selectors.EVENT_READ,('control',None))
    selector.register(0,selectors.EVENT_READ,('dc_input',None))
    selector.register(child.stdout.fileno(),selectors.EVENT_READ,('child_output','stdout'))
    selector.register(child.stderr.fileno(),selectors.EVENT_READ,('child_output','stderr'))
    state_doc={'state':'running','owner_pid':os.getpid(),'child_identity':EXPORT.identity(child.pid),
               'application_pids':[child.pid,*descendants(child.pid)],'control_socket':str(control_path),
               'stdout_history':str(state/'stdout.history'),'stderr_history':str(state/'stderr.history'),
               'raw_owner_io':True,'started_unix_ms':int(time.time()*1000)}
    atomic(state/'status.json',state_doc)
    print('HEPTA_DC_OWNER_READY '+json.dumps({k:state_doc[k] for k in ('owner_pid','child_identity','application_pids','control_socket')}),flush=True)
    handed=False;input_closed=False
    def current():
        pids=[child.pid,*descendants(child.pid)] if child.poll() is None else state_doc['application_pids']
        return {**state_doc,'state':'running' if child.poll() is None else 'child_exited',
                'application_pids':pids,'child_exit_code':child.poll(),'stdin_pending_bytes':pending_stdin(),
                'stdout_history_size':os.fstat(history['stdout']).st_size,'stderr_history_size':os.fstat(history['stderr']).st_size}
    try:
        while True:
            if child.poll() is not None:
                # Drain both child output pipes before owner exit.
                for fd,name in ((child.stdout.fileno(),'stdout'),(child.stderr.fileno(),'stderr')):
                    while True:
                        try:data=os.read(fd,MAX_IO)
                        except BlockingIOError:break
                        if not data:break
                        write_all(history[name],data);write_all(1 if name=='stdout' else 2,data)
                for fd in history.values():os.fsync(fd)
                final={**current(),'state':'child_exited','history_finalized':True}
                atomic(state/'final.json',final);return child.returncode
            events=selector.select(.1)
            for key,_ in events:
                kind,name=key.data
                if kind=='child_output':
                    fd=key.fileobj
                    try:data=os.read(fd,MAX_IO)
                    except BlockingIOError:continue
                    if not data:
                        try:selector.unregister(fd)
                        except KeyError:pass
                        continue
                    write_all(history[name],data)
                    write_all(1 if name=='stdout' else 2,data)
                elif kind=='dc_input':
                    try:data=os.read(0,MAX_IO)
                    except BlockingIOError:continue
                    if not data:
                        selector.unregister(0)
                        if not input_closed:
                            child.stdin.close();input_closed=True
                        continue
                    if input_closed:raise RuntimeError('DC input arrived after child stdin closed')
                    write_all(child.stdin.fileno(),data)
                else:
                    conn,_=control.accept()
                    with conn:
                        conn.settimeout(5)
                        try:
                            request=json.loads(conn.recv(MAX_CONTROL));op=request['op']
                            if op=='status':
                                response=current()
                            elif op=='handoff':
                                expected=request['application_pids'];actual=[child.pid,*descendants(child.pid)]
                                if expected!=actual:raise ValueError('application identity list changed before handoff')
                                queued=pending_stdin()
                                if queued is None:raise ValueError('cannot prove raw owner stdin is quiescent')
                                if queued!=0:raise ValueError('unconsumed owner stdin exists; drain before handoff')
                                for fd in history.values():os.fsync(fd)
                                descriptions={}
                                with open(state/'stdout.history','rb',buffering=0) as stdout_history,open(state/'stderr.history','rb',buffering=0) as stderr_history:
                                    descriptions={'stdin_writer':child.stdin.fileno(),'stdout_reader':child.stdout.fileno(),
                                                  'stderr_reader':child.stderr.fileno(),'stdout_history':stdout_history.fileno(),
                                                  'stderr_history':stderr_history.fileno()}
                                    ack=EXPORT.transfer(request['handoff_socket'],request['session_id'],descriptions,actual,
                                                        acknowledge_quiesced_io=True)
                                for stream in (child.stdin,child.stdout,child.stderr):
                                    try:selector.unregister(stream.fileno())
                                    except Exception:pass
                                    stream.close()
                                receipt={**ack,'owner_pid':os.getpid(),'child_identity':EXPORT.identity(child.pid),
                                         'application_pids':actual,'history_finalized':True,
                                         'stdout_history_sha256':hashlib.sha256((state/'stdout.history').read_bytes()).hexdigest(),
                                         'stderr_history_sha256':hashlib.sha256((state/'stderr.history').read_bytes()).hexdigest(),
                                         'userspace_read_ahead_bytes_unaccounted':0,'stdin_pending_bytes':0}
                                atomic(state/'handoff.json',receipt);state_doc.update(state='handed_off',session_id=request['session_id'])
                                atomic(state/'status.json',state_doc)
                                response=receipt;handed=True
                            else:raise ValueError('unknown owner control operation')
                            conn.sendall(json.dumps(response).encode())
                        except Exception as error:
                            conn.sendall(json.dumps({'error':type(error).__name__+': '+str(error)}).encode())
                    if handed:
                        print('HEPTA_DC_OWNER_HANDOFF '+json.dumps({'session_id':state_doc['session_id'],'child_pid':child.pid,'state_dir':str(state)}),flush=True)
                        return 0
    finally:
        selector.close();control.close();control_path.unlink(missing_ok=True)
        for fd in history.values():
            try:os.fsync(fd);os.close(fd)
            except OSError:pass
        if not handed and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)


def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest='mode',required=True)
    run=sub.add_parser('run');run.add_argument('--state-dir',required=True);run.add_argument('command',nargs=argparse.REMAINDER)
    status=sub.add_parser('status');status.add_argument('--socket',required=True)
    handoff=sub.add_parser('handoff');handoff.add_argument('--socket',required=True);handoff.add_argument('--handoff-socket',required=True);handoff.add_argument('--session-id',required=True);handoff.add_argument('--application-pids',required=True)
    args=ap.parse_args()
    if args.mode=='run':
        command=args.command[1:] if args.command and args.command[0]=='--' else args.command
        raise SystemExit(run_owner(pathlib.Path(args.state_dir),command))
    if args.mode=='status':
        print(json.dumps(control_request(args.socket,{'op':'status'})));return
    pids=json.loads(args.application_pids)
    print(json.dumps(control_request(args.socket,{'op':'handoff','handoff_socket':args.handoff_socket,'session_id':args.session_id,'application_pids':pids})))


if __name__=='__main__':main()
