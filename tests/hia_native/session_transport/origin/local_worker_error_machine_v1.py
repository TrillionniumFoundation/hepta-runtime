#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Physical ABI transport for 38 actual HIA LocalWorkerError, Client/ServerMessage, Worker and channel images."""
from pathlib import Path
import argparse,ctypes,fcntl,hashlib,json,os,select,struct,sys,time,traceback

D=Path('/home/qq/hepta-http-transport-bd947-v1')
BUILD=D/'local-worker-error-callable-build-v1'
ARTIFACT_SHA='eafb3da336e0829375a3403c65dcaa983b7af4c51992a514d13b406fa95872a8'
INVALID=0xffffffff
SHA=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
word=lambda p,at=0:ctypes.c_uint64.from_address(p+at).value
Q=ctypes.c_uint64
class Span(ctypes.Structure):
    _fields_=[('pointer',Q),('size',Q)]

def request(op,generation,value=0,waker=0):
    return b'HRONQ001'+struct.pack('<9Q',op,generation,value,waker,0,0,0,0,0)

class Machine:
    def __init__(self,folder,report,build_sha):
        self.folder=folder;self.report=report;self.base=None;self.closed=False;self.ordinal=0
        self.calls=(folder/'physical.calls.jsonl').open('xb',buffering=0)
        raw=(BUILD/'result.json').read_bytes();assert SHA(raw)==build_sha
        build=json.loads(raw);assert build['status']=='BUILT_NOT_SEMANTICALLY_QUALIFIED'
        self.exports=build['exports'];self.raw=(BUILD/'hia-local-worker-error-callable.elf').read_bytes()
        assert SHA(self.raw)==ARTIFACT_SHA==build['artifact']['sha256']
        assert len(self.raw)==build['artifact']['bytes']
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        self.libc.mmap.restype=ctypes.c_void_p
        self.libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];self.libc.munmap.restype=ctypes.c_int
        fd=os.memfd_create('qualified-hia-session-error',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            at=0
            while at<len(self.raw):at+=os.write(fd,self.raw[at:])
            seals=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,seals);assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==seals
            base=self.libc.mmap(None,len(self.raw),1|4,2,fd,0)
            assert base not in (None,ctypes.c_void_p(-1).value),ctypes.get_errno()
            self.base=base;assert ctypes.string_at(base,len(self.raw))==self.raw
        finally:os.close(fd)
        self.functions={}
        sizes={'cooperative_scheduler_create':2,'cooperative_scheduler_register':3,'cooperative_scheduler_next':1,
            'cooperative_scheduler_finish':3,'cooperative_scheduler_proceed':2,'cooperative_scheduler_progress':2,
            'cooperative_scheduler_restore':2,'cooperative_scheduler_after_park':1,'cooperative_scheduler_retire':1,
            'cooperative_scheduler_destroy':1,'cooperative_scheduler_retain':1,'cooperative_scheduler_release':1,
            'cooperative_scheduler_notify':3,'oneshot_create':3,'oneshot_call':5,'oneshot_stats':3,'oneshot_destroy':1,
            'value_lease_create':5,'value_lease_span':1,'value_lease_drop':1,'probe_create':1,'probe_destroy':1,
            'yield_now_create':2,'yield_now_poll':2,'yield_now_destroy':1,'batch_observer_attach':2,
            'batch_budget_remaining':1,'cooperative_scheduler_defer_current':2,'batch_anchor_drop':1,'typed_drop_observer_attach':2,'owned_oneshot_send':4,'batch_semaphore_create':5,'batch_semaphore_call':5,'batch_semaphore_destroy':1,'bounded_mpsc_create':5,'bounded_mpsc_call':5,'bounded_mpsc_destroy':1,'bounded_mpsc_retire_owned':1,'session_event_take':3,'session_result_take':3,'session_error_call':5,'session_error_into_io':5,'session_handle_future_create':6,'session_handle_future_call':6,'scheduler_timer_install':1,'scheduler_timer_uninstall':1,'scheduler_sleep_relative':3,'scheduler_sleep_until':3,'scheduler_sleep_reset':4,'scheduler_sleep_poll':3,'scheduler_sleep_drop':2,'scheduler_timer_prepare':4,'scheduler_timer_notification_fd':1,'scheduler_timer_after_io':1,'scheduler_timer_park_once':4,'timer_owner_shutdown':1,'cancellation_token_create':2,'cancellation_token_call':5,'cancellation_token_destroy':1,'server_message_call':5,'worker_send_request_take':3,'worker_result_take':3,'channel_waker_observer_table':0,'client_message_call':5,'local_worker_error_create':5}
        assert set(sizes)|{'probe_drop_entry','owned_oneshot_handle_drop_entry','session_event_drop_entry','owned_mpsc_handle_drop_entry','streamable_http_receiver_drop_entry','session_result_drop_entry','session_error_drop_entry','server_message_drop_entry','worker_send_request_drop_entry','worker_result_drop_entry','client_message_drop_entry','local_worker_error_drop_entry'}==set(self.exports)
        for name,count in sizes.items():
            offset=self.exports[name];assert 176<=offset<len(self.raw)
            result=Span if name=='value_lease_span' else Q
            self.functions[name]=ctypes.CFUNCTYPE(result,*([Q]*count))(base+offset)
        report['sealed_rx_image']=dict(bytes=len(self.raw),sha256=SHA(self.raw),writable_executable=False)
        report['exports_returned']=0;report['exports_attempted']=0
    def call(self,name,*args):
        row=dict(ordinal=self.ordinal,phase=self.report.get('phase',0),frame=self.report.get('frames',0),name=name,args=list(args))
        self.ordinal+=1;self.calls.write((json.dumps(dict(row,event='ENTER'),sort_keys=True)+'\n').encode())
        self.report['exports_attempted']+=1
        result=self.functions[name](*args)
        self.report['exports_returned']+=1
        encoded=[result.pointer,result.size] if isinstance(result,Span) else int(result)
        self.calls.write((json.dumps(dict(row,event='RETURN',result=encoded),sort_keys=True)+'\n').encode())
        return result
    def close(self):
        if self.closed:return
        self.closed=True
        if self.base is not None:
            assert self.libc.munmap(self.base,len(self.raw))==0
            self.report['image_unmapped']=True;self.base=None
        self.calls.flush();os.fsync(self.calls.fileno());self.calls.close()
