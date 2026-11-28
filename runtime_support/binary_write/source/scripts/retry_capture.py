#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual open-EINTR retry controls, stopped by an explicit external SIGTERM.

The target installs an ordinary kernel seccomp ERRNO filter. The observer counts
actual completed openat calls and sends SIGTERM after eight EINTR returns. It
does not change a result, register or memory byte and never synthesizes success.
These six controls remain separate from the 992 naturally completed lane runs.
"""
import gzip
import hashlib
import os
from pathlib import Path
import signal
import struct
import sys
import time
from carrier import Carrier
from kernel_trace import Trace
from evidence_common import encoded,pin,require
from parent_protocol import wire
from protocol import U,proc_fds


class RetryTrace(Trace):
    required_phase=None
    attempt_limit=8

    def __init__(self,pid,folder):
        self.retries=[];self.cancellation=None
        super().__init__(pid,folder)

    def emit(self,row):
        super().emit(row)
        if row["record"]!="LEAVE"or row["number"]!=257 or row["result"]!=-4:return
        current=self.current
        phase=current["phase"]
        require(phase is not None and phase["magic_hex"]==b"HBPWHK01".hex()
                and phase["words"][5]==self.required_phase,"actual EINTR arrived outside the frozen parent call")
        require(self.cancellation is None,"retry continued after the explicit stop boundary")
        self.retries.append(dict(ordinal=row["ordinal"],phase=phase,args=current["args"],result=-4))
        if len(self.retries)==self.attempt_limit:
            # This executes while the actual child is stopped at syscall exit.
            # Its original return value is still -EINTR and remains unchanged.
            self.cancellation=dict(signal=signal.SIGTERM,after_actual_eintr_returns=len(self.retries),
                fds_before_signal=proc_fds(self.pid),sender_pid=os.getpid(),target_pid=self.pid,
                issued_monotonic_ns=time.monotonic_ns(),result_replacements=0,memory_or_register_writes=0)
            os.kill(self.pid,signal.SIGTERM)


class RetryCarrier(Carrier):
    def finish_cancelled(self):
        require(self.trace.cancellation is not None,"explicit frozen retry cancellation was never issued")
        deadline=time.monotonic()+5
        while self.trace.status is None:
            self.trace.pump();self.drain_journal();self.drain_hooks()
            require(time.monotonic()<deadline,"actual cancellation cleanup exceeded five seconds")
            if self.trace.status is None:time.sleep(.0001)
        require(os.waitstatus_to_exitcode(self.trace.status)==-signal.SIGTERM,"actual unchanged SIGTERM termination")
        self.drain_journal();self.drain_hooks()
        require(self.journal_eof and self.notify_eof and not self.notify_buffer,"complete retry observer streams")
        require(not os.read(self.output_fd,65536),"retry produced an application result after cancellation")
        for name in("input_fd","output_fd","journal_fd","notify_fd","ack_fd"):
            os.close(getattr(self,name));setattr(self,name,None)
        self.receipt["returncode"]=-signal.SIGTERM
        self.receipt["kernel"]=self.trace.finish()
        self.close_wakeup()
        self.receipt["elapsed_ns"]=time.monotonic_ns()-self.receipt["started_ns"]
        self.receipt["explicit_cancellation"]=self.trace.cancellation
        for stream in(self.sent,self.received,self.received_raw,self.errors,self.records,self.journal,self.journal_raw):stream.close()
        self.finished=True
        self.receipt["journal"]=dict(raw=dict(bytes=self.journal_bytes,sha256=self.journal_digest.hexdigest()),
            compressed=pin(self.folder/"carrier.journal.gz"))
        self.receipt["streams"]={name:pin(self.folder/("carrier."+name))for name in("stdin","stderr")}
        self.receipt["stdout"]=dict(raw=dict(bytes=self.received_bytes,sha256=self.received_digest.hexdigest()),
            compressed=pin(self.folder/"carrier.stdout.gz"))
        require((self.folder/"carrier.stderr").read_bytes()==b"","actual retry stderr")
        (self.folder/"carrier-process.json").write_bytes(encoded(self.receipt))
        return self.receipt


def run_retry(case,lane,root,folder,binary,store,source,preparer):
    from parent_capture import setup,discard,concrete,Hooks,projection
    started=time.monotonic_ns();folder.mkdir()
    native=lane=="native-observed"
    initial=setup(root);query=concrete(case,root,True)
    trace=type("FixedRetryTrace",(RetryTrace,),dict(required_phase=case["retry_phase"]))
    carrier_type=type("FixedRetryCarrier",(RetryCarrier,),dict(TRACE_CLASS=trace))
    executable=binary if native else Path(sys.executable).resolve()
    argv=None if native else [executable,"-I","-S","-B",source/"parent/scripts/reference_worker.py",source/"parent"]
    carrier=carrier_type(executable,folder,store,argv)
    hooks=Hooks(carrier,case,store);carrier.hooks=hooks
    complete=False
    try:
        raw,_=carrier.exchange(8,0);require(U(raw,8)==0,"fresh retry owner")
        plan=b"".join(struct.pack("<7Q",*item)for item in case["fault_plans"])
        raw,_=carrier.exchange(18,0,plan);require(U(raw,8)==0,"actual permanent EINTR plan")
        packet,preparation=preparer.request(query,10000+case["id"],"retry-"+lane)if native else(encoded(query),None)
        require(packet is not None,"fixed EINTR input belongs to the original typed String domain")
        error=None
        try:carrier.exchange(1,0,packet,application=True)
        except (ValueError,BrokenPipeError)as caught:error=dict(type=type(caught).__name__,message=str(caught))
        require(error is not None and carrier.trace.cancellation is not None,"retry incorrectly returned normally")
        process=carrier.finish_cancelled()
        require(not(Path("/proc")/str(carrier.pid)).exists(),"retry process was not reaped")
        row=dict(input=case,lane=lane,query=query,setup=initial,application_input=store.put(packet),
            process=process,preparation=preparation,hooks=dict(events=hooks.events,eof=hooks.eof),
            actual_eintr=carrier.trace.retries,cancellation=carrier.trace.cancellation,
            partial_exchange_error=error,after_exit=projection(root),whole_process_exited=True,
            elapsed_ns=time.monotonic_ns()-started,normal_application_result=False)
        require(row["elapsed_ns"]<60_000_000_000,"original retry-control sixty-second bound")
        (folder/"RETRY.json").write_bytes(encoded(row));complete=True
        return dict(id=case["id"],name=case["name"],lane=lane,case=pin(folder/"RETRY.json"),elapsed_ns=row["elapsed_ns"])
    finally:
        carrier.cleanup()
        if complete:discard(root)
