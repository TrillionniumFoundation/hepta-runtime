#!/usr/bin/env python3
"""Single direct-child passive stdio trace, complete read bytes and stable exit inventory."""
from pathlib import Path
import os,stat,struct
from kernel_trace import Trace
from evidence_common import require
def process_snapshot(pid):
    proc=Path("/proc")/str(pid);before=(proc/"maps").read_bytes();fds={}
    names=sorted((proc/"fd").iterdir(),key=lambda p:int(p.name))
    for path in names:
        st=path.stat();fds[path.name]=dict(target=os.readlink(path),
            stat=dict(mode=st.st_mode,dev=st.st_dev,inode=st.st_ino,links=st.st_nlink,uid=st.st_uid,gid=st.st_gid,
                size=st.st_size,mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns),
            fdinfo_hex=(proc/"fdinfo"/path.name).read_bytes().hex())
    after=(proc/"maps").read_bytes()
    require(before==after and [p.name for p in sorted((proc/"fd").iterdir(),key=lambda p:int(p.name))]==list(fds),
        "stopped child inventory changed")
    return dict(pid=pid,maps_hex=before.hex(),maps_after_hex=after.hex(),fds=fds,
        readonly=True,stopped_at_syscall_entry=True)
class StdioTrace(Trace):
    def __init__(self,pid,folder,*,observed,expected_input_bytes):
        self.observed=observed;self.expected_input_bytes=expected_input_bytes
        self.stdin_returned=0;self.before_eof=None;self.pre_exit=None;self.output_counts=None
        super().__init__(pid,folder)
    def entry_memory(self,n,a):
        if n==0 and a[0]==0 and self.execs==1 and self.stdin_returned==self.expected_input_bytes and self.before_eof is None:
            self.before_eof=dict(snapshot=process_snapshot(self.pid),stdin_returned=self.stdin_returned,
                output_bytes=self.output_counts()if self.output_counts else None,
                syscall_ordinal=self.calls,hold_milliseconds=5)
            return [dict(label="pre-eof-inventory",value=self.before_eof)]
        if n in(60,231):
            require(self.pre_exit is None,"multiple process-exit entries")
            self.pre_exit=dict(snapshot=process_snapshot(self.pid),syscall_ordinal=self.calls,
                number=n,requested_exit_code=a[0])
            return [dict(label="process-exit-inventory",value=self.pre_exit)]
        if n==1:
            if self.observed and a[0]in(3,4):return []
            return [self.take("write",a[1],a[2])]
        if n==20 and a[0]in(1,2):
            require(a[2]<=1024,"bounded full stdio writev")
            row=self.take("iovec",a[1],16*a[2]);out=[row]
            if "hex"in row:
                value=bytes.fromhex(row["hex"])
                for i in range(a[2]):
                    address,size=struct.unpack_from("<2Q",value,i*16)
                    out.append(self.take("writev-"+str(i),address,size))
            return out
        return super().entry_memory(n,a)
    def exit_memory(self,n,a,result):
        if n in(0,17)and result>=0:
            if n==0 and a[0]==0 and self.execs==1:self.stdin_returned+=result
            return [self.take("read",a[1],result)]
        return super().exit_memory(n,a,result)
    def finish(self):
        require(self.pre_exit is not None and self.before_eof is not None,"complete stdin EOF and actual process-exit stops")
        require(self.stdin_returned==self.expected_input_bytes,"all stdin bytes actually consumed")
        value=super().finish()
        require(not value["capture_errors"]and value["execs"]==1 and value["application_calls"]==1,
            "complete passive single-target observation")
        return value
class BodyFrames:
    """Framing only: preserve full body stream; recognize final observer ACK boundary."""
    def __init__(self):
        self.header=bytearray();self.header_size=None;self.remaining=0;self.total=0
        self.final_ack=False;self.final_offset=None;self.records=0
    def put(self,raw):
        offset=0
        while offset<len(raw):
            if self.remaining:
                count=min(self.remaining,len(raw)-offset);self.remaining-=count;offset+=count;self.total+=count
                continue
            need=(8 if self.header_size is None else self.header_size)-len(self.header)
            count=min(need,len(raw)-offset);self.header.extend(raw[offset:offset+count]);offset+=count;self.total+=count
            if self.header_size is None and len(self.header)==8:
                require(bytes(self.header)in(b"HBRDJR01",b"HBRLJR01"),"complete known body/lifecycle header")
                self.header_size=128 if self.header==b"HBRDJR01"else 64
            if self.header_size is not None and len(self.header)==self.header_size:
                require(not self.final_ack,"body bytes after final lifecycle boundary")
                h=bytes(self.header);size=struct.unpack_from("<Q",h,32 if self.header_size==128 else 16)[0]
                require(size<=256<<20,"bounded full body span")
                if self.header_size==64 and struct.unpack_from("<Q",h,8)[0]==5:
                    require(size==0,"final lifecycle frame has no payload")
                    self.final_ack=True;self.final_offset=self.total
                self.remaining=size;self.header=bytearray();self.header_size=None;self.records+=1
    def finish(self):
        require(not self.remaining and not self.header and self.final_ack,"complete body/lifecycle frame boundary")
        return dict(records=self.records,bytes=self.total,final_ack_offset=self.final_offset)
