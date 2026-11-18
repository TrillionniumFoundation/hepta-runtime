#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual ServerMessage owner/drop private ABI controls with complete protected arenas."""
from pathlib import Path
import ctypes,gzip,hashlib,importlib.util,json,mmap,os,struct,time,traceback
M=Path('/home/qq/hepta-server-message-codec-bd947-v1')
D=Path('/home/qq/hepta-http-transport-bd947-v1')
OUT=M/'message-private-v1'
INVALID=0xffffffff
CAPACITY=0xfffffffe
CALL=0xfffffff0
PAGE=4096
SHA=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()
Q=lambda n:struct.pack('<Q',n)
U=lambda b,at=0:struct.unpack_from('<Q',b,at)[0]
def module(path,digest,name):
    raw=Path(path).read_bytes();assert SHA(raw)==digest,(str(path),SHA(raw))
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
libc=ctypes.CDLL(None,use_errno=True)
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
libc.mmap.restype=ctypes.c_void_p
libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
class Arena:
    def __init__(self,capacity,canary):
        self.capacity=capacity;self.canary=canary
        self.access=((capacity+16+PAGE-1)//PAGE)*PAGE
        self.total=self.access+2*PAGE
        self.mapping=libc.mmap(None,self.total,0,mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,-1,0)
        assert self.mapping not in (None,ctypes.c_void_p(-1).value)
        self.pointer=self.mapping+PAGE;self.readonly=False;self.closed=False
        self.protect(False);self.reset(0)
    def protect(self,readonly):
        assert not self.closed
        assert libc.mprotect(self.pointer,self.access,1 if readonly else 3)==0,ctypes.get_errno()
        self.readonly=readonly
    def reset(self,fill):
        assert not self.readonly
        ctypes.memset(self.pointer,fill,self.capacity)
        ctypes.memset(self.pointer+self.capacity,self.canary,16)
    def read(self,offset=0,size=None):
        if size is None:size=self.capacity-offset
        assert 0<=offset<=self.capacity and 0<=size<=self.capacity-offset
        return ctypes.string_at(self.pointer+offset,size)
    def write(self,offset,raw):
        assert not self.readonly and 0<=offset<=self.capacity and len(raw)<=self.capacity-offset
        ctypes.memmove(self.pointer+offset,raw,len(raw))
    def word(self,offset):
        assert 0<=offset<=self.capacity-8
        return ctypes.c_uint64.from_address(self.pointer+offset).value
    def guard(self):
        assert ctypes.string_at(self.pointer+self.capacity,16)==bytes([self.canary])*16
    def digest(self):
        h=hashlib.sha256()
        for at in range(0,self.capacity,1<<20):h.update(self.read(at,min(1<<20,self.capacity-at)))
        return h.hexdigest()
    def close(self):
        if not self.closed:
            assert libc.munmap(self.mapping,self.total)==0
            self.closed=True
class Evidence:
    def __init__(self,report):
        self.report=report;self.ordinal=0;self.snapshot_id=0
        self.trace=(OUT/'calls.jsonl').open('xb',buffering=0)
        self.blob=(OUT/'small-bytes.bin').open('xb',buffering=0)
    def bytes(self,raw):
        at=self.blob.tell();self.blob.write(raw)
        return dict(offset=at,bytes=len(raw),sha256=SHA(raw))
    def row(self,value):
        self.trace.write((json.dumps(value,sort_keys=True)+'\n').encode())
    def snapshot(self,arena,label):
        self.snapshot_id+=1;name='arena-'+str(self.snapshot_id).zfill(4)+'.bin.gz'
        h=hashlib.sha256()
        with (OUT/name).open('xb')as f:
            with gzip.GzipFile(fileobj=f,mode='wb',compresslevel=1,mtime=0)as z:
                for at in range(0,arena.capacity,1<<20):
                    raw=arena.read(at,min(1<<20,arena.capacity-at));h.update(raw);z.write(raw)
        packed=(OUT/name).read_bytes()
        row=dict(id=self.snapshot_id,label=label,path=name,bytes=arena.capacity,sha256=h.hexdigest(),
            gzip_bytes=len(packed),gzip_sha256=SHA(packed),canary=arena.canary,guard_pages=True)
        self.row(dict(event='SNAPSHOT',**row));return row
    def call(self,mod,wire,output,workspace,label,*,oc=None,wc=None,readonly=False,basis=None,patches=None,expected=None):
        if oc is None:oc=output.capacity
        if wc is None:wc=workspace.capacity
        assert 0<=oc<=output.capacity and 0<=wc<=workspace.capacity
        source=Arena(max(1,len(wire)),0xc3);source.write(0,wire);source.protect(True)
        self.ordinal+=1
        row=dict(ordinal=self.ordinal,label=label,role=mod.role,input=self.bytes(wire),output_capacity=oc,
            workspace_capacity=wc,full_allocated_output_capacity=output.capacity,
            full_allocated_workspace_capacity=workspace.capacity,manifest_sha256=mod.manifest_sha256,
            kernel_readonly_output_and_workspace=readonly,basis=basis,patches=patches or [],expected=expected)
        self.row(dict(event='ENTER',**row))
        self.report['actual_hia_entries']+=1
        self.report['hia_roles'][mod.role]=self.report['hia_roles'].get(mod.role,0)+1
        if readonly:output.protect(True);workspace.protect(True)
        try:
            code=int(mod._entry(source.pointer,len(wire),output.pointer,oc,workspace.pointer,wc))
            source.guard();output.guard();workspace.guard();assert source.read(0,len(wire))==wire
            if readonly:
                self.report['immutable_refusals']+=1
                output_snapshot=None;workspace_snapshot=None
            else:
                output_snapshot=self.snapshot(output,label+'/output')
                workspace_snapshot=self.snapshot(workspace,label+'/workspace')
            result=dict(event='RETURN',ordinal=self.ordinal,label=label,role=mod.role,code=code,
                observed=self.bytes(output.read(0,min(output.capacity,code))) if code<0xffff0000 else None,
                output_snapshot=output_snapshot,workspace_snapshot=workspace_snapshot,
                readonly_returned=readonly,all_canaries_intact=True,input_unchanged=True)
            self.row(result)
            assert expected is None or code==expected,(label,code,expected)
            return code,result
        finally:
            if readonly:workspace.protect(False);output.protect(False)
            source.close()
    def close(self):
        for f in (self.trace,self.blob):f.flush();os.fsync(f.fileno());f.close()
def frame(operation,mode,kind,variant,body,ident=b'',legacy=0,sc=0x713000,generation=37):
    if mode==1:sc=generation=0
    return b'HSSMQ001'+struct.pack('<11Q',operation,mode,kind,variant,len(body),len(ident),legacy,sc,generation,0,0)+body+ident
def changed(raw,offset,value):
    b=bytearray(raw);b[offset:offset+8]=Q(value);return bytes(b)
def admit(ad):
    compiled=json.loads(ad.pin(M/'message-owner-native-build-v3/result.json','13b3dd687b0d338722522cae1f93721971e6223ce038aa273b88152c9f4e60dd'))
    ext=json.loads(ad.pin(M/'message-owner-native-build-v3.external.json','ed5594efc92a5cfaa1568f55ab91d40f6ce5d3f7f3f0f3abf281ec28a4e6ff5f'))
    out,err=ad.durable(ext['status'],ext['read'],'1a1eb3d0abe-392-42fa')
    assert not err and json.loads(out)=={k:v for k,v in compiled.items()if k not in ('source_pins','bootstrap_files','compiler_dependency','authoring','schema_derivation')}
    assert compiled['status']=='BUILT_NOT_SEMANTICALLY_QUALIFIED'
    assert compiled['actual_native_compiles']==5 and compiled['actual_native_semantic_executions']==compiled['actual_original_executions']==0
    assert compiled['unresolved_prior_compile_job']=='1a1eb0dfca7-392-42cd' and compiled['prior_unknown_relabelled'] is False
    for path,want in compiled['source_pins'].items():
        raw=ad.pin(path,want['sha256']);assert len(raw)==want['bytes']
    build=ad.admit_callable(M/'server-message-callable-build-v3',
        '5ad5308481a4214484c1f1ea63cae26edbaaa7e245d505a56f8a4eed6e06f846',
        M/'server-message-callable-build-v3.external.json',
        '5a450c303dc7cdfd50e16b1b1518a77485e3f4119cbc07751c64c9e8205cd931',
        '1a1eb4113c6-392-4301')
    roles=('server-message-owner','server-message-drop','server-message','server-message-schema','server-message-emitter')
    for role in roles:
        item=compiled['modules'][role]
        meta=json.loads(ad.pin(item['path'],item['sha256']));root=Path(item['path']).parent
        ad.pin(root/meta['source'],meta['source_sha256']);ad.pin(root/meta['image'],meta['image_sha256'])
        matches=[x for x in build['modules'].values()if x['sha256']==item['sha256']]
        assert len(matches)==1 and matches[0]['path']==item['path']
    return compiled,roles

class OwnerHarness:
    def __init__(self,evidence,mods,report):
        self.e=evidence;self.mods=mods;self.report=report
        self.w=Arena(201326592,0x5a);self.o=Arena(65536,0xa5)
        self.cw=Arena(268435456,0x5a);self.co=Arena(67108864,0xa5);self.aux=Arena(65536,0xa5)
        self.phase_controls_done=set()
    def close(self):
        for a in (self.w,self.o,self.cw,self.co,self.aux):a.close()
    def refusal(self,wire,label,patches=(),*,oc=None,wc=None,expected=INVALID,basis=None):
        prior=[];records=[]
        try:
            for offset,data in patches:
                old=self.w.read(offset,len(data));prior.append((offset,old));self.w.write(offset,data)
                records.append(dict(offset=offset,before=self.e.bytes(old),after=self.e.bytes(data)))
            code,_=self.e.call(self.mods['server-message-owner'],wire,self.o,self.w,label,
                oc=oc,wc=wc,readonly=True,basis=basis,patches=records,expected=expected)
            return code
        finally:
            for offset,data in reversed(prior):self.w.write(offset,data)
    def initial_controls(self,wire):
        self.w.reset(0);self.o.reset(0xa9)
        wb=self.e.snapshot(self.w,'owner-initial-controls/workspace')
        ob=self.e.snapshot(self.o,'owner-initial-controls/output');basis=dict(workspace=wb['id'],output=ob['id'])
        bad=[('empty',b''),('short',wire[:95]),('truncated',wire[:-1]),('extra-byte',wire+b'\0')]
        for off,vals in ((0,(0,)),(8,(0,3)),(16,(0,3)),(24,(0,5)),(32,(0,6)),(40,(8388609,)),(48,(0,8388609)),(56,(1,2)),(64,(0,)),(72,(0,)),(80,(1,)),(88,(1,))):
            for value in vals:bad.append(('header-'+str(off)+'-'+str(value),changed(wire,off,value)))
        for label,raw in bad:
            self.refusal(raw,'initial/'+label,basis=basis)
        self.refusal(changed(wire,0,0),'initial/invalid-before-capacity',oc=0,wc=0,basis=basis)
        self.refusal(wire,'initial/output-capacity',oc=63,expected=CAPACITY,basis=basis)
        self.refusal(wire,'initial/workspace-capacity',wc=201326591,expected=CAPACITY,basis=basis)
        for offset in (0,8,128,512,1024,2048,4088):
            self.refusal(wire,'initial/dirty-'+str(offset),[(offset,Q(1))],basis=basis)
        assert self.w.digest()==wb['sha256'] and self.o.digest()==ob['sha256']
        self.e.row(dict(event='CONTROL_BATCH_RESTORED',workspace=wb,output=ob))
    def typed(self,wire,label):
        self.cw.reset(0);self.co.reset(0xa9);self.aux.reset(0xa9)
        parent=self.mods['server-message'];schema=self.mods['server-message-schema'];emitter=self.mods['server-message-emitter']
        code,_=self.e.call(parent,wire,self.co,self.cw,label+'/initial',expected=64)
        raw=self.co.read(0,64)
        assert raw[:8]==b'HSSVC001' and tuple(U(raw,x)for x in (8,16,24,32,40))==(1,1,1,len(wire),32) and U(raw,56)==0
        code,_=self.e.call(schema,wire,self.aux,self.cw,label+'/parse',expected=32)
        assert self.aux.read(0,8)==b'HSSVPR01'
        self.co.reset(0xa9)
        code,_=self.e.call(parent,wire,self.co,self.cw,label+'/validate')
        if code==64:
            raw=self.co.read(0,64)
            assert raw[:8]==b'HSSVC001' and tuple(U(raw,x)for x in (8,16,24,32,40))==(2,2,2,len(wire),self.co.capacity) and U(raw,56)==0
            self.co.reset(0xa9)
            emitted,_=self.e.call(emitter,wire,self.co,self.cw,label+'/emit')
            pre=self.co.digest()
            code,_=self.e.call(parent,wire,self.co,self.cw,label+'/finish')
            assert code==emitted and self.co.digest()==pre
        else:assert code in (INVALID,CAPACITY)
        self.report['actual_pure_child_invocations']+=1
        return code,self.co.read(0,code)if code<0xffff0000 else b''
    def supply(self,wire,label):
        phase=self.w.word(24)
        assert self.w.read(512,8)==b'HSSMA001' and self.w.word(520)==self.w.word(528)==phase
        assert self.w.read(512,128)==self.w.read(640,128)
        if phase in (1,2):
            offset=self.w.word(536);size=self.w.word(544);reply=self.w.word(552);capacity=self.w.word(560)
            assert offset==17825792 and reply==(27262976 if phase==1 else 94371840)
            assert capacity==(67108864 if phase==1 else 16777216) and self.w.word(568)==268435456
            query=self.w.read(offset,size);assert query[:8]==b'HSSVQ001'
            code,raw=self.typed(query,label+'/child-'+str(phase))
            assert len(raw)<=capacity
            self.w.write(reply,raw);self.w.write(592,Q(1)+Q(code)+Q(len(raw)))
            self.e.row(dict(event='ACTUAL_PURE_CHILD_RECEIPT',label=label,phase=phase,
                input=self.e.bytes(query),reply_offset=reply,reply_capacity=capacity,code=code,reply=self.e.bytes(raw)))
            return code
        assert phase==3 and self.w.word(536)==111149056 and self.w.word(552)==1024 and self.w.word(560)==16
        assert self.w.word(576)==U(wire,72) and self.w.word(584)==U(wire,64)
        payload=self.w.read(self.w.word(536),self.w.word(544))
        assert payload[:8]==b'HSSMV001'
        descriptor=0x7f0000001000+self.report['synthetic_value_lease_receipts']*4096
        receipt=Q(descriptor)+Q(U(wire,72))
        self.w.write(1024,receipt);self.w.write(592,Q(1)+Q(0)+Q(16))
        self.report['synthetic_value_lease_receipts']+=1
        self.e.row(dict(event='SYNTHETIC_VALUE_LEASE_ACK',label=label,descriptor=descriptor,
            payload=self.e.bytes(payload),receipt=self.e.bytes(receipt),actual_physical_callback=False))
        return 0
    def phase_controls(self,wire,label):
        phase=self.w.word(24)
        if phase in self.phase_controls_done:return
        self.phase_controls_done.add(phase);self.o.reset(0xa9)
        wb=self.e.snapshot(self.w,label+'/basis-workspace');ob=self.e.snapshot(self.o,label+'/basis-output')
        basis=dict(workspace=wb['id'],output=ob['id'])
        offsets=[0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,248,504,768,1016,1040,2040]
        offsets+=list(range(512,592,8))+list(range(640,720,8))+list(range(720,768,8))+list(range(616,640,8))
        for offset in offsets:
            self.refusal(wire,label+'/state-'+str(offset),[(offset,Q(self.w.word(offset)+1))],basis=basis)
        for value in (0,2):
            self.refusal(wire,label+'/completion-'+str(value),[(592,Q(value))],basis=basis)
        self.refusal(wire,label+'/input-copy',[(4096+len(wire)-1,bytes([self.w.read(4096+len(wire)-1,1)[0]^1]))],basis=basis)
        self.refusal(wire[:-1]+bytes([wire[-1]^1]),label+'/actual-input-changed',basis=basis)
        self.refusal(wire,label+'/output-capacity',oc=63,expected=CAPACITY,basis=basis)
        self.refusal(wire,label+'/workspace-capacity',wc=201326591,expected=CAPACITY,basis=basis)
        if phase in (1,2):
            b=self.w.word(552);size=self.w.word(608)
            for offset,value in ((0,0),(8,0),(16,0),(24,0),(32,0),(40,size-63),(48,0),(56,1)):
                self.refusal(wire,label+'/typed-reply-'+str(offset),[(b+offset,Q(value))],basis=basis)
            self.refusal(wire,label+'/typed-short',[(600,Q(64)),(608,Q(64))],basis=basis)
            self.refusal(wire,label+'/typed-too-large',[(600,Q(self.w.word(560)+1)),(608,Q(self.w.word(560)+1))],basis=basis)
            self.refusal(wire,label+'/wrong-code',[(600,Q(size+1))],basis=basis)
            self.refusal(wire,label+'/invalid-with-bytes',[(600,Q(INVALID)),(608,Q(1))],basis=basis)
            self.refusal(wire,label+'/capacity-with-bytes',[(600,Q(CAPACITY)),(608,Q(1))],basis=basis)
            if phase==1:
                for offset in (64,size-1):
                    self.refusal(wire,label+'/typed-brace-'+str(offset),[(b+offset,b'!')],basis=basis)
            q=17825792
            for offset in range(0,40,8):
                self.refusal(wire,label+'/child-query-'+str(offset),[(q+offset,Q(self.w.word(q+offset)+1))],basis=basis)
            self.refusal(wire,label+'/child-query-body',[(q+40,b'!')],basis=basis)
            self.refusal(wire,label+'/unexpected-ack',[(1024,Q(1))],basis=basis)
        else:
            for offset,value in ((600,1),(608,0),(608,15),(1024,0),(1032,U(wire,72)+1)):
                self.refusal(wire,label+'/lease-ack-'+str(offset)+'-'+str(value),[(offset,Q(value))],basis=basis)
            for offset in (0,8,16,24):
                b=111149056
                self.refusal(wire,label+'/payload-prefix-'+str(offset),[(b+offset,Q(self.w.word(b+offset)+1))],basis=basis)
            p=111149088
            for offset in (0,8,16,24,32,88,96,104,112,120):
                self.refusal(wire,label+'/projection-'+str(offset),[(p+offset,Q(self.w.word(p+offset)+1))],basis=basis)
            for offset in (40,56):
                if self.w.word(p+offset):
                    self.refusal(wire,label+'/span-start-'+str(offset),[(p+offset,Q(127))],basis=basis)
                    self.refusal(wire,label+'/span-empty-'+str(offset),[(p+offset+8,Q(0))],basis=basis)
                    self.refusal(wire,label+'/span-end-'+str(offset),[(p+offset+8,Q(self.w.word(80)))],basis=basis)
            self.refusal(wire,label+'/required-id',[(p+40,Q(0)),(p+48,Q(0))],basis=basis)
            self.refusal(wire,label+'/wrong-body-reply',[(27262976,Q(0))],basis=basis)
            self.refusal(wire,label+'/wrong-id-reply',[(94371840,Q(0))],basis=basis)
        assert self.w.digest()==wb['sha256'] and self.o.digest()==ob['sha256']
        self.e.row(dict(event='CONTROL_BATCH_RESTORED',workspace=wb,output=ob))
    def run(self,wire,label,*,expected=None,declared_output=None):
        self.w.reset(0);self.o.reset(0xa9)
        code,_=self.e.call(self.mods['server-message-owner'],wire,self.o,self.w,label+'/begin',
            oc=declared_output,expected=CALL)
        phases=[]
        while code==CALL:
            phase=self.w.word(24);assert phase in (1,2,3) and phase not in phases;phases.append(phase)
            child_code=self.supply(wire,label)
            if child_code<0xffff0000:self.phase_controls(wire,label+'/phase-'+str(phase))
            self.o.reset(0xa9)
            code,_=self.e.call(self.mods['server-message-owner'],wire,self.o,self.w,label+'/resume-'+str(phase),oc=declared_output)
        if expected is not None:assert code==expected,(label,code,expected)
        if code<0xffff0000:
            raw=self.o.read(0,code)
            assert raw[:8]==(b'HSSMR001'if U(wire,16)==2 else b'HSSMP001')
            if U(wire,16)==2:
                assert code==64 and U(raw,24)>0 and U(raw,40)==U(wire,8) and U(raw,48)==U(wire,56)
                self.report['positive_owned_acks']+=1
            else:assert U(raw,24)==code-128 and U(raw,32)==128
        else:assert self.o.read()==b'\xa9'*self.o.capacity
        assert self.w.word(24)==0 and self.w.word(88)==1 and self.w.read(512,256)==bytes(256)
        wb=self.e.snapshot(self.w,label+'/terminal-workspace');ob=self.e.snapshot(self.o,label+'/terminal-output')
        self.refusal(wire,label+'/terminal-replay',basis=dict(workspace=wb['id'],output=ob['id']))
        assert self.w.digest()==wb['sha256'] and self.o.digest()==ob['sha256']
        self.report['positive_owner_sequences']+=1
        self.e.row(dict(event='OWNER_SEQUENCE_COMPLETE',label=label,phases=phases,code=code))

def drop_tests(e,mod,report):
    o=Arena(256,0xa5);w=Arena(2048,0x5a)
    def wire(kind=1,variant=1,size=162):
        return b'HSSMD001'+struct.pack('<7Q',0x771000,37,0x713000,size,0,0,0)+b'HSSMV001'+struct.pack('<3Q',size-32,kind,variant)
    try:
        raw=wire();w.reset(0);o.reset(0xa9)
        wb=e.snapshot(w,'drop-initial/workspace');ob=e.snapshot(o,'drop-initial/output')
        basis=dict(workspace=wb['id'],output=ob['id'])
        def reject(inp,label,patches=(),oc=None,wc=None,expected=INVALID):
            prior=[];records=[]
            try:
                for offset,data in patches:
                    old=w.read(offset,len(data));prior.append((offset,old));w.write(offset,data)
                    records.append(dict(offset=offset,before=e.bytes(old),after=e.bytes(data)))
                return e.call(mod,inp,o,w,label,oc=oc,wc=wc,readonly=True,expected=expected,basis=basis,patches=records)
            finally:
                for offset,data in reversed(prior):w.write(offset,data)
        for length in (0,7,63,64,95):
            reject(raw[:length],'drop/short-'+str(length))
        reject(raw+b'\0','drop/extra')
        for off,values in ((0,(0,)),(8,(0,)),(16,(0,)),(24,(0,)),(32,(0,161,67108897)),(40,(1,)),(48,(1,)),(56,(1,)),(64,(0,)),(72,(129,131)),(80,(0,5)),(88,(0,6))):
            for value in values:reject(changed(raw,off,value),'drop/header-'+str(off)+'-'+str(value))
        for kind,variant in ((2,19),(3,11),(4,2)):
            reject(wire(kind,variant),'drop/invalid-kind-variant-'+str(kind))
        reject(changed(raw,0,0),'drop/invalid-before-capacity',oc=0,wc=0)
        reject(raw,'drop/output-capacity',oc=79,expected=CAPACITY)
        reject(raw,'drop/workspace-capacity',wc=2047,expected=CAPACITY)
        for offset in range(0,2048,8):
            reject(raw,'drop/dirty-'+str(offset),[(offset,Q(1))])
        assert w.digest()==wb['sha256'] and o.digest()==ob['sha256']
        e.row(dict(event='CONTROL_BATCH_RESTORED',workspace=wb,output=ob))
        for kind,maximum in ((1,5),(2,18),(3,10),(4,1)):
            for variant in range(1,maximum+1):
                w.reset(0);o.reset(0xa9);raw=wire(kind,variant)
                code,_=e.call(mod,raw,o,w,'drop/positive-'+str(kind)+'-'+str(variant),expected=80)
                expected=b'HRTDR001'+struct.pack('<9Q',0,37,0x771000,12,0,0,0,0,0)
                assert o.read(0,80)==expected and o.read(80)==b'\xa9'*(o.capacity-80)
                assert w.word(56)==1 and w.read(256,96)==raw
                report['positive_drop_header_sequences']+=1
                wb=e.snapshot(w,'drop/terminal-workspace');ob=e.snapshot(o,'drop/terminal-output')
                basis=dict(workspace=wb['id'],output=ob['id'])
                reject(raw,'drop/replay-'+str(kind)+'-'+str(variant))
        for size in (162,67108896):
            w.reset(0);o.reset(0xa9)
            e.call(mod,wire(4,1,size),o,w,'drop/payload-length-'+str(size),expected=80)
            report['positive_drop_header_sequences']+=1
    finally:o.close();w.close()
def main():
    assert os.getpid()==os.getpgrp()
    os.umask(0o077);OUT.mkdir(mode=0o700);started=time.monotonic()
    report=dict(schema='hepta.server-message.private.v1',status='RUNNING',actual_hia_entries=0,
        hia_roles={},immutable_refusals=0,positive_owner_sequences=0,positive_owned_acks=0,
        positive_drop_header_sequences=0,actual_pure_child_invocations=0,synthetic_value_lease_receipts=0,
        actual_physical_callbacks=0,actual_original_processes=0,new_compiles=0,
        full_workspace_readonly_refusals=True,signal_interception=False,
        synthetic_drop_headers_are_not_real_owned_values=True,prior_unknown_relabelled=False,
        prior_unknown_job='1a1eb0dfca7-392-42cd',production_activated=False,whole_runtime_replaced=False)
    evidence=None;harness=None;mods={};ad=None
    (OUT/'result.json').write_bytes(J(report))
    try:
        ad=module(M/'admit_server_message_inputs_v2.py','14a5975dbef33429f656635cf2ba79b516af8c6dd6b5b75f9bac35319e22bad8','sm_private_inputs')
        ad.pin(__file__)
        compiled,roles=admit(ad)
        loader=ad.module(D/'session-cache-native-source-v1/scripts/hia_native_loader.py',
            '58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06','sm_private_loader')
        for role in roles:
            item=compiled['modules'][role]
            obj=loader.NativeModule(item['path'],manifest_sha256=item['sha256']);obj.role=role;mods[role]=obj
        report['module_pins']={role:compiled['modules'][role]for role in roles}
        evidence=Evidence(report);harness=OwnerHarness(evidence,mods,report)
        first=frame(2,2,1,1,b'{"method":"ping"}',b'7')
        harness.initial_controls(first)
        harness.run(first,'owned-request',expected=64)
        harness.run(frame(2,1,2,17,b'{}',b'"private"'),'project-response')
        harness.run(frame(2,2,4,1,b'{"code":-32603,"message":"error"}',b' \nnull\t'),'owned-error-null',expected=64)
        harness.run(frame(1,2,0,0,b'{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}'),'owned-decode-notification',expected=64)
        harness.run(frame(1,2,0,0,b'null'),'actual-typed-rejection',expected=INVALID)
        harness.run(frame(2,1,1,1,b'{"method":"ping"}',b'7'),'terminal-output-capacity',expected=CAPACITY,declared_output=128)
        assert harness.phase_controls_done=={1,2,3}
        harness.close();harness=None
        drop_tests(evidence,mods['server-message-drop'],report)
        assert report['positive_owner_sequences']==6
        assert report['positive_owned_acks']==3 and report['synthetic_value_lease_receipts']==3
        assert report['positive_drop_header_sequences']==36
        assert report['actual_hia_entries']==sum(report['hia_roles'].values())
        ad.recheck_all();report['all_sources_rechecked']=True
        report['status']='PASS_FINITE_PRIVATE_ABI'
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        if harness:harness.close()
        for mod in mods.values():mod.close()
        if evidence:evidence.close()
        report['pins']={}if ad is None else ad.PINS
        report['elapsed_seconds']=time.monotonic()-started
        report['captures']={}
        for path in sorted(OUT.iterdir()):
            if path.name=='result.json':continue
            h=hashlib.sha256()
            with path.open('rb')as f:
                while raw:=f.read(1<<20):h.update(raw)
            report['captures'][path.name]=dict(bytes=path.stat().st_size,sha256=h.hexdigest(),mode=path.stat().st_mode&0o777)
        (OUT/'result.json').write_bytes(J(report))
        print(json.dumps({k:v for k,v in report.items()if k not in ('pins','module_pins','captures','traceback')},sort_keys=True),flush=True)
if __name__=='__main__':main()
