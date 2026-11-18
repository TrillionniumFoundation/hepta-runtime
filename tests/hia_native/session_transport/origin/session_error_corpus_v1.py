# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Input-only error and EventId cases; no expected values or runtime implementation."""
import itertools,json,struct
KIND_NAMES=["AddrInUse","AddrNotAvailable","AlreadyExists","ArgumentListTooLong","BrokenPipe","ConnectionAborted","ConnectionRefused","ConnectionReset","CrossesDevices","Deadlock","DirectoryNotEmpty","ExecutableFileBusy","FileTooLarge","FilesystemLoop","HostUnreachable","InProgress","Interrupted","InvalidData","InvalidFilename","InvalidInput","IsADirectory","NetworkDown","NetworkUnreachable","NotADirectory","NotConnected","NotFound","NotSeekable","Other","OutOfMemory","PermissionDenied","QuotaExceeded","ReadOnlyFilesystem","ResourceBusy","StaleNetworkFileHandle","StorageFull","TimedOut","TooManyLinks","Uncategorized","UnexpectedEof","Unsupported","WouldBlock","WriteZero"]
STABLE_KIND_NAMES=[x for x in KIND_NAMES if x not in ('FilesystemLoop','InProgress','Uncategorized')]
TEXTS=['','plain','quote"slash\\','nul\0inside','line\nbreak\rend\ttab','中文与日本語','e\u0301','é','😀','\u2028\u2029','x'*4096]
def cases():
    rows=[]
    def add(label,v):rows.append((label,v))
    ids=[0,1,9,10,255,65535,2**32-1,2**32,2**63-1,2**63,2**64-1]
    for n in ids:
        add('duplicated:'+str(n),dict(op='session_error',variant=1,id=n))
        add('closed:'+str(n),dict(op='session_error',variant=2,id=n))
    add('closed:none',dict(op='session_error',variant=2,id=None))
    for tag in (1,2):
        for kind in range(1,6):add('parse:'+str(tag)+':'+str(kind),dict(op='session_error',variant=3,event_error=tag,parse_kind=kind))
    for tag in (3,4):add('parse:'+str(tag),dict(op='session_error',variant=3,event_error=tag,parse_kind=0))
    for variant in (4,5):add('unit:'+str(variant),dict(op='session_error',variant=variant))
    for name in STABLE_KIND_NAMES:
        add('io-kind:'+name,dict(op='session_error',variant=6,io_form='kind',io_kind=name))
        for i,text in enumerate(TEXTS):
            add('io-text:'+name+':'+str(i),dict(op='session_error',variant=6,io_form='text',io_kind=name,text=text))
        for n in (1,2,3,8,32):
            add('io-source:'+name+':'+str(n),dict(op='session_error',variant=6,io_form='source',io_kind=name,chain=[TEXTS[i%len(TEXTS)]+'#'+str(i)for i in range(n)]))
    codes=sorted(set(range(-256,257))|{-2**31,-2**31+1,2**31-2,2**31-1,4095,4096,65535,65536,2**30})
    for n in codes:add('io-os:'+str(n),dict(op='session_error',variant=6,io_form='os',os_code=n))
    for n in range(1,33):
        add('event-store:'+str(n),dict(op='session_error',variant=7,chain=[TEXTS[(i+n)%len(TEXTS)]+'#'+str(i)for i in range(n)]))
    values=['','+','-','/','//','+/0','0/+','0/-','0//0','0/0/0',' 0','0 ','0\n','\0','０','١','1_0','0x10','+0','-0']
    for ch in map(chr,range(128)):values += [ch,'0'+ch,ch+'0','0/'+ch,ch+'/0']
    integers={0,1,2**64-1,2**64}
    for n in range(1,66):
        for d in (-1,0,1):integers.add(2**n+d)
    for n in range(0,25):
        for d in (-1,0,1):integers.add(max(0,10**n+d))
    for n in sorted(integers):
        raw=str(n);values += [raw,'+'+raw,'0'+raw,raw+'/0','0/'+raw,raw+'/+01']
    for left in ['','+','-','0','+00','1','18446744073709551615','18446744073709551616','9'*21,'0'*64,'0'*64+'1']:
        for right in ['','+','-','0','+1','01','18446744073709551615','18446744073709551616','1/2','x','0'*64+'1']:
            values.append(left+'/'+right)
    for n in (16,17,19,20,21,32,128,4096):
        for c in ('0','1','9'):
            for suffix in ('','x','/0','/x','/+'):
                values.append(c*n+suffix)
    for i,v in enumerate(dict.fromkeys(values)):add('event-id:'+str(i),dict(op='event_id',text=v))
    return rows
def frame(value,operation=None):
    op=2 if value['op']=='event_id' else 1
    variant=0 if op==2 else value['variant'];present=0;identity=0;event=0;parse=0;form=0;kind=0;code=0;strings=[]
    if op==2:strings=[value['text']]
    elif variant==1:present=1;identity=value['id']
    elif variant==2:
        present=int(value.get('id')is not None);identity=value.get('id')or 0
    elif variant==3:event=value['event_error'];parse=value['parse_kind']
    elif variant==6:
        form={'kind':1,'os':2,'text':3,'source':4}[value['io_form']]
        if form==2:code=value['os_code']&0xffffffff
        else:kind=KIND_NAMES.index(value['io_kind'])+1
        if form==3:strings=[value['text']]
        if form==4:strings=value['chain']
    elif variant==7:strings=value['chain']
    if operation is not None:
        op=operation;variant=0;present=0;identity=0
    body=b''.join(struct.pack('<Q',len(raw))+raw for raw in (s.encode()for s in strings))
    return b'HRSEQ001'+struct.pack('<15Q',op,variant,present,identity,event,parse,form,kind,code,len(strings),len(body),0,0,0,0)+body
