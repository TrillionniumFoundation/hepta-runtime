"""Input-only protocol controls, executed against owned buffer copies."""
from protocol import INVALID, CAPACITY, put, word

def changed(raw, at, value):
    copied=bytearray(raw);put(copied,at,value);return bytes(copied)

def initial_controls(wire,out_size,work_size):
    rows=[]
    def add(name,raw=wire,out=out_size,work=work_size,writes=()):
        rows.append((name,raw,out,work,list(writes),INVALID))
    for size in (0,1,7,8,15,31,63,127):
        add('initial-truncated-%d'%size,wire[:size])
    for at,value in ((0,0),(8,0),(8,5),(16,0),(24,0),(32,4),(40,0xffffffffffffffff),(48,0)):
        add('initial-header-%d-%d'%(at,value),changed(wire,at,value))
    for at in range(56,128,8):
        add('initial-reserved-%d'%at,changed(wire,at,1))
    add('initial-extra-byte',wire+b'\0')
    for at,value in ((128,0),(136,2),(144,2),(168,3),(184,1),(192,0),(200,63),(208,0),(216,65),(224,0),(232,65),(240,1),(248,1)):
        add('initial-Record-%d'%at,changed(wire,at,value))
    for name,out,work in (('output-8191',8191,work_size),
                          ('workspace-initial-minus-one',out_size,16384+len(wire)-1),
                          ('workspace-zero',out_size,0)):
        rows.append((name,wire,out,work,[],CAPACITY))
    return rows

def acknowledgement_controls(wire,out_size,work_size):
    rows=[]
    def add(name,raw=wire,writes=()):
        rows.append((name,raw,out_size,work_size,list(writes),INVALID))
    for at,value in ((0,0),(8,0),(16,0),(24,0),(32,99),(40,99),(48,4096),
                     (64,0xffffffffffffffff),(72,len(wire)+1)):
        add('ack-header-%d'%at,changed(wire,at,value))
    for at in range(80,128,8):
        add('ack-reserved-%d'%at,changed(wire,at,1))
    for at,value in ((0,0),(8,0),(16,0),(48,0),(56,0),(64,0),(72,99),(80,0xffffffffffffffff),
                     (160,2050),(168,2049),(176,0xffffffffffffffff),(144,4097),(456,2177),
                     (16384,0),(16432,0),(16440,1)):
        add('work-header-%d'%at,writes=((at,value),))
    add('ack-extra-byte',wire+b'\0')
    if word(wire,24)==2 and word(wire,32)==2 and word(wire,40)==0:
        for at,value in ((128,0x100000000),(136,0x100000000),(176,1),(184,1)):
            add('metadata-field-%d'%at,changed(wire,at,value))
    if word(wire,24)==3:
        add('codec-return-mismatch',changed(wire,56,word(wire,56)+1))
    return rows
